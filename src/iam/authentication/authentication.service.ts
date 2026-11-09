import { localAdminMode } from '../../local-admin-development';
import {
  ConflictException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import axios from 'axios';
import { Model, Types } from 'mongoose';
import jwtConfig from '../config/jwt.config';
import { MongoErrorCodes } from '../enums/mongo-error-codes.enum';
import { HashingService } from '../hashing/hashing.service';
import { IActiveUserData } from '../interfaces/active-user-data.interface';
import { IUser } from '../interfaces/user.interface';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RoleDto } from './dto/role.dto';
import { AdminCreateUserDto } from './dto/admin-create-user.dto';
import { UserAuthDto } from './dto/user-auth.dto';
import { User, UserDocument } from './schemas/user.schema';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
    private readonly hashService: HashingService,
    private readonly jwtService: JwtService,
  ) {}

  private oauthDummyHash: string;

  async onModuleInit() {
    this.oauthDummyHash = await this.hashService.hash(
      'oauth-timing-placeholder',
    );
  }

  private readonly logger = new Logger(AuthenticationService.name);
  private readonly metadataClient = axios.create({
    baseURL: localAdminMode()
      ? 'http://127.0.0.1:3004'
      : process.env.USER_METADATA_URL,
    timeout: 3000,
  });

  async ensureUserMetadata({ _id: uuid }: IUser, accessToken) {
    try {
      await this.metadataClient.put(
        `/user-metadata`,
        { uuid },
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );
    } catch {
      // Keep bearer headers out of logs when the metadata service is unavailable.
      this.logger.warn(`Failed to upsert UserMetadata for ${uuid}`);
    }
  }

  async provisionUser(dto: AdminCreateUserDto, actor: string) {
    const email = dto.email.trim().toLowerCase();
    const previous = await this.userModel.findOne({
      provisioningRequestId: dto.requestId,
    });
    const result = (user: UserDocument) => {
      if (
        user.provisioningActor !== actor ||
        user.email !== email ||
        user.role !== dto.role
      )
        throw new ConflictException(
          'Creation request conflicts with an existing account',
        );
      return { uuid: String(user._id), email: user.email, role: user.role };
    };
    if (previous) return result(previous);
    try {
      const user = await this.userModel.create({
        email,
        role: dto.role,
        password: await this.hashService.hash(dto.password),
        provisioningRequestId: dto.requestId,
        provisioningActor: actor,
      });
      return result(user);
    } catch (error) {
      if (error.code === MongoErrorCodes.DuplicateKey) {
        const retry = await this.userModel.findOne({
          provisioningRequestId: dto.requestId,
        });
        if (retry) return result(retry);
        throw new ConflictException('Email already exists');
      }
      throw error;
    }
  }

  async signUp(userAuthDto: UserAuthDto): Promise<IUser> {
    try {
      const user = new User();
      user.email = userAuthDto.email;
      user.password = await this.hashService.hash(userAuthDto.password);

      const created = await this.userModel.create(user);
      return created;
    } catch (error) {
      if (error.code === MongoErrorCodes.DuplicateKey) {
        throw new ConflictException('Email already exists');
      }
      throw error;
    }
  }

  async signIn(
    userAuthDto: UserAuthDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const user = await this.userModel.findOne({ email: userAuthDto.email });
    if (!user) throw new UnauthorizedException('User not found');
    if (!user.password) throw new UnauthorizedException('Invalid credentials');

    const isPasswordValid = await this.hashService.compare(
      userAuthDto.password,
      user.password,
    );
    if (!isPasswordValid) throw new UnauthorizedException('Invalid password');

    return await this.generateTokens(user);
  }

  // OAuth uses the same account and password verifier, without minting legacy JWTs.
  async authenticateOAuth(
    email: string,
    password: string,
  ): Promise<string | undefined> {
    const user = await this.userModel.findOne({ email }).maxTimeMS(3000).exec();
    const valid = await this.hashService.compare(
      password,
      user?.password ?? this.oauthDummyHash,
    );
    if (!user?.password || !valid) return undefined;
    return String(user._id);
  }

  async findOAuthAccount(id: string): Promise<boolean> {
    if (!Types.ObjectId.isValid(id)) return false;
    return !!(await this.userModel
      .exists({ _id: new Types.ObjectId(id) })
      .maxTimeMS(3000));
  }

  // Called only after the server has validated the provider response.
  async signInExternal(provider: string, subject: string, email: string) {
    const identity = `${provider}:${subject}`;
    let user = await this.userModel.findOne({ externalIdentities: identity });
    if (!user) {
      // Never merge by email: an existing password or different provider account
      // must prove ownership in a future explicit linking flow.
      if (await this.userModel.exists({ email }))
        throw new ConflictException('Account linking required');
      try {
        user = await this.userModel.create({
          email,
          externalIdentities: [identity],
        });
      } catch (error) {
        if (error.code !== MongoErrorCodes.DuplicateKey) throw error;
        user = await this.userModel.findOne({ externalIdentities: identity });
        if (!user) throw new ConflictException('Account linking required');
      }
    }
    const tokens = await this.generateTokens(user);
    // Retry the idempotent metadata upsert on every social login after outages.
    await this.ensureUserMetadata(user, tokens.accessToken);
    return tokens;
  }

  async refreshTokens(refreshTokenDto: RefreshTokenDto) {
    try {
      const { sub } = await this.jwtService.verifyAsync<
        Pick<IActiveUserData, 'sub'>
      >(refreshTokenDto.refreshToken, {
        secret: this.jwtConfiguration.secret,
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
      });

      const user = await this.userModel
        .findById(new Types.ObjectId(sub))
        .exec();
      return await this.generateTokens(user as IUser);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private async generateTokens(user: IUser) {
    const [accessToken, refreshToken] = await Promise.all([
      this.signToken<Partial<IActiveUserData>>(
        user._id,
        this.jwtConfiguration.accessTokenTtl,
        { email: user.email, role: user.role },
      ),
      this.signToken(user._id, this.jwtConfiguration.refreshTokenTtl),
    ]);

    return { accessToken, refreshToken };
  }

  private async signToken<T>(userId: string, expiresIn: number, payload?: T) {
    return await this.jwtService.signAsync(
      { sub: userId, ...payload },
      {
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
        secret: this.jwtConfiguration.secret,
        expiresIn,
      },
    );
  }

  async updateUserRole({ userId, role }: RoleDto) {
    const updatedRole = await this.userModel
      .findByIdAndUpdate(
        new Types.ObjectId(userId),
        { role },
        { new: true, runValidators: true },
      )
      .exec();
    this.logger.log(
      `Updated user role: ${updatedRole?._id} -> ${updatedRole?.role}`,
    );
    return updatedRole;
  }
}
