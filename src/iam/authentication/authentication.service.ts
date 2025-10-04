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

  private readonly logger = new Logger(AuthenticationService.name);
  private readonly metadataClient = axios.create({
    baseURL: process.env.USER_METADATA_URL, // Used VPC
    timeout: 3000,
  });

  async ensureUserMetadata({ _id: uuid }: IUser, accessToken) {
    try {
      await this.metadataClient.put(
        `/user-metadata`,
        { uuid },
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );
    } catch (err) {
      // Non-blocking on purpose
      this.logger.warn(`Failed to upsert UserMetadata for ${uuid}`, err);
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

    const isPasswordValid = await this.hashService.compare(
      userAuthDto.password,
      user.password,
    );
    if (!isPasswordValid) throw new UnauthorizedException('Invalid password');

    return await this.generateTokens(user);
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

  async updateUserRole({ id, role }: RoleDto) {
    const updatedRole = await this.userModel
      .findByIdAndUpdate(id, { role }, { new: true, runValidators: true })
      .exec();
    this.logger.log(
      `Updated user role: ${updatedRole?._id} -> ${updatedRole?.role}`,
    );
    return updatedRole;
  }
}
