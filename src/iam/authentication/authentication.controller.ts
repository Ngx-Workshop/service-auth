import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Put,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import { ActiveUser } from '../decorators/active-user.decorator';
import { Auth } from '../decorators/auth.decorator';
import { Roles } from '../decorators/role.decorator';
import { AuthType } from '../enums/auth-type.enum';
import { Role } from '../enums/role.enum';
import { IActiveUserData } from '../interfaces/active-user-data.interface';
import { AuthenticationService } from './authentication.service';
import { RoleDto } from './dto/role.dto';
import { UserAuthDto } from './dto/user-auth.dto';

const cookieOptions = {
  domain: process.env.DOMAIN || 'localhost',
  secure: process.env.NODE_ENV === 'production',
  httpOnly: true,
  sameSite: true,
};

@Controller()
export class AuthenticationController {
  constructor(private readonly authService: AuthenticationService) {}

  @Post('sign-up')
  @Auth(AuthType.None)
  async signUp(
    @Res({ passthrough: true }) response: Response,
    @Body() userAuthDto: UserAuthDto,
  ) {
    await this.authService.signUp(userAuthDto);
    const jwt = await this.authService.signIn(userAuthDto);
    response.cookie('accessToken', jwt.accessToken, cookieOptions);
  }

  @Post('sign-in')
  @Auth(AuthType.None)
  @HttpCode(HttpStatus.OK)
  async signIn(
    @Res({ passthrough: true }) response: Response,
    @Body() userAuthDto: UserAuthDto,
  ) {
    const jwt = await this.authService.signIn(userAuthDto);
    response.cookie('accessToken', jwt.accessToken, cookieOptions);
  }

  @Get('sign-out')
  @Auth(AuthType.None)
  @HttpCode(HttpStatus.OK)
  async signOut(@Res({ passthrough: true }) response: Response) {
    response.clearCookie('accessToken');
    response.end();
  }

  @Get('validate-access-token')
  @Roles(Role.Admin, Role.Regular, Role.Publisher)
  @HttpCode(HttpStatus.OK)
  isLoggedIn(): boolean {
    return true;
  }

  @Get('user-metadata')
  @Roles(Role.Admin, Role.Regular, Role.Publisher)
  @HttpCode(HttpStatus.OK)
  async getUserMetadata(@ActiveUser() user: IActiveUserData) {
    return {
      email: user.email,
      role: user.role,
    };
  }

  @Put('role')
  @Roles(Role.Admin)
  @HttpCode(HttpStatus.OK)
  async updateUserRole(@Body() role: RoleDto) {
    return this.authService.updateUserRole(role);
  }

  // Let's think about the need of refresh-tokens
  // @HttpCode(HttpStatus.OK)
  // @Post('refresh-tokens')
  // async refreshTokens(
  //   @Res({ passthrough: true }) response: Response,
  //   @Body() refreshTokenDto: RefreshTokenDto,
  // ): Promise<void> {
  //   const jwt = await this.authService.refreshTokens(refreshTokenDto);
  //   response.cookie('accessToken', jwt.accessToken, cookieOptions);
  //   response.cookie('refreshToken', jwt.refreshToken, cookieOptions);
  // }
}
