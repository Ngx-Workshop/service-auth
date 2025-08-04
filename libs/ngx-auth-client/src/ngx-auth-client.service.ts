import { Injectable, UnauthorizedException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { Request } from 'express';

@Injectable()
export class AuthClientService {
  constructor(private httpService: HttpService) {}

  async validateAccessToken(request: Request): Promise<boolean> {
    // Grab token from cookies or headers as your guard does
    const accessToken = request.cookies?.accessToken || request.headers['authorization']?.replace('Bearer ', '');
    if (!accessToken) {
      throw new UnauthorizedException('No access token found');
    }
    try {
      // Hit the auth service endpoint
      const res = await firstValueFrom(
        this.httpService.get('http://ngx-auth-service:3000/is-user-logged-in', {
          headers: {
            Cookie: `accessToken=${accessToken}`,
          },
          // You could also send as Bearer if your auth service supports it
        })
      );
      return res.data === true;
    } catch (err) {
      throw new UnauthorizedException('Invalid access token');
    }
  }
}