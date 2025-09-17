import { HttpService } from '@nestjs/axios';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { firstValueFrom } from 'rxjs';
import { RequestKeys } from './enums/request-keys.enum';
import { IActiveUserData } from './interfaces/active-user-data.interface';

function decodeJwtPayload(token: string): Partial<IActiveUserData> | undefined {
  try {
    const [, payloadB64] = token.split('.');
    if (!payloadB64) return undefined;
    const json = Buffer.from(payloadB64, 'base64url').toString('utf8');
    const payload = JSON.parse(json);
    // Normalize to the shape our decorators expect
    return {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
    } as Partial<IActiveUserData>;
  } catch {
    return undefined;
  }
}

@Injectable()
export class AuthClientService {
  constructor(private httpService: HttpService) {}

  private readonly baseUrl =
    process.env.AUTH_BASE_URL ?? 'https://auth.ngx-workshop.io';
  async validateAccessToken(request: Request): Promise<boolean> {
    // Grab token from cookies or headers as your guard does
    const rawAuth = Array.isArray(request.headers['authorization'])
      ? request.headers['authorization'][0]
      : request.headers['authorization'];
    const headerToken = rawAuth?.toString().startsWith('Bearer ')
      ? rawAuth.toString().slice(7).trim()
      : undefined;
    const accessToken = request.cookies?.accessToken || headerToken;
    if (!accessToken) {
      throw new UnauthorizedException('No access token found');
    }
    try {
      // Hit the auth service endpoint
      const res = await firstValueFrom(
        this.httpService.get(`${this.baseUrl}/validate-access-token`, {
          headers: {
            Cookie: `accessToken=${accessToken}`,
            Authorization: `Bearer ${accessToken}`,
          },
          // You could also send as Bearer if your auth service supports it
        }),
      );
      // return res.data === true;
      if (res.data === true) {
        const payload = decodeJwtPayload(accessToken);
        if (payload) {
          (request as any)[RequestKeys.REQUEST_USER_KEY] = payload;
        }
        return true;
      }
      throw new UnauthorizedException('Invalid access token');
    } catch (err) {
      throw new UnauthorizedException('Invalid access token');
    }
  }
}
