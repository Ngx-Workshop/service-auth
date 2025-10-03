import { HttpService } from '@nestjs/axios';
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { firstValueFrom } from 'rxjs';
import { RequestKeys } from './enums/request-keys.enum';
import { Role } from './enums/role.enum';
import { IActiveUserData } from './interfaces/active-user-data.interface';

function decodeJwtPayload(token: string): Partial<IActiveUserData> | undefined {
  try {
    const [, payloadB64] = token.split('.');
    if (!payloadB64) return undefined;

    // base64url -> base64 for broad Node compatibility
    const base64 = payloadB64
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(Math.ceil(payloadB64.length / 4) * 4, '=');
    const json = Buffer.from(base64, 'base64').toString('utf8');
    const payload = JSON.parse(json);

    return {
      sub: payload.sub,
      email:
        payload.email ??
        payload['email_address'] ??
        payload['preferred_username'],
      role: payload.role,
    };
  } catch {
    return undefined;
  }
}

function getAccessTokenFromRequest(request: Request): string | undefined {
  const hdr = (
    Array.isArray(request.headers.authorization)
      ? request.headers.authorization[0]
      : request.headers.authorization
  ) as string | undefined;

  const fromHeader = hdr?.startsWith('Bearer ')
    ? hdr.slice(7).trim()
    : undefined;
  return request.cookies?.accessToken || fromHeader;
}

@Injectable()
export class AuthClientService {
  logger = new Logger(AuthClientService.name);
  constructor(private httpService: HttpService) {}

  private readonly baseUrl =
    process.env.AUTH_BASE_URL ?? 'https://auth.ngx-workshop.io';

  async validateAccessToken(request: Request): Promise<boolean> {
    const accessToken = getAccessTokenFromRequest(request);
    if (!accessToken) throw new UnauthorizedException('No access token found');

    try {
      const res = await firstValueFrom(
        this.httpService.get(`${this.baseUrl}/validate-access-token`, {
          headers: {
            Cookie: `accessToken=${accessToken}`,
            Authorization: `Bearer ${accessToken}`,
          },
        }),
      );

      if (res.data !== true)
        throw new UnauthorizedException('Invalid access token');

      this.logger.debug('This is the token: ' + accessToken);
      // Decode locally to keep all claims, including email
      const payload = decodeJwtPayload(accessToken);
      if (!payload?.sub)
        throw new UnauthorizedException('Invalid token payload');

      const existing = (request as any)[RequestKeys.REQUEST_USER_KEY] as
        | Partial<IActiveUserData>
        | undefined;

      const merged: IActiveUserData = {
        sub: existing?.sub ?? payload.sub!,
        email: existing?.email ?? payload.email ?? 'NOTHING_TO_SEE_HERE',
        role: existing?.role ?? payload.role ?? Role.Regular,
      };

      (request as any)[RequestKeys.REQUEST_USER_KEY] = merged;

      // Optionally also mirror onto req.user for other middleware
      if (!(request as any).user) (request as any).user = merged;

      return true;
    } catch {
      throw new UnauthorizedException('Invalid access token');
    }
  }
}
