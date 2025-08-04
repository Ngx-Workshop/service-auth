import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { AuthClientService } from './ngx-auth-client.service';

@Injectable()
export class RemoteAuthGuard implements CanActivate {
  constructor(private authClientService: AuthClientService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    return this.authClientService.validateAccessToken(request);
  }
}
