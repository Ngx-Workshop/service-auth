import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { AuthenticationGuard } from './authentication.guard';
import { AuthClientService } from './ngx-auth-client.service';
import { RemoteAuthGuard } from './ngx-remote-auth.guard';
import { RolesGuard } from './roles.guard';

@Module({
  imports: [HttpModule],
  providers: [
    AuthClientService,
    AuthenticationGuard,
    RemoteAuthGuard,
    RolesGuard,
  ],
  exports: [
    AuthClientService,
    AuthenticationGuard,
    RemoteAuthGuard,
    RolesGuard,
  ],
})
export class NgxAuthClientModule {}
