import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { AuthClientService } from './ngx-auth-client.service';
import { RemoteAuthGuard } from './ngx-remote-auth.guard';
import { RolesGuard } from './roles.guard';

@Module({
  imports: [HttpModule],
  providers: [AuthClientService, RemoteAuthGuard, RolesGuard],
  exports: [AuthClientService, RemoteAuthGuard, RolesGuard],
})
export class NgxAuthClientModule {}
