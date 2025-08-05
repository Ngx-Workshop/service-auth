import { Module } from '@nestjs/common';
import { AuthClientService } from './ngx-auth-client.service';
import { HttpModule } from '@nestjs/axios';
import { RemoteAuthGuard } from './ngx-remote-auth.guard';

@Module({
  imports: [HttpModule],
  providers: [AuthClientService, RemoteAuthGuard],
  exports: [AuthClientService, RemoteAuthGuard],
})
export class NgxAuthClientModule {}

