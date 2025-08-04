import { Module } from '@nestjs/common';
import { AuthClientService } from './ngx-auth-client.service';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [HttpModule],
  providers: [AuthClientService],
  exports: [AuthClientService],
})
export class NgxAuthClientModule {}

