import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { IamModule } from './iam/iam.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        uri: config.get<string>('MONGODB_URI'),
        ...(config.get<string>('RUNTIME_PROFILE') === 'production'
          ? { autoIndex: false, autoCreate: false }
          : {}),
        ...(config.get<string>('RUNTIME_PROFILE') === 'production' &&
        config.get<string>('OAUTH_ENABLED') === 'true'
          ? { tls: true, tlsCAFile: config.get<string>('MONGODB_TLS_CA_FILE') }
          : {}),
        serverSelectionTimeoutMS: 5000, // Timeout in 5 seconds
        ...(config.get<string>('OAUTH_ENABLED') === 'true'
          ? { socketTimeoutMS: 5000, connectTimeoutMS: 5000 }
          : {}),
      }),
    }),
    IamModule,
  ],
})
export class AppModule {}
