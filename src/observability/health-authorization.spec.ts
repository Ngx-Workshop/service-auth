import type { Server } from 'node:http';
import { AuthenticationGuard } from '../iam/authentication/guards/authentication.guard';
import {
  Controller,
  Get,
  INestApplication,
  UnauthorizedException,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
// eslint-disable-next-line @typescript-eslint/no-require-imports -- Match callable Supertest in CommonJS service builds.
import request = require('supertest');
import { ObservabilityModule } from './observability.module';

@Controller('protected-observability-test')
class ProtectedController {
  @Get() get() {
    return { secret: true };
  }
}

describe('Heartbeat authorization boundary', () => {
  let app: INestApplication<Server>;
  const denied = jest.fn(() => {
    throw new UnauthorizedException();
  });
  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [ObservabilityModule],
      controllers: [ProtectedController],
    }).compile();
    app = module.createNestApplication({ logger: false });
    app.useGlobalGuards(
      new AuthenticationGuard(new Reflector(), {
        canActivate: denied,
      } as unknown as ConstructorParameters<typeof AuthenticationGuard>[1]),
    );
    await app.init();
  });
  afterAll(async () => {
    await app.close();
  });
  it('allows heartbeat but still enforces authentication for business routes', async () => {
    await request(app.getHttpServer()).get('/health').expect(200);
    expect(denied).not.toHaveBeenCalled();
    await request(app.getHttpServer())
      .get('/protected-observability-test')
      .expect(401);
    expect(denied).toHaveBeenCalledTimes(1);
  });
});
