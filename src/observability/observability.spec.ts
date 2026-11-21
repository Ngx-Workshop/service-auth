import type { Server } from 'node:http';
import { Controller, Get, INestApplication, Logger } from '@nestjs/common';
import { Test } from '@nestjs/testing';
// eslint-disable-next-line @typescript-eslint/no-require-imports -- Match callable Supertest in CommonJS service builds.
import request = require('supertest');
import { ObservabilityModule } from './observability.module';
import { createServiceLogger, httpLoggingMiddleware } from './observability';

@Controller('items')
class TestController {
  @Get(':id')
  get() {
    return { ok: true };
  }
}

describe('Service observability', () => {
  let app: INestApplication<Server>;
  const log = jest.fn();
  const warn = jest.fn();
  const error = jest.fn();

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [ObservabilityModule],
      controllers: [TestController],
    }).compile();
    app = module.createNestApplication({ logger: false });
    app.use(httpLoggingMiddleware({ log, warn, error } as unknown as Logger));
    await app.init();
  });
  afterAll(async () => {
    await app.close();
  });
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('serves an anonymous, non-cached heartbeat without database or auth providers', async () => {
    const response = await request(app.getHttpServer())
      .get('/health')
      .expect(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body).toEqual({
      status: 'ok',
      info: { heartbeat: { status: 'up' } },
      error: {},
      details: { heartbeat: { status: 'up' } },
    });
    expect(log).not.toHaveBeenCalled();
  });

  it('logs route templates and timings without request data or concrete identifiers', async () => {
    const response = await request(app.getHttpServer())
      .get('/items/private-person?token=private-query')
      .set('Authorization', 'Bearer private-auth')
      .set('Cookie', 'session=private-cookie')
      .expect(200);
    expect(response.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'http_request',
        method: 'GET',
        route: '/items/:id',
        statusCode: 200,
        durationMs: expect.any(Number) as unknown,
        requestId: response.headers['x-request-id'],
      }),
    );
    expect(JSON.stringify(log.mock.calls)).not.toContain('private-');
  });

  it('logs unknown routes without their raw paths or query values', async () => {
    await request(app.getHttpServer())
      .get('/private-missing?secret=private-query')
      .expect(404);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ route: '/unmatched', statusCode: 404 }),
    );
    expect(JSON.stringify(warn.mock.calls)).not.toContain('private-');
  });

  it('does not provide a write endpoint for heartbeat', async () => {
    await request(app.getHttpServer())
      .post('/health')
      .send({ secret: 'private-body' })
      .expect(404);
    expect(warn).toHaveBeenCalled();
    expect(JSON.stringify(warn.mock.calls)).not.toContain('private-body');
  });

  it('uses native Nest JSON logging with a contextual, structured message', () => {
    const write = jest
      .spyOn(process.stdout, 'write')
      .mockImplementation(() => true);
    try {
      createServiceLogger().log({ event: 'test_event' }, 'ObservabilityTest');
      expect(write).toHaveBeenCalled();
      const entry: unknown = JSON.parse(String(write.mock.calls[0][0]));
      expect(entry).toEqual(
        expect.objectContaining({
          level: 'log',
          context: 'ObservabilityTest',
          message: { event: 'test_event' },
        }),
      );
    } finally {
      write.mockRestore();
    }
  });
});
