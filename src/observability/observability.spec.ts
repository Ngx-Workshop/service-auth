import type { Server } from 'node:http';
import {
  Controller,
  Get,
  INestApplication,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
// eslint-disable-next-line @typescript-eslint/no-require-imports -- Match callable Supertest in CommonJS service builds.
import request = require('supertest');
import { ObservabilityModule } from './observability.module';
import {
  createServiceLogger,
  httpLoggingMiddleware,
  logOperation,
} from './observability';

const domainLogger = {
  log: jest.fn<void, [unknown]>(),
  warn: jest.fn<void, [unknown]>(),
  error: jest.fn<void, [unknown]>(),
};

@Controller('items')
class TestController {
  @Get(':id')
  async get() {
    return logOperation(domainLogger, 'auth_password_sign_in', async () => {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      return { ok: true };
    });
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
    expect(domainLogger.log).not.toHaveBeenCalled();
    await request(app.getHttpServer()).head('/health').expect(200);
    expect(log).not.toHaveBeenCalled();
    expect(domainLogger.log).not.toHaveBeenCalled();
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

  it('isolates concurrent async domain context and ignores untrusted incoming IDs', async () => {
    const incoming = '00000000-0000-4000-8000-000000000001';
    const responses = await Promise.all([
      request(app.getHttpServer())
        .get('/items/one')
        .set('X-Request-ID', incoming),
      request(app.getHttpServer())
        .get('/items/two')
        .set('X-Request-ID', 'canary-content'),
    ]);
    const ids: unknown[] = responses.map((r) => r.headers['x-request-id']);
    expect(new Set(ids).size).toBe(2);
    expect(ids).not.toContain(incoming);
    expect(domainLogger.log).toHaveBeenCalledTimes(2);
    for (const requestId of ids) {
      expect(domainLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          requestId,
          event: 'auth_password_sign_in',
          outcome: 'success',
          durationMs: expect.any(Number) as unknown,
          operationId: expect.stringMatching(/^[0-9a-f-]{36}$/) as unknown,
        }),
      );
    }
    expect(JSON.stringify(domainLogger.log.mock.calls)).not.toContain('canary');
    await logOperation(domainLogger, 'auth_role_update', () =>
      Promise.resolve(null),
    );
    expect(domainLogger.log).toHaveBeenLastCalledWith(
      expect.objectContaining({ outcome: 'not_found' }),
    );
    const last: unknown = domainLogger.log.mock.calls.at(-1)?.[0];
    expect(last).not.toHaveProperty('requestId');
  });

  it('logs native JSON success and failure without result or exception content', async () => {
    const writes: string[] = [];
    const stdout = jest
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk) => {
        writes.push(String(chunk));
        return true;
      });
    const stderr = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk) => {
        writes.push(String(chunk));
        return true;
      });
    try {
      const logger = createServiceLogger();
      logger.setContext('DomainTest');
      await logOperation(logger, 'auth_role_update', () =>
        Promise.resolve('canary-result'),
      );
      const denied = new UnauthorizedException('canary-password');
      await expect(
        logOperation(logger, 'auth_password_sign_in', () =>
          Promise.reject(denied),
        ),
      ).rejects.toBe(denied);
      const failure = new Error('canary-token');
      await expect(
        logOperation(logger, 'auth_role_update', () => Promise.reject(failure)),
      ).rejects.toBe(failure);
      const entries = writes.map((line): unknown => JSON.parse(line));
      expect(entries).toEqual([
        expect.objectContaining({
          level: 'log',
          context: 'DomainTest',
          message: expect.objectContaining({ outcome: 'success' }) as unknown,
        }),
        expect.objectContaining({
          level: 'warn',
          context: 'DomainTest',
          message: expect.objectContaining({ outcome: 'rejected' }) as unknown,
        }),
        expect.objectContaining({
          level: 'error',
          context: 'DomainTest',
          message: expect.objectContaining({ outcome: 'failure' }) as unknown,
        }),
      ]);
      expect(writes.join('')).not.toContain('canary');
    } finally {
      stdout.mockRestore();
      stderr.mockRestore();
    }
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
