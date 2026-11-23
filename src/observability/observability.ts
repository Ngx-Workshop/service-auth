import {
  ConsoleLogger,
  HttpException,
  INestApplication,
  Logger,
} from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

const requestContext = new AsyncLocalStorage<{ requestId: string }>();

type DomainEvent =
  | 'auth_password_sign_in'
  | 'auth_role_update'
  | 'user_metadata_upsert';

export async function logOperation<T>(
  logger: Pick<Logger, 'log' | 'warn' | 'error'>,
  event: DomainEvent,
  work: () => Promise<T>,
  failureLevel: 'warn' | 'error' = 'error',
): Promise<T> {
  const started = process.hrtime.bigint();
  const operationId = randomUUID();
  const requestId = requestContext.getStore()?.requestId;
  const entry = (outcome: string) => ({
    event,
    outcome,
    operationId,
    ...(requestId ? { requestId } : {}),
    durationMs: Math.round(Number(process.hrtime.bigint() - started) / 1e6),
  });
  try {
    const result = await work();
    logger.log(entry(result === null ? 'not_found' : 'success'));
    return result;
  } catch (error) {
    const rejected = error instanceof HttpException && error.getStatus() < 500;
    logger[rejected ? 'warn' : failureLevel](
      entry(rejected ? 'rejected' : 'failure'),
    );
    throw error;
  }
}

export function createServiceLogger(): ConsoleLogger {
  return new ConsoleLogger({
    json: true,
    colors: false,
    logLevels: ['log', 'warn', 'error', 'fatal'],
  });
}

export function httpLoggingMiddleware(logger = new Logger('HTTP')) {
  return (request: Request, response: Response, next: NextFunction): void => {
    // Heartbeats are represented by probe metrics, not repetitive access logs.
    if (
      request.path === '/health' &&
      ['GET', 'HEAD'].includes(request.method)
    ) {
      next();
      return;
    }
    const requestId = randomUUID();
    const started = process.hrtime.bigint();
    response.setHeader('X-Request-ID', requestId);
    response.once('finish', () => {
      const route = request.route as { path?: unknown } | undefined;
      const entry = {
        event: 'http_request',
        requestId,
        method: request.method,
        // Never export concrete paths, queries, bodies, cookies or auth headers.
        route: typeof route?.path === 'string' ? route.path : '/unmatched',
        statusCode: response.statusCode,
        durationMs: Math.round(Number(process.hrtime.bigint() - started) / 1e6),
      };
      if (entry.statusCode >= 500) logger.error(entry);
      else if (entry.statusCode >= 400) logger.warn(entry);
      else logger.log(entry);
    });
    requestContext.run({ requestId }, next);
  };
}

export function configureObservability(app: INestApplication): void {
  app.use(httpLoggingMiddleware());
  app.enableShutdownHooks();
}
