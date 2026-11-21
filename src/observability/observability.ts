import { ConsoleLogger, INestApplication, Logger } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

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
    next();
  };
}

export function configureObservability(app: INestApplication): void {
  app.use(httpLoggingMiddleware());
  app.enableShutdownHooks();
}
