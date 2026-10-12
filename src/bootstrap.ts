import { NestExpressApplication } from '@nestjs/platform-express';
import { NestFactory } from '@nestjs/core';
import { getConnectionToken } from '@nestjs/mongoose';
import { Connection } from 'mongoose';
import { AppModule } from './app.module';
import { AuthenticationService } from './iam/authentication/authentication.service';
import * as cookieParser from 'cookie-parser';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

// Native import is required: the protocol engine is ESM, the Nest build is CJS.
// eslint-disable-next-line @typescript-eslint/no-require-imports -- Native ESM loader is packaged as CommonJS.
const loadNative = require('./oauth/loader.cjs') as (url: string) => Promise<{
  loadConfig?: () => Promise<
    { issuer: string; runtime: { bind: string } } | undefined
  >;
  installOAuth?: (
    app: unknown,
    connection: Connection,
    auth: AuthenticationService,
    config: unknown,
  ) => Promise<unknown>;
}>;

export async function createAuthApp() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bodyParser: false,
  });
  try {
    const configModule = await loadNative(
      pathToFileURL(join(__dirname, 'oauth/config.mjs')).href,
    );
    const config = await configModule.loadConfig!();
    if (config) {
      const engine = await loadNative(
        pathToFileURL(join(__dirname, 'oauth/provider.mjs')).href,
      );
      await engine.installOAuth!(
        app,
        app.get<Connection>(getConnectionToken()),
        app.get(AuthenticationService),
        config,
      );
    }
    app.use(cookieParser());
    app.useBodyParser('json');
    app.useBodyParser('urlencoded', { extended: true });
    return { app, host: config ? config.runtime.bind : '0.0.0.0' };
  } catch (error) {
    await app.close();
    throw error;
  }
}
