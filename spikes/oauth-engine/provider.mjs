import 'reflect-metadata';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import Provider, { errors } from 'oidc-provider';
import { createAdapter, digest, transactions } from './mongo-adapter.mjs';

// Exercise the same CommonJS->ESM seam needed by the NestJS service.
const require = createRequire(import.meta.url);
const { NestFactory } = require('@nestjs/core');
const { Module } = require('@nestjs/common');
const resource = 'http://127.0.0.1:3011/mcp';
const redirect = 'http://127.0.0.1:39999/callback';
export const RESOURCE = resource;
export const REDIRECT = redirect;
export const SUBJECT = 'oauth-spike-user';
export const PUBLIC_CLIENT = 'oauth-spike-public';
export const SERVICE_CLIENT = 'oauth-spike-resource-server';
export const OTHER_CLIENT = 'oauth-spike-other-resource-server';
export const OTHER_PUBLIC_CLIENT = 'oauth-spike-other-public';
export const METADATA_CLIENT =
  'https://mcp-client.example.test/oauth-client.json';
// Random fixture-only credentials. Never emitted to logs.
export const SERVICE_SECRET = randomBytes(32).toString('base64url');
export const OTHER_SECRET = randomBytes(32).toString('base64url');

export async function startProvider(fixture, options = {}) {
  class SpikeModule {}
  Module({})(SpikeModule);
  const app = await NestFactory.create(SpikeModule, {
    bodyParser: false,
    logger: false,
  });
  let callback;
  app.use((req, res) => callback(req, res));
  await app.listen(options.port ?? 0, '127.0.0.1');
  const port = app.getHttpServer().address().port;
  const issuer = `http://127.0.0.1:${port}`;
  const key = options.key ?? randomBytes(32);
  const faults = options.faults ?? {};
  try {
    const provider = new Provider(issuer, {
      adapter: createAdapter(fixture.db, key, faults),
      jwks: {
        keys: [
          {
            ...generateKeyPairSync('rsa', {
              modulusLength: 2048,
            }).privateKey.export({ format: 'jwk' }),
            kid: 'spike-only',
            use: 'sig',
            alg: 'RS256',
          },
        ],
      },
      ...(options.metadata
        ? {
            fetch: options.metadata.fetch,
          }
        : {}),
      clients: [
        {
          client_id: OTHER_PUBLIC_CLIENT,
          redirect_uris: [redirect],
          response_types: ['code'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'none',
          scope: 'catalog:read',
        },
        {
          client_id: PUBLIC_CLIENT,
          redirect_uris: [redirect],
          response_types: ['code'],
          grant_types: ['authorization_code'],
          token_endpoint_auth_method: 'none',
          scope: 'catalog:read',
        },
        {
          client_id: SERVICE_CLIENT,
          client_secret: SERVICE_SECRET,
          redirect_uris: [],
          response_types: [],
          grant_types: [],
          token_endpoint_auth_method: 'client_secret_basic',
        },
        {
          client_id: OTHER_CLIENT,
          client_secret: OTHER_SECRET,
          redirect_uris: [],
          response_types: [],
          grant_types: [],
          token_endpoint_auth_method: 'client_secret_basic',
        },
      ],
      scopes: ['catalog:read'],
      responseTypes: ['code'],
      clockTolerance: 0,
      ttl: {
        AuthorizationCode: 60,
        AccessToken: 600,
        Interaction: 600,
        Grant: 600,
        Session: 600,
      },
      formats: { bitsOfOpaqueRandomness: 256 },
      cookies: { keys: [randomBytes(32).toString('base64url')] },
      routes: {
        authorization: '/oauth/authorize',
        token: '/oauth/token',
        introspection: '/oauth/introspect',
        revocation: '/oauth/revoke',
      },
      pkce: { required: () => true },
      allowOmittingSingleRegisteredRedirectUri: false,
      features: {
        ...(options.metadata
          ? {
              clientIdMetadataDocument: {
                enabled: true,
                ack: 'draft-02',
                allowFetch: (_ctx, id) => id === METADATA_CLIENT,
                allowClient: (_ctx, client) =>
                  client.clientId === METADATA_CLIENT &&
                  client.clientAuthMethod === 'none' &&
                  client.redirectUris.length === 1 &&
                  client.redirectUris[0] === redirect &&
                  client.grantTypes.length === 1 &&
                  client.grantTypeAllowed('authorization_code'),
              },
            }
          : {}),
        devInteractions: { enabled: false },
        userinfo: { enabled: false },
        registration: { enabled: false },
        introspection: {
          enabled: true,
          allowedPolicy: (_ctx, client, token) =>
            client.clientId === SERVICE_CLIENT &&
            token.kind === 'AccessToken' &&
            token.aud === resource,
        },
        revocation: {
          enabled: true,
          allowedPolicy: (_ctx, client, token) =>
            client.clientId === token.clientId,
        },
        resourceIndicators: {
          enabled: true,
          defaultResource: () => {
            throw new errors.InvalidTarget('resource is required');
          },
          useGrantedResource: () => false,
          getResourceServerInfo: (ctx, value) => {
            if (
              ctx.oidc.route === 'token' &&
              ctx.oidc.params.resource !== resource
            )
              throw new errors.InvalidTarget('exact resource is required');
            if (
              (ctx.oidc.route === 'token' &&
                ctx.oidc.body.scope !== undefined) ||
              (ctx.oidc.params.scope &&
                ctx.oidc.params.scope !== 'catalog:read')
            )
              throw new errors.InvalidScope(
                'only consented catalog scope allowed',
              );
            if (value !== resource)
              throw new errors.InvalidTarget('unknown resource');
            return {
              scope: 'catalog:read',
              audience: resource,
              accessTokenTTL: 600,
              accessTokenFormat: 'opaque',
            };
          },
        },
      },
      findAccount: (_ctx, id) =>
        id === SUBJECT
          ? { accountId: id, claims: () => ({ sub: id }) }
          : undefined,
      interactions: {
        url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
      },
      renderError: (ctx, _out, error) => {
        ctx.type = 'application/json';
        ctx.body = { error: error.error };
      },
    });
    provider.on('server_error', (_ctx, error) => {
      const session = transactions.getStore();
      if (session) session.spikeError = error;
    });
    provider.on('grant.revoked', (_ctx, grantId) => {
      const session = transactions.getStore();
      if (session) (session.spikeRevocations ??= new Set()).add(grantId);
    });
    // Native resource resolution permits some omitted-resource exchanges. An
    // explicit application profile hook rejects missing resource and scope drift.
    provider.use(async (ctx, next) => {
      if (ctx.path === '/oauth/token') {
        const session = fixture.client.startSession();
        session.startTransaction();
        try {
          await transactions.run(session, next);
          if (ctx.status >= 400) {
            await session.abortTransaction();
            if (
              session.spikeError?.code === 112 ||
              session.spikeError?.errorLabels?.includes(
                'TransientTransactionError',
              )
            ) {
              ctx.status = 400;
              ctx.body = { error: 'invalid_grant' };
            }
          } else {
            if (faults.commit) {
              faults.commit = false;
              throw new Error('Injected precommit failure');
            }
            await session.commitTransaction();
          }
        } catch (error) {
          if (session.inTransaction()) await session.abortTransaction();
          if (
            error?.code === 112 ||
            error?.errorLabels?.includes('TransientTransactionError')
          ) {
            ctx.status = 400;
            ctx.body = { error: 'invalid_grant' };
            return;
          }
          ctx.status = 500;
          ctx.body = { error: 'server_error' };
        } finally {
          // Replay invalidation is a security effect intentionally retained even
          // when the failed redemption transaction rolls back.
          if (ctx.status >= 400 && session.spikeRevocations) {
            for (const grantId of session.spikeRevocations)
              await fixture.db.collection('oauth_state').deleteMany({
                $or: [
                  { _id: `Grant:${digest(grantId)}` },
                  { grantHash: digest(grantId) },
                ],
              });
          }
          await session.endSession();
        }
      } else await next();
    });
    const engineCallback = provider.callback();
    callback = async (req, res) => {
      try {
        if (req.url.startsWith('/interaction/')) {
          // Fixture-only identity and consent through the real interaction API;
          // not a real login page and never mounted in the application's AppModule.
          const details = await provider.interactionDetails(req, res);

          if (details.prompt.name === 'login') {
            await provider.interactionFinished(
              req,
              res,
              { login: { accountId: SUBJECT } },
              { mergeWithLastSubmission: false },
            );
          } else if (details.prompt.name === 'consent') {
            const grant = new provider.Grant({
              accountId: SUBJECT,
              clientId: details.params.client_id,
            });
            grant.addResourceScope(resource, 'catalog:read');
            grant.addOIDCScope('catalog:read');
            const grantId = await grant.save();
            await provider.interactionFinished(
              req,
              res,
              { consent: { grantId } },
              { mergeWithLastSubmission: true },
            );
          } else throw new Error('Unsupported fixture interaction');
        } else await engineCallback(req, res);
      } catch {
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end('Spike interaction failed');
        }
      }
    };
    return {
      app,
      provider,
      issuer,
      port,
      key,
      faults,
      close: () => app.close(),
    };
  } catch (error) {
    await app.close();
    throw error;
  }
}
