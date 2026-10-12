import { provisionOAuthSchema, validateOAuthSchema } from './mongo-schema.mjs';
import { productionIngress } from './profile.mjs';
import { createMetadataFetcher } from './metadata-fetch.mjs';
import Provider, { errors } from 'oidc-provider';
import {
  createAdapter,
  digest,
  transactions,
  storageRequests,
} from './mongo-adapter.mjs';
import { grantHandler } from './grants.mjs';
import { interactionHandler } from './interactions.mjs';

export async function installOAuth(
  app,
  connection,
  auth,
  config,
  metadataDependencies = {},
) {
  const db = connection.db;
  const client = connection.getClient();
  const resource = config.resource;
  const issuer = config.issuer;
  const production = config.runtime?.production === true;
  if (
    !production &&
    !['127.0.0.1', 'localhost', '::1'].includes(connection.host)
  )
    throw new Error('OAuth database must be local');
  const options = client.options;
  if (
    production &&
    (options.tls !== true ||
      options.replicaSet !== process.env.MONGODB_REPLICA_SET ||
      !options.credentials ||
      !options.tlsCAFile ||
      options.tlsAllowInvalidCertificates ||
      options.tlsAllowInvalidHostnames ||
      options.directConnection)
  )
    throw new Error('Production Mongo security configuration required');
  const hello = await db.admin().command({ hello: 1 }, { maxTimeMS: 3000 });
  if (
    !hello.setName ||
    !hello.isWritablePrimary ||
    (production && hello.setName !== process.env.MONGODB_REPLICA_SET)
  )
    throw new Error('OAuth requires writable configured MongoDB replica set');
  if (production) await validateOAuthSchema(db);
  else await provisionOAuthSchema(db);
  // Prove transaction support before making the HTTP listener available.
  const probe = client.startSession();
  try {
    probe.startTransaction({
      writeConcern: { w: 'majority' },
      maxCommitTimeMS: 3000,
    });
    await db
      .collection('oauth_state')
      .findOne({ _id: 'startup-probe' }, { session: probe, maxTimeMS: 3000 });
    await probe.abortTransaction();
  } finally {
    await probe.endSession();
  }
  const provider = new Provider(issuer, {
    clientBasedCORS: (_ctx, origin, client) =>
      production &&
      config.runtime.origins.includes(origin) &&
      [...config.clients, ...config.metadataClients].some(
        (approved) => approved.client_id === client.clientId,
      ),
    adapter: createAdapter(db, config.storageKeys, config.activeStorageKey),
    jwks: config.jwks,
    ...(config.metadataClients.length
      ? {
          fetch: createMetadataFetcher(
            config.metadataClients,
            metadataDependencies,
          ),
        }
      : {}),
    clients: [
      ...config.clients.map((client) => ({
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'none',
        scope: 'catalog:read',
      })),
      {
        client_id: config.resourceClient.id,
        client_secret: config.resourceClient.secret,
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
    cookies: {
      keys: config.cookieKeys,
      short: {
        httpOnly: true,
        sameSite: 'lax',
        ...(production ? { secure: true } : {}),
      },
      long: {
        httpOnly: true,
        sameSite: 'lax',
        ...(production ? { secure: true } : {}),
      },
    },
    routes: {
      authorization: '/oauth/authorize',
      token: '/oauth/token',
      introspection: '/oauth/introspect',
      revocation: '/oauth/revoke',
    },
    pkce: { required: () => true },
    allowOmittingSingleRegisteredRedirectUri: false,
    features: {
      clientIdMetadataDocument: {
        enabled: config.metadataClients.length > 0,
        ack: 'draft-02',
        allowFetch: (_ctx, id) =>
          config.metadataClients.some((client) => client.client_id === id),
        allowClient: (_ctx, client) => {
          const approved = config.metadataClients.find(
            (value) => value.client_id === client.clientId,
          );
          return (
            !!approved &&
            client.clientName === approved.client_name &&
            client.clientAuthMethod === 'none' &&
            client.grantTypes.length === 1 &&
            client.grantTypeAllowed('authorization_code') &&
            client.responseTypes.length === 1 &&
            client.responseTypeAllowed('code') &&
            client.redirectUris.length === approved.redirect_uris.length &&
            client.redirectUris.every((uri) =>
              approved.redirect_uris.includes(uri),
            ) &&
            client.scope === 'catalog:read'
          );
        },
      },
      devInteractions: { enabled: false },
      userinfo: { enabled: false },
      registration: { enabled: false },
      introspection: {
        enabled: true,
        allowedPolicy: async (_ctx, client, token) =>
          client.clientId === config.resourceClient.id &&
          token.kind === 'AccessToken' &&
          token.aud === resource &&
          (await auth.findOAuthAccount(token.accountId)),
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
            (ctx.oidc.route === 'authorization' &&
              ctx.oidc.params.scope !== 'catalog:read') ||
            (ctx.oidc.route === 'token' && ctx.oidc.body.scope !== undefined) ||
            (ctx.oidc.params.scope && ctx.oidc.params.scope !== 'catalog:read')
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
    findAccount: async (_ctx, id) =>
      (await auth.findOAuthAccount(id))
        ? { accountId: id, claims: () => ({ sub: id }) }
        : undefined,
    interactions: {
      url: (_ctx, interaction) => `/oauth/interaction/${interaction.uid}`,
    },
    extraTokenClaims: () => ({ iss: issuer }),
    renderError: (ctx, _out, error) => {
      ctx.type = 'application/json';
      ctx.body = { error: error.error };
    },
  });

  provider.proxy = production;
  provider.on('server_error', (_ctx, error) => {
    const session = transactions.getStore();
    if (session) session.oauthError = error;
  });
  provider.on('grant.revoked', (_ctx, id) => {
    const session = transactions.getStore();
    if (session) (session.oauthRevocations ??= new Set()).add(id);
  });
  provider.use(async (ctx, next) => {
    const state = {};
    await storageRequests.run(state, next);
    // The engine may treat lookup failures as inactive tokens. Retain the
    // storage signal so an outage is reported as unavailable, never as active.
    if (
      state.error &&
      state.error.code !== 112 &&
      !state.error.hasErrorLabel?.('TransientTransactionError')
    ) {
      ctx.status = 503;
      ctx.body = { error: 'temporarily_unavailable' };
    }
  });
  provider.use(async (ctx, next) => {
    if (ctx.path !== '/oauth/token') {
      await next();
      if (ctx.status >= 500) {
        ctx.status = 503;
        ctx.body = { error: 'temporarily_unavailable' };
      }
      return;
    }
    const session = client.startSession();
    session.startTransaction({
      readConcern: { level: 'snapshot' },
      writeConcern: { w: 'majority' },
      maxCommitTimeMS: 3000,
    });
    try {
      await transactions.run(session, next);
      if (ctx.status >= 400) {
        await session.abortTransaction();
        if (
          session.oauthError?.code === 112 ||
          session.oauthError?.hasErrorLabel?.('TransientTransactionError')
        ) {
          ctx.status = 400;
          ctx.body = { error: 'invalid_grant' };
        } else if (session.oauthError) {
          ctx.status = 503;
          ctx.body = { error: 'temporarily_unavailable' };
        }
      } else {
        // Never replay the request on an unknown commit outcome.
        for (let attempt = 0; ; attempt++) {
          try {
            await session.commitTransaction();
            break;
          } catch (error) {
            if (
              attempt >= 2 ||
              !error.hasErrorLabel?.('UnknownTransactionCommitResult')
            )
              throw error;
          }
        }
      }
    } catch (error) {
      if (session.inTransaction())
        await session.abortTransaction().catch(() => {});
      ctx.status =
        error.code === 112 || error.hasErrorLabel?.('TransientTransactionError')
          ? 400
          : 503;
      ctx.body = {
        error: ctx.status === 400 ? 'invalid_grant' : 'temporarily_unavailable',
      };
    } finally {
      try {
        // Preserve replay invalidation outside an aborted redemption transaction.
        if (ctx.status >= 400)
          for (const id of session.oauthRevocations ?? []) {
            await db.collection('oauth_revoked').updateOne(
              { _id: digest(id) },
              { $set: { expiresAt: new Date(Date.now() + 1200000) } },
              {
                upsert: true,
                writeConcern: { w: 'majority', wtimeoutMS: 3000 },
                maxTimeMS: 3000,
              },
            );
          }
      } catch {
        ctx.status = 503;
        ctx.body = { error: 'temporarily_unavailable' };
      } finally {
        await session.endSession();
      }
    }
  });
  const grants = grantHandler(provider, db, auth, config);
  const interact = interactionHandler(provider, db, auth, config);
  const callback = provider.callback();
  const paths = new Set([
    '/oauth/authorize',
    '/oauth/token',
    '/oauth/introspect',
    '/oauth/revoke',
    '/jwks',
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
  ]);
  const ingress = production ? productionIngress(config) : undefined;
  if (ingress)
    app.use((req, res, next) => {
      const path = req.url.split('?')[0];
      if (paths.has(path) || path.startsWith('/oauth/'))
        return ingress(req, res, next);
      next();
    });
  app.use((req, res, next) => {
    const path = req.url.split('?')[0];
    const oauthPath =
      paths.has(path) ||
      path === '/oauth/grants' ||
      /^\/oauth\/(interaction|authorize)\/[A-Za-z0-9_-]+$/.test(path);
    if (oauthPath && req.headers.host !== new URL(issuer).host) {
      res.statusCode = 400;
      return res.end('Invalid OAuth host');
    }
    if (path === '/oauth/grants') {
      grants(req, res).catch(() => {
        if (!res.headersSent) {
          res.statusCode = 503;
          res.end('Grant management unavailable');
        }
      });
    } else if (/^\/oauth\/interaction\/[A-Za-z0-9_-]+$/.test(path)) {
      interact(req, res).catch(() => {
        if (!res.headersSent) {
          res.statusCode = 400;
          res.end('Interaction unavailable');
        }
      });
    } else if (
      paths.has(path) ||
      /^\/oauth\/authorize\/[A-Za-z0-9_-]+$/.test(path)
    )
      callback(req, res);
    else next();
  });
  return provider;
}
