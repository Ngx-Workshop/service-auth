import 'reflect-metadata';
import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import {
  randomBytes,
  generateKeyPairSync,
  createHash,
  createDecipheriv,
} from 'node:crypto';
import { createServer } from 'node:net';
import {
  createServer as createHttpServer,
  request as rawRequest,
} from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import { startMongoFixture } from '../../spikes/oauth-engine/mongo-fixture.mjs';
import { installOAuth } from '../../src/oauth/provider.mjs';
import { tlsFixture } from './tls-fixture.mjs';
import { validateConfig } from '../../src/oauth/config.mjs';
import { createAdapter, digest } from '../../src/oauth/mongo-adapter.mjs';
const require = createRequire(import.meta.url);
const { Logger } = require('@nestjs/common');
Logger.overrideLogger(false);
const { createAuthApp } = require('../../dist/src/bootstrap.js');
let mongo, app, directory, config, account, metadataServer;
let metadataCalls = 0;
const password = 'ExistingPassword1!';
const email = 'oauth-account@example.test';
let cookies;
const resource = 'http://127.0.0.1:3011/mcp';
const redirect = 'http://127.0.0.1:39999/callback';
const secret = randomBytes(32).toString('base64url');
async function start() {
  ({ app } = await createAuthApp());
  await app.listen(Number(process.env.PORT), '127.0.0.1');
}
before(async () => {
  mongo = await startMongoFixture();
  directory = await mkdtemp(join(tmpdir(), 'auth-oauth-app-'));
  const reservation = createServer();
  await new Promise((resolve) => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  config = {
    issuer: `http://127.0.0.1:${port}`,
    resource,
    clients: [
      {
        client_id: 'catalog-client',
        client_name: 'Workshop client',
        redirect_uris: [redirect],
      },
      {
        client_id: 'other-client',
        client_name: 'Other client',
        redirect_uris: [redirect],
      },
    ],
    resourceClient: { id: 'gateway', secret },
    cookieKeys: [randomBytes(32).toString('base64url')],
    activeStorageKey: 'v1',
    storageKeys: { v1: randomBytes(32).toString('base64') },
    jwks: {
      keys: [
        {
          ...generateKeyPairSync('rsa', {
            modulusLength: 2048,
          }).privateKey.export({ format: 'jwk' }),
          kid: 'local',
          use: 'sig',
          alg: 'RS256',
        },
      ],
    },
  };
  const file = join(directory, 'config.json');
  await writeFile(file, JSON.stringify(config), { mode: 0o600 });
  Object.assign(process.env, {
    NODE_ENV: 'test',
    OAUTH_ENABLED: 'true',
    OAUTH_LOCAL_DEV: 'true',
    OAUTH_CONFIG_FILE: file,
    PORT: String(port),
    MONGODB_URI: `mongodb://127.0.0.1:${mongo.client.options.hosts[0].port}/${mongo.db.databaseName}?replicaSet=oauthSpike`,
    JWT_SECRET: randomBytes(32).toString('base64url'),
    JWT_ISSUER: 'legacy-test',
    JWT_AUDIENCE: 'legacy-test',
  });
  const created = await mongo.db.collection('users').insertOne({
    email,
    password: await bcrypt.hash(password, 10),
    role: 'regular',
  });
  account = String(created.insertedId);
  metadataServer = createHttpServer((req, res) => {
    metadataCalls++;
    req.resume();
    res.end('{}');
  });
  await new Promise((resolve) =>
    metadataServer.listen(0, '127.0.0.1', resolve),
  );
  process.env.USER_METADATA_URL = `http://127.0.0.1:${metadataServer.address().port}`;
  await start();
});
after(async () => {
  try {
    await app?.close();
  } finally {
    await mongo?.close();
    if (metadataServer)
      await new Promise((resolve) => metadataServer.close(resolve));
    if (directory) await rm(directory, { recursive: true, force: true });
  }
});
async function http(path, init = {}) {
  const result = await fetch(new URL(path, config.issuer), {
    ...init,
    redirect: 'manual',
    headers: { connection: 'close', ...init.headers },
    signal: AbortSignal.timeout(12000),
  });
  return result;
}
function saveCookies(res) {
  for (const item of res.headers.getSetCookie()) {
    const pair = item.split(';')[0],
      i = pair.indexOf('=');
    cookies.set(pair.slice(0, i), pair.slice(i + 1));
  }
}
function cookieHeader() {
  return [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
}
async function authorize(options = {}) {
  cookies = new Map();
  const verifier = randomBytes(32).toString('base64url');
  const params = {
    client_id: 'catalog-client',
    redirect_uri: redirect,
    response_type: 'code',
    scope: 'catalog:read',
    resource,
    state: 'state-check',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...options.params,
  };
  for (const key in params) if (params[key] === undefined) delete params[key];
  let path = `/oauth/authorize?${new URLSearchParams(params)}`;
  for (let i = 0; i < 14; i++) {
    const res = await http(path, { headers: { cookie: cookieHeader() } });
    saveCookies(res);
    const location = res.headers.get('location');
    if (location) {
      const url = new URL(location, config.issuer);
      if (url.origin !== config.issuer) {
        assert.equal(url.origin, new URL(redirect).origin);
        return {
          code: url.searchParams.get('code'),
          error: url.searchParams.get('error'),
          verifier,
        };
      }
      path = url.href;
      continue;
    }
    if (!res.headers.get('content-type')?.includes('text/html'))
      return { status: res.status, error: (await res.json()).error, verifier };
    const html = await res.text();
    assert.match(
      res.headers.get('content-security-policy'),
      /frame-ancestors 'none'/,
    );
    const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
    const login = html.includes('<h1>Sign in</h1>');
    if (!login) {
      assert.match(html, /Workshop client/);
      assert.match(html, /catalog:read/);
      assert.match(html, /3011\/mcp/);
    }
    const form = {
      csrf,
      ...(login
        ? { action: 'login', email, password }
        : { action: options.deny ? 'deny' : 'allow' }),
    };
    if (options.inspect) await options.inspect({ path, csrf, login, form });
    const submitted = await http(path, {
      method: 'POST',
      headers: {
        origin: config.issuer,
        cookie: cookieHeader(),
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(form),
    });
    saveCookies(submitted);
    assert.equal(submitted.status, 303, await submitted.text());
    path = submitted.headers.get('location');
  }
  throw new Error('Flow did not complete');
}
async function form(path, data, credentials) {
  const res = await http(path, {
    method: 'POST',
    body: new URLSearchParams(data),
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(credentials
        ? {
            authorization: `Basic ${Buffer.from(credentials.join(':')).toString('base64')}`,
          }
        : {}),
    },
  });
  const text = await res.text();
  return { status: res.status, data: text ? JSON.parse(text) : {} };
}
async function exchange(code, overrides = {}) {
  return form('/oauth/token', {
    grant_type: 'authorization_code',
    client_id: 'catalog-client',
    redirect_uri: redirect,
    resource,
    code: code.code,
    code_verifier: code.verifier,
    ...overrides,
  });
}
async function mint() {
  const code = await authorize();
  assert(code.code);
  const token = await exchange(code);
  assert.equal(token.status, 200, JSON.stringify(token));
  return { token: token.data.access_token, code };
}
async function introspect(token, credentials = ['gateway', secret]) {
  return form('/oauth/introspect', { token }, credentials);
}

test('approved CIMD uses native TLS, real login/consent and persisted PKCE tokens', async () => {
  const clientId = 'https://client.example.test/oauth.json';
  const document = {
    client_id: clientId,
    client_name: 'Workshop client',
    redirect_uris: [redirect],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: 'catalog:read',
  };
  const tls = await tlsFixture(document);
  const saved = config;
  let middleware;
  const server = createHttpServer((req, res) =>
    middleware(req, res, () => {
      res.statusCode = 404;
      res.end();
    }),
  );
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    config = validateConfig(
      {
        ...saved,
        issuer: `http://127.0.0.1:${server.address().port}`,
        metadataClients: [
          {
            client_id: clientId,
            client_name: 'Workshop client',
            redirect_uris: [redirect],
          },
        ],
      },
      { OAUTH_LOCAL_DEV: 'true', PORT: String(server.address().port) },
    );
    const { getConnectionToken } = require('@nestjs/mongoose');
    const {
      AuthenticationService,
    } = require('../../dist/src/iam/authentication/authentication.service.js');
    await installOAuth(
      {
        use: (value) => {
          middleware = value;
        },
      },
      app.get(getConnectionToken()),
      app.get(AuthenticationService),
      config,
      tls.dependencies,
    );
    const discovery = await (
      await http('/.well-known/oauth-authorization-server')
    ).json();
    assert.equal(discovery.client_id_metadata_document_supported, true);
    const code = await authorize({ params: { client_id: clientId } });
    assert(code.code, JSON.stringify(code));
    const issued = await exchange(code, { client_id: clientId });
    assert.equal(issued.status, 200);
    const inspected = await introspect(issued.data.access_token);
    assert.equal(inspected.data.active, true);
    assert.equal(inspected.data.client_id, clientId);
    assert.equal(inspected.data.iss, config.issuer);
    assert(tls.calls > 0);
    assert.equal(
      (
        await form('/oauth/revoke', {
          token: issued.data.access_token,
          client_id: clientId,
        })
      ).status,
      200,
    );
    assert.equal(
      (await introspect(issued.data.access_token)).data.active,
      false,
    );
    // The approved policy also applies to cached metadata clients.
    config.metadataClients[0].redirect_uris = [
      'http://127.0.0.1:39999/changed',
    ];
    const rejected = await authorize({ params: { client_id: clientId } });
    assert.equal(rejected.code, undefined);
    assert(rejected.error);
  } finally {
    config = saved;
    await new Promise((resolve) => server.close(resolve));
    await tls.close();
  }
});
test('real account login and explicit consent issue an opaque, resource-bound token', async () => {
  const { token } = await mint();
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  const result = await introspect(token);
  assert.equal(result.data.active, true);
  assert.equal(result.data.sub, account);
  assert.equal(result.data.aud, resource);
  assert.equal(result.data.scope, 'catalog:read');
  assert.equal(result.data.iss, config.issuer);
  assert.equal(result.data.exp - result.data.iat, 600);
});
test('consent denial issues no code', async () => {
  const result = await authorize({ deny: true });
  assert.equal(result.error, 'access_denied');
  assert.equal(result.code, null);
});
test('login forms reject cross-origin POST, missing CSRF and wrong password', async () => {
  let inspected = false;
  await authorize({
    inspect: async ({ path, login, form }) => {
      if (!login || inspected) return;
      inspected = true;
      const post = async (body, origin) =>
        http(path, {
          method: 'POST',
          headers: {
            origin,
            cookie: cookieHeader(),
            'content-type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams(body),
        });
      assert.equal((await post(form, 'https://attacker.example')).status, 403);
      assert.equal(
        (await post({ ...form, csrf: '' }, config.issuer)).status,
        403,
      );
      const bad = await post({ ...form, password: 'incorrect' }, config.issuer);
      assert.equal(bad.status, 401);
      const html = await bad.text();
      assert.match(html, /Invalid email or password/);
      assert.equal((await post(form, config.issuer)).status, 403);
      form.csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
    },
  });
});
test('PKCE, resource, redirect and scope restrictions are enforced in actual app', async () => {
  for (const params of [
    { code_challenge: undefined, code_challenge_method: undefined },
    { code_challenge_method: 'plain' },
    { resource: undefined },
    { resource: 'http://127.0.0.1:3011/other' },
    { scope: 'admin' },
    { scope: undefined },
  ])
    assert((await authorize({ params })).error);
  for (const overrides of [
    { code_verifier: 'wrong' },
    { resource: '' },
    { resource: resource + '/other' },
    { scope: 'catalog:read admin' },
    { redirect_uri: redirect + '/other' },
    { client_id: 'other-client' },
  ]) {
    const code = await authorize();
    assert.equal((await exchange(code, overrides)).status, 400);
  }
});
test('introspection rejects bad credentials and legacy JWT; revocation is owner-bound', async () => {
  const { token } = await mint();
  assert.equal((await introspect(token, ['gateway', 'incorrect'])).status, 401);
  await form('/oauth/revoke', { token, client_id: 'other-client' });
  assert.equal((await introspect(token)).data.active, true);
  assert.equal(
    (await form('/oauth/revoke', { token, client_id: 'catalog-client' }))
      .status,
    200,
  );
  assert.equal((await introspect(token)).data.active, false);
  assert.equal((await introspect('ey.fake.jwt')).data.active, false);
});
test('concurrent redemption has one winner and replay invalidates grant', async () => {
  const code = await authorize();
  const results = await Promise.all(
    Array.from({ length: 6 }, () => exchange(code)),
  );
  assert.equal(
    results.filter((result) => result.status === 200).length,
    1,
    JSON.stringify(results),
  );
  assert.equal((await exchange(code)).data.error, 'invalid_grant');
  assert.equal(
    (
      await introspect(
        results.find((result) => result.status === 200).data.access_token,
      )
    ).data.active,
    false,
  );
});
test('token write failure rolls back code consumption and permits retry', async () => {
  const code = await authorize();
  const prototype = mongoose.mongo.Collection.prototype;
  const original = prototype.updateOne;
  prototype.updateOne = function (filter, update, ...args) {
    if (update?.$set?.model === 'AccessToken') {
      prototype.updateOne = original;
      return Promise.reject(new Error('Test storage unavailable'));
    }
    return original.call(this, filter, update, ...args);
  };
  try {
    const result = await exchange(code);
    assert(result.status >= 400);
    assert.equal(result.data.access_token, undefined);
  } finally {
    prototype.updateOne = original;
  }
  assert.equal((await exchange(code)).status, 200);
});
test('persistent storage keys retain tokens across application restart', async () => {
  const { token } = await mint();
  const pendingCode = await authorize();
  await app.close();
  await mongo.restart();
  await start();
  assert.equal((await introspect(token)).data.active, true);
  assert.equal((await exchange(pendingCode)).status, 200);
});
test('storage checks expiry and protects ciphertext with record-bound encryption and key IDs', async () => {
  const Adapter = createAdapter(mongo.db, config.storageKeys, 'v1');
  const adapter = new Adapter('AccessToken');
  const id = randomBytes(32).toString('base64url');
  await adapter.upsert(id, { jti: id, accountId: account }, 60);
  let record = await mongo.db
    .collection('oauth_state')
    .findOne({ _id: `AccessToken:${digest(id)}` });
  assert.equal(record.encrypted.kid, 'v1');
  assert(!JSON.stringify(record).includes(id));
  const ring = {
    ...config.storageKeys,
    v2: randomBytes(32).toString('base64'),
  };
  const Rotated = createAdapter(mongo.db, ring, 'v2');
  assert.equal((await new Rotated('AccessToken').find(id)).jti, id);
  await mongo.db
    .collection('oauth_state')
    .updateOne({ _id: record._id }, { $set: { expiresAt: new Date(0) } });
  assert.equal(await adapter.find(id), undefined);
  await mongo.db
    .collection('oauth_state')
    .insertOne({ ...record, _id: `AccessToken:${digest('other')}` });
  await assert.rejects(adapter.find('other'));
});
test('legacy cookie sign-in, validation, metadata, roles and sign-out preserve behavior', async () => {
  const signed = await http('/sign-in', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(signed.status, 200);
  const cookie = signed.headers
    .getSetCookie()
    .find((value) => value.startsWith('accessToken='))
    .split(';')[0];
  assert.equal(
    await (
      await http('/validate-access-token', { headers: { cookie } })
    ).json(),
    true,
  );
  assert.equal(
    await (
      await http('/validate-access-token', {
        headers: { authorization: `Bearer ${cookie.slice(12)}` },
      })
    ).json(),
    false,
  );
  assert.equal(
    (await http('/user-metadata', { headers: { cookie } })).status,
    200,
  );
  assert.equal(
    (
      await http('/role', {
        method: 'PUT',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ userId: account, role: 'admin' }),
      })
    ).status,
    403,
  );
  const legacyIntrospection = await introspect(cookie.slice(12));
  assert.equal(legacyIntrospection.status, 400);
  assert.equal(legacyIntrospection.data.error, 'unsupported_token_type');
  const { token } = await mint();
  const out = await http('/sign-out', { headers: { cookie } });
  assert.equal(out.status, 200);
  assert.match(out.headers.get('set-cookie'), /accessToken=;/);
  assert.equal((await introspect(token)).data.active, true);
});
test('configuration rejects production, missing persistence keys and unsafe resource URLs', () => {
  const env = { OAUTH_LOCAL_DEV: 'true', PORT: process.env.PORT };
  assert.throws(() =>
    validateConfig(config, { ...env, NODE_ENV: 'production' }),
  );
  assert.throws(() => validateConfig({ ...config, cookieKeys: [] }, env));
  assert.throws(() =>
    validateConfig({ ...config, resource: 'http://public.example/mcp' }, env),
  );
});
test('authenticated grant management revokes access and rejects forged or cross-origin forms', async () => {
  const { token } = await mint();
  assert.equal((await http('/oauth/grants')).status, 401);
  const page = await http('/oauth/grants', {
    headers: { cookie: cookieHeader() },
  });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Workshop client/);
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1],
    grant = html.match(/name="grant" value="([^"]+)"/)[1];
  const post = async (body, origin = config.issuer) =>
    http('/oauth/grants', {
      method: 'POST',
      headers: {
        origin,
        cookie: cookieHeader(),
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(body),
    });
  assert.equal(
    (await post({ csrf, grant }, 'https://attacker.example')).status,
    403,
  );
  assert.equal((await post({ csrf, grant: 'other-grant' })).status, 403);
  assert.equal((await post({ csrf, grant })).status, 303);
  assert.equal((await introspect(token)).data.active, false);
  assert.equal((await post({ csrf, grant })).status, 403);
});
test('precommit failure never exposes a token, and unknown commit retries only commit', async () => {
  const probe = mongo.client.startSession();
  const prototype = Object.getPrototypeOf(probe);
  await probe.endSession();
  const original = prototype.commitTransaction;
  let code = await authorize();
  prototype.commitTransaction = async function () {
    prototype.commitTransaction = original;
    throw new Error('Test precommit failure');
  };
  try {
    const result = await exchange(code);
    assert.equal(result.status, 503);
    assert.equal(result.data.access_token, undefined);
  } finally {
    prototype.commitTransaction = original;
  }
  assert.equal((await exchange(code)).status, 200);
  code = await authorize();
  let calls = 0;
  prototype.commitTransaction = async function () {
    calls++;
    if (calls === 1) {
      const error = new Error('Test unknown outcome');
      error.hasErrorLabel = (label) =>
        label === 'UnknownTransactionCommitResult';
      throw error;
    }
    return original.call(this);
  };
  try {
    const result = await exchange(code);
    assert.equal(result.status, 200);
    assert.equal(calls, 2);
    assert.equal(
      (await introspect(result.data.access_token)).data.active,
      true,
    );
  } finally {
    prototype.commitTransaction = original;
  }
});
test('discovery advertises only the supported OAuth endpoints and grant', async () => {
  const response = await http('/.well-known/oauth-authorization-server');
  assert.equal(response.status, 200);
  const doc = await response.json();
  assert.equal(doc.issuer, config.issuer);
  assert.equal(doc.authorization_endpoint, config.issuer + '/oauth/authorize');
  assert.equal(doc.token_endpoint, config.issuer + '/oauth/token');
  assert.equal(doc.introspection_endpoint, config.issuer + '/oauth/introspect');
  assert.equal(doc.revocation_endpoint, config.issuer + '/oauth/revoke');
  assert.deepEqual(doc.grant_types_supported, ['authorization_code']);
  assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(doc.scopes_supported, ['catalog:read']);
  assert.deepEqual(doc.token_endpoint_auth_methods_supported.sort(), [
    'client_secret_basic',
    'none',
  ]);
  assert.equal(doc.registration_endpoint, undefined);
  assert.notEqual(doc.client_id_metadata_document_supported, true);
  const rejectedHost = await new Promise((resolve, reject) => {
    const request = rawRequest(
      config.issuer + '/.well-known/oauth-authorization-server',
      { headers: { host: 'attacker.example', connection: 'close' } },
      (response) => {
        response.resume();
        resolve(response.statusCode);
      },
    );
    request.on('error', reject);
    request.end();
  });
  assert.equal(rejectedHost, 400);
  for (const grant_type of ['refresh_token', 'password', 'client_credentials'])
    assert.equal(
      (await form('/oauth/token', { grant_type, client_id: 'catalog-client' }))
        .data.error,
      'unsupported_grant_type',
    );
});
test('Mongo validator rejects unencrypted state; HTTP introspection honors expiry before TTL cleanup', async () => {
  await assert.rejects(
    mongo.db.collection('oauth_state').insertOne({
      _id: 'unsafe',
      model: 'AccessToken',
      rawToken: 'must-not-persist',
      expiresAt: new Date(Date.now() + 10000),
    }),
    (error) => error.code === 121,
  );
  const { token } = await mint();
  await mongo.db
    .collection('oauth_state')
    .updateOne(
      { _id: `AccessToken:${digest(token)}` },
      { $set: { expiresAt: new Date(Date.now() - 1000) } },
    );
  assert.equal((await introspect(token)).data.active, false);
});
test('OAuth startup rejects an actual standalone MongoDB and closes the failed app', async () => {
  const standalone = await startMongoFixture({ replicaSet: false });
  const savedUri = process.env.MONGODB_URI;
  try {
    process.env.MONGODB_URI = `mongodb://127.0.0.1:${standalone.client.options.hosts[0].port}/${standalone.db.databaseName}`;
    await assert.rejects(createAuthApp(), /replica set/);
  } finally {
    process.env.MONGODB_URI = savedUri;
    await standalone.close();
  }
});
test('legacy sign-up, duplicate detection, credential errors and admin role updates remain compatible', async () => {
  const post = (path, body, cookie) =>
    http(path, {
      method: path === '/role' ? 'PUT' : 'POST',
      headers: {
        'content-type': 'application/json',
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify(body),
    });
  const signedUp = await post('/sign-up', {
    email: 'new-account@example.test',
    password,
  });
  assert.equal(signedUp.status, 201);
  assert(
    signedUp.headers
      .getSetCookie()
      .some((value) => value.startsWith('accessToken=')),
  );
  assert.equal(metadataCalls, 1);
  assert.equal(
    (await post('/sign-up', { email: 'new-account@example.test', password }))
      .status,
    409,
  );
  assert.equal(
    (
      await (
        await post('/sign-in', {
          email: 'missing-account@example.test',
          password,
        })
      ).json()
    ).message,
    'User not found',
  );
  assert.equal(
    (await (await post('/sign-in', { email, password: 'wrong' })).json())
      .message,
    'Invalid password',
  );
  await mongo.db.collection('users').insertOne({
    email: 'admin-account@example.test',
    password: await bcrypt.hash(password, 10),
    role: 'admin',
  });
  const admin = await post('/sign-in', {
    email: 'admin-account@example.test',
    password,
  });
  const cookie = admin.headers
    .getSetCookie()
    .find((value) => value.startsWith('accessToken='))
    .split(';')[0];
  const changed = await post(
    '/role',
    { userId: account, role: 'publisher' },
    cookie,
  );
  assert.equal(changed.status, 200);
  assert.equal((await changed.json()).role, 'publisher');
  await mongo.db
    .collection('users')
    .updateOne(
      { _id: new mongoose.Types.ObjectId(account) },
      { $set: { role: 'regular' } },
    );
});
test('actual code and token payloads persist no raw credentials, even after decryption', async () => {
  const { token, code } = await mint();
  for (const [model, credential] of [
    ['AuthorizationCode', code.code],
    ['AccessToken', token],
  ]) {
    const record = await mongo.db
      .collection('oauth_state')
      .findOne({ _id: `${model}:${digest(credential)}` });
    const decipher = createDecipheriv(
      'aes-256-gcm',
      Buffer.from(config.storageKeys[record.encrypted.kid], 'base64'),
      Buffer.from(record.encrypted.iv, 'base64'),
    );
    decipher.setAAD(Buffer.from(record._id));
    decipher.setAuthTag(Buffer.from(record.encrypted.tag, 'base64'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(record.encrypted.data, 'base64')),
      decipher.final(),
    ]).toString();
    assert(
      !plain.includes(credential),
      'Raw credential must not survive encryption',
    );
    assert.equal(JSON.parse(plain).jti, undefined);
  }
});
test('unknown commit results stop after three attempts without returning a token', async () => {
  const code = await authorize();
  const probe = mongo.client.startSession();
  const prototype = Object.getPrototypeOf(probe);
  await probe.endSession();
  const original = prototype.commitTransaction;
  let calls = 0;
  prototype.commitTransaction = async function () {
    calls++;
    const error = new Error('Unknown commit result');
    error.hasErrorLabel = (label) => label === 'UnknownTransactionCommitResult';
    throw error;
  };
  try {
    const result = await exchange(code);
    assert.equal(calls, 3);
    assert.equal(result.status, 503);
    assert.equal(result.data.access_token, undefined);
  } finally {
    prototype.commitTransaction = original;
  }
  assert.equal((await exchange(code)).status, 200);
});
test('introspection reports storage outages without accepting the token', async () => {
  const { token } = await mint();
  const prototype = mongoose.mongo.Collection.prototype,
    original = prototype.findOne;
  prototype.findOne = function (filter, ...args) {
    if (filter?._id === `AccessToken:${digest(token)}`)
      return Promise.reject(new Error('Test database outage'));
    return original.call(this, filter, ...args);
  };
  try {
    const result = await introspect(token);
    assert.equal(result.status, 503);
    assert.equal(result.data.error, 'temporarily_unavailable');
    assert.notEqual(result.data.active, true);
  } finally {
    prototype.findOne = original;
  }
  assert.equal((await introspect(token)).data.active, true);
});
test('failed login attempts are bounded without trusting forwarding headers', async () => {
  await app.close();
  await start();
  cookies = new Map();
  const verifier = randomBytes(32).toString('base64url');
  let res = await http(
    '/oauth/authorize?' +
      new URLSearchParams({
        client_id: 'catalog-client',
        redirect_uri: redirect,
        response_type: 'code',
        scope: 'catalog:read',
        resource,
        code_challenge: createHash('sha256')
          .update(verifier)
          .digest('base64url'),
        code_challenge_method: 'S256',
      }),
  );
  saveCookies(res);
  const path = res.headers.get('location');
  res = await http(path, { headers: { cookie: cookieHeader() } });
  saveCookies(res);
  let html = await res.text();
  for (let i = 0; i < 11; i++) {
    const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
    res = await http(path, {
      method: 'POST',
      headers: {
        origin: config.issuer,
        cookie: cookieHeader(),
        'x-forwarded-for': `10.0.0.${i}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        csrf,
        email,
        password: 'wrong',
        action: 'login',
      }),
    });
    assert.equal(res.status, i === 10 ? 429 : 401);
    html = await res.text();
  }
});
test('OAuth disabled retains legacy service without an OAuth endpoint', async () => {
  await app.close();
  process.env.OAUTH_ENABLED = 'false';
  await start();
  assert.equal(
    (await http('/.well-known/oauth-authorization-server')).status,
    404,
  );
  assert.equal(
    (
      await http('/sign-in', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })
    ).status,
    200,
  );
});
