import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { startMongoFixture } from './mongo-fixture.mjs';
import { createAdapter, digest } from './mongo-adapter.mjs';
import {
  startProvider,
  RESOURCE,
  REDIRECT,
  SUBJECT,
  PUBLIC_CLIENT,
  SERVICE_CLIENT,
  SERVICE_SECRET,
  OTHER_CLIENT,
  OTHER_SECRET,
  OTHER_PUBLIC_CLIENT,
  METADATA_CLIENT,
} from './provider.mjs';

let mongo;
let server;
const seen = [];
before(async () => {
  mongo = await startMongoFixture();
  server = await startProvider(mongo);
});
after(async () => {
  try {
    await server?.close();
  } finally {
    await mongo?.close();
  }
});

async function http(path, init = {}) {
  return fetch(new URL(path, server.issuer), {
    ...init,
    headers: { ...init.headers, connection: 'close' },
    redirect: 'manual',
    signal: AbortSignal.timeout(8000),
  });
}
async function form(path, body, credentials) {
  const res = await http(path, {
    method: 'POST',
    body: new URLSearchParams(body),
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
  const data = text ? JSON.parse(text) : {};
  return { status: res.status, data };
}
async function authorize(overrides = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('hex');
  const params = {
    client_id: PUBLIC_CLIENT,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'catalog:read',
    resource: RESOURCE,
    state,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...overrides,
  };
  for (const key of Object.keys(params))
    if (params[key] === undefined) delete params[key];
  const cookies = new Map();
  let url = `/oauth/authorize?${new URLSearchParams(params)}`;
  for (let step = 0; step < 10; step++) {
    const res = await http(url, {
      headers: {
        cookie: [...cookies]
          .map(([name, value]) => `${name}=${value}`)
          .join('; '),
      },
    });
    for (const cookie of res.headers.getSetCookie()) {
      const [pair] = cookie.split(';');
      const index = pair.indexOf('=');
      cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
    const location = res.headers.get('location');
    if (!location)
      return { status: res.status, error: (await res.json()).error, verifier };
    const dest = new URL(location, server.issuer);
    if (dest.origin !== server.issuer) {
      assert.equal(
        dest.origin,
        new URL(REDIRECT).origin,
        'Never follow an unvalidated external callback',
      );
      if (dest.searchParams.has('code')) {
        assert.equal(dest.searchParams.get('state'), state);
        assert.equal(dest.searchParams.get('iss'), server.issuer);
        const code = dest.searchParams.get('code');
        seen.push(code);
        return { code, verifier, state };
      }
      return { error: dest.searchParams.get('error'), verifier };
    }
    url = dest.href;
  }
  throw new Error('Authorization interaction did not complete');
}
async function exchange(authorization, overrides = {}) {
  const params = {
    grant_type: 'authorization_code',
    client_id: PUBLIC_CLIENT,
    code: authorization.code,
    code_verifier: authorization.verifier,
    redirect_uri: REDIRECT,
    resource: RESOURCE,
    ...overrides,
  };
  for (const key of Object.keys(params))
    if (params[key] === undefined) delete params[key];
  const result = await form('/oauth/token', params);
  if (result.data.access_token) seen.push(result.data.access_token);
  return result;
}
async function mint() {
  const authorization = await authorize();
  assert(authorization.code, 'Real engine must issue a code');
  const result = await exchange(authorization);
  assert.equal(result.status, 200);
  assert.equal(result.data.token_type, 'Bearer');
  assert.equal(result.data.expires_in, 600);
  assert.equal(result.data.scope, 'catalog:read');
  assert(!result.data.refresh_token && !result.data.id_token);
  return result.data.access_token;
}
async function introspect(
  token,
  credentials = [SERVICE_CLIENT, SERVICE_SECRET],
) {
  return form(
    '/oauth/introspect',
    { token, token_type_hint: 'access_token' },
    credentials,
  );
}

// No passwords/users are created: the fixed identity tests the interaction hook.
test('discovery exposes native code/S256/resource/introspection/revocation capabilities', async () => {
  const data = await (
    await http('/.well-known/oauth-authorization-server')
  ).json();
  assert.equal(data.issuer, server.issuer);
  assert(data.code_challenge_methods_supported.includes('S256'));
  assert(data.introspection_endpoint.endsWith('/oauth/introspect'));
  assert(data.revocation_endpoint.endsWith('/oauth/revoke'));
  assert.deepEqual(data.response_types_supported, ['code']);
  assert(!data.grant_types_supported.includes('refresh_token'));
  assert(!data.registration_endpoint);
});
test('real code/S256 exchange produces opaque resource-bound token and trusted distinct user/client', async () => {
  const token = await mint();
  assert(token.length >= 43 && !token.includes('.'));
  const { status, data } = await introspect(token);
  assert.equal(status, 200);
  assert.equal(data.active, true);
  assert.equal(data.sub, SUBJECT);
  assert.equal(data.client_id, PUBLIC_CLIENT);
  assert.notEqual(data.sub, data.client_id);
  assert.equal(data.aud, RESOURCE);
  assert.equal(data.iss, server.issuer);
  assert.equal(data.token_type, 'Bearer');
  assert.equal(data.scope, 'catalog:read');
  assert.equal(data.exp - data.iat, 600);
});
for (const [name, overrides, error] of [
  [
    'missing PKCE challenge',
    { code_challenge: undefined, code_challenge_method: undefined },
    'invalid_request',
  ],
  ['plain PKCE', { code_challenge_method: 'plain' }, 'invalid_request'],
  ['missing authorization resource', { resource: undefined }, 'invalid_target'],
  [
    'wrong authorization resource',
    { resource: 'http://127.0.0.1:3011/other' },
    'invalid_target',
  ],
  [
    'unauthorized scope',
    { scope: 'catalog:read catalog:write' },
    'invalid_scope',
  ],
  [
    'unregistered redirect',
    { redirect_uri: 'http://127.0.0.1:39999/evil' },
    'invalid_redirect_uri',
  ],
])
  test(`authorization rejects ${name}`, async () => {
    const result = await authorize(overrides);
    assert(!result.code);
    assert.equal(result.error, error);
  });
for (const [name, overrides, error] of [
  ['wrong verifier', { code_verifier: 'x'.repeat(43) }, 'invalid_grant'],
  ['missing verifier', { code_verifier: undefined }, 'invalid_grant'],
  [
    'wrong resource',
    { resource: 'http://127.0.0.1:3011/other' },
    'invalid_target',
  ],
  ['missing resource', { resource: undefined }, 'invalid_target'],
  ['scope escalation', { scope: 'catalog:write' }, 'invalid_scope'],
  [
    'redirect mismatch',
    { redirect_uri: 'http://127.0.0.1:39999/evil' },
    'invalid_grant',
  ],
  ['different client', { client_id: OTHER_PUBLIC_CLIENT }, 'invalid_grant'],
])
  test(`token exchange rejects ${name}`, async () => {
    const result = await exchange(await authorize(), overrides);
    assert(
      [400, 401].includes(result.status),
      'Rejected exchange returns a protocol error',
    );
    assert.equal(result.data.error, error);
    assert(!result.data.access_token);
  });
test('introspection requires service credentials and enforces resource-server allow policy', async () => {
  const token = await mint();
  assert.equal(
    (await introspect(token, [SERVICE_CLIENT, 'wrong'])).status,
    401,
  );
  assert.deepEqual(
    (await introspect(token, [OTHER_CLIENT, OTHER_SECRET])).data,
    { active: false },
  );
  assert.equal((await form('/oauth/introspect', { token })).status, 400);
  assert.deepEqual((await introspect('unknown')).data, { active: false });
  assert.deepEqual((await introspect('a.b.c')).data, { active: false });
});
test('token revocation is owner-bound, idempotent, and visible on next introspection', async () => {
  const token = await mint();
  assert.equal(
    (await form('/oauth/revoke', { token }, [OTHER_CLIENT, OTHER_SECRET]))
      .status,
    200,
  );
  assert.equal((await introspect(token)).data.active, true);
  assert.equal(
    (await form('/oauth/revoke', { token, client_id: PUBLIC_CLIENT })).status,
    200,
  );
  assert.deepEqual((await introspect(token)).data, { active: false });
  assert.equal(
    (await form('/oauth/revoke', { token, client_id: PUBLIC_CLIENT })).status,
    200,
  );
});
test('grant removal revokes associated token validity', async () => {
  const token = await mint();
  const model = await server.provider.AccessToken.find(token);
  await (await server.provider.Grant.find(model.grantId)).destroy();
  assert.deepEqual((await introspect(token)).data, { active: false });
});
test('expired token/code denied before MongoDB TTL cleanup', async () => {
  const token = await mint();
  const auth = await authorize();
  await mongo.db.collection('oauth_state').updateMany(
    {
      _id: {
        $in: [
          `AccessToken:${digest(token)}`,
          `AuthorizationCode:${digest(auth.code)}`,
        ],
      },
    },
    { $set: { expiresAt: new Date(Date.now() - 1000) } },
  );
  assert.deepEqual((await introspect(token)).data, { active: false });
  assert.equal((await exchange(auth)).data.error, 'invalid_grant');
});
test('provider and mongod restart retain disk-backed state with same storage key', async () => {
  const token = await mint();
  const auth = await authorize();
  const { port, key } = server;
  await server.close();
  await mongo.restart();
  server = await startProvider(mongo, { port, key });
  assert.equal((await introspect(token)).data.active, true);
  assert.equal((await exchange(auth)).status, 200);
});
test('concurrent code redemption issues at most one successful token', async () => {
  const auth = await authorize();
  const responses = await Promise.all(
    Array.from({ length: 8 }, () => exchange(auth)),
  );
  assert.equal(responses.filter((res) => res.status === 200).length, 1);
  assert(
    responses
      .filter((res) => res.status !== 200)
      .every((res) => res.data.error === 'invalid_grant'),
  );
  assert.equal((await exchange(auth)).data.error, 'invalid_grant');
  const winner = responses.find((res) => res.status === 200);
  assert.deepEqual(
    (await introspect(winner.data.access_token)).data,
    { active: false },
    'Replay invalidates the grant',
  );
});
test('token storage failure rolls consumption back; retry mints exactly one token', async () => {
  const auth = await authorize();
  const before = await mongo.db
    .collection('oauth_state')
    .countDocuments({ model: 'AccessToken' });
  server.faults.tokenWrite = true;
  const failed = await exchange(auth);
  assert.equal(failed.status, 500);
  assert(!failed.data.access_token);
  assert.equal(
    await mongo.db
      .collection('oauth_state')
      .countDocuments({ model: 'AccessToken' }),
    before,
  );
  const code = await server.provider.AuthorizationCode.find(auth.code);
  assert(code && !code.consumed, 'Failed issuance must leave no consumed code');
  assert.equal((await exchange(auth)).status, 200);
});
test('precommit failure sends no token and rolls token plus code consumption back', async () => {
  const auth = await authorize();
  const before = await mongo.db
    .collection('oauth_state')
    .countDocuments({ model: 'AccessToken' });
  server.faults.commit = true;
  const failed = await exchange(auth);
  assert.equal(failed.status, 500);
  assert(!failed.data.access_token);
  assert.equal(
    await mongo.db
      .collection('oauth_state')
      .countDocuments({ model: 'AccessToken' }),
    before,
  );
  assert(!(await server.provider.AuthorizationCode.find(auth.code)).consumed);
  assert.equal((await exchange(auth)).status, 200);
});
test('no raw code/token persisted; hash lookups plus encrypted adapter payloads', async () => {
  const docs = await mongo.db.collection('oauth_state').find().toArray();
  assert(docs.length > 0);
  const serialized = JSON.stringify(docs);
  for (const doc of docs.filter((doc) =>
    ['AccessToken', 'AuthorizationCode'].includes(doc.model),
  )) {
    const decrypt = createDecipheriv(
      'aes-256-gcm',
      server.key,
      Buffer.from(doc.encrypted.iv, 'base64'),
    );
    decrypt.setAuthTag(Buffer.from(doc.encrypted.tag, 'base64'));
    const raw = Buffer.concat([
      decrypt.update(Buffer.from(doc.encrypted.data, 'base64')),
      decrypt.final(),
    ]).toString();
    assert(
      !('jti' in JSON.parse(raw)),
      'Code/token value must not be retained even in encrypted payload',
    );
    for (const value of seen)
      assert(
        !raw.includes(value),
        'No recoverable raw code/token in adapter payload',
      );
  }
  for (const value of seen)
    assert(
      !serialized.includes(value),
      'Secrets must not be stored in plaintext',
    );
  const token = await mint();
  const doc = await mongo.db
    .collection('oauth_state')
    .findOne({ _id: `AccessToken:${digest(token)}` });
  assert(doc?.encrypted && !doc.payload && !doc.jti);
});
test('adapter consume uses atomic compare-and-set outside transaction too', async () => {
  const Adapter = createAdapter(mongo.db, server.key);
  const adapter = new Adapter('AuthorizationCode');
  const id = randomBytes(32).toString('base64url');
  await adapter.upsert(id, { jti: id, kind: 'AuthorizationCode' }, 60);
  const results = await Promise.allSettled(
    Array.from({ length: 8 }, () => adapter.consume(id)),
  );
  assert.equal(
    results.filter((result) => result.status === 'fulfilled').length,
    1,
  );
  assert(
    results
      .filter((result) => result.status === 'rejected')
      .every((result) => result.reason.error === 'invalid_grant'),
  );
});

test('ESM engine loads from a CommonJS Nest host without changing service module target', async () => {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const result = await promisify(execFile)(process.execPath, [
    '--input-type=commonjs',
    '-e',
    "import('oidc-provider').then(m => {if(typeof m.default !== 'function') process.exit(1)})",
  ]);
  assert.equal(result.stderr, '');
});

test('metadata-document extension admits approved client and rejects forbidden fetch without network access', async () => {
  const original = server;
  let requests = 0;
  server = await startProvider(mongo, {
    key: original.key,
    metadata: {
      fetch: async (url) => {
        requests++;
        assert.equal(String(url), METADATA_CLIENT);
        return new Response(
          JSON.stringify({
            client_id: METADATA_CLIENT,
            redirect_uris: [REDIRECT],
            response_types: ['code'],
            grant_types: ['authorization_code'],
            token_endpoint_auth_method: 'none',
          }),
          { headers: { 'content-type': 'application/json' } },
        );
      },
    },
  });
  try {
    const metadata = await (
      await http('/.well-known/oauth-authorization-server')
    ).json();
    assert.equal(metadata.client_id_metadata_document_supported, true);
    const auth = await authorize({ client_id: METADATA_CLIENT });
    assert(auth.code, 'Engine interaction must accept metadata client');
    const result = await exchange(auth, { client_id: METADATA_CLIENT });
    assert.equal(result.status, 200);
    assert.equal(
      (await introspect(result.data.access_token)).data.client_id,
      METADATA_CLIENT,
    );
    const count = requests;
    const denied = await authorize({
      client_id: 'https://127.0.0.1/metadata.json',
    });
    assert.equal(denied.error, 'invalid_client');
    assert.equal(
      requests,
      count,
      'Denied URL must never reach the custom fetch',
    );
  } finally {
    await server.close();
    server = original;
  }
});
test('metadata-document mismatched client_id is rejected by native engine validation', async () => {
  const original = server;
  server = await startProvider(mongo, {
    key: original.key,
    metadata: {
      fetch: async () =>
        new Response(
          JSON.stringify({
            client_id: 'https://mcp-client.example.test/wrong.json',
            redirect_uris: [REDIRECT],
            response_types: ['code'],
            grant_types: ['authorization_code'],
            token_endpoint_auth_method: 'none',
          }),
          { headers: { 'content-type': 'application/json' } },
        ),
    },
  });
  try {
    assert.equal(
      (await authorize({ client_id: METADATA_CLIENT })).error,
      'invalid_client_metadata',
    );
  } finally {
    await server.close();
    server = original;
  }
});

test('engine expiration rejects code/token even while storage TTL is still live', async () => {
  const token = await mint();
  const auth = await authorize();
  const Adapter = createAdapter(mongo.db, server.key);
  for (const [name, id] of [
    ['AccessToken', token],
    ['AuthorizationCode', auth.code],
  ]) {
    const adapter = new Adapter(name);
    const data = await adapter.find(id);
    data.exp = Math.floor(Date.now() / 1000) - 1;
    await adapter.upsert(id, data, 60);
  }
  assert.deepEqual((await introspect(token)).data, { active: false });
  assert.equal((await exchange(auth)).data.error, 'invalid_grant');
});

test('refresh, password and client-credentials grants are not enabled for the catalog profile', async () => {
  for (const grant_type of [
    'refresh_token',
    'password',
    'client_credentials',
  ]) {
    const result = await form('/oauth/token', {
      grant_type,
      client_id: PUBLIC_CLIENT,
    });
    assert.equal(result.status, 400);
    assert.equal(result.data.error, 'unsupported_grant_type');
    assert(!result.data.access_token);
  }
});
