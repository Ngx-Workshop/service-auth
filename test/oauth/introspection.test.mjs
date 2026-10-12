import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const {
  OAuthIntrospectionClient,
  OAuthVerificationError,
  AuthClientService,
  NgxAuthClientModule,
  RolesGuard,
} = require('../../dist/libs/ngx-auth-client');
const token = 'a'.repeat(43),
  resource = 'http://127.0.0.1:3011/mcp';
async function fixture(callback) {
  const server = createServer(callback);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const issuer = `http://127.0.0.1:${server.address().port}`;
  return {
    issuer,
    client: new OAuthIntrospectionClient({
      issuer,
      introspectionUrl: issuer + '/oauth/introspect',
      resource,
      clientId: 'gateway',
      clientSecret: 'fixture-only',
      allowLocalHttp: true,
      timeoutMs: 100,
    }),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
const active = (issuer) => ({
  active: true,
  iss: issuer,
  aud: resource,
  sub: 'account',
  client_id: 'client',
  scope: 'catalog:read',
  token_type: 'Bearer',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 600,
});
test('additive exports preserve old client API and map subject independently of client', async () => {
  assert(AuthClientService && NgxAuthClientModule && RolesGuard);
  const state = await fixture((req, res) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.headers.cookie, undefined);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(active(state.issuer)));
  });
  try {
    const principal = await state.client.verifyAccessToken(token);
    assert.equal(principal.subject, 'account');
    assert.equal(principal.clientId, 'client');
    assert(Object.isFrozen(principal));
  } finally {
    await state.close();
  }
});
for (const [name, mutate, category] of [
  ['inactive', () => ({ active: false }), 'invalid_token'],
  [
    'wrong audience',
    (data) => ({ ...data, aud: resource + '/' }),
    'invalid_token',
  ],
  [
    'wrong issuer',
    (data) => ({ ...data, iss: 'https://other.example' }),
    'invalid_token',
  ],
  ['expired', (data) => ({ ...data, exp: 0 }), 'invalid_token'],
  [
    'missing identity',
    (data) => ({ ...data, sub: undefined }),
    'invalid_auth_response',
  ],
  [
    'wrong token use',
    (data) => ({ ...data, token_type: 'ID' }),
    'invalid_auth_response',
  ],
  [
    'bad scope',
    (data) => ({ ...data, scope: 'catalog:read  admin' }),
    'invalid_auth_response',
  ],
])
  test(`rejects ${name}`, async () => {
    const state = await fixture((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(mutate(active(state.issuer))));
    });
    try {
      await assert.rejects(
        state.client.verifyAccessToken(token),
        (error) =>
          error instanceof OAuthVerificationError &&
          error.category === category,
      );
    } finally {
      await state.close();
    }
  });
for (const mode of [
  'redirect',
  'malformed',
  'oversized',
  'timeout',
  'unauthorized',
])
  test(`fails closed for ${mode}`, async () => {
    const state = await fixture((_req, res) => {
      res.setHeader('content-type', 'application/json');
      if (mode === 'timeout') return;
      if (mode === 'redirect') {
        res.statusCode = 302;
        res.setHeader('location', 'http://127.0.0.1:1');
      }
      if (mode === 'unauthorized') res.statusCode = 401;
      res.end(mode === 'oversized' ? 'x'.repeat(65537) : 'bad-json');
    });
    try {
      await assert.rejects(
        state.client.verifyAccessToken(token),
        OAuthVerificationError,
      );
    } finally {
      await state.close();
    }
  });
test('rejects JWTs before contacting auth and rejects unsafe configuration', async () => {
  const state = await fixture(() => assert.fail('No HTTP request expected'));
  try {
    await assert.rejects(
      state.client.verifyAccessToken('ey.fake.jwt'),
      (error) => error.category === 'invalid_token',
    );
  } finally {
    await state.close();
  }
  assert.throws(
    () =>
      new OAuthIntrospectionClient({
        issuer: 'http://public.example',
        introspectionUrl: 'http://public.example/oauth/introspect',
        resource,
        clientId: 'g',
        clientSecret: 's',
        allowLocalHttp: true,
      }),
  );
});
