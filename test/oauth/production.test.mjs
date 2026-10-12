import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, symlink, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { runtimeProfile, productionIngress } from '../../src/oauth/profile.mjs';
import { validateConfig, loadConfig } from '../../src/oauth/config.mjs';
import { validateMongoSettings } from '../../src/oauth/mongo-settings.mjs';
const env = {
  RUNTIME_PROFILE: 'production',
  NODE_ENV: 'production',
  LISTEN_HOST: '0.0.0.0',
  TRUSTED_PROXY_IPS: '10.116.0.3',
  MONGODB_URI:
    'mongodb://auth:password@mongo.example.test:27017/accounts?authSource=accounts&replicaSet=rs0&tls=true',
  MONGODB_ALLOWED_HOSTS: 'mongo.example.test',
  MONGODB_REPLICA_SET: 'rs0',
  MONGODB_TLS_CA_FILE: '/run/secrets/ca.pem',
};
function fixture() {
  return {
    issuer: 'https://auth.example.test',
    resource: 'https://mcp.example.test/mcp',
    clients: [
      {
        client_id: 'approved',
        client_name: 'Approved',
        redirect_uris: ['https://client.example.test/callback'],
      },
    ],
    resourceClient: {
      id: 'gateway',
      secret: randomBytes(32).toString('base64url'),
    },
    cookieKeys: [randomBytes(32).toString('base64url')],
    activeStorageKey: 'v1',
    storageKeys: { v1: randomBytes(32).toString('base64') },
    jwks: {
      keys: [
        {
          ...generateKeyPairSync('rsa', {
            modulusLength: 2048,
          }).privateKey.export({ format: 'jwk' }),
          kid: 'test',
          alg: 'RS256',
        },
      ],
    },
  };
}
test('production identities independent of listener and private TLS settings', () => {
  const config = validateConfig(fixture(), env);
  assert.equal(config.runtime.production, true);
  assert.equal(config.runtime.bind, '0.0.0.0');
});
for (const change of [
  { OAUTH_LOCAL_DEV: 'true' },
  { NODE_ENV: 'development' },
  { TRUSTED_PROXY_IPS: '0.0.0.0/0' },
  { LISTEN_HOST: '' },
  { RUNTIME_PROFILE: 'invalid' },
])
  test('unsafe profile fails closed ' + JSON.stringify(change), () =>
    assert.throws(() => runtimeProfile({ ...env, ...change })),
  );
for (const change of [
  { MONGODB_URI: env.MONGODB_URI.replace('&tls=true', '') },
  { MONGODB_URI: env.MONGODB_URI + '&tlsAllowInvalidHostnames=true' },
  { MONGODB_URI: env.MONGODB_URI.replace('rs0', 'wrong') },
  { MONGODB_ALLOWED_HOSTS: 'other.example.test' },
  { MONGODB_TLS_CA_FILE: '' },
])
  test('Mongo security config rejects ' + Object.keys(change)[0], () =>
    assert.throws(() => validateMongoSettings({ ...env, ...change })),
  );
test('production rejects loopback callbacks and HTTP identities', () => {
  const c = fixture();
  c.clients[0].redirect_uris = ['http://127.0.0.1:39999/callback'];
  assert.throws(() => validateConfig(c, env));
  c.issuer = 'http://auth.example.test';
  assert.throws(() => validateConfig(c, env));
});
test('durable config rejects weak permissions and symlinks without regenerating keys', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'auth-prod-config-')),
    file = join(dir, 'private.json');
  try {
    const c = fixture();
    await writeFile(file, JSON.stringify(c), { mode: 0o600 });
    const e = { ...env, OAUTH_ENABLED: 'true', OAUTH_CONFIG_FILE: file };
    assert.deepEqual((await loadConfig(e)).jwks, c.jwks);
    assert.deepEqual((await loadConfig(e)).storageKeys, c.storageKeys);
    await chmod(file, 0o644);
    await assert.rejects(loadConfig(e));
    await chmod(file, 0o600);
    await symlink(file, join(dir, 'link'));
    await assert.rejects(
      loadConfig({ ...e, OAUTH_CONFIG_FILE: join(dir, 'link') }),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test('trusted HTTPS ingress uses normalized client IP; spoofs and direct traffic rejected', () => {
  const boundary = productionIngress({
    issuer: 'https://auth.example.test',
    runtime: runtimeProfile(env),
  });
  const make = () => ({
    socket: { remoteAddress: '10.116.0.3' },
    rawHeaders: [
      'Host',
      'auth.example.test',
      'X-Forwarded-Proto',
      'https',
      'X-Forwarded-For',
      '203.0.113.1',
    ],
    headers: {
      host: 'auth.example.test',
      'x-forwarded-proto': 'https',
      'x-forwarded-for': '203.0.113.1',
    },
  });
  const res = { end: () => {} };
  let calls = 0;
  const req = make();
  boundary(req, res, () => calls++);
  assert.equal(calls, 1);
  assert.equal(req.oauthClientIp, '203.0.113.1');
  for (const change of [
    { host: 'evil.test' },
    { 'x-forwarded-proto': 'http' },
    { 'x-forwarded-for': '203.0.113.1, 127.0.0.1' },
    { forwarded: 'proto=https' },
    { 'x-forwarded-host': 'evil.test' },
  ]) {
    const bad = make();
    Object.assign(bad.headers, change);
    boundary(bad, res, () => {
      throw Error('Must reject');
    });
    assert.equal(res.statusCode, 403);
  }
  const direct = make();
  direct.socket.remoteAddress = '10.116.0.99';
  boundary(direct, res, () => {
    throw Error('Must reject');
  });
  assert.equal(res.statusCode, 403);
});
