import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParser from 'cookie-parser';
import supertest from 'supertest';
import { generateKeyPair, SignJWT, exportPKCS8 } from 'jose';
import {
  installSocial,
  loadSocialConfig,
  providerIdentity,
  safeRedirect,
} from '../../src/oauth/social.mjs';

test('redirects allow exact workshop origins and reject external/credential URLs', () => {
  assert.equal(
    safeRedirect('https://admin.ngx-workshop.io/users?q=1'),
    'https://admin.ngx-workshop.io/users?q=1',
  );
  for (const url of [
    'https://evil.example',
    '//evil.example',
    'javascript:alert(1)',
    'https://admin.ngx-workshop.io.evil.test',
    'https://a@admin.ngx-workshop.io',
  ])
    assert.throws(() => safeRedirect(url));
});
test('providers default disabled; partially configured credentials fail startup', () => {
  assert.deepEqual(loadSocialConfig({}), {});
  assert.throws(() => loadSocialConfig({ SOCIAL_GOOGLE_CLIENT_ID: 'id' }));
  assert.throws(() =>
    loadSocialConfig({
      SOCIAL_APPLE_CLIENT_ID: 'id',
      SOCIAL_APPLE_CLIENT_SECRET: 'wrong',
    }),
  );
});

test('OIDC validates signature, issuer, audience, expiry, nonce and verified email', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const p = {
    clientId: 'client',
    secret: 'secret',
    issuer: 'https://issuer.example',
    keys: publicKey,
  };
  const claims = {
    sub: 'stable-sub',
    email: 'A@Example.com',
    email_verified: true,
    nonce: 'nonce',
  };
  for (const [overrides, issuer, audience, expiry, ok] of [
    [{}, p.issuer, p.clientId, '5m', true],
    [{ nonce: 'bad' }, p.issuer, p.clientId, '5m', false],
    [{ email_verified: false }, p.issuer, p.clientId, '5m', false],
    [{}, 'https://wrong.example', p.clientId, '5m', false],
    [{}, p.issuer, 'wrong-client', '5m', false],
    [{}, p.issuer, p.clientId, '-1m', false],
  ]) {
    const token = await new SignJWT({ ...claims, ...overrides })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime(expiry)
      .sign(privateKey);
    const result = providerIdentity(
      'google',
      p,
      'code',
      { nonce: 'nonce', verifier: 'v' },
      {
        json: async () => ({ id_token: token }),
      },
    );
    if (ok)
      assert.deepEqual(await result, {
        subject: 'stable-sub',
        email: 'a@example.com',
      });
    else await assert.rejects(result);
  }
});

test('Apple generates a short-lived ES256 secret and accepts verified relay email', async () => {
  const signing = await generateKeyPair('ES256', { extractable: true });
  const provider = await generateKeyPair('RS256');
  const p = {
    clientId: 'services-id',
    teamId: 'team',
    keyId: 'key',
    privateKey: await exportPKCS8(signing.privateKey),
    issuer: 'https://appleid.apple.com',
    keys: provider.publicKey,
  };
  const id_token = await new SignJWT({
    sub: 'apple-sub',
    email: 'relay@privaterelay.appleid.com',
    email_verified: 'true',
    nonce: 'n',
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(p.issuer)
    .setAudience(p.clientId)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(provider.privateKey);
  const { jwtVerify } = await import('jose');
  const result = await providerIdentity(
    'apple',
    p,
    'code',
    { nonce: 'n' },
    {
      json: async (_url, options) => {
        const { payload } = await jwtVerify(
          options.body.get('client_secret'),
          signing.publicKey,
          {
            issuer: 'team',
            audience: p.issuer,
            subject: 'services-id',
            algorithms: ['ES256'],
          },
        );
        assert.equal(payload.exp - payload.iat, 300);
        return { id_token };
      },
    },
  );
  assert.equal(result.email, 'relay@privaterelay.appleid.com');
});

test('GitHub uses stable numeric ID and a primary verified private email', async () => {
  const request = async (url) =>
    url === 'token'
      ? { access_token: 'secret' }
      : url.endsWith('/emails')
        ? [{ email: 'private@example.com', primary: true, verified: true }]
        : { id: 123, login: 'mutable-name' };
  assert.deepEqual(
    await providerIdentity(
      'github',
      { token: 'token' },
      'code',
      {},
      { json: request },
    ),
    { subject: '123', email: 'private@example.com' },
  );
  await assert.rejects(
    providerIdentity(
      'github',
      { token: 'token' },
      'code',
      {},
      {
        json: async (url) =>
          url.endsWith('/emails')
            ? [{ email: 'bad@example.com', primary: true, verified: false }]
            : request(url),
      },
    ),
  );
});

async function fixture(name = 'google', conflict = false) {
  const rows = new Map(),
    calls = [];
  const collection = {
    createIndex: async () => {},
    insertOne: async (row) => rows.set(row._id, row),
    findOneAndDelete: async (filter) => {
      const row = rows.get(filter._id);
      if (
        !row ||
        row.name !== filter.name ||
        row.browser !== filter.browser ||
        row.expiresAt <= filter.expiresAt.$gt
      )
        return null;
      rows.delete(row._id);
      return row;
    },
  };
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  await installSocial(
    app,
    { db: { collection: () => collection } },
    {
      signInExternal: async (...args) => {
        calls.push(args);
        if (conflict) throw { getStatus: () => 409 };
        return { accessToken: 'our-session' };
      },
    },
    {
      config: {
        [name]: {
          authorize: 'https://provider.example/authorize',
          clientId: 'id',
          callback: 'https://auth.ngx-workshop.io/api/auth/social/callback',
          scope: 'openid email',
        },
      },
      identity: async () => ({ subject: 'sub', email: 'person@example.com' }),
    },
  );
  const client = supertest(app);
  const start = await client
    .get(
      `/social/${name}/start?redirect=${encodeURIComponent('https://admin.ngx-workshop.io/users')}`,
    )
    .expect(303);
  const state = new URL(start.headers.location).searchParams.get('state');
  const cookie = start.headers['set-cookie'][0].split(';')[0];
  return { client, state, cookie, rows, calls };
}

test('callback is browser-bound, one-use, sets our cookie and returns to original destination', async () => {
  const f = await fixture();
  await f.client
    .get(`/social/google/callback?state=${f.state}&code=code`)
    .expect(303);
  assert.equal(f.calls.length, 0);
  const response = await f.client
    .get(`/social/google/callback?state=${f.state}&code=code`)
    .set('Cookie', f.cookie)
    .expect(303);
  assert.equal(
    response.headers.location,
    'https://admin.ngx-workshop.io/users',
  );
  assert.match(
    response.headers['set-cookie'].join(';'),
    /accessToken=our-session/,
  );
  assert.deepEqual(f.calls, [['google', 'sub', 'person@example.com']]);
  await f.client
    .get(`/social/google/callback?state=${f.state}&code=code`)
    .set('Cookie', f.cookie)
    .expect(303);
  assert.equal(f.calls.length, 1);
});

test('Apple form POST callback, cancellation, expiry and collisions', async () => {
  for (const scenario of ['success', 'cancel', 'expired', 'conflict']) {
    const f = await fixture('apple', scenario === 'conflict');
    if (scenario === 'expired')
      for (const row of f.rows.values()) row.expiresAt = new Date(0);
    const response = await f.client
      .post('/social/apple/callback')
      .type('form')
      .set('Cookie', f.cookie)
      .send({
        state: f.state,
        ...(scenario === 'cancel'
          ? { error: 'access_denied' }
          : { code: 'code' }),
      })
      .expect(303);
    assert.equal(
      response.headers.location,
      scenario === 'success'
        ? 'https://admin.ngx-workshop.io/users'
        : `https://auth.ngx-workshop.io/login?social_error=${scenario === 'conflict' ? 'link_required' : 'failed'}`,
    );
    if (scenario !== 'success')
      assert.doesNotMatch(
        response.headers['set-cookie']?.join(';') ?? '',
        /accessToken=/,
      );
  }
});

test('production index validation does not need schema mutation privileges', async () => {
  const { validateSocialSchema } = await import(
    '../../src/oauth/social-schema.mjs'
  );
  const valid = {
    social_login_transactions: [
      { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
    ],
    users: [{ key: { externalIdentities: 1 }, unique: true, sparse: true }],
  };
  const db = (indexes) => ({
    collection: (name) => ({
      listIndexes: () => ({ toArray: async () => indexes[name] }),
    }),
  });
  await validateSocialSchema(db(valid));
  await assert.rejects(
    validateSocialSchema(db({ ...valid, users: [] })),
    /provision separately/,
  );
  await assert.rejects(
    validateSocialSchema(
      db({
        ...valid,
        social_login_transactions: [
          { key: { expiresAt: 1 }, expireAfterSeconds: 600 },
        ],
      }),
    ),
    /provision separately/,
  );
});
