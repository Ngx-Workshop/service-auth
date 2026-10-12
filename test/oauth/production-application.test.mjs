import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createServer as httpsServer } from 'node:https';
import { randomBytes, generateKeyPairSync, createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import { startMongoFixture } from '../../spikes/oauth-engine/mongo-fixture.mjs';
import {
  provisionOAuthSchema,
  validateOAuthSchema,
} from '../../src/oauth/mongo-schema.mjs';
const require = createRequire(import.meta.url);
require('@nestjs/common').Logger.overrideLogger(false);
const { createAuthApp } = require('../../dist/src/bootstrap.js');
const { request } = require('node:https');
test('production Nest auth uses TLS authenticated scoped Mongo and trusted proxy secure sessions', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'auth-production-app-'));
  let fixture, app, edge, client;
  const saved = { ...process.env };
  try {
    const key = join(dir, 'key.pem'),
      ca = join(dir, 'ca.pem'),
      pem = join(dir, 'server.pem'),
      member = join(dir, 'member');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-keyout',
        key,
        '-out',
        ca,
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
      ],
      { stdio: 'ignore' },
    );
    await writeFile(
      pem,
      Buffer.concat([await readFile(key), await readFile(ca)]),
      { mode: 0o600 },
    );
    await writeFile(member, randomBytes(64).toString('base64'), {
      mode: 0o600,
    });
    fixture = await startMongoFixture({ tls: { pem, ca } });
    const db = fixture.db,
      dbName = db.databaseName;
    await provisionOAuthSchema(db);
    await db.collection('oauth_state').dropIndex('model_1_accountHash_1');
    await assert.rejects(validateOAuthSchema(db), /indexes/);
    await provisionOAuthSchema(db);
    await db.command({ collMod: 'oauth_state', validationLevel: 'off' });
    await assert.rejects(validateOAuthSchema(db), /validator/);
    await provisionOAuthSchema(db);
    await db.collection('users').insertOne({
      email: 'production@example.test',
      password: await bcrypt.hash('ExistingPassword1!', 10),
      role: 'regular',
    });
    const actions = ['find', 'insert', 'update', 'remove', 'listIndexes'];
    await db.command({
      createRole: 'authRuntime',
      privileges: [
        {
          resource: { db: dbName, collection: '' },
          actions: ['listCollections'],
        },
        ...['users', 'oauth_state', 'oauth_forms', 'oauth_revoked'].map(
          (collection) => ({ resource: { db: dbName, collection }, actions }),
        ),
      ],
      roles: [],
    });
    const password = randomBytes(32).toString('hex');
    await db.command({
      createUser: 'runtime',
      pwd: password,
      roles: [{ role: 'authRuntime', db: dbName }],
    });
    await fixture.enableAuth(member);
    const port = fixture.client.options.hosts[0].port;
    const uri = `mongodb://runtime:${password}@127.0.0.1:${port}/${dbName}?authSource=${dbName}&replicaSet=oauthSpike&tls=true`;
    client = new mongoose.mongo.MongoClient(uri, {
      tlsCAFile: ca,
      serverSelectionTimeoutMS: 3000,
    });
    await client.connect();
    await assert.rejects(
      client.db().collection('unrelated').findOne({}),
      (e) => e.code === 13,
    );
    await assert.rejects(
      client.db().command({ collMod: 'oauth_state', validationLevel: 'off' }),
      (e) => e.code === 13,
    );
    let backend;
    edge = httpsServer(
      { key: await readFile(key), cert: await readFile(ca) },
      (req, res) => {
        const forwarded = require('node:http').request(
          {
            hostname: '127.0.0.1',
            port: backend,
            path: req.url,
            method: req.method,
            headers: {
              ...req.headers,
              host: 'auth.example.test',
              'x-forwarded-proto': 'https',
              'x-forwarded-for': '203.0.113.7',
            },
          },
          (upstream) => {
            res.writeHead(upstream.statusCode, upstream.headers);
            upstream.pipe(res);
          },
        );
        forwarded.on('error', () => {
          res.statusCode = 503;
          res.end();
        });
        req.pipe(forwarded);
      },
    );
    await new Promise((resolve) => edge.listen(0, '127.0.0.1', resolve));
    const config = {
      issuer: 'https://auth.example.test',
      resource: 'https://mcp.example.test/mcp',
      clients: [
        {
          client_id: 'approved',
          client_name: 'Approved client',
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
            kid: 'persistent',
            alg: 'RS256',
          },
        ],
      },
    };
    const file = join(dir, 'private.json');
    await writeFile(file, JSON.stringify(config), { mode: 0o600 });
    Object.assign(process.env, {
      NODE_ENV: 'production',
      RUNTIME_PROFILE: 'production',
      OAUTH_LOCAL_DEV: 'false',
      OAUTH_ENABLED: 'true',
      OAUTH_CONFIG_FILE: file,
      LISTEN_HOST: '0.0.0.0',
      TRUSTED_PROXY_IPS: '127.0.0.1',
      MONGODB_URI: uri,
      MONGODB_ALLOWED_HOSTS: '127.0.0.1',
      MONGODB_REPLICA_SET: 'oauthSpike',
      MONGODB_TLS_CA_FILE: ca,
      JWT_SECRET: randomBytes(32).toString('base64url'),
      JWT_ISSUER: 'existing',
      JWT_AUDIENCE: 'existing',
    });
    ({ app } = await createAuthApp());
    await app.listen(0, '127.0.0.1');
    backend = app.getHttpServer().address().port;
    const cookies = new Map();
    async function call(path, method = 'GET', body, headers = {}) {
      const parsed = new URL(path, config.issuer);
      path = parsed.pathname + parsed.search;
      return new Promise((resolve, reject) => {
        const req = request(
          {
            hostname: '127.0.0.1',
            port: edge.address().port,
            path,
            method,
            ca: require('node:fs').readFileSync(ca),
            headers: {
              cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; '),
              ...headers,
            },
          },
          (res) => {
            for (const item of res.headers['set-cookie'] ?? []) {
              assert.match(item, /; secure/i);
              assert.match(item, /; httponly/i);
              const pair = item.split(';')[0],
                i = pair.indexOf('=');
              cookies.set(pair.slice(0, i), pair.slice(i + 1));
            }
            let text = '';
            res.on('data', (chunk) => (text += chunk));
            res.on('end', () =>
              resolve({ status: res.statusCode, headers: res.headers, text }),
            );
          },
        );
        req.setTimeout(10000, () => req.destroy(new Error('Fixture timeout')));
        req.on('error', reject);
        req.end(body);
      });
    }
    const discovery = await call('/.well-known/oauth-authorization-server');
    assert.equal(discovery.status, 200);
    assert.equal(JSON.parse(discovery.text).issuer, config.issuer);
    assert.equal(
      (
        await fetch(
          `http://127.0.0.1:${backend}/.well-known/oauth-authorization-server`,
        )
      ).status,
      403,
    );
    const verifier = randomBytes(32).toString('base64url');
    let path =
      '/oauth/authorize?' +
      new URLSearchParams({
        client_id: 'approved',
        redirect_uri: 'https://client.example.test/callback',
        scope: 'catalog:read',
        response_type: 'code',
        resource: config.resource,
        code_challenge: createHash('sha256')
          .update(verifier)
          .digest('base64url'),
        code_challenge_method: 'S256',
        state: 'checked',
      });
    let code;
    for (let i = 0; i < 14; i++) {
      const result = await call(path);
      const loc = result.headers.location;
      if (loc) {
        const url = new URL(loc, config.issuer);
        if (url.origin === 'https://client.example.test') {
          assert.equal(url.searchParams.get('state'), 'checked');
          code = url.searchParams.get('code');
          break;
        }
        path = url.pathname + url.search;
        continue;
      }
      const csrf = result.text.match(/name="csrf" value="([^"]+)"/)?.[1];
      assert(csrf, `Secure production form required (status ${result.status})`);
      const login = result.text.includes('<h1>Sign in</h1>');
      const submitted = await call(
        path,
        'POST',
        new URLSearchParams({
          csrf,
          ...(login
            ? {
                action: 'login',
                email: 'production@example.test',
                password: 'ExistingPassword1!',
              }
            : { action: 'allow' }),
        }).toString(),
        {
          origin: config.issuer,
          'content-type': 'application/x-www-form-urlencoded',
        },
      );
      assert.equal(submitted.status, 303);
      path = submitted.headers.location;
    }
    assert(code, 'Production code flow completed');
    const exchange = await call(
      '/oauth/token',
      'POST',
      new URLSearchParams({
        client_id: 'approved',
        grant_type: 'authorization_code',
        redirect_uri: 'https://client.example.test/callback',
        resource: config.resource,
        code,
        code_verifier: verifier,
      }).toString(),
      { 'content-type': 'application/x-www-form-urlencoded' },
    );
    assert.equal(exchange.status, 200);
    const token = JSON.parse(exchange.text).access_token;
    const introspect = () =>
      call(
        '/oauth/introspect',
        'POST',
        new URLSearchParams({ token }).toString(),
        {
          'content-type': 'application/x-www-form-urlencoded',
          authorization:
            'Basic ' +
            Buffer.from('gateway:' + config.resourceClient.secret).toString(
              'base64',
            ),
        },
      );
    assert.equal(JSON.parse((await introspect()).text).active, true);
    await app.close();
    ({ app } = await createAuthApp());
    await app.listen(0, '127.0.0.1');
    backend = app.getHttpServer().address().port;
    assert.equal(JSON.parse((await introspect()).text).active, true);
    const grants = await call('/oauth/grants');
    assert.equal(grants.status, 200);
    const csrf = grants.text.match(/name="csrf" value="([^"]+)"/)[1],
      grant = grants.text.match(/name="grant" value="([^"]+)"/)[1];
    assert.equal(
      (
        await call(
          '/oauth/grants',
          'POST',
          new URLSearchParams({ csrf, grant }).toString(),
          {
            origin: config.issuer,
            'content-type': 'application/x-www-form-urlencoded',
          },
        )
      ).status,
      303,
    );
    assert.equal(JSON.parse((await introspect()).text).active, false);
  } finally {
    await app?.close();
    if (edge) await new Promise((resolve) => edge.close(resolve));
    await client?.close();
    await fixture?.close();
    await rm(dir, { recursive: true, force: true });
    for (const key of Object.keys(process.env))
      if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
  }
});
