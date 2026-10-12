import { tlsFixture } from './tls-fixture.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import {
  createMetadataFetcher,
  publicAddress,
  metadataUrl,
} from '../../src/oauth/metadata-fetch.mjs';
const id = 'https://client.example.test/oauth.json';
const approved = [{ client_id: id }];
const resolve = async () => [{ address: '93.184.216.34', family: 4 }];
function transport(response = {}) {
  return (_url, options, callback) => {
    const req = new EventEmitter();
    req.end = () =>
      queueMicrotask(() => {
        const res = Readable.from([
          Buffer.from(response.body ?? '{"client_id":"test"}'),
        ]);
        res.statusCode = response.status ?? 200;
        res.headers = {
          'content-type': 'application/json',
          ...response.headers,
        };
        callback(res);
      });
    options.signal.addEventListener(
      'abort',
      () => req.emit('error', new Error('Aborted')),
      { once: true },
    );
    return req;
  };
}
test('approved metadata fetch pins DNS, disables connection reuse and verifies TLS', async () => {
  let calls = 0;
  const fetch = createMetadataFetcher(approved, {
    resolve: async (...args) => {
      calls++;
      return resolve(...args);
    },
    request: (url, options, callback) => {
      assert.equal(options.agent, false);
      assert.equal(options.rejectUnauthorized, true);
      assert.equal(options.servername, 'client.example.test');
      assert.equal(options.headers.authorization, undefined);
      options.lookup(url.hostname, { all: true }, (_error, addresses) =>
        assert.deepEqual(addresses, [{ address: '93.184.216.34', family: 4 }]),
      );
      return transport()(url, options, callback);
    },
  });
  assert.equal((await fetch(id)).status, 200);
  assert.equal(calls, 1);
});
for (const address of [
  '127.0.0.1',
  '10.0.0.1',
  '169.254.169.254',
  '100.64.0.1',
  '192.0.2.1',
  '198.18.0.1',
  '224.0.0.1',
  '240.0.0.1',
  '::1',
  '::ffff:127.0.0.1',
  '::ffff:93.184.216.34',
  'fc00::1',
  'fe80::1',
  '2001:db8::1',
  '2002::1',
  '64:ff9b::1',
])
  test(`rejects reserved address ${address}`, () =>
    assert.equal(publicAddress(address), false));
test('rejects mixed public/private DNS before opening a connection', async () => {
  await assert.rejects(
    createMetadataFetcher(approved, {
      resolve: async () => [
        { address: '93.184.216.34', family: 4 },
        { address: '10.0.0.1', family: 4 },
      ],
      request: () => {
        throw new Error('Must not connect');
      },
    })(id),
    /DNS/,
  );
});
test('URL allowlist rejects unapproved, literal-IP and malformed identities', async () => {
  await assert.rejects(
    createMetadataFetcher(approved)('https://unknown.example/oauth.json'),
    /approved/,
  );
  for (const value of [
    'http://client.example/oauth.json',
    'https://127.0.0.1/oauth.json',
    'https://user:pass@client.example/oauth.json',
    'https://client.example/',
    'https://client.example/oauth.json?x=1',
    'https://client.example/oauth.json#x',
    'https://client.example:443/oauth.json',
  ])
    assert.throws(() => metadataUrl(value));
});
for (const response of [
  { status: 302, headers: { location: 'https://other.example/' } },
  { headers: { 'content-type': 'text/html' } },
  { headers: { 'content-encoding': 'gzip' } },
  { body: 'bad-json' },
  { body: 'x'.repeat(65537) },
])
  test('rejects unsafe response without following redirects', async () => {
    await assert.rejects(
      createMetadataFetcher(approved, {
        resolve,
        request: transport(response),
      })(id),
    );
  });
test('bounds stalled DNS within the total deadline', async () => {
  const start = Date.now();
  await assert.rejects(
    createMetadataFetcher(approved, { resolve: () => new Promise(() => {}) })(
      id,
    ),
    /timeout/,
  );
  assert(Date.now() - start < 4000);
});

test('native HTTPS rejects an untrusted metadata certificate', async () => {
  const tls = await tlsFixture({ client_id: id }, { trust: false });
  try {
    await assert.rejects(
      createMetadataFetcher(approved, tls.dependencies)(id),
      /failed/,
    );
    assert.equal(tls.calls, 0);
  } finally {
    await tls.close();
  }
});
test('pre-aborted requests never resolve DNS or connect', async () => {
  await assert.rejects(
    createMetadataFetcher(approved, {
      resolve: () => {
        throw new Error('Must not resolve');
      },
    })(id, { signal: AbortSignal.abort() }),
    /timeout/,
  );
});
