import assert from 'node:assert/strict';
import { createServer, request } from 'node:https';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// Test-only socket routing: exercise native TLS with a private fixture CA while
// retaining production DNS checks, pin validation, SNI and certificate validation.
export async function tlsFixture(document, { trust = true } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'oauth-cimd-tls-'));
  const key = join(directory, 'key.pem'),
    cert = join(directory, 'cert.pem');
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
      cert,
      '-subj',
      '/CN=client.example.test',
      '-addext',
      'subjectAltName=DNS:client.example.test',
    ],
    { stdio: 'ignore' },
  );
  const ca = await readFile(cert);
  let calls = 0;
  const server = createServer(
    { key: await readFile(key), cert: ca },
    (_req, res) => {
      calls++;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(document));
    },
  );
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    get calls() {
      return calls;
    },
    dependencies: {
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      request: (url, options, callback) => {
        assert.equal(options.rejectUnauthorized, true);
        assert.equal(options.servername, 'client.example.test');
        assert.equal(options.agent, false);
        options.lookup(url.hostname, { all: true }, (error, addresses) => {
          assert.equal(error, null);
          assert.deepEqual(addresses, [
            { address: '93.184.216.34', family: 4 },
          ]);
        });
        return request(
          {
            ...options,
            hostname: '127.0.0.1',
            port: server.address().port,
            path: url.pathname,
            ...(trust ? { ca } : {}),
            headers: { ...options.headers, host: url.host },
          },
          callback,
        );
      },
    },
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
      await rm(directory, { recursive: true, force: true });
    },
  };
}
