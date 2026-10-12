import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import mongoose from 'mongoose';

// Always owns a fresh mongod/replica set; never connects to existing MongoDB.
export async function startMongoFixture({ replicaSet = true, tls } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'auth-oauth-spike-'));
  const reservation = createServer();
  await new Promise((resolve) => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  let child;
  let authKeyFile;
  let spawnError;
  const client = new mongoose.mongo.MongoClient(
    `mongodb://127.0.0.1:${port}/?directConnection=true`,
    {
      serverSelectionTimeoutMS: 500,
      ...(tls ? { tls: true, tlsCAFile: tls.ca } : {}),
    },
  );
  async function start() {
    spawnError = undefined;
    child = spawn(
      process.env.OAUTH_SPIKE_MONGOD ?? 'mongod',
      [
        '--dbpath',
        directory,
        '--bind_ip',
        '127.0.0.1',
        '--port',
        String(port),
        ...(replicaSet ? ['--replSet', 'oauthSpike'] : []),
        '--logpath',
        join(directory, 'mongod.log'),
        '--quiet',
        ...(tls
          ? [
              '--tlsMode',
              'requireTLS',
              '--tlsCertificateKeyFile',
              tls.pem,
              '--tlsCAFile',
              tls.ca,
              '--tlsAllowConnectionsWithoutCertificates',
            ]
          : []),
        ...(authKeyFile ? ['--keyFile', authKeyFile, '--auth'] : []),
      ],
      { stdio: 'ignore' },
    );
    child.on('error', (error) => {
      spawnError = error;
    });
    for (let attempt = 0; ; attempt++) {
      if (spawnError || child.exitCode !== null)
        throw new Error(
          'Cannot start isolated mongod; install it or set OAUTH_SPIKE_MONGOD',
        );
      try {
        await client.connect();
        await client.db('admin').command({ ping: 1 });
        break;
      } catch {
        if (attempt >= 40) throw new Error('Isolated mongod did not start');
        await delay(100);
      }
    }
  }
  async function primary() {
    for (let attempt = 0; ; attempt++) {
      if ((await client.db('admin').command({ hello: 1 })).isWritablePrimary)
        break;
      if (attempt >= 100)
        throw new Error('Isolated MongoDB primary did not become ready');
      await delay(100);
    }
  }
  async function stop() {
    await client.close();
    if (child?.exitCode === null && !spawnError) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      await exited;
    }
  }
  async function close() {
    try {
      await stop();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
  try {
    await start();
    if (replicaSet)
      await client.db('admin').command({
        replSetInitiate: {
          _id: 'oauthSpike',
          members: [{ _id: 0, host: `127.0.0.1:${port}` }],
        },
      });
    await primary();
    const db = client.db('auth_oauth_engine_spike');
    await db
      .collection('oauth_state')
      .createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await db.collection('oauth_state').createIndex({ model: 1, grantHash: 1 });
    await db.collection('oauth_state').createIndex({ model: 1, uidHash: 1 });
    return {
      client,
      db,
      close,
      enableAuth: async (keyFile) => {
        await stop();
        authKeyFile = keyFile;
        await start();
        await primary();
      },
      restart: async () => {
        await stop();
        await start();
        await primary();
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}
