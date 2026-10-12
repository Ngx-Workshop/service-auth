import { AsyncLocalStorage } from 'node:async_hooks';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';
import { errors } from 'oidc-provider';

export const digest = (value) =>
  createHash('sha256').update(value).digest('hex');
export const transactions = new AsyncLocalStorage();

// Spike adapter only: encryption key is supplied by the harness and retained
// across provider restarts. Production key ownership/rotation is future work.
export function createAdapter(db, key, faults = {}) {
  const collection = db.collection('oauth_state');
  function encrypt(value) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const data = Buffer.concat([
      cipher.update(JSON.stringify(value)),
      cipher.final(),
    ]);
    return {
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
  }
  function decrypt(value) {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(value.iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
    return JSON.parse(
      Buffer.concat([
        decipher.update(Buffer.from(value.data, 'base64')),
        decipher.final(),
      ]).toString(),
    );
  }
  const run = (operation) => {
    const session = transactions.getStore();
    if (!session) return operation();
    // Provider may revoke several models concurrently. MongoDB transactions
    // require sequential operations on their session.
    const result = (session.spikeQueue ?? Promise.resolve()).then(operation);
    session.spikeQueue = result;
    return result;
  };
  const options = () => ({ session: transactions.getStore() });
  const filter = (name, id) => ({
    _id: `${name}:${digest(id)}`,
    expiresAt: { $gt: new Date() },
  });
  const hashOnly = new Set(['AuthorizationCode', 'AccessToken']);
  function payload(doc, id) {
    if (!doc) return undefined;
    const data = decrypt(doc.encrypted);
    if (hashOnly.has(doc.model)) data.jti = id;
    if (doc.consumed) data.consumed = doc.consumed;
    return data;
  }
  return class MongoAdapter {
    constructor(name) {
      this.name = name;
    }
    async upsert(id, data, expiresIn) {
      if (this.name === 'AccessToken' && faults.tokenWrite) {
        faults.tokenWrite = false;
        throw new Error('Injected token storage failure');
      }
      const stored = { ...data };
      // Engine token values equal jti. Persist only their hash; reconstruct jti
      // from the caller's credential after a successful hashed lookup.
      if (hashOnly.has(this.name)) delete stored.jti;
      const doc = {
        encrypted: encrypt(stored),
        model: this.name,
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        ...(data.grantId ? { grantHash: digest(data.grantId) } : {}),
        ...(data.uid ? { uidHash: digest(data.uid) } : {}),
        ...(data.userCode ? { userCodeHash: digest(data.userCode) } : {}),
      };
      await run(() =>
        collection.updateOne(
          { _id: `${this.name}:${digest(id)}` },
          { $set: doc },
          { ...options(), upsert: true },
        ),
      );
    }
    async find(id) {
      return payload(
        await run(() => collection.findOne(filter(this.name, id), options())),
        id,
      );
    }
    async findByUid(uid) {
      return payload(
        await run(() =>
          collection.findOne(
            {
              model: this.name,
              uidHash: digest(uid),
              expiresAt: { $gt: new Date() },
            },
            options(),
          ),
        ),
      );
    }
    async findByUserCode(code) {
      return payload(
        await run(() =>
          collection.findOne(
            {
              model: this.name,
              userCodeHash: digest(code),
              expiresAt: { $gt: new Date() },
            },
            options(),
          ),
        ),
      );
    }
    async consume(id) {
      const result = await run(() =>
        collection.updateOne(
          { ...filter(this.name, id), consumed: { $exists: false } },
          { $set: { consumed: Math.floor(Date.now() / 1000) } },
          options(),
        ),
      );
      if (result.modifiedCount !== 1)
        throw new errors.InvalidGrant(
          'authorization code already consumed or expired',
        );
    }
    async destroy(id) {
      await run(() =>
        collection.deleteOne({ _id: `${this.name}:${digest(id)}` }, options()),
      );
    }
    async revokeByGrantId(grantId) {
      await run(() =>
        collection.deleteMany(
          { model: this.name, grantHash: digest(grantId) },
          options(),
        ),
      );
    }
  };
}
