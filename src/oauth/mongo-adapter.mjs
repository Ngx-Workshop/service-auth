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
export const storageRequests = new AsyncLocalStorage();

export function createAdapter(db, keys, activeKey) {
  const collection = db.collection('oauth_state');
  function encrypt(value, aad) {
    const key = Buffer.from(keys[activeKey], 'base64');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(aad));
    const data = Buffer.concat([
      cipher.update(JSON.stringify(value)),
      cipher.final(),
    ]);
    return {
      kid: activeKey,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
  }
  function decrypt(value, aad) {
    if (!keys[value.kid]) throw new Error('Unknown storage key');
    const key = Buffer.from(keys[value.kid], 'base64');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(value.iv, 'base64'),
    );
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
    return JSON.parse(
      Buffer.concat([
        decipher.update(Buffer.from(value.data, 'base64')),
        decipher.final(),
      ]).toString(),
    );
  }
  const observe = async (operation) => {
    try {
      return await operation();
    } catch (error) {
      const state = storageRequests.getStore();
      if (state) state.error = error;
      throw error;
    }
  };
  const run = (operation) => {
    const session = transactions.getStore();
    if (!session) return observe(operation);
    // Provider may revoke several models concurrently. MongoDB transactions
    // require sequential operations on their session.
    const result = (session.oauthQueue ?? Promise.resolve()).then(() =>
      observe(operation),
    );
    session.oauthQueue = result;
    return result;
  };
  const options = () =>
    transactions.getStore()
      ? { session: transactions.getStore(), maxTimeMS: 3000 }
      : { maxTimeMS: 3000, writeConcern: { w: 'majority', wtimeoutMS: 3000 } };
  const filter = (name, id) => ({
    _id: `${name}:${digest(id)}`,
    expiresAt: { $gt: new Date() },
  });
  const hashOnly = new Set(['AuthorizationCode', 'AccessToken']);
  function payload(doc, id) {
    if (!doc) return undefined;
    const data = decrypt(doc.encrypted, doc._id);
    if (hashOnly.has(doc.model)) data.jti = id;
    if (doc.consumed) data.consumed = doc.consumed;
    return data;
  }
  return class MongoAdapter {
    constructor(name) {
      this.name = name;
    }
    async listForAccount(accountId) {
      const records = await collection
        .find(
          {
            model: 'Grant',
            accountHash: digest(accountId),
            expiresAt: { $gt: new Date() },
          },
          { maxTimeMS: 3000 },
        )
        .sort({ expiresAt: -1 })
        .limit(100)
        .toArray();
      return records.map((record) => payload(record)).filter(Boolean);
    }
    async upsert(id, data, expiresIn) {
      if (!Number.isFinite(expiresIn) || expiresIn <= 0 || expiresIn > 86400)
        throw new Error('Invalid provider expiry');
      // Write the grant in the redemption transaction so concurrent grant
      // deletion conflicts instead of allowing a new token after revocation.
      if (
        this.name === 'AccessToken' &&
        data.grantId &&
        transactions.getStore()
      ) {
        const touched = await run(() =>
          collection.updateOne(
            filter('Grant', data.grantId),
            { $set: { touchedAt: new Date() } },
            options(),
          ),
        );
        if (touched.matchedCount !== 1)
          throw new errors.InvalidGrant('grant unavailable');
      }
      const stored = { ...data };
      // Engine token values equal jti. Persist only their hash; reconstruct jti
      // from the caller's credential after a successful hashed lookup.
      if (hashOnly.has(this.name)) delete stored.jti;
      const doc = {
        encrypted: encrypt(stored, `${this.name}:${digest(id)}`),
        model: this.name,
        ...(data.accountId ? { accountHash: digest(data.accountId) } : {}),
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
      if (
        this.name === 'Grant' &&
        (await observe(() =>
          db
            .collection('oauth_revoked')
            .findOne({ _id: digest(id) }, { maxTimeMS: 3000 }),
        ))
      )
        return undefined;
      const result = await this.lookup(id);
      if (
        result?.grantId &&
        (await observe(() =>
          db
            .collection('oauth_revoked')
            .findOne({ _id: digest(result.grantId) }, { maxTimeMS: 3000 }),
        ))
      )
        return undefined;
      return result;
    }
    async lookup(id) {
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
