import { randomBytes } from 'node:crypto';
import { createAdapter, digest } from './mongo-adapter.mjs';
import { escape, readForm } from './interactions.mjs';

export function grantHandler(provider, db, auth, config) {
  const Adapter = createAdapter(
    db,
    config.storageKeys,
    config.activeStorageKey,
  );
  const forms = db.collection('oauth_forms');
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const session = await provider.Session.get({
      req,
      res,
      secure: config.runtime?.production === true,
    });
    if (
      !session.accountId ||
      !(await auth.findOAuthAccount(session.accountId))
    ) {
      res.statusCode = 401;
      return res.end('Sign in through an OAuth client to manage grants');
    }
    if (req.method === 'POST') {
      if (req.headers.origin !== config.issuer) {
        res.statusCode = 403;
        return res.end('Invalid form origin');
      }
      const body = await readForm(req);
      const record = await forms.findOneAndDelete(
        {
          _id: digest(body.get('csrf') ?? ''),
          sessionHash: digest(session.id),
          accountHash: digest(session.accountId),
          grantHash: digest(body.get('grant') ?? ''),
          expiresAt: { $gt: new Date() },
        },
        { maxTimeMS: 3000 },
      );
      if (!record) {
        res.statusCode = 403;
        return res.end('Invalid form');
      }
      const grant = await provider.Grant.find(body.get('grant'));
      if (!grant || grant.accountId !== session.accountId) {
        res.statusCode = 403;
        return res.end('Invalid grant owner');
      }
      // Tombstone is the durable security decision; cleanup can be retried.
      await db.collection('oauth_revoked').updateOne(
        { _id: digest(grant.jti) },
        { $set: { expiresAt: new Date(Date.now() + 1200000) } },
        {
          upsert: true,
          writeConcern: { w: 'majority', wtimeoutMS: 3000 },
          maxTimeMS: 3000,
        },
      );
      await grant.destroy();
      res.statusCode = 303;
      res.setHeader('Location', '/oauth/grants');
      return res.end();
    }
    if (req.method !== 'GET') {
      res.statusCode = 405;
      return res.end();
    }
    const grants = await new Adapter('Grant').listForAccount(session.accountId);
    const rows = [];
    for (const grant of grants) {
      if (!(await provider.Grant.find(grant.jti))) continue;
      const csrf = randomBytes(32).toString('base64url');
      await forms.insertOne(
        {
          _id: digest(csrf),
          sessionHash: digest(session.id),
          accountHash: digest(session.accountId),
          grantHash: digest(grant.jti),
          expiresAt: new Date(Date.now() + 600000),
        },
        { writeConcern: { w: 'majority', wtimeoutMS: 3000 } },
      );
      const client = [...config.clients, ...config.metadataClients].find(
        (c) => c.client_id === grant.clientId,
      );
      rows.push(
        `<li>${escape(client?.client_name ?? grant.clientId)} — catalog:read at ${escape(config.resource)}<form method="post" action="/oauth/grants"><input type="hidden" name="csrf" value="${csrf}"><input type="hidden" name="grant" value="${escape(grant.jti)}"><button>Revoke access</button></form></li>`,
      );
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(
      `<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorized clients</title><main><h1>Authorized clients</h1><p>Showing up to 100 recent active grants. Revocation takes effect immediately.</p><ul>${rows.join('')}</ul></main></html>`,
    );
  };
}
