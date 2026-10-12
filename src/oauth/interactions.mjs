import { randomBytes } from 'node:crypto';
import { digest } from './mongo-adapter.mjs';

export const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ],
  );
export async function readForm(req) {
  if (
    req.headers['content-type']?.split(';')[0] !==
    'application/x-www-form-urlencoded'
  )
    throw new Error('Invalid form');
  let body = '';
  for await (const chunk of req) {
    body += chunk.toString();
    if (Buffer.byteLength(body) > 8192) throw new Error('Form too large');
  }
  const form = new URLSearchParams(body);
  for (const key of form.keys())
    if (form.getAll(key).length !== 1) throw new Error('Repeated field');
  return form;
}
export function interactionHandler(provider, db, auth, config) {
  const attempts = new Map();
  const forms = db.collection('oauth_forms');
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    // no-referrer makes native browser form POSTs send Origin: null.
    // Keep same-origin submissions verifiable without leaking URLs to clients.
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const details = await provider.interactionDetails(req, res);
    const { uid, prompt, params } = details;
    const client = [...config.clients, ...config.metadataClients].find(
      (client) => client.client_id === params.client_id,
    );
    if (!client || !['login', 'consent'].includes(prompt.name))
      throw new Error('Unsupported interaction');
    if (!client.redirect_uris.includes(params.redirect_uri))
      throw new Error('Unregistered interaction callback');
    // Chrome applies form-action to redirects after the native form POST.
    // Only the current client's registered callback origin may receive them.
    const callbackOrigin = new URL(params.redirect_uri).origin;
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'none'; form-action 'self' ${callbackOrigin}; frame-ancestors 'none'; base-uri 'none'`,
    );
    async function page(message = '') {
      const csrf = randomBytes(32).toString('base64url');
      await forms.insertOne(
        {
          _id: digest(csrf),
          uidHash: digest(uid),
          prompt: prompt.name,
          expiresAt: new Date(Date.now() + 600000),
        },
        { writeConcern: { w: 'majority', wtimeoutMS: 3000 }, maxTimeMS: 3000 },
      );
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      const fields =
        prompt.name === 'login'
          ? '<label>Email <input name="email" type="email" autocomplete="username" maxlength="254" required></label><label>Password <input name="password" type="password" autocomplete="current-password" maxlength="100" required></label><button name="action" value="login">Sign in</button>'
          : `<p>Allow ${escape(client.client_name)} to read the workshop catalog?</p><p>Permission: catalog:read</p><p>Resource: ${escape(config.resource)}</p><button name="action" value="allow">Allow</button><button name="action" value="deny">Deny</button>`;
      res.end(
        `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ngx Workshop authorization</title><main><h1>${prompt.name === 'login' ? 'Sign in' : 'Consent'}</h1><p role="alert">${escape(message)}</p><form method="post" action="/oauth/interaction/${escape(uid)}"><input type="hidden" name="csrf" value="${csrf}">${fields}</form></main></html>`,
      );
    }
    if (req.method === 'GET') return page();
    if (req.method !== 'POST') {
      res.statusCode = 405;
      return res.end();
    }
    if (req.headers.origin !== config.issuer) {
      res.statusCode = 403;
      return res.end('Invalid form origin');
    }
    const form = await readForm(req);
    const consumed = await forms.findOneAndDelete(
      {
        _id: digest(form.get('csrf') ?? ''),
        uidHash: digest(uid),
        prompt: prompt.name,
        expiresAt: { $gt: new Date() },
      },
      { maxTimeMS: 3000 },
    );
    if (!consumed) {
      res.statusCode = 403;
      return res.end('Expired or invalid form');
    }
    if (prompt.name === 'login') {
      // Socket identity is deliberate: never trust forwarding headers locally.
      const key = config.runtime?.production
        ? req.oauthClientIp
        : req.socket.remoteAddress;
      const now = Date.now();
      for (const [id, attempt] of attempts)
        if (attempt.until <= now) attempts.delete(id);
      const attempt = attempts.get(key) ?? {
        count: 0,
        failures: 0,
        until: now + 60000,
      };
      attempts.set(key, attempt);
      if (
        ++attempt.count > 60 ||
        attempt.failures >= 10 ||
        attempts.size > 10000
      ) {
        res.statusCode = 429;
        return res.end('Try again later');
      }
      const email = form.get('email') ?? '',
        password = form.get('password') ?? '';
      const accountId =
        email.length <= 254 &&
        password.length >= 1 &&
        password.length <= 100 &&
        form.get('action') === 'login'
          ? await auth.authenticateOAuth(email, password)
          : undefined;
      if (!accountId) {
        attempt.failures++;
        res.statusCode = 401;
        return page('Invalid email or password');
      }
      return provider.interactionFinished(
        req,
        res,
        { login: { accountId } },
        { mergeWithLastSubmission: false },
      );
    }
    if (form.get('action') === 'deny')
      return provider.interactionFinished(
        req,
        res,
        {
          error: 'access_denied',
          error_description: 'User denied catalog access',
        },
        { mergeWithLastSubmission: false },
      );
    if (
      form.get('action') !== 'allow' ||
      !details.session?.accountId ||
      !(await auth.findOAuthAccount(details.session.accountId))
    )
      throw new Error('Invalid consent');
    const grant = details.grantId
      ? await provider.Grant.find(details.grantId)
      : new provider.Grant({
          accountId: details.session.accountId,
          clientId: client.client_id,
        });
    if (
      !grant ||
      grant.accountId !== details.session.accountId ||
      grant.clientId !== client.client_id
    )
      throw new Error('Invalid grant owner');
    grant.addResourceScope(config.resource, 'catalog:read');
    grant.addOIDCScope('catalog:read');
    const grantId = await grant.save();
    return provider.interactionFinished(
      req,
      res,
      { consent: { grantId } },
      { mergeWithLastSubmission: true },
    );
  };
}
