import { escape } from './interactions.mjs';

const path = '/api/auth/social/link';
const cookieName = '__Host-social_link';
const cookieOptions = {
  secure: true,
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
};
const names = { google: 'Google', github: 'GitHub' };
const ttl = 300000;

export function socialLink({
  transactions,
  auth,
  configured,
  origin,
  random,
  hash,
  finish,
}) {
  return {
    async start(res, provider, identity, redirect) {
      if (!Object.hasOwn(names, provider)) return false;
      const accountId = await auth.findPasswordLinkAccount(identity.email);
      if (!accountId) return false;

      const browser = random();
      await transactions.insertOne({
        _id: hash(browser),
        kind: 'password-link',
        csrf: random(),
        provider,
        accountId,
        subject: identity.subject,
        email: identity.email,
        redirect,
        expiresAt: new Date(Date.now() + ttl),
      });
      res.cookie(cookieName, browser, { ...cookieOptions, maxAge: ttl });
      res.redirect(303, path);
      return true;
    },

    async handle(req, res) {
      if (!transactions) return res.sendStatus(404);
      if (!['GET', 'POST'].includes(req.method)) return res.sendStatus(405);
      const { password, csrf } = req.body ?? {};
      if (req.method === 'POST') {
        if (req.headers.origin !== origin) return res.sendStatus(403);
        if (
          !req.is('application/x-www-form-urlencoded') ||
          typeof csrf !== 'string' ||
          typeof password !== 'string' ||
          !password ||
          password.length > 1024
        )
          return res.sendStatus(400);
      }

      const browser = req.cookies?.[cookieName];
      if (typeof browser !== 'string') return expired(res);
      const filter = {
        _id: hash(browser),
        kind: 'password-link',
        expiresAt: { $gt: new Date() },
        ...(req.method === 'POST' ? { csrf } : {}),
      };
      const transaction =
        req.method === 'GET'
          ? await transactions.findOne(filter)
          : await transactions.findOneAndDelete(filter);
      if (!transaction || !configured[transaction.provider])
        return expired(res);

      if (req.method === 'GET') {
        const name = names[transaction.provider];
        return page(
          res,
          'Connect ' + name,
          `<p>Enter your NGX Workshop password to connect ${name} to your existing account.</p>
          <form method="post" action="${path}">
            <input type="hidden" name="csrf" value="${escape(transaction.csrf)}">
            <p><label>Email <input autocomplete="username" value="${escape(transaction.email)}" readonly></label></p>
            <p><label>NGX Workshop password <input name="password" type="password" autocomplete="current-password" maxlength="1024" required></label></p>
            <button type="submit">Connect ${name} and sign in</button>
          </form><p><a href="/login">Cancel</a></p>`,
          new URL(transaction.redirect).origin,
        );
      }

      res.clearCookie(cookieName, cookieOptions);
      try {
        const { accessToken } = await auth.linkExternalToPasswordAccount(
          transaction.accountId,
          transaction.provider,
          transaction.subject,
          transaction.email,
          password,
        );
        return finish(res, accessToken, transaction.redirect);
      } catch {
        return page(
          res.status(401),
          'Could not connect your account',
          '<p>We could not verify your existing account or connect this provider. Start again from the sign-in page.</p><a href="/login">Back to sign in</a>',
        );
      }
    },
  };
}

function expired(res) {
  return page(
    res.status(410),
    'Connection request expired',
    '<p>Start a new sign-in with your provider to connect your account.</p><a href="/login">Back to sign in</a>',
  );
}

function page(res, title, content, destination = '') {
  // Chrome applies form-action to the redirect after a native form POST.
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; form-action 'self' ${destination}; frame-ancestors 'none'; base-uri 'none'`,
  );
  // Same-origin keeps a native form POST's Origin available to verify.
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return res
    .type('html')
    .send(
      `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)} | NGX Workshop</title><main><h1>${escape(title)}</h1>${content}</main></html>`,
    );
}
