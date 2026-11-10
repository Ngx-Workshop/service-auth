import { socialLink } from './social-link.mjs';
import { validateSocialSchema } from './social-schema.mjs';
import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, importPKCS8, SignJWT } from 'jose';

const origin = 'https://auth.ngx-workshop.io';
const redirects = new Set([
  'https://beta.ngx-workshop.io',
  'https://admin.ngx-workshop.io',
  origin,
]);
const random = () => randomBytes(32).toString('base64url');
const hash = (s) => createHash('sha256').update(s).digest('base64url');
const providers = {
  google: {
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    issuer: 'https://accounts.google.com',
    jwks: 'https://www.googleapis.com/oauth2/v3/certs',
    scope: 'openid email',
  },
  apple: {
    authorize: 'https://appleid.apple.com/auth/authorize',
    token: 'https://appleid.apple.com/auth/token',
    issuer: 'https://appleid.apple.com',
    jwks: 'https://appleid.apple.com/auth/keys',
    scope: 'openid email',
  },
  github: {
    authorize: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token',
    scope: 'read:user user:email',
  },
};
for (const p of Object.values(providers))
  if (p.jwks) p.keys = createRemoteJWKSet(new URL(p.jwks));

export function safeRedirect(value) {
  if (!value) return 'https://beta.ngx-workshop.io/';
  const url = new URL(value);
  if (!redirects.has(url.origin) || url.username || url.password)
    throw new Error('Unapproved redirect');
  return url.href;
}

export function loadSocialConfig(env = process.env) {
  const enabled = {};
  for (const [name, p] of Object.entries(providers)) {
    const prefix = `SOCIAL_${name.toUpperCase()}_`;
    const clientId = env[`${prefix}CLIENT_ID`];
    if (!clientId) continue;
    const secret = env[`${prefix}CLIENT_SECRET`];
    const privateKey = env[`${prefix}PRIVATE_KEY`];
    const teamId = env[`${prefix}TEAM_ID`];
    const keyId = env[`${prefix}KEY_ID`];
    if (name === 'apple' ? !(privateKey && teamId && keyId) : !secret)
      throw new Error(`Incomplete ${name} social configuration`);
    enabled[name] = {
      ...p,
      clientId,
      secret,
      privateKey,
      teamId,
      keyId,
      callback: `${origin}/api/auth/social/${name}/callback`,
    };
  }
  return enabled;
}

async function json(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
    headers: { Accept: 'application/json', ...options.headers },
  });
  if (!response.ok) throw new Error('Provider request failed');
  return response.json();
}

export async function providerIdentity(name, p, code, transaction, deps = {}) {
  const request = deps.json ?? json;
  let secret = p.secret;
  if (name === 'apple') {
    secret = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: p.keyId })
      .setIssuer(p.teamId)
      .setSubject(p.clientId)
      .setAudience('https://appleid.apple.com')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(await importPKCS8(p.privateKey.replace(/\\n/g, '\n'), 'ES256'));
  }
  const tokens = await request(p.token, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: p.callback,
      client_id: p.clientId,
      client_secret: secret,
      ...(name !== 'apple' ? { code_verifier: transaction.verifier } : {}),
    }),
  });
  if (tokens.error) throw new Error('Provider rejected code');
  if (name === 'github') {
    if (typeof tokens.access_token !== 'string')
      throw new Error('Missing token');
    const options = {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    };
    const user = await request('https://api.github.com/user', options);
    const emails = await request('https://api.github.com/user/emails', options);
    const email = emails.find(
      (e) => e.primary === true && e.verified === true,
    )?.email;
    if (!Number.isSafeInteger(user.id) || user.id <= 0 || !email)
      throw new Error('Verified email required');
    return { subject: String(user.id), email: email.toLowerCase().trim() };
  }
  const { payload } = await jwtVerify(tokens.id_token, p.keys, {
    issuer: p.issuer,
    audience: p.clientId,
    algorithms: ['RS256'],
    requiredClaims: ['sub', 'iat', 'exp', 'nonce', 'email', 'email_verified'],
  });
  if (
    payload.nonce !== transaction.nonce ||
    ![true, 'true'].includes(payload.email_verified) ||
    typeof payload.sub !== 'string' ||
    !payload.sub ||
    typeof payload.email !== 'string'
  )
    throw new Error('Invalid identity');
  return { subject: payload.sub, email: payload.email.toLowerCase().trim() };
}

function finish(res, accessToken, redirect) {
  res.cookie('accessToken', accessToken, {
    domain: process.env.DOMAIN || 'ngx-workshop.io',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
  });
  return res.redirect(303, redirect);
}

export async function installSocial(app, connection, auth, deps = {}) {
  const configured = deps.config ?? loadSocialConfig();
  let transactions;
  if (Object.keys(configured).length) {
    transactions = connection.db.collection('social_login_transactions');
    if (process.env.RUNTIME_PROFILE === 'production')
      await validateSocialSchema(connection.db);
    else
      await transactions.createIndex(
        { expiresAt: 1 },
        { expireAfterSeconds: 0 },
      );
  }
  const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
  };
  const link = socialLink({
    transactions,
    auth,
    configured,
    origin,
    random,
    hash,
    finish,
  });
  // Public paths are /api/auth/social/*; the existing ingress strips /api/auth.
  app.use('/social', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.path === '/providers' && req.method === 'GET')
      return res.json(Object.keys(configured));
    if (req.path === '/link') {
      try {
        return await link.handle(req, res);
      } catch {
        return res.redirect(303, `${origin}/login?social_error=failed`);
      }
    }
    const match = /^\/(google|apple|github)\/(start|callback)$/.exec(req.path);
    const name = match?.[1],
      action = match?.[2],
      p = configured[name];
    if (!p || !['GET', 'POST'].includes(req.method)) return res.sendStatus(404);
    const cookieName = `__Host-social_${name}`;
    // Host-only prefix prevents sibling subdomains from injecting login cookies.
    const options = cookieOptions;
    try {
      if (action === 'start') {
        if (req.method !== 'GET') return res.sendStatus(405);
        const redirect = safeRedirect(req.query.redirect);
        const state = random(),
          browser = random(),
          verifier = random(),
          nonce = random();
        await transactions.insertOne({
          _id: hash(state),
          browser: hash(browser),
          name,
          verifier,
          nonce,
          redirect,
          expiresAt: new Date(Date.now() + 600000),
        });
        res.cookie(cookieName, browser, { ...options, maxAge: 600000 });
        const url = new URL(p.authorize);
        url.search = new URLSearchParams({
          client_id: p.clientId,
          redirect_uri: p.callback,
          response_type: 'code',
          scope: p.scope,
          state,
          nonce,
          ...(name === 'apple'
            ? { response_mode: 'form_post' }
            : {
                code_challenge: hash(verifier),
                code_challenge_method: 'S256',
              }),
        }).toString();
        return res.redirect(303, url.href);
      }
      if (req.method !== (name === 'apple' ? 'POST' : 'GET'))
        return res.sendStatus(405);
      const input = name === 'apple' ? req.body : req.query;
      if (
        typeof input?.state !== 'string' ||
        typeof req.cookies?.[cookieName] !== 'string'
      )
        throw new Error('Missing state');
      const transaction = await transactions.findOneAndDelete({
        _id: hash(input.state),
        browser: hash(req.cookies[cookieName]),
        name,
        expiresAt: { $gt: new Date() },
      });
      res.clearCookie(cookieName, options);
      if (
        !transaction ||
        input.error ||
        typeof input.code !== 'string' ||
        input.code.length > 4096
      )
        throw new Error('Invalid callback');
      const identity = await (deps.identity ?? providerIdentity)(
        name,
        p,
        input.code,
        transaction,
      );
      if (
        !identity.email ||
        identity.email.length > 254 ||
        !identity.email.includes('@')
      )
        throw new Error('Invalid email');
      try {
        const { accessToken } = await auth.signInExternal(
          name,
          identity.subject,
          identity.email,
        );
        return finish(res, accessToken, transaction.redirect);
      } catch (error) {
        if (
          error?.getStatus?.() === 409 &&
          (await link.start(res, name, identity, transaction.redirect))
        )
          return;
        throw error;
      }
    } catch (error) {
      const reason = error?.getStatus?.() === 409 ? 'link_required' : 'failed';
      return res.redirect(303, `${origin}/login?social_error=${reason}`);
    }
  });
}
