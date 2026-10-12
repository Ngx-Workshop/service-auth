import { isIP } from 'node:net';
export function runtimeProfile(env = process.env) {
  const name = env.RUNTIME_PROFILE ?? 'local';
  if (!['local', 'production'].includes(name))
    throw new Error('Invalid runtime profile');
  if (name === 'local') {
    if (env.NODE_ENV === 'production' || env.OAUTH_LOCAL_DEV !== 'true')
      throw new Error('OAuth requires explicit local development');
    return { production: false, bind: '127.0.0.1', proxies: [] };
  }
  if (
    env.NODE_ENV !== 'production' ||
    env.OAUTH_LOCAL_DEV === 'true' ||
    !isIP(env.LISTEN_HOST ?? '')
  )
    throw new Error('Unsafe production profile');
  const proxies = (env.TRUSTED_PROXY_IPS ?? '').split(',');
  if (proxies.some((ip) => !isIP(ip)))
    throw new Error('Exact trusted proxies required');
  const origins = env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',') : [];
  for (const value of origins) {
    const url = new URL(value);
    if (
      url.protocol !== 'https:' ||
      value !== url.origin ||
      url.username ||
      url.password ||
      url.hostname.includes('*')
    )
      throw new Error('Invalid allowed origin');
  }
  return { production: true, bind: env.LISTEN_HOST, proxies, origins };
}
export function productionIngress(config) {
  const host = new URL(config.issuer).host;
  return (req, res, next) => {
    const peer = req.socket.remoteAddress?.replace(/^::ffff:/, '');
    const count = (name) =>
      req.rawHeaders.filter(
        (value, i) => i % 2 === 0 && value.toLowerCase() === name,
      ).length;
    const client = req.headers['x-forwarded-for'];
    if (
      !config.runtime.proxies.includes(peer) ||
      req.headers.host !== host ||
      count('host') !== 1 ||
      count('x-forwarded-proto') !== 1 ||
      count('x-forwarded-for') !== 1 ||
      req.headers['x-forwarded-proto'] !== 'https' ||
      typeof client !== 'string' ||
      !isIP(client) ||
      req.headers.forwarded !== undefined ||
      req.headers['x-forwarded-host'] !== undefined
    ) {
      res.statusCode = 403;
      res.end('Invalid production ingress');
      return;
    }
    req.oauthClientIp = client;
    next();
  };
}
