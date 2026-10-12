import { isIP } from 'node:net';
import { validateMongoSettings } from './mongo-settings.mjs';
import { metadataUrl } from './metadata-fetch.mjs';
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { runtimeProfile } from './profile.mjs';

function loopback(value, resource = false, production = false) {
  const url = new URL(value);
  if (
    (production
      ? url.protocol !== 'https:' ||
        url.port !== '' ||
        isIP(url.hostname.replace(/^\[|\]$/g, '')) ||
        url.hostname === 'localhost' ||
        url.hostname.endsWith('.localhost')
      : url.protocol !== 'http:' ||
        !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (resource ? url.pathname !== '/mcp' : url.pathname !== '/') ||
    value !== (resource ? url.href : url.origin)
  )
    throw new Error('OAuth requires canonical local URLs');
  return url;
}
export function validateConfig(config, env = process.env) {
  const runtime = runtimeProfile(env);
  if (runtime.production) validateMongoSettings(env);
  const issuer = loopback(config.issuer, false, runtime.production);
  loopback(config.resource, true, runtime.production);
  if (
    !runtime.production &&
    Number(issuer.port || 80) !== Number(env.PORT ?? 3000)
  )
    throw new Error('OAuth issuer port must match PORT');
  if (
    !Array.isArray(config.cookieKeys) ||
    !config.cookieKeys.length ||
    config.cookieKeys.some(
      (key) =>
        typeof key !== 'string' || Buffer.from(key, 'base64url').length < 32,
    )
  )
    throw new Error('Persistent cookie keys required');
  if (
    !config.jwks?.keys?.length ||
    config.jwks.keys.some(
      (key) => !key.kid || key.kty !== 'RSA' || !key.d || key.alg !== 'RS256',
    )
  )
    throw new Error('Persistent private RS256 JWKS required');
  if (
    !config.storageKeys ||
    !Object.hasOwn(config.storageKeys, config.activeStorageKey) ||
    Object.entries(config.storageKeys).some(
      ([id, key]) =>
        !/^[a-zA-Z0-9_-]{1,64}$/.test(id) ||
        typeof key !== 'string' ||
        Buffer.from(key, 'base64').length !== 32,
    )
  )
    throw new Error('32-byte storage key ring required');
  if (
    !Array.isArray(config.clients) ||
    !config.clients.length ||
    new Set(config.clients.map((c) => c.client_id)).size !==
      config.clients.length
  )
    throw new Error('Unique public clients required');
  config.metadataClients ??= [];
  if (!Array.isArray(config.metadataClients))
    throw new Error('Invalid metadata registry');
  const ids = [...config.clients, ...config.metadataClients].map(
    (client) => client.client_id,
  );
  if (new Set(ids).size !== ids.length)
    throw new Error('Duplicate client identity');
  for (const client of config.metadataClients) metadataUrl(client.client_id);
  for (const client of [...config.clients, ...config.metadataClients]) {
    if (
      typeof client.client_id !== 'string' ||
      !client.client_id ||
      typeof client.client_name !== 'string' ||
      !client.client_name ||
      !Array.isArray(client.redirect_uris) ||
      !client.redirect_uris.length
    )
      throw new Error('Client identity and redirects required');
    for (const value of client.redirect_uris) {
      const uri = new URL(value);
      if (
        uri.username ||
        uri.password ||
        uri.hash ||
        uri.href.includes('*') ||
        (runtime.production &&
          (isIP(uri.hostname.replace(/^\[|\]$/g, '')) ||
            uri.hostname === 'localhost' ||
            uri.hostname.endsWith('.localhost'))) ||
        !(
          uri.protocol === 'https:' ||
          (!runtime.production &&
            uri.protocol === 'http:' &&
            ['localhost', '127.0.0.1', '[::1]'].includes(uri.hostname))
        )
      )
        throw new Error('Invalid client redirect');
    }
  }
  if (
    !config.resourceClient?.id ||
    typeof config.resourceClient.secret !== 'string' ||
    Buffer.byteLength(config.resourceClient.secret) < 32 ||
    [...config.clients, ...config.metadataClients].some(
      (c) => c.client_id === config.resourceClient.id,
    )
  )
    throw new Error('Distinct resource server credentials required');
  return { ...config, runtime };
}
export async function loadConfig(env = process.env) {
  if (
    env.OAUTH_ENABLED !== undefined &&
    !['true', 'false'].includes(env.OAUTH_ENABLED)
  )
    throw new Error('OAUTH_ENABLED must be true or false');
  if (env.OAUTH_ENABLED !== 'true') return undefined;
  runtimeProfile(env);
  const file = await open(
    env.OAUTH_CONFIG_FILE,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  try {
    const info = await file.stat();
    if (
      !info.isFile() ||
      (info.mode & 0o777) !== 0o600 ||
      info.uid !== process.getuid?.() ||
      info.size > 65536
    )
      throw new Error(
        'OAuth config must be owned by runtime UID with mode 0600',
      );
    return validateConfig(JSON.parse(await file.readFile('utf8')), env);
  } catch {
    throw new Error('Invalid OAuth private configuration');
  } finally {
    await file.close();
  }
}
