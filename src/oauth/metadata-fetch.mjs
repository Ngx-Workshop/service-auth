import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';

export function publicAddress(address) {
  if (!ipaddr.isValid(address)) return false;
  const ip = ipaddr.parse(address);
  if (ip.kind() === 'ipv6') {
    // Accept only ordinary global unicast, excluding transition/reserved ranges.
    if (ip.isIPv4MappedAddress() || !ip.match(ipaddr.parse('2000::'), 3))
      return false;
  }
  return ip.range() === 'unicast';
}
export function metadataUrl(value) {
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    url.port ||
    isIP(url.hostname.replace(/^\[|\]$/g, '')) ||
    value !== url.href ||
    url.pathname === '/' ||
    /[\s\\]/.test(value)
  )
    throw new Error('Invalid metadata URL');
  return url;
}
// Dependencies support controlled DNS/TLS test fixtures. Runtime never injects
// them and has no flag permitting private addresses or invalid certificates.
export function createMetadataFetcher(approved, dependencies = {}) {
  const resolve = dependencies.resolve ?? lookup;
  const send = dependencies.request ?? request;
  const ids = new Set(approved.map((client) => client.client_id));
  return async (value, options = {}) => {
    const id = String(value);
    if (!ids.has(id)) throw new Error('Metadata client not approved');
    const url = metadataUrl(id);
    const controller = new AbortController();
    const abort = () => controller.abort();
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) controller.abort();
    const timer = setTimeout(abort, 3000);
    try {
      if (controller.signal.aborted) throw new Error('Metadata timeout');
      const addresses = await Promise.race([
        resolve(url.hostname, { all: true, verbatim: true }),
        new Promise((_, reject) =>
          controller.signal.addEventListener(
            'abort',
            () => reject(new Error('Metadata timeout')),
            { once: true },
          ),
        ),
      ]);
      if (
        !addresses.length ||
        addresses.some(
          (entry) =>
            !publicAddress(entry.address) ||
            isIP(entry.address) !== entry.family,
        )
      )
        throw new Error('Metadata DNS answer rejected');
      const pinned = addresses[0];
      return await new Promise((resolve, reject) => {
        const req = send(
          url,
          {
            method: 'GET',
            agent: false,
            rejectUnauthorized: true,
            servername: url.hostname,
            signal: controller.signal,
            headers: {
              accept: 'application/json',
              'accept-encoding': 'identity',
            },
            lookup: (_host, options, callback) =>
              options.all
                ? callback(null, [pinned])
                : callback(null, pinned.address, pinned.family),
          },
          (res) => {
            const type = res.headers['content-type']?.split(';')[0];
            if (
              res.statusCode !== 200 ||
              type !== 'application/json' ||
              (res.headers['content-encoding'] &&
                res.headers['content-encoding'] !== 'identity') ||
              Number(res.headers['content-length'] ?? 0) > 65536
            ) {
              res.destroy();
              reject(new Error('Invalid metadata response'));
              return;
            }
            let bytes = 0;
            const chunks = [];
            res.on('data', (chunk) => {
              bytes += chunk.length;
              if (bytes > 65536) {
                res.destroy();
                reject(new Error('Metadata response too large'));
              } else chunks.push(chunk);
            });
            res.on('error', () =>
              reject(new Error('Metadata response failed')),
            );
            res.on('end', () => {
              try {
                const body = Buffer.concat(chunks);
                JSON.parse(body.toString());
                resolve(
                  new Response(body, {
                    status: 200,
                    headers: {
                      'content-type': 'application/json',
                      'cache-control': 'no-store',
                    },
                  }),
                );
              } catch {
                reject(new Error('Invalid metadata JSON'));
              }
            });
          },
        );
        req.on('error', () => reject(new Error('Metadata fetch failed')));
        req.end();
      });
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
    }
  };
}
