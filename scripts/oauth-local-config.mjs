import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
const file = resolve(process.argv[2] ?? '.oauth-local/config.json');
const config = {
  issuer: 'http://127.0.0.1:3000',
  resource: 'http://127.0.0.1:3011/mcp',
  clients: [
    {
      client_id: 'ngx-workshop-local',
      client_name: 'Ngx Workshop local client',
      redirect_uris: ['http://127.0.0.1:39999/callback'],
    },
  ],
  resourceClient: {
    id: 'ngx-workshop-gateway',
    secret: randomBytes(32).toString('base64url'),
  },
  cookieKeys: [randomBytes(32).toString('base64url')],
  activeStorageKey: 'v1',
  storageKeys: { v1: randomBytes(32).toString('base64') },
  jwks: {
    keys: [
      {
        ...generateKeyPairSync('rsa', {
          modulusLength: 2048,
        }).privateKey.export({ format: 'jwk' }),
        kid: 'local-v1',
        use: 'sig',
        alg: 'RS256',
      },
    ],
  },
};
await mkdir(dirname(file), { recursive: true, mode: 0o700 });
await writeFile(file, JSON.stringify(config, null, 2) + '\n', {
  mode: 0o600,
  flag: 'wx',
});
console.log(`Created owner-only OAuth configuration: ${file}`);
