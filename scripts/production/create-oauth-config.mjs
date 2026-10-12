// Run once inside the application host's Node container, mounting /production.
// Never logs key material and refuses to replace an existing configuration.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { writeFileSync, chmodSync, chownSync } from 'node:fs';
const secret = randomBytes(48).toString('base64url');
const config = {
  issuer: 'https://auth.ngx-workshop.io',
  resource: 'https://mcp.ngx-workshop.io/mcp',
  clients: [{ client_id: 'ngx-workshop-chatgpt-prod', client_name: 'Ngx Workshop — ChatGPT', redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'] }],
  metadataClients: [],
  resourceClient: {id: 'ngx-workshop-gateway-prod', secret},
  cookieKeys: [randomBytes(48).toString('base64url')],
  activeStorageKey: 'prod-v1',
  storageKeys: {'prod-v1': randomBytes(32).toString('base64')},
  jwks: {keys: [{...generateKeyPairSync('rsa', {modulusLength:3072}).privateKey.export({format:'jwk'}), kid:'prod-20261012-v1',use:'sig',alg:'RS256'}]},
};
for (const [path, value] of [['/production/auth/config.json',JSON.stringify(config,null,2)+'\n'],['/production/gateway/introspection',secret]]) {
  writeFileSync(path,value,{mode:0o600,flag:'wx'});
  chmodSync(path,0o600);chownSync(path,1000,1000);
}
console.log('Created persistent OAuth keys and gateway credential; no key material logged.');
