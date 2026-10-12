# Run service-auth OAuth locally

OAuth is off by default. Use Node 22 LTS and retain the existing legacy JWT env
configuration. Use a separate local MongoDB replica set with your local auth
accounts; standalone Mongo is deliberately rejected. Do not convert or reset the
shared local database. Tests provision and remove their own replica set.

Generate persistent keys and local client credentials once:

```sh
npm run oauth:local:config
```

The owner-only file .oauth-local/config.json is ignored by Git; the generator
refuses to overwrite it. Keep it private and preserve it across restarts. Edit the
registered public client names/redirects and resource if needed. Never paste the
private JWKS or resource-client secret into logs, documentation, or source.

```sh
export OAUTH_ENABLED=true
export OAUTH_LOCAL_DEV=true
export OAUTH_CONFIG_FILE="$PWD/.oauth-local/config.json"
export PORT=3000
export MONGODB_URI='mongodb://127.0.0.1:27018/auth_oauth_local?replicaSet=oauthLocal'
npm run start
```

The replica set must already be initialized and writable. The example port/database
are illustrative; the service does not create or reconfigure mongod. NODE_ENV
must not be production. Issuer is http://127.0.0.1:3000 and the initial resource is
http://127.0.0.1:3011/mcp. Clients use ngx-workshop-local and the exact callback
http://127.0.0.1:39999/callback by default. The gateway's Basic credentials live
only in resourceClient in the private file; configure those same credentials privately in gateway OAuth mode.

Read /.well-known/oauth-authorization-server for endpoints. Request an explicit
S256 authorization code with scope catalog:read, resource, redirect and state.
Sign in using an existing auth account, then Allow or Deny. Exchange with the
same client, redirect and resource plus verifier. Browser /oauth/grants lists the
signed-in account's active grants and can revoke them. Legacy sign-out preserves
OAuth grants; OAuth login does not mint a legacy accessToken cookie.

Storage-key rotation: add a fresh 32-byte base64 key under a new ID and change
activeStorageKey; retain old keys until all records encrypted with them have
expired and TTL cleanup has removed them. Startup creates no new keys. The
cookie key list signs with its first key and retains later keys for verification.
Private JWKS must retain their key IDs across application restarts.

```sh
npm run test:oauth
npm run test:oauth:spike
npm run lint:oauth
npm run build:ngx-auth-client
```

OAuth tests require mongod on PATH (or OAUTH_SPIKE_MONGOD). They seed only an owned
temporary database, never access the shared auth database, and close owned apps
and processes. HTTPS/proxies, remote databases, deployment and CI changes remain
deferred. See [ADR 0002](adr/0002-local-oauth-implementation.md).

## Approved metadata clients and gateway

Optionally add `metadataClients` to the private JSON config. Each entry has
`client_id` (exact canonical HTTPS URL with a non-root document path),
`client_name` and `redirect_uris` (approved exact loopback callbacks). Static
client IDs and metadata IDs must be distinct. Document fields must match those
values plus grant_types=[authorization_code], response_types=[code],
token_endpoint_auth_method=none and scope=catalog:read. The engine also verifies
client_id consistency. No query, fragment, explicit port, credentials or IP
literal in metadata IDs. All resolved addresses must be public; no private DNS
or TLS bypass exists. An absent/empty list disables CIMD discovery support.

Gateway defaults to OAuth and requires MCP_LOCAL_DEV=true, configured resource,
issuer, /oauth/introspect URL and AUTH_INTROSPECTION_CLIENT_ID/SECRET matching
resourceClient. Keep secrets private. Header bearer access requires catalog:read;
public protected-resource metadata points back to this issuer. No deployment or
hosted-client connectivity is implied. See [ADR 0003](adr/0003-oauth-cimd-introspection.md).

## Production planning boundary

[Feature004](../specs/004-deployment/handoff.md) now plans existing infrastructure
reuse and public deployment. It does not change these local instructions or lift
local runtime restrictions. Do not reuse fixture callbacks/keys or set local dev
flags to bypass production requirements. Implementation and release remain pending.
