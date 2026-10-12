# Production-readiness implementation

Implemented locally on 2026-10-12. Deployment and publication are deferred.

## Proxy contract

Set `NODE_ENV=production`, `RUNTIME_PROFILE=production`, an explicit numeric
`LISTEN_HOST`, and comma-separated exact `TRUSTED_PROXY_IPS` (no CIDR or wildcard).
Compose listens inside the container and publishes only the approved private
application IP. A firewall must restrict access to the approved edge.

The final trusted proxy must overwrite Host with the configured public authority,
X-Forwarded-Proto with `https`, and X-Forwarded-For with a single verified client IP.
It must remove Forwarded and X-Forwarded-Host. Appending an arbitrary forwarded
chain is rejected. This assumes one normalized final hop; adapt and test deliberately
if the real edge has additional trusted hops. Configure exact HTTPS browser origins
through `ALLOWED_ORIGINS`; server-to-server clients may omit Origin.

Production public identity uses canonical HTTPS on port 443, independent of the
private listen port. Public DNS/certificates, trusted edge addresses, firewall and
verified encrypted backhaul remain release gates; no Nginx change was made here.

## Containers and CI

Both images use a digest-pinned Node 22 Alpine base, multi-stage builds, production
dependencies, UID 1000, and private-file exclusions. Compose specifies read-only
filesystem/secrets, temporary writable /tmp, dropped capabilities and no new
privileges. Runtime secrets must be regular files owned by UID 1000 with mode 0600;
symlinks and broader permissions fail. Prepare ownership before mounting read-only.

Actions validates pull requests/main/manual runs, builds candidates locally, checks
UID/private-file exclusion, and retains image archives with SHA256 for review. It
contains no publish, SSH, production-secret or deployment job. Workflows were not
dispatched. Candidate image archives do not authorize later promotion.

## Remaining release gates

Confirm actual clients/callbacks and domains, CA/certificate validity, topology,
private-network policy, scoped credential ownership, encrypted backup/restore, key
rotation and outage targets. Implement edge limits/no-cache/native routes, public
client smoke and compatible image/config rollback before separately authorized
rollout. Do not reset rs0, regenerate keys, or restore shared data for app rollback.

## Auth configuration and MongoDB

Enable `OAUTH_ENABLED=true` and mount durable OAuth JSON at `OAUTH_CONFIG_FILE`
(`/run/secrets/oauth.json` in Compose). Its existing config shape holds canonical
issuer/resource, approved client names/IDs/exact HTTPS callbacks, private RS256
JWKS, cookie signing ring, AES storage ring/active key ID and a distinct resource
client credential. Use independently generated persistent secrets; startup never
generates keys. Preserve existing legacy JWT/cookie settings independently.
See [local config shape](oauth-local.md); do not promote local fixture keys or
loopback callbacks to production. Discovery exposes only public signing keys.

Set `MONGODB_URI` with authenticated `mongodb://` credentials, database,
`replicaSet`, `authSource` and `tls=true`; set `MONGODB_ALLOWED_HOSTS`,
`MONGODB_REPLICA_SET` and absolute `MONGODB_TLS_CA_FILE`. Compose mounts the CA at
/run/secrets/mongo-ca.pem via `MONGODB_TLS_CA_HOST_FILE`. This implementation
validates the documented single-host replica topology; SRV/multiple seed hosts
need a reviewed extension. Unknown/duplicate URI options and TLS bypasses fail.

Startup verifies TLS/authenticated driver settings, writable configured replica,
transactions, strict encrypted-state BSON validator and required TTL/model indexes.
Production Mongoose disables automatic collection/index creation. Provision schema
separately with `npm run oauth:mongo:provision`, from an operator checkout and
provisioning identity; runtime never runs collMod/createIndex. Do not run that
command against live infrastructure without the later release authorization.

Runtime role: database listCollections; users and oauth_state/oauth_forms/
oauth_revoked scoped find/insert/update/remove/listIndexes only as required by
existing login/OAuth operations. Separate provisioning and backup identities. The
production test proves unrelated collection reads and collMod are denied; operators
must verify the real role grants before release. Auth OAuth cookies are Secure,
HttpOnly, SameSite=lax; trusted normalized client IP drives OAuth throttling. Proxy
checks apply to OAuth/discovery paths and preserve legacy browser routes.

## Verification evidence

79 auth tests passed, including real account login/consent/S256 through a verified
TLS proxy, owned authenticated TLS MongoDB replica set, collection-scoped role,
missing-index/validator rejection, transactions, restart with persistent keys and
grant revocation. Existing legacy and additive auth-client regressions passed.
Auth/native/spike and affected TypeScript lint and builds passed. No shared local
or remote database was modified. Local Docker build and native bcrypt checks pass.
This is local evidence, not public-client or infrastructure acceptance.

Live release decision: [2026-10-12 preflight](deployment-preflight-2026-10-12.md). Audit completed; release gates failed or remain unverified.
