# Production launch evidence — 2026-10-12

The user authorized infrastructure remediation, deployment and publication. Both
services are deployed. Private ChatGPT account linking remains unverified: its
builder rejects the settings before opening OAuth. This is the only outstanding
client acceptance item; do not represent the private connection as installed.

## Public identities and client

- MCP resource: https://mcp.ngx-workshop.io/mcp.
- Protected metadata: https://mcp.ngx-workshop.io/.well-known/oauth-protected-resource/mcp.
- Auth issuer: https://auth.ngx-workshop.io.
- Public client: ngx-workshop-chatgpt-prod; token auth none; S256; catalog:read only.
- Exact registered callbacks: https://chatgpt.com/connector_platform_oauth_redirect
  and https://chatgpt.com/connector/oauth/eHT5kMMVPJuJ (copied from this connection's UI).
- No wildcard redirects, DCR, refresh tokens, anonymous tool access or public
  ChatGPT directory submission. The initial connection is private.

Discovery advertises exactly catalog:read and token methods none/client_secret_basic.
Both successful and denied authorization callbacks include the exact issuer.
The public signing JWKS contains no private fields.

## Released artifacts and delivery

| Component | Reviewed merged source | Running CI image revision | Validation/publication |
| --- | --- | --- | --- |
| service-auth | 665106407c829c4e40817cd7684fff2f504c0a3c | 40a588d0ca885c851c989fe1893fdf284bf0726b | CI 38313706735; publish 38312384697 |
| service-mcp-gateway | 382167dad9575773de0eff2dc135c14eb7ace47e | b9e793af95c9f74f699820956b4c5345867f946c | CI 38313935033; publish 38312987246 |

The CI pull-request merge revisions have the same Git trees as their reviewed
merged source. Images were transferred as immutable archives, SHA256 checked,
revision/architecture/non-root labels verified, then promoted explicitly.
Image names: service-auth:40a588d0ca88 and service-mcp-gateway:b9e793af95c9.
Edge/backhaul nginx uses pinned digest
sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94.
Nginx owner PR1 was merged and its public/native routing activated.

Published through trusted NPM OIDC after validation:
@tmdjr/ngx-auth-client 0.0.66 and @tmdjr/service-mcp-gateway-contracts 1.0.0.
Auth-client retains legacy exports and adds introspection. Gateway 1.0.0 deliberately
replaces seed CRUD exports; it publishes the three stable MCP schemas/models.
Registry tarball content/integrity and gateway's registry-pinned consumer were checked.
Main is protected by required strict validate, enforced for administrators, without
force pushes or deletion. PR/push builds do not publish or deploy. Publication is
manual; operator promotion is explicit. These evidence commits do not change the
already deployed application code or require another package publication.

## Infrastructure and secret boundaries

App containers run UID1000, read-only roots, dropped capabilities, no-new-privileges
and bounded tmpfs. They publish no host ports. Edge uses verified private HTTPS
to the backhaul bound only to 10.116.0.4:3443; backhaul admits only 10.116.0.3.
Headers are normalized at edge; runtime trusts only backhaul 172.18.0.240.
OAuth/MCP access logs omit sensitive request URLs. Existing SPA/legacy routes remain.
Public wildcard HTTPS certificate and renewal timer were verified; public DNS A
records resolve through independent resolvers.

MongoDB remains authenticated single-member rs0, isolated to the private app host.
Server preferTLS preserves legacy owners; new auth requires CA-verified TLS.
This is a staged migration, not a claim that all legacy database traffic is encrypted.
Runtime can access users and encrypted OAuth collections only; provisioning and
backup use separate principals. Unrelated reads and runtime collMod were denied.
Strict validators/TTL indexes, transactions and primary readiness passed live.

Persistent OAuth JSON /etc/ngx-workshop/oauth/auth/config.json, gateway secret
/etc/ngx-workshop/oauth/gateway/introspection and legacy runtime config stay outside
Git with private ownership and read-only mounts. RSA signing, AES storage, cookie,
introspection and legacy JWT keys remain stable across restart. Gateway holds no
Mongo credentials or signing keys. CA leaf expiry/rotation must be maintained;
never regenerate production keys on restart or restore shared data for app rollback.

## Recovery proof

Fresh encrypted stopped-DB physical baseline 20261012T212935Z: 183,468,726 bytes.
Isolated physical restore preserved 21 existing users in 4.61 seconds.
Daily consistent logical backups include oplog, replica key/config, Mongo TLS and
scoped credential recovery. Latest cleaned-account snapshot 20261012T221113Z
restored 21 users and strict OAuth schema in 3.93 seconds. The isolated clone
invalidates restored OAuth state before reuse, preventing revoked grants from reviving.
No restoration into the live database occurred.

Private independent bucket ngx-workshop-oauth-recovery, SFO3, has a dedicated
ngx-oauth-recovery-prod key limited to that bucket's Read/Write/Delete operations.
The key was proven unable to list the asset bucket. Objects are explicitly private;
length/checksum metadata and anonymous 403 were verified. The existing uploader
key and asset bucket are preserved. Earlier encrypted bootstrap copies remain
redundant recovery copies; the backup job now uses only the dedicated key.
Daily systemd timer ngx-oauth-recovery.timer is enabled/active (04:00 UTC plus jitter).
This provides daily recovery points; no strict RPO/RTO SLA was promised. Single-node
downtime is accepted. Take an additional backup before each infrastructure change.

Matching OAuth/JWT/backhaul/backup config escrow was refreshed at 20261012T221219Z.
Private CA signing material has separate encrypted escrow. Independent owner-only
workstation recovery directory is /Users/ba5ik7/.codex/private-recovery/ngx-oauth-20261012,
outside Git, with decryption material separated from cloud ciphertext. On hosts,
operator credentials are root-only and not mounted into application containers.
Retain and inspect backup job failures with journalctl -u ngx-oauth-recovery.service.

## Acceptance and remaining client gap

Public real-account login, secure cookies, explicit consent, S256 exchange and
resource-bound 600-second opaque tokens passed. All three tools passed with modern
and legacy official clients, covering all 6 real workshops, 4 sections and 2
published labs. Results match real service-document/service-coding-labs public reads;
pinned versions, projections, empty/missing/wrong-section and malformed cases passed.
Both immediate token revocation and authenticated browser grant revocation return
401 for subsequent requests. Denied consent preserves issuer/state. Invalid Origin
returns403; missing bearer returns401 before JSON parsing. A controlled auth outage
returned503 before JSON/tool execution and recovery returned public discovery200.
Restart preserved keys and the authenticated browser session. The temporary owned
launch account was removed by exact ID/email match, leaving the original21 users.
Legacy public invalid sign-in remains401;79 auth regressions and49 gateway unit/
40 e2e checks passed CI. Full legacy user browser journeys were not manually exercised.

ChatGPT's builder still reports “Some app settings were rejected” and OAuth discovery
failure, including with verified manual endpoints/client settings. No OAuth login or
private plugin was created. A bounded edge path/status probe saw no corresponding
requests; DNS/cache or hosted validation is a hypothesis, not an established cause.
Do not weaken bearer, resource, callback, SSRF or TLS checks to bypass that error.
The prepared browser connection remains available for troubleshooting. When it
accepts the settings, the owner must sign in with their own account and consent;
never link ChatGPT to the deleted temporary acceptance account.

Public acceptance runner: test/production-oauth.integration.mjs in the gateway.
It requires an explicitly provisioned private MCP_TEST_LOGIN_FILE; it never prints
credentials or follows external callbacks. Local logs are private ephemeral
operator evidence, not checked-in credentials.
