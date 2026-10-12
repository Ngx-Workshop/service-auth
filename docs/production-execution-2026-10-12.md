# Production launch evidence — 2026-10-12

The user authorized infrastructure remediation, deployment and publication. Both
services are deployed. Private ChatGPT plugin creation and hosted OAuth discovery succeeded. The owner
is completing account sign-in/consent in the browser. Account linking and
ChatGPT tool use remain unverified until that finishes.

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
| service-auth | f3ff49468699ca5151693adf073c39b95238cd9d | b013fb9f6cc5a96e31217237b7f4b13d86e81619 | CI 38315988019; publish 38312384697 |
| service-mcp-gateway | ea230981f39f59973ff5b3d1cdf456035eb1cbff | 9e6630a2e6e059805f9e6580ac845f8b86a5a89a | CI 38315972629; publish 38312987246 |

The CI pull-request merge revisions have the same Git trees as their reviewed
merged source. Images were transferred as immutable archives, SHA256 checked,
revision/architecture/non-root labels verified, then promoted explicitly.
Image names: service-auth:b013fb9f6cc5 and service-mcp-gateway:9e6630a2e6e0.
Image IDs: auth sha256:d34034caf4aa840b931b4468e6fc0d9f0426d2d80bea2de0a7fb2ddef0b9cdad;
gateway sha256:d3daa1eab4d4c7161e57feda161c2cb28369af6f6a554d07f4700290389da4fc.
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
scoped credential recovery. Final cleaned-account snapshot 20261012T222708Z
restored 21 users and strict OAuth schema in 3.98 seconds. The isolated clone
invalidates restored OAuth state before reuse, preventing revoked grants from reviving.
No restoration into the live database occurred.

Private independent bucket ngx-workshop-oauth-recovery, SFO3, has a dedicated
ngx-oauth-recovery-prod key limited to that bucket's Read/Write/Delete operations.
The key was proven unable to list the asset bucket. Objects are explicitly private;
length/checksum metadata and anonymous 403 were verified. An independently downloaded cloud archive matched the SHA256 of the archive used in the isolated restore. The existing uploader
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
Legacy public invalid sign-in remains401;80 auth regressions and49 gateway unit/
40 e2e checks passed CI. Public legacy sign-in also passed using an account hashed by the old bcrypt5 image: Secure/HttpOnly/Strict JWT cookie, authenticated validation and own-user metadata read, plus false validation without a cookie. Full legacy UI navigation was not manually exercised.

ChatGPT initially rejected settings and could not discover OAuth. A later hosted
discovery succeeded, selected the stable registered callback, and exposed the
correct catalog:read scope and native endpoints. The private plugin was created
with static client ngx-workshop-chatgpt-prod, token auth none and OIDC identity
sharing disabled. “Continue to Ngx Workshop” opened the real auth-owned sign-in
interaction. Owner account sign-in/consent is now pending; the earlier builder
rejection is resolved. DNS/cache was only a hypothesis, not a proven root cause.
Do not represent account linking or actual ChatGPT tool execution as completed
until the owner finishes that flow. Never connect the deleted acceptance account.

Public acceptance runner: test/production-oauth.integration.mjs in the gateway.
It requires an explicitly provisioned private MCP_TEST_LOGIN_FILE; it never prints
credentials or follows external callbacks. Local logs are private ephemeral
operator evidence, not checked-in credentials.

## Runtime dependency gate

Final npm runtime audit found vulnerable dependency versions in auth. Compatible
lockfile updates remove affected proxy-addr/Nest/HTTP/validation dependencies;
bcrypt6 replaces the vulnerable node-pre-gyp/tar installer chain. A fixed hash
produced by the old production bcrypt5 image validates under bcrypt6, including
2a/2b prefixes and wrong-password rejection. Existing users/passwords stay intact.
Gateway pins Swagger's js-yaml5.4.3 through a narrow override because its declared
5.3.0 dependency has an advisory. CI now rejects high/critical production
dependency advisories with npm audit --omit=dev --audit-level=high. Development
toolchain advisories are separate remaining maintenance work, not removed by this
runtime-only gate. Both corrected CI images were promoted after review/merge and archive checksum verification, retaining compatible previous containers. Public three-tool acceptance, token/browser revocation, denied consent, legacy sign-in and key/session persistence across restart all passed again. Both runtime audits report zero findings. The historical Jest npm test scaffold contains no tests; the80 OAuth tests are the actual auth gate (plus30 separately passing engine-spike checks).
