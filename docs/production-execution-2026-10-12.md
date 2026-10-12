# Production launch evidence — 2026-10-12

The user authorized infrastructure remediation, deployment and publication. Both
services are deployed. Private ChatGPT account linking, authenticated tool discovery
and all three read-only tool calls passed with the owner's existing account.

## Browser form correction

The owner reported `Invalid form origin` while submitting the real Chrome login
form. The interaction and grant pages sent `Referrer-Policy: no-referrer`, which
causes native HTML POST navigations to send `Origin: null` under the
[Fetch origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header).
The HTTP acceptance runner explicitly supplied Origin and therefore missed this
browser behavior. Both pages now use `same-origin`: same-origin form submissions
retain the issuer origin, while cross-origin callbacks receive no Referer.
Exact issuer Origin validation, single-use CSRF tokens, cookies, CSP and grant
ownership checks remain enforced. Regression coverage checks the rendered policy
for login, consent and grant management and rejects literal null origins.
PR5 merged as bc7cd383d1188c7585025a764820bea04a3db0a9 after CI38320347975
passed all80 OAuth tests, lint, runtime audit and image checks. Its tree matches
CI revision c9437f4c605af3ab6db4afc509cfca6a062f50be. The checksum-verified image
was promoted with existing persistent secrets and no host ports; previous image
retained. Public fresh login returns200 with the corrected same-origin policy,
and gateway discovery remains200. After the owner dismissed the password-manager
blocker, a native Chrome HTML login POST using a nonexistent deployment.invalid
account reached authentication and rendered `Invalid email or password`, rather
than `Invalid form origin`. No account was created or owner's password entered.
The form returned with empty credentials and a fresh single-use CSRF token.
This was the interim state; subsequent owner consent and successful ChatGPT
three-tool verification are recorded below.

The owner subsequently completed real sign-in and consent, but Chrome stayed on
the interaction page. Server inspection confirmed a session and catalog grant,
and an unexchanged authorization code; no token values or account identifiers
were exported. An isolated native Chrome form reproduced the cause: a POST with
`form-action 'self'` remained on the original page when its303 redirect crossed
origins; allowing the registered callback origin reached the callback. See the
[CSP form-action redirect discussion](https://github.com/w3c/webappsec-csp/issues/8).
Interaction CSP now includes only self and the current client's validated,
registered redirect origin. Exact redirect URI registration, PKCE, resource,
Origin, CSRF, default-src none and framing restrictions remain enforced. Grant
management keeps its self-only form policy. All80 OAuth tests pass, including
exact login/consent CSP assertions in local and production profiles. PR7 merged as b0176b81fad654b38f5e0896a398fd19b701d43d after CI38321784974
passed. The reviewed tree matches image revision c4c0a6b6d2666feb9681640a9136135b8997a523.
Its checksum-verified image was promoted with existing keys and previous image
retained. Public login returns200 with same-origin referrer policy and CSP
allowing only self and the registered ChatGPT origin. The isolated native Chrome
regression reached its callback; the real existing-consent session resumed via
GET and ChatGPT successfully exchanged its code and invoked all three tools.
A new first-login/consent POST roundtrip on this final image has not been repeated
with the owner; do not conflate isolated browser coverage with that additional
manual journey.

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
| service-auth | b0176b81fad654b38f5e0896a398fd19b701d43d | c4c0a6b6d2666feb9681640a9136135b8997a523 | CI 38321784974; publish 38312384697 (client unchanged) |
| service-mcp-gateway | ea230981f39f59973ff5b3d1cdf456035eb1cbff | 9e6630a2e6e059805f9e6580ac845f8b86a5a89a | CI 38315972629; publish 38312987246 |

The CI pull-request merge revisions have the same Git trees as their reviewed
merged source. Images were transferred as immutable archives, SHA256 checked,
revision/architecture/non-root labels verified, then promoted explicitly.
Image names: service-auth:c4c0a6b6d266 and service-mcp-gateway:9e6630a2e6e0.
Image IDs: auth sha256:c81eea59b2f78a1a39a13037668122d65367c535f40b76d3d39a7929b1c4f709;
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
interaction. The owner completed sign-in and catalog:read consent. Chrome initially
blocked the form callback; resuming the approved session completed ChatGPT's token
exchange. The plugin then displayed its authenticated Read3 tool catalogue.
A real ChatGPT verification conversation called all three tools successfully:

- list_workshops(sectionId=angular): six public workshop summaries.
- get_workshop(sectionId=angular, workshopId=6acaffbb4d4ddb09fe84ff6d):
  What is Angular?, five ordered items (three pages, one lab, one assessment).
- get_coding_lab(labId=6abca5763b2ecd0f16ae87fa): Sum an array — demo challenge,
  version1 / 6abca5763b2ecd0f16ae8804, TypeScript, public starter/hint/sample test.

The results matched public service-document/service-coding-labs reads.
[Verify Ngx Workshop Tools](https://chatgpt.com/c/6acd6bbd-1b60-83e9-8bc5-02e31dc5cc94)
is the owner's private verification conversation, not a publicly shared link.
No web search, mutations, hidden tests or solutions were involved. The deleted
acceptance account was never connected. The earlier builder rejection is resolved;
DNS/cache was only a hypothesis, not a proven root cause. Existing600-second
access-token lifetime and no-refresh policy remain: later use may require reconnecting.

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
