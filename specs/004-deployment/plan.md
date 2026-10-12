# Auth deployment implementation plan
Status: Readiness implementation verified locally; release and infrastructure work deferred · 2026-10-12
[Spec](spec.md) · [Inventory](research.md) · [Tasks](tasks.md)

## Future changes and contract

- src/oauth/config.mjs: separate explicit production/local profiles; HTTPS issuer
  and resource without private-port coupling; environment separation; client/cookie/
  key policy validation; production mounted config is durable, not generated at boot.
- src/bootstrap.ts, src/main.ts: configurable private listener reachable from
  authorized edge; narrowly trusted Express/provider proxy context, independent
  public issuer. Never blanket trust every proxy. Keep current local binding.
- src/oauth/provider.mjs: replace loopback-only DB check with configured permitted
  private authenticated deployment topology in production; validate readiness/
  transactions/schema without broad runtime collMod. Set secure cookies and tested
  provider proxy handling using installed 9.12.2. Preserve issuance transaction logic.
- src/oauth/grants.mjs, interactions.mjs: secure HTTPS session context, exact Origin
  and CSRF; tested trusted client IP for throttling. Do not weaken local socket checks.
- src/app.module.ts: production Mongo TLS/CA and bounded connect/selection/socket
  settings through private mounts; no TLS verification bypass or generic admin role.
- Authentication controller: preserve existing production JWT cookie domain/TTL/
  secure/SameSite behavior; test actual legacy SPA/API routes before any alteration.
- Dockerfile/.dockerignore/Compose/workflow: exclude .oauth-local and private config
  files and mount persistent config outside image; non-root/runtime dependencies,
  pinned base digest, Node 22. Normalize trailing-space compose filename and test
  workflow/compose parity. Current workflow uses docker run, not Compose.

Public/secret contract remains OAUTH_ENABLED, OAUTH_CONFIG_FILE, PORT=3000,
MONGODB_URI and current JWT_*/DOMAIN/USER_METADATA_URL. Proposed profile/private
bind/trusted-proxy/DB-CA settings are new and must be named consistently by future
implementation. NODE_ENV=production; no local OAuth flags. Private JSON retains
issuer/resource/clients/metadataClients/resourceClient/cookieKeys/jwks/storageKeys/
activeStorageKey. Public registration policy and private key material are distinct
operational concerns even if consumed through one strict mounted config today.

## Mongo and secrets preparation

Inventory documents, not live inspection, indicate 10.116.0.2:27017, MongoDB
8.0.17, workshop-viewer/authSource workshop-viewer, rs0 already initialized.
Keep existing users collection in that DB; add only auth OAuth collections. Do
not use the 2026-10-04 shared database archive as a current OAuth rollback point.
Verify live set name/primary/transaction support, permissions/indexes/validators,
backup freshness and actual network encryption before future rollout.

Provision auth-only collection role for required legacy users operations and
OAuth state/forms/revoked CRUD. Enumerate privileges from actual repository
operations and prove unrelated collection denial. A migration/provisioning principal
creates exact collections/indexes/validators; runtime checks them and fails closed
if missing/mismatched. Avoid runtime dbAdmin/root grants merely for collMod startup.
Retain SHA-256 identifiers/AES-256-GCM record binding and majority commit policy.
Set connection replicaSet=rs0 and matching authSource explicitly, with scoped user,
verified TLS/CA when provisioned. If current DB transport lacks TLS, plan staged
server/client TLS adoption coordinated with other owners; no unilateral requireTLS
flip breaking them. Don't reinitialize/change replica member addresses blindly.

Secret inventory/rotation and recovery are in ADRs 0005/0006. Use environment-scoped
GitHub secrets for existing deployment identity and config delivery, minimal
runtime copies outside checkout, persistent owner-only files and read-only mounts.
A root-managed staging file must be installed for the dedicated runtime UID as
0600; verify permission checks as that UID. Avoid plaintext backup/artifact uploads
and never give ordinary build/publishing jobs access to secret payloads. Reuse SSH
fingerprints and cleanup traps; add config version/hash reference, not secret hash
or content in logs. Configuration revision references must be non-sensitive.

## Delivery, compatibility and owner ordering

First implement/prove runtime/container changes offline. Add CI test/build/package
validation including an isolated Mongo replica set; no production env in tests.
Separate client OIDC publication from service promotion and prevent main push
from unconditionally deploying this feature. Verify protected environments plan
support; require explicit manual release with operator authorization regardless.
Build/test immutable image once and transport via current SCP/docker-load pattern;
no new registry required. Record source SHA/image digest/config schema revision.
Save compatible image/config pairs and sanitized diagnostics before failed container
removal. Existing workflow saves :previous but lacks automatic rollback.

Provision/back up DB and persistent secrets before first auth activation. Release
production-capable auth with OAuth ingress closed while preserving existing legacy
routes. Verify private readiness against DB and actual transaction; liveness is
not a database query. Configure the edge native AS/OAuth/JWKS paths on auth host
without changing SPA / or legacy /api/auth. Test secure proxy cookies and actual
approved client. Gateway follows auth-compatible package/endpoint contract, then
edge exposes /mcp after private smoke. Publish actual client registration only
when verified; no default local callback in production.

Prefer verified encrypted cross-droplet backhaul using existing proxy tooling.
Existing edge HTTP over VPC is not automatically deemed sufficient. Gateway HTTPS
introspection stays at canonical issuer; internal routing must preserve public
Host/SNI/cert validation. Approved trusted-proxy peers/firewalls prevent spoofing;
limit app ports to authorized callers and verify Docker firewall interactions.

Rollback code/config without changing identity database or weakening bearer
access. Retain old storage/cookie/JWKS keys until all relevant records/cache/backups
expire or are deliberately invalidated. Unknown key/schema requires closed ingress,
not regeneration. On DB restore, maintenance-close OAuth traffic, restore accounts
in isolated validation, invalidate all restored OAuth state and sessions before
opening issuance; deny pre-restore tokens. Confirm legacy session impact explicitly.

## Required verification (future)

Baseline npm run test:oauth (64 checks), lint:oauth, library typed lint/build and
existing client exports; add production config/native TLS/proxy/session/client IP
cases, secret-free Docker builds, non-root mounted-key persistence, real private
rs0 least-privilege transaction/index/TLS checks, isolated backup/restore/rotation
and rollback. Measure limits and redacted observability; review release-reachable
dependency findings without unrelated broad upgrades. Test actual legacy consumers
and selected external MCP client, not just localhost or a mock TLS document.

No production smoke command exists yet; implement a bounded disposable-account/
grant smoke separate from local runner. Cleanup only owned temporary test data.
Current planning checks docs/links/asset immutability; no application test or public
success is claimed by these documents. No infrastructure/secret/workflow operation now.

Readiness scope and current evidence: [runbook](../../docs/production-readiness.md).
Release acceptance remains broader than the completed local checks.

Live release decision: [2026-10-12 preflight](../../docs/deployment-preflight-2026-10-12.md). Audit completed; release gates failed or remain unverified.

2026-10-12 user clarification: no production traffic; downtime accepted. Initial
launch retains single-member rs0 without a strict RTO or zero-downtime requirement.
Data-loss policy is not waived. [Recommended ChatGPT registration and recovery
baseline](../../docs/launch-client-and-recovery.md) replace the open availability
question; exact callback/issuer acceptance and recoverable backups remain gates.
No deployment or publication is authorized.

## Authorized production execution — 2026-10-12

The user now authorizes the recommended ChatGPT setup, infrastructure/secret/
MongoDB TLS/scoped-access/recovery remediation, deployment and publication.
Earlier no-deploy/no-publish restrictions are historical and superseded. Downtime
is acceptable; existing shared records/legacy auth and independent keys remain
preserved. No renewed permission is required for the explicitly authorized
release. Record exact versions, images, recovery proof and public smoke evidence.

Execution order: fresh encrypted consistent backup and isolated restore; durable
keys/CA/scoped roles; validated service and private TLS backhaul images; safe CI
and package release; private service rollout; edge/DNS; ChatGPT linking and public
three-tool/revocation/legacy acceptance. Compatibility-mode Mongo TLS preserves
older consumers until their own TLS migration; auth requires verified TLS.
