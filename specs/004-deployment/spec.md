# Production OAuth authorization server deployment
Status: Deployed/published; owner ChatGPT sign-in pending · 2026-10-12
Updated: 2026-10-12 · Deployment is not authorized in this turn.

## Scope

Prepare service-auth for the existing Actions → Docker application droplet →
Nginx HTTPS edge and existing documented MongoDB rs0. Keep users, legacy cookie
login/roles/metadata/sign-out, JWT settings and existing browser consumers. No
cloud/platform migration, public DCR, refresh grant, DB reset or live operation.
Runtime, container and validation-only CI readiness are implemented. Live infrastructure and rollout remain deferred.

Proposed public issuer is existing https://auth.ngx-workshop.io, resource
https://mcp.ngx-workshop.io/mcp. Exact issuer endpoints stay /oauth/authorize,
/oauth/token, /oauth/introspect, /oauth/revoke, /oauth/interaction/*, /oauth/grants,
/.well-known/oauth-authorization-server and /jwks. Preserve existing SPA at /
and legacy /api/auth proxies. Actual public host/cert state and approved clients
are not inferred from local fixtures.

## Requirements

- FR-001: Add explicit production profile for canonical HTTPS origin issuer/exact gateway resource, independent private listener/port and trusted proxy peers. Local profile remains unchanged. No OAUTH_LOCAL_DEV or secure:false session path in production; invalid/missing configuration fails closed. Preserve the ability to disable OAuth while supporting legacy auth during phased deployment.
- FR-002: Use persistent auth-only OAuth sessions with Secure/HttpOnly/SameSite cookies, appropriate path/host scope and CSRF/Origin protections behind verified edge forwarding. Provider proxy handling and grant Session.get must reflect trusted HTTPS. Keep OAuth cookies separate from existing accessToken cookie and retain legacy DOMAIN/JWT semantics. No domain-wide OAuth cookie shared with mcp host.
- FR-003: Register real intended clients using verified client IDs, exact HTTPS callbacks and approved browser origins, or approved HTTPS CIMD documents with existing public-DNS/TLS/pinning/capability checks. No wildcard callbacks/open DCR, guessed ChatGPT URL, shared public-client secret, production fixture IDs/callbacks or automatic consent. S256/catalog:read/exact resource, 600-second opaque access and no refresh remain.
- FR-004: Dedicated resource client authenticates introspection; credential cannot request user grants/tools. Store separately from public clients and legacy JWT secret. Gateway trusts canonical issuer HTTPS introspection and receives only immutable principal fields. Token/grant revocation must reject next request after commit without cache. Cross-environment tokens/clients/keys are isolated.
- FR-005: Private JWKS, cookie-key ring, AES-GCM storage keys, introspection credential, DB URI and legacy JWT secret are independently provisioned/persisted with least privilege. No startup key generation, key material in images/source/logs/artifacts, world-readable mounts or publishing job. Auth private config loader's owner-only 0600 policy must work with non-root runtime UID/read-only mount.
- FR-006: Reuse current account DB and authenticated private rs0 after live verification; no new copied identity store. Auth-specific collection privileges replace shared workshop DB user for this service. OAuth indexes/validators are additive, installed by controlled provisioning/migration and validated at runtime; separate privileged provisioning credentials from runtime. Gateway gets no DB credentials.
- FR-007: Require writable replica-set transaction/majority semantics, encrypted OAuth payloads/hash-only credentials, application expiry checks, bounded transaction/storage timeouts and no request replay on unknown commit. Prove private Mongo TLS or explicitly review current transport remediation; no tlsAllowInvalid flags. Single-member rs0 supports transactions but lacks failover: operator accepts bounded first-launch availability or adds redundancy in separate infra work.
- FR-008: Scheduled encrypted backup and isolated restore drill protect accounts and matching persistent keys/config. Restore never resurrects formerly revoked grants: discard restored OAuth sessions/codes/tokens/grants/forms/revocation state as one maintenance operation and require reauthorization before ingress opens; retain users. Record restoration/rotation/release procedures, ownership, recovery targets and tests.
- FR-009: Reuse existing pinned Actions/SSH/SCP/OIDC/Docker delivery with test-before-publish/deploy, protected manual promotion, immutable image/config versions, private readiness and rollback. Existing workflow doesn't mount OAuth config or enforce replicaSet/auth-specific credentials; fix later. Production secrets never enter PR tests. No workflow dispatch/publication/deployment now.
- FR-010: Public login/rate limits use verified client address through known proxy chain rather than raw edge socket for every user. Add bounded edge/app rate and concurrency limits, sanitized metrics/alerts, support diagnostics without password/code/token/Basic secret/request-query logs. Preserve all local/legacy tests and add production TLS/proxy/cookie/restart/revocation/restore/public-client acceptance.

## Future acceptance

| ID | Scenario | Result required |
| --- | --- | --- |
| AC-001 | Production config/private listener | HTTPS origin/resource accepted, local/dev/unsafe/unknown host rejected; remote authenticated rs0 works; local fixtures unchanged |
| AC-002 | Public discovery/login/consent and old browser app | Native AS routes/metadata match canonical HTTPS; secure OAuth cookies; CSRF/Origin/spoofed forwarding denied; legacy SPA/API/cookie roles/sign-out remain |
| AC-003 | Actual preregistered/CIMD client | Exact verified callback/ID, S256 flow and three MCP tools; metadata SSRF/TLS/cache policy protections; no production fixture registration |
| AC-004 | Introspection/revocation/isolation | Dedicated credential only own resource, wrong Basic inactive/JWT rejected, token/grant revocation next request denied; auth/storage outage yields sanitized 503 |
| AC-005 | Secrets/build/restart/rotation | No private config in image/artifacts; 0600 mount readable only by runtime owner; same keys retain compatible tokens after restart; planned rotations/rollback tested |
| AC-006 | Mongo/provisioning/expiry/concurrency | Runtime can't access unrelated collections/admin functions; migration sets exact indexes/validator; real transactions single redemption, enforced expiry, outage failures unchanged |
| AC-007 | Backup/recovery | Current encrypted backup and escrowed keys restore isolated users; restored OAuth state invalidated; old tokens denied, new login/consent works; no shared DB rewind for code rollback |
| AC-008 | CI/promote/rollback/limits | Failed tests block publish/deploy; unauthorized promotion denied; failed public/private smoke restores compatible image/config; rate limits distinguish clients and cannot trust spoofed IP |

## Pre-release unknowns

Confirm exact host/cert coverage/client registrations and environment separation;
GitHub protected environment availability/secret ownership; live Mongo version,
set name/primary/address/TLS/auth-role/backup scheduler; encrypted edge backhaul
versus explicit VPC trust acceptance; legacy DOMAIN/current cookie consumers.
Proposed recovery targets RPO <=24h/RTO <=4h require operator confirmation and a
measured restore; no current guarantee or high-availability claim. No additional
members, DNS entries, callbacks or credentials are provisioned by this spec.

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
