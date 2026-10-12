# ADR 0005: Durable separate production credentials and key rings
Status: Accepted for readiness implementation; release operations deferred · 2026-10-12
Feature: [004 deployment](../../specs/004-deployment/spec.md)

## Context

Local encrypted storage, sessions and provider state require persistent keys.
Before this change, the workflow sent legacy env only, Docker exclusions omitted
.oauth-local, and publishing/production jobs were coupled. A release or rollback must not regenerate or accidentally bake key data.

## Proposed ownership and delivery

| Material | Owner / permitted consumer | Lifecycle |
| --- | --- | --- |
| Legacy JWT secret/JWT issuer/audience/TTL/DOMAIN | Auth; existing legacy consumers unchanged | Preserve current configuration, separate rotation project if it changes browser compatibility |
| Private RS256 JWKS | Auth only | Persistent key IDs; publish only public /jwks; old verification keys retained through relevant signed-artifact/cache lifetime |
| OAuth cookie signing ring | Auth only | New first key signs, old keys verify until session expiry/rollback period |
| AES256-GCM storage ring + active ID | Auth only | New writes active ID; retain decryption keys for unexpired records and retained backups or re-encrypt/expire those records |
| Resource-client Basic secret | Auth and gateway only | Environment/resource-specific; authenticates introspection, never user/tool access |
| Runtime Mongo scoped URI/CA | Auth only | Scoped collection role; no DB credential in gateway; provisioning/backup principals separate |
| SSH identity/fingerprint | Existing protected deploy jobs | Reuse pins/fingerprint; production access isolated from PR/build/publish jobs |
| NPM publish identity | Existing NPM OIDC job | Separate release decision; no OAuth/JWT/DB keys accessible to publisher |
| Backup encryption/escrow credentials | Backup/operator only | Separate access and encrypted retained recovery material; not ordinary release CI |

Use existing GitHub environment-scoped secrets plus durable owner-managed files
on app droplet, outside code checkout/release directories. No new secret platform
needed. A protected delivery step writes temporary private data with umask077,
validates shape without values, transfers through pinned SSH/SCP, installs durable
versioned config atomically and removes temporary files on every exit. Reuse
production env for legacy settings; privately mount OAuth JSON read-only as 0600
owned by dedicated runtime UID. Root staging ownership must be corrected before
non-root startup; don't loosen loader checks to world-readable files.

Explicitly exclude all keys/private config/env from Docker context and test image
layers/CI source/package artifacts. No startup generation or secrets in build args,
labels, OpenAPI/tool schemas, logs, query strings or diagnostic dumps. Legacy env
and OAuth config are separate. Ordinary build/tests use disposable owned keys,
never production secret access. Keep an authorized recovery copy of key/config
revisions encrypted and access-controlled alongside recoverable database backups.

## Rotation and rollback

Storage: add new ID, activate writes, retain prior decryptors; retire only after
record expiry/re-encryption and backup-retention policy. Cookies: prepend new key,
keep old verifiers until max session lifetime and rollback window. JWKS: stable
kids and tested public-cache propagation; old verification keys live through
maximum affected artifact/cache window. Do not claim JWKS rotation revokes opaque
tokens; those use grant/state revocation. OAuth and legacy signing secrets are
independent.

Current resourceClient supports one active secret. Initial rotation uses an
explicit bounded maintenance window: close MCP ingress, update auth and gateway
as a compatible config pair, verify introspection/revocation, reopen. Do not assume
unimplemented dual-secret grace or roll back one side independently. A later
zero-downtime overlap needs separate tested multi-credential policy. DB credential
rotation proves new permissions/connectivity before retiring the old role.
Compromise revokes affected OAuth grants and rotates relevant material; never
recover by anonymous mode. Previous configs remain private and retention-bound.

## Consequences

Release/rollback preserves encrypted records and sessions; recovery without keys
must fail closed. Persistent mounts are implemented; production credential provisioning and rotation
proof remain deferred. GitHub protections depend on repository plan; manual
operator authorization is required even if environment reviewers are unavailable.

Reference: [GitHub environment secrets and protections](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

## Implementation evidence

The readiness subset is implemented and verified locally; see
[production readiness](../production-readiness.md). CI now validates and retains
reviewable candidates only. Secret provisioning, live client registration, edge
configuration, backup/rotation proof and protected promotion remain future release
operations. No publishing or deployment occurred.

## Live preflight — 2026-10-12

[Audit evidence](../deployment-preflight-2026-10-12.md) verifies current hosts,
certificate, authenticated single-member rs0 and historical backup integrity.
Installed production configuration does not yet satisfy this decision; deployment
is blocked by the recorded infrastructure/client/secret/recovery/CI gaps. No
production change or publication occurred.
