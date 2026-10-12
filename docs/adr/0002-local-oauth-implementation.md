# ADR 0002: Integrate OAuth as an opt-in local authorization server

Status: Accepted for local implementation (2026-10-12); deployment deferred.

## Decision

Use oidc-provider 9.12.2 as a runtime dependency behind a native ESM loader,
packaged with the existing CommonJS Nest service. Mount explicit OAuth paths
before Express parsing and Nest guards. Disabled OAuth leaves legacy routing,
cookie JWT validation, role checks, sign-in/up/out and auth-client exports intact.
Use AuthenticationService's existing Mongo accounts and HashingService verifier;
OAuth login neither creates users nor issues legacy JWTs. A dummy hash comparison
makes unknown-user login failures follow the same password-verification path.

Browser login and consent use signed interaction cookies, single-use hashed CSRF
forms bound to interaction/prompt, strict same-origin POST, bounded input, 10 failed/60 total login attempts per minute per socket IP, no-store and restrictive CSP. Show the registered client name,
catalog:read and exact resource; grant only after Allow. /oauth/grants uses the
provider session and account-bound CSRF for user-owned grant revocation. Legacy
sign-out continues to clear only the legacy cookie; OAuth grants are independent.

Require a writable local replica set. Persist encrypted provider payloads with
AES-256-GCM, per-record AAD, retained key IDs and random IVs; hash code/token IDs
and remove their raw jti even from encrypted payloads. Check expiry on reads and
CAS consumption independently of TTL cleanup. Hash secondary lookup identifiers. Enforce encrypted state shape with a strict Mongo validator.
Keep keys in an owner-only configuration file, generated once, never at startup.

Wrap redemption in a majority-write transaction and serialize adapter operations
on its session. Touch the grant before token insertion to conflict with deletion.
Commit before response, retry only commit for unknown outcomes (at most three
application attempts, each bounded), and never re-run redemption. Roll back on
failure. Persist replay-revocation tombstones outside aborted transactions;
checks bypass transaction snapshots so revocation is observed on the next
lookup. Always close sessions, including cleanup failures. A failed revocation
persistence returns an error rather than claiming successful revocation.

Expose authorization-server discovery, authorize, token, introspect, revoke and
public JWKS. Require S256, exact resource and registered redirect; only
catalog:read, authorization_code, 60-second codes and 600-second opaque access
tokens. Introspection requires distinct gateway Basic credentials and returns
issuer/account/client/audience/scope/expiry. The engine rejects structured legacy
JWTs with 400 unsupported_token_type; unknown opaque strings return active:false.
Public clients may revoke only their own tokens, with an idempotent empty 200.
No cache delays revocation. Adapter failure signals survive engine token-lookup
error handling, so introspection storage outages return 503.

## Boundaries and consequences

OAuth is disabled by default; explicit OAUTH_LOCAL_DEV=true, canonical loopback
issuer/resource, fixed port and non-production mode are mandatory. Enabled OAuth
binds loopback and rejects untrusted Host headers on its own routes. Existing
non-OAuth listeners retain their default binding when OAuth is disabled.

This increment uses preregistered clients. CIMD resolution, SSRF-safe HTTPS fetch,
additive auth-client introspection exports, gateway enforcement and end-to-end
three-tool bearer verification remain subsequent OAuth integration tasks. This
ADR does not complete gateway feature 003 or authorize deployment. Cookie/session
and grant TTL are ten minutes; grant management currently lists up to 100 recent
active grants. Local throttling is per process; distributed throttling, TLS,
production key ownership/rotation operations, database credentials and monitoring
belong to the deferred deployment phase.

## Evidence

See [feature handoff](../../specs/002-oauth-implementation/handoff.md) for final
commands and test counts. Tests boot the actual AppModule, real bcrypt accounts,
real HTTP interactions and an owned temporary MongoDB replica set. Fault injection
is test-only monkey patching at driver methods, not a runtime bypass flag.

References: [provider API](https://github.com/panva/node-oidc-provider/blob/v9.12.2/docs/README.md),
[engine recommendation](0001-oauth-engine.md), and
[implementation spec](../../specs/002-oauth-implementation/spec.md).
