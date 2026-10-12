# ADR 0001: Use oidc-provider for the service-auth OAuth engine
Status: Accepted — engine selection (local application implementation: [ADR 0002](0002-local-oauth-implementation.md))
Date: 2026-10-12
Spec: [OAuth engine spike](../../specs/001-oauth-engine-spike/spec.md)
Evidence: [handoff](../../specs/001-oauth-engine-spike/handoff.md)

## Recommendation

Use **oidc-provider 9.12.2 (MIT)** as the OAuth protocol engine inside service-auth,
with a custom MongoDB adapter and request transaction middleware. Keep existing
identity/password verification and auth-client consumers. The spike establishes
that the planned PKCE/resource/introspection/revocation/storage hooks are viable;
it does not install OAuth into the running service. At spike completion the engine was pinned as a devDependency; ADR 0002
now promotes it to a runtime dependency for local application integration.

The tested profile uses authorization code/S256, one catalog:read scope and exact
http://127.0.0.1:3011/mcp resource in a controlled local harness. It issues 256-bit
opaque access tokens for 600 seconds and codes for 60 seconds; no ID/refresh token,
password grant, implicit flow or client-credentials grant is enabled. service-auth
owns real login and explicit consent in subsequent implementation.

## Context and alternatives

Existing cookie JWT login is not an OAuth issuer. oidc-provider implements the
protocols this phase needs and provides interaction, account and adapter hooks.
Its supported v9 line, MIT license and ESM packaging were checked in the installed
package and [upstream repository](https://github.com/panva/node-oidc-provider).
Native capabilities are documented for [resource indicators](https://oidc-provider.dev/configuration/features/resource-indicators/),
[introspection](https://oidc-provider.dev/configuration/features/introspection/),
and [revocation](https://oidc-provider.dev/configuration/features/revocation/).

@node-oauth/oauth2-server 5.3.0 (MIT) was considered through its primary docs and
package metadata; it has PKCE/model hooks but its public server API does not offer
the same native resource/introspection/discovery profile. It was not installed or
execution-tested. Selecting it would leave more protocol glue for this service.
See its [server API](https://node-oauth.github.io/node-oauth2-server/api/server.html)
and [model API](https://node-oauth.github.io/node-oauth2-server/api/model.html).
An external issuer remains a contingency if later identity or operational needs
warrant it; it is unnecessary to prove the local owner integration seam. A custom
OAuth implementation and frozen MCP legacy issuer helpers are not recommended.

## Proof and required policy

Thirty executable cases passed using real provider HTTP through Nest 11.1.3 and
real MongoDB 6.0.1 storage with Mongoose 8.16.3's bundled driver, on Node 22.23.3 LTS.
CommonJS native dynamic import and an isolated Nest middleware mount were proved.
No change to the service's CommonJS compiler target is required; preserve native
import() through the integration loader instead of assuming TypeScript's emitted
require() is the same seam. Node 18 is insufficient for this engine; the existing
README's legacy minimum is not the new OAuth runtime requirement. Node 24.9.0 on
this machine is a non-LTS release and triggered the engine warning; final evidence
uses the supported Node 22 runtime.

| Requirement | Native capability | Application/adapter policy proven |
| --- | --- | --- |
| S256 and code binding | PKCE verification, exact redirect/client checks | Require PKCE for every client; missing/plain/wrong/missing verifier rejected |
| MCP resource/audience | ResourceIndicators + opaque access token aud | Reject absent/wrong resource in authorize and token exchange; reject scope mutation using engine-parsed body before issuance; catalog scope only |
| Trusted introspection | RFC 7662 response including sub/client_id/aud/iss/iat/exp/scope/type | Separate authenticated resource-server client, restrict to own audience and AccessToken; other caller sees active:false |
| Token and grant revocation | Native revoke and Grant lifecycle | Owner-bound revoke; denial for another client, immediate inactive after token/grant revoke; explicit grant removal hook needed for real user UI |
| Durable storage | Custom adapter interface | Hash-only code/token lookup/value storage, encrypted remaining state, explicit expiry + TTL index, provider and mongod disk restart |
| Atomic consume/issuance | Adapter consume + provider request middleware | CAS consumption, transaction spans consumption and token write before Koa sends response; one success from eight simultaneous requests; rollback after token write/precommit failures and successful retry |
| Metadata-document clients | Experimental draft-02 feature and allowFetch/allowClient/fetch hooks | Real engine resolves a controlled fetch fixture, allows approved client, denies unapproved private URL before fetch and native mismatched ID; full HTTPS/DNS/SSRF fetch protection is still application work |

Native defaults are not the application profile: omitted token resource can fall
back to a granted resource, unknown/non-grant parameters may be ignored, and
confidential introspection defaults are broader than desired. Explicit hooks are
required. The profile rejects raw scope on exchange because native code-grant
parameter filtering otherwise ignores it; this protects the planned stricter
request contract even though native issuance did not grant the attempted new scope.
Do not provide a false-returning issueRefreshToken override merely to disable
refresh: a custom hook advertises refresh support. With no offline_access or
refresh grant on clients and the default hook, metadata and issuance match this
profile. Catalog consent needs both configured scope bookkeeping and resource
scope; no openid scope is requested and no ID token is returned.

## Storage decision and limits

A default/demo adapter is insufficient. The spike adapter stores code/token IDs
as model-qualified SHA-256 hashes and **removes raw jti from their persisted payloads**.
It reconstructs jti from the presented credential after a successful hashed lookup,
so neither plaintext nor encrypted records retain recoverable code/token values.
Remaining provider state is AES-256-GCM encrypted; grant/uid indexes are hashes.
The encryption key must remain stable across restart and be externally managed
in implementation. Spike keys, service credentials and signing keys are ephemeral
fixtures and never represent production key handling.

**MongoDB replica-set capability is required** for code consumption and token
issuance in one transaction. A fresh loopback single-member replica set is created
and removed by the test; the existing standalone MongoDB and data are untouched.
The adapter serializes operations in the transaction's request-local session
because provider grant revocation may issue parallel adapter calls. No shared
transaction/principal singleton is used and no retry of parsed HTTP middleware
is attempted. Eight-way concurrent writes produce one token response and safe
invalid_grant losers. A replay revokes the grant; that security effect is retained
outside an aborted failed-redemption transaction so rollback does not undo it.

The spike proves deterministic write/precommit failures, rollback and restart,
not network-ambiguous commit outcomes, multi-process failover or key rotation.
The real adapter must handle UnknownTransactionCommitResult with safe commit
resolution and must never return a token before a confirmed commit. Bound
transaction/session lifetimes, guarantee endSession on cleanup failure, require
supported replica topology at startup, and add integration tests for Mongo
connection failure before exposing runtime routes. Do not copy this spike wrapper
as a production module without that hardening. No requirement was weakened to
accept standalone non-transactional issuance.

## Consequences and next work

Recommend the engine with these integration constraints (local application work
is now recorded in ADR 0002); this completes engine
selection, not the OAuth feature. Subsequent owner work must implement actual
credential verification/CSRF/login/consent UI, approved client metadata resolution
with pinned DNS/address checks and limits, persistent adapter/key lifecycle,
resource-server credential management and additive auth-client introspection.
CIMD is experimental and version-acknowledged; retain exact pin/retest on changes
and leave it disabled in runtime until its complete security acceptance passes.

At spike completion, legacy src and libs remained unchanged and no OAuth endpoints
were mounted in AppModule,
no real users were created and no package was published. Deployment, public URLs,
TLS/proxies/CI, production binding and operational rollout remain deferred.
