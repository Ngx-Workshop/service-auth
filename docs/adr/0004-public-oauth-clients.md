# ADR 0004: Public HTTPS issuer and verified OAuth clients
Status: Accepted for readiness implementation; release operations deferred · 2026-10-12
Feature: [004 deployment](../../specs/004-deployment/spec.md)

## Context

Auth already owns users/legacy cookies and now supplies local OAuth through
OIDC-provider9.12.2. Existing Nginx serves auth.ngx-workshop.io SPA and /api/auth.
Client fixtures and loopback issuer/resource aren't deployable registrations.

## Proposed decision

Use existing auth.ngx-workshop.io as canonical HTTPS origin issuer, adding exact
native /oauth endpoints, AS metadata and /jwks while preserving SPA / and legacy
/api/auth routes/cookie contracts. Proposed gateway resource is
https://mcp.ngx-workshop.io/mcp. Both identities are independent of internal port;
exact URLs come from config, never guessed from arbitrary forwarded headers.
Edge overwrites forwarding fields and services trust only verified edge peers.
Native session/grant handlers must recognize HTTPS with secure auth-only cookies
and retain CSRF/exact Origin checks. Don't share OAuth cookies with the MCP host.

Launch with explicitly verified preregistered clients or approved HTTPS CIMD IDs;
record client owner/environment, exact ID/document/name/callbacks/origins and
capabilities before enabling. Obtain current values from intended client/provider
configuration, not guessed ChatGPT examples. Preserve hardened public DNS/TLS/
pinning, cached client policy and exact capabilities. Unknown clients/redirects
fail; no public DCR/wildcards or production loopback fixture registrations.

Use S256, catalog:read, exact resource, opaque600-second access tokens; no refresh,
password/client-credential grant or silent consent. Expiry requires reauthorization.
Dedicated gateway Basic credential validates introspection only. Client subject
and client ID remain distinct; neither a cookie JWT nor service secret grants tool
access. Introspection uses canonical issuer HTTPS, no cached authorization. Rotate
public client policy deliberately, invalidate grants for removed clients, and test
actual public-client login/discovery/tool access/revocation before claiming support.

## Consequences

Keeps identity/consent inside existing auth; introduces no new provider or platform.
Public redirect/CIMD values and Nginx certificate coverage are future release
gates. Existing-client browser/JWT consumers retain behavior and credentials;
production mode/proxy/session/rate-limiting implementation is still required.
No live registration or hosting change is made by this ADR.

References: [MCP authorization](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/index.mdx),
[oidc-provider9.12.2](https://github.com/panva/node-oidc-provider/blob/v9.12.2/docs/README.md).

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

## Launch-policy clarification

The user accepts downtime because there is no production traffic. Retain the
single-member replica for launch; no strict recovery-time commitment or
zero-downtime deployment is required. Preserve data and keys and prove recovery.
Initial ChatGPT registration is a recommendation awaiting exact client callback
acceptance; see [client/recovery note](../launch-client-and-recovery.md).
Nothing was provisioned, deployed or published.

## Authorized launch evidence — 2026-10-12

Decision implemented in production after explicit user authorization. See [launch evidence](../production-execution-2026-10-12.md) for reviewed commits/images, persistent secrets, verified TLS/scoped storage, actual recovery/public acceptance and the unresolved private ChatGPT builder error. Earlier no-deploy statements describe the historical phase.
