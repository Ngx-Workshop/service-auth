# ADR 0003: Approved CIMD and additive introspection
Status: Accepted for authorized local scope · 2026-10-12

## Decision

Keep oidc-provider as protocol owner and inject a hardened native HTTPS fetch
implementation for approved Client ID Metadata Documents. A separate
metadataClients registry records exact canonical HTTPS client_id, approved name
and exact redirects. Fixed policy allows only authorization_code/code, auth none
and catalog:read; the provider validates fetched identity and rechecks policy on
cached clients. Empty registry keeps support disabled/unadvertised. No public
registration or unbounded fetch of arbitrary client URLs.

Validate every IPv4/IPv6 DNS answer as public ordinary unicast; reject mixed
answers, literals, reserved/transition/private addresses, credentials, ports,
query/fragment and noncanonical URLs. Resolve once, pin the selected address to
that request's lookup, retain hostname SNI and certificate verification, disable
connection pooling and use native HTTPS without ambient proxies. Total deadline
3 seconds; body cap 64 KiB; JSON/200/uncompressed response only, no redirects.
Browser consent and grant pages name the approved client rather than arbitrary
remote display text. Test dependencies route a controlled TLS fixture; normal
bootstrap passes none and exposes no security-bypass flag.

Add OAuthIntrospectionClient, OAuthPrincipal and sanitized typed errors to
@tmdjr/ngx-auth-client. Native HTTP(S), no redirect/proxy/cache/cookie/JWT decoding,
strict active/Bearer/issuer/audience/client/subject/scope/expiry validation, immutable
principal. Dedicated resource-client Basic credential stays at introspection.
Gateway separately requires catalog:read through the official SDK and attaches
request-local AuthInfo; roles never become scopes. No signing secret or auth DB
moves into gateway.

Use local version 0.0.22-local.0 and a checked-in integrity-pinned tarball for
consumer proof, preserving old exports. No package publishing. A future registry
release and deployment identities/credentials/transport policy require separate
work; current runtime remains local and rejects production.

## Evidence and consequences

64 producer tests pass: real existing-account browser/consent and transaction
storage regressions; approved CIMD over native TLS through code/token/introspection/
revocation; policy rejection even after metadata cache; untrusted certificate,
private/mixed DNS, redirects, malformed/oversize response and bounded stalled DNS;
14 additive client checks preserve legacy exports. Gateway has 40 unit and 31
HTTP/protocol cases and a real-owner OAuth flow (5 sections/11 workshops/1 lab,
modern and legacy tools, token/grant revocation, auth outage). See
[handoff](../../specs/003-oauth-integration/handoff.md).

CIMD draft support is optional and operator-approved, not open trust. Every MCP
request depends on introspection availability; no cache ensures immediate
revocation. Test-only TLS/controlled DNS evidence does not claim external host
reachability. No hosted client connection or deployment is performed.

Primary basis: [oidc-provider v9.12.2 configuration](https://github.com/panva/node-oidc-provider/blob/v9.12.2/docs/README.md),
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html),
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html).
