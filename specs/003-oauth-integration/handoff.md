# Handoff: remaining local OAuth integration
Status: Complete (local scope) · 2026-10-12 · Node 22.23.3
Spec: [spec.md](spec.md) · Plan: [plan.md](plan.md) · Tasks: [tasks.md](tasks.md)
ADR: [0003](../../docs/adr/0003-oauth-cimd-introspection.md)

## Delivered

Optional approved metadataClients registry with exact HTTPS ID/name/redirects,
native hardened fetch and strict oidc-provider capability checks. All DNS answers
must be public; pin one address for TLS; 3 seconds/64 KiB; no redirect/proxy/pooling/
credentials or unverified certificates. UI uses approved names. Empty registry
keeps support disabled. Additive auth-client exports preserve legacy guards,
decorators and interfaces; native typed introspection returns immutable principals
and sanitized categories, no cache or cookie fallback. Package build remains flat
at its existing index entrypoint; gateway consumes local 0.0.22-local.0 tarball.

## Verification

`npm run test:oauth`: 64 passed, zero failed/skipped (23 app/storage/CIMD,
14 auth-client, 27 metadata cases). It builds service and library first. Native
TLS fixture completed approved-client login/consent/PKCE/resource-bound issuance,
introspection and revocation; cached policy mismatch and untrusted certificate
were denied. Controlled DNS tests reject private/mixed/transition answers and pin
one public address, and cover deadline, malformed/oversize/redirect responses.
There is no local-address or TLS bypass in normal bootstrap. The fixture injects
only test networking dependencies and uses an ephemeral CA; it proves local
integration, not reachability of a public metadata host.

`npm run lint:oauth` and `npx eslint libs/ngx-auth-client/src/oauth-introspection.ts`
passed. Build/library packaging and gateway installed exports/integrity passed.
Legacy app sign-up/sign-in/validation/cookie metadata/roles/sign-out tests passed.
Existing 99 dependency audit findings remain outside these scoped changes.

Gateway `npm test -- --runInBand`: 40 passed; `npm run test:e2e -- --runInBand`:
31 passed. Build/lint/source-generated HTTP/contracts passed. Its real OAuth
runner used an owned auth replica set/config/account (created via sign-up), real
login/consent and both MCP clients against real document/coding-labs owners:
5 sections, 11 workshops, 1 published lab, all three tools and negative cases.
Token and browser grant revocation denied next requests; auth shutdown caused 503.
No domain data/source changed. Owned auth/Mongo/gateway and owner test listeners
closed; shared Mongo stayed intact. Producer and consumer sources remain uncommitted.

## Reproduce and next phase

See [auth runbook](../../docs/oauth-local.md). For real-owner acceptance start
catalog owners in supported local modes, build auth/gateway, then run
`npm run test:integration:oauth:local` from gateway. AUTH_SERVICE_ROOT identifies
this checkout only for that opt-in integration; normal gateway runtime uses its
versioned package artifact. No secrets or tokens are printed/committed.

Deployment, public clients/URLs, TLS termination/proxies/Host/Origin/CORS policy,
production Mongo/credentials, operational rotation, distributed rate limits and
monitoring/publication remain deferred. No commit, package release, push or deploy.
