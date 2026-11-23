# Maintenance audit

Inspected 2026-11-22, HEAD `682a2f8`. Existing dirty work comprises the local
workflow/context setup and feature index; retained. Parent entry-point paths do
not exist; this checkout's AGENTS.md and specs index are authoritative.

## T001 baseline

- Node v24.9.0 / npm 11.6.0 locally; image/CI pins Node 22.23.5.
- Installed Nest common 11.2.7, ESLint 9.31.0, Prettier 3.6.2.
- `npm test -- --runInBand`: 5 suites, 21 tests pass.
- `npm run build`: pass.
- `npm run test:oauth`: 81 pass, no skips; disposable local Mongo fixtures.
- `npm run test:social`: 9 pass; protocol doubles, not real provider consent.
- `npm run lint:oauth`: pass.
- `npx --no-install eslint "{src,apps,libs,test}/**/*.ts"`: 45 errors,
  16 warnings, primarily unsafe legacy typing; no fixes applied.
- `npx --no-install prettier --check "src/**/*.ts" "test/**/*.ts" "libs/**/*.ts"`:
  only src/iam/config/jwt.config.ts fails.
- Docker CLI exists but daemon is unavailable. Live image execution and pinned
  Linux runtime checks require CI. No live Grafana or provider credentials used.

## T002 dependency and responsibility map

- AppModule composes global ConfigModule (intentional application configuration),
  Mongoose root connection, ObservabilityModule and IamModule.
- IamModule owns User schema, JWT/config, hashing abstraction implemented by
  BcryptService, AuthenticationService, AuthenticationController and the global
  authentication/roles guards. It exports only AuthenticationService, consumed by
  bootstrap's native ESM OAuth/social adapters. No circular module flow,
  duplicate provider registrations or forwardRef found.
- AuthenticationGuard delegates cookie verification to AccessTokenGuard; RolesGuard
  applies route metadata. Preserve optional authentication, local provisioning,
  issuer/audience, cookie options and all DTO/route decorators.
- AuthenticationService owns accounts/passwords/tokens, idempotent provisioning,
  social identity collision/linking and role updates. Mongoose persists only this
  owner's User schema. Metadata writes use the metadata owner's HTTP API.
- OAuth ESM engine owns protocol/config/ingress/metadata-fetch and its dedicated
  encrypted Mongo adapter, transaction context, schema validation and grants.
  It calls the exported authentication boundary, not sibling service collections.
  Existing 81 protocol tests cover timeout, replay, recovery and access boundaries.
- ngx-auth-client is a separately built consumer module with explicit HttpModule
  import and public guards/client exports. Keep its API/claim behavior unchanged.
- ObservabilityModule owns anonymous Terminus liveness. Existing middleware emits
  safe route-template HTTP JSON but generated IDs do not yet reach use cases.

## Selected findings and scope

1. High: controller role logging serializes user IDs/body; service role and metadata
   messages also expose identity. Replace with bounded operation/outcome events,
   never raw exceptions, account data or HTTP client configuration.
2. Medium: controller sign-up coordinates persistence, password verification and
   metadata provisioning. Characterize sequence/failures, move this use case into
   AuthenticationService while keeping cookie transport in the controller.
3. Medium: AuthenticationService constructs axios and knows upstream timeout/URL.
   Extract one internal UserMetadataService in IamModule with constructor injection.
   Keep 3-second timeout, local URL and best-effort failure semantics. Do not split
   account behavior into speculative layers or change social retries.
4. Medium: no staged workflow or full non-mutating CI checks. Add pinned compatible
   Husky/lint-staged and package-only-safe inline prepare. Track legacy ESLint
   diagnostics with native bulk suppressions and the single unchanged formatting
   file by digest; CI must reject new drift, not rewrite legacy source.
5. Medium: add request AsyncLocalStorage in existing observability utility and one
   safe operation helper. Always generate IDs locally, ignore incoming IDs. A
   separate generated operation ID correlates background invocations.

## Compatibility and constitution

No routes, DTOs, persisted schemas, roles, cookie behavior, protocol response,
timeouts, token claims, concurrency or public exports change. No contract generation
needed beyond building the existing client. Characterization covers success,
conflict/denial and storage/upstream failures before extraction; existing admin,
social and heartbeat regressions remain mandatory. Role not-found remains null,
not a newly introduced 404. Metadata failure remains non-fatal and explicitly warns.
All six constitution principles apply; no deviation or external-owner source
dependency is required. Collector/live deployment remains infrastructure-owned.

## Completion evidence (T003–T010)

- Before extraction, `npm test -- --runInBand
src/iam/authentication/maintenance.spec.ts`: 4 characterization cases passed.
  They cover cookie transport after account/token/metadata sequence, duplicate
  conflict, password denial, non-fatal metadata outage and null/storage role results.
- After extraction, final unit suite: 6 suites / 27 tests pass. Existing admin
  validation/access/local restrictions, social collision/retry and sign-out cases
  remain green. Added native JSON success/rejection/error canaries, concurrent
  request IDs, background context absence and quiet GET/HEAD heartbeat assertions.
- Final `npm run test:oauth`: builds service and exported client; 81 local isolated
  OAuth/Mongo cases pass with no skips. Final social protocol suite: 9 pass.
- `npm run test:maintenance`: 9 real fixture cases pass. Developer hooks format
  partial staging without capturing unstaged changes; generated contracts remain
  ignored. Formatter syntax failure blocks fixture commit. CI checks reject both
  new/changed formatting drift and new-file lint errors without writing files.
  Full developer, CI, HUSKY=0, no-Git/package-only, production/no-dev and plain
  omit-dev installs pass, and bcrypt's dependency lifecycle remains usable.
- `npm run lint:check`: pass with 16 baseline warnings; 43 original errors retained
  in native bulk suppression baseline (two identity-logging/type errors removed).
  Newly added TS and maintenance JS have no unsuppressed errors.
- `npm run format:check`: pass, explicitly reports the unchanged JWT-config digest
  exception. Only touched source/config/docs were formatted.
- `npm run lint:oauth` and `npm run lint:oauth:spike`: pass.
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/production
-p 'test_*.py'`: 4 pass.
- `npm audit --omit=dev --json`: zero production dependency findings. Full npm
  installation reports 37 dev-inclusive findings; no broad dependency remediation
  is authorized here. Hook packages are pinned; no runtime/framework upgrade.
- Reviewed source/module and lockfile diff for preserved routes, claims, roles,
  schema, HTTP metadata payload, timeout and exports. Existing auth-client/OAuth
  source is unchanged; build is sufficient, no contract regeneration required.

Early iterations exposed a misplaced middleware context call, an argument-order
mistake in an existing test, new-test lint issues and dependency configuration
discovery in the fixture hook. These were corrected; final checks above passed.
Explicit root lint-staged configuration prevents nested dependency configs from
interfering with hooks. No tests or checks are counted from those failed iterations.

The unavailable Docker daemon prevents image execution on pinned Node 22/Linux.
Local fixtures run Node 24/macOS and do not replace hosted CI or live integration.
Live provider consent and Grafana/Alloy receipt were not exercised. No production
writes, deployment, package publication, push or real-repository commit occurred.
