# Local OAuth implementation handoff

Status: Complete for the requested service-auth local increment, 2026-10-12.
Deployment remains deferred. No commits, publishing, or infrastructure changes.

## Delivered

- oidc-provider 9.12.2 promoted from spike-only to runtime dependency.
- Explicit middleware routing before legacy parsers/guards; native ESM assets
  packaged under dist/src/oauth through the CommonJS Nest build.
- Real existing-account login, bcrypt verification, dummy comparison for unknown
  users, generic OAuth login errors, 10 failed/60 total attempts per minute per
  socket IP, signed interaction cookies, single-use CSRF and explicit consent.
- Canonical issuer/resource/Host validation, production rejection, opt-in local
  mode, loopback listener when enabled; disabled legacy listener stays unchanged.
- Owner-only persistent key/config generator; fixed public client registry.
- Mongo replica-set startup gate (including actual standalone rejection test),
  strict encrypted-state validator, hashed indexes, explicit expiry and TTL,
  AES-256-GCM with record AAD and retained key IDs, bounded storage/network waits.
- Transactional redemption with grant conflict protection, CAS code consumption,
  commit-before-response, three bounded commit-only attempts, rollback and
  replay-revocation tombstones. Session cleanup runs even on cleanup errors.
- Discovery, authorize/token, resource-server Basic introspection, public JWKS,
  client-owned token revocation and authenticated /oauth/grants management.
- Introspection storage errors produce 503 rather than active credentials.
- Existing cookie JWT sign-up/in/out, validation, role authorization, metadata
  upsert and auth-client exports preserved. Legacy sign-out does not revoke OAuth.

## Validation

Executed using Node 22.23.3 LTS and isolated MongoDB 6.0.1 processes. Tests own
all their databases, user accounts, local metadata stub, ports and temp keys.
They never modify the shared MongoDB process or connect to live user metadata.

| Check                         | Result                                                                                                                              |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| npm run test:oauth            | 22 passed, 0 failed, 0 skipped; includes actual AppModule HTTP, real login/consent, legacy regressions, faults, storage and restart |
| npm run test:oauth:spike      | 30 passed, 0 failed, 0 skipped; original protocol/metadata-hook engine evidence retained                                            |
| npm run lint:oauth            | Pass; runtime ESM, browser handlers, new tests, config generator and bootstrap/main                                                 |
| npm run lint:oauth:spike      | Pass                                                                                                                                |
| npm run build                 | Pass (also prerequisite of application suite)                                                                                       |
| npm run build:ngx-auth-client | Pass; library source/export contracts unchanged                                                                                     |
| Config generator smoke check  | Valid persistent keys; owner-only mode; existing-file overwrite refused; temp files removed                                         |
| git diff --check              | Pass                                                                                                                                |

The new suite covers successful real login/consent, denial, wrong password,
origin/CSRF rejection, PKCE/resource/scope/redirect/client binding, introspection
credentials and legacy JWT rejection, token/grant revocation, six concurrent code
exchanges with one winner, replay invalidation, token-write and precommit failure,
bounded unknown-commit handling, database outage, app+Mongo restart with retained
code/token, key-ring reads, record-AAD tamper rejection, no raw credential even
inside decrypted records, strict Mongo validation, expiry before TTL cleanup,
production/config/Host policy, real standalone startup rejection, legacy signup,
duplicate email, exact legacy credential errors, regular/admin roles, legacy
cookie/bearer distinction, sign-out independence, throttling and disabled OAuth.

Repository-wide legacy lint is not claimed clean: the existing AuthenticationService
has pre-existing unsafe-any/restrict-template diagnostics outside the OAuth
additions. The old Hello World e2e placeholder was not used; the new suite boots
the real service against an owned database and tests its actual routes.
The install still reports the existing broad dependency audit backlog (99 findings);
this change does not perform unrelated dependency upgrades or claim an audit pass.

## Follow-on work

Run locally using [the runbook](../../docs/oauth-local.md). The service requires
an already initialized local replica set and existing local accounts. No private
config was generated in the repository, and no application was left listening.

Gateway feature 003 T002/T003 now have owner implementation evidence here, but
its checklist was not changed. T004 is partial: introspection/token/grant revocation
are implemented; hardened CIMD HTTPS fetching remains unimplemented and disabled.
T005 auth-client additive OAuth exports, gateway bearer middleware and full
OAuth-to-three-tools integration remain subsequent OAuth work. Deployment, TLS,
proxy policy, production database credentials, distributed rate limiting,
operational key rotation and CI/infrastructure are deferred.

See [ADR 0002](../../docs/adr/0002-local-oauth-implementation.md),
[HTTP contracts](contracts.md), [spec](spec.md), [plan](plan.md), [tasks](tasks.md).

Subsequent feature 003 completes hardened CIMD, additive package and gateway
integration. The follow-on gaps above describe the earlier feature boundary; see
[current evidence](../003-oauth-integration/handoff.md). Deployment remains deferred.
