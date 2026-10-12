# OAuth engine spike handoff
Status: Complete (engine spike only)
Updated: 2026-10-12
Spec: [spec.md](spec.md) · Plan: [plan.md](plan.md) · Tasks: [tasks.md](tasks.md)
Recommendation: [ADR 0001](../../docs/adr/0001-oauth-engine.md)

## Delivered

Recommend oidc-provider 9.12.2, MIT, with a custom encrypted/hash-based MongoDB
adapter and code-exchange transaction middleware. Added a repeatable dev-only
spike outside src; no existing application route or auth-client export changed.

| File | Responsibility |
| --- | --- |
| spikes/oauth-engine/provider.mjs | Isolated Nest mount, engine profile, fixture interaction/account hooks, transaction boundary |
| spikes/oauth-engine/mongo-adapter.mjs | Hashed ID lookups, code/token jti omission, encrypted state, CAS consume, serial session operations |
| spikes/oauth-engine/mongo-fixture.mjs | Own temporary loopback mongod replica set and cleanup; no existing DB access |
| spikes/oauth-engine/engine.test.mjs | Real HTTP behavior, Mongo restart, concurrency, failure injection and extension seams |
| package.json/package-lock.json | Pinned dev-only engine and opt-in scripts; debug transitive dependency updated to meet engine requirement |

## Actual checks

| Check | Result / scope |
| --- | --- |
| Node 22.23.3 --test --test-concurrency=1 spikes/oauth-engine/engine.test.mjs | PASS: 30 tests, 0 skipped; real engine/Nest/isolated MongoDB 6.0.1; fixture identity/consent |
| PKCE/client/redirect | Missing/plain PKCE, missing/wrong verifier, client/redirect mismatch rejected; S256 code exchange succeeds |
| Resource/scopes | Absent/wrong resource at both endpoints and attempted scope escalation rejected; exact aud/iss/scope on introspection |
| Introspection | Service Basic credential required; invalid service secret rejected; unauthorized resource server, unknown/JWT token inactive; sub distinct from client_id |
| Revocation | Other client cannot revoke; rightful client idempotently revokes; grant destroy and code replay invalidate tokens on next introspection |
| Expiry | Engine exp and adapter expiresAt checked independently before TTL cleanup |
| Durability | Stop/restart provider and own mongod, reusing disk directory/key; old token remains active and previously issued code exchanges successfully |
| Concurrency | Eight HTTP exchanges of one code: one token response, seven invalid_grant; direct eight-way adapter CAS: one winner; sequential replay denied and winning token then inactive |
| Atomicity | Injected token upsert failure and precommit failure: 500 with no token, no persisted token, code unconsumed; subsequent legitimate retry succeeds |
| Hash-only values | Raw code/token omitted even from decrypted persisted payload; hashes used for lookup; encrypted remaining state |
| CommonJS/ESM/Nest | Native dynamic import from CommonJS process and isolated real Nest middleware mount pass; no service compiler target change |
| Metadata clients | Real engine resolution/interaction/code exchange with controlled fetch Response double; private URL denied before fetch; mismatched client_id rejected. No real remote HTTPS/DNS-rebinding proof |
| npm run lint:oauth:spike | PASS: scoped JavaScript/Prettier lint; no root legacy lint modification |
| npm run build | PASS: existing Nest application compile; spike not wired into it |
| npm run build:ngx-auth-client | PASS: existing library compile unchanged |
| git diff --check / local docs links | PASS |

For rerun, use supported Node 22 LTS and installed mongod:

```sh
npm ci
npm run test:oauth:spike
npm run lint:oauth:spike
```

OAUTH_SPIKE_MONGOD optionally names the mongod binary. No .env or live JWT/auth
credentials are loaded. The test binds ephemeral loopback ports, creates its own
new temporary disk directory and single-member replica set, and stops/removes
these in cleanup. Existing process on 27017 and existing local records remain
untouched. Cleanup verified: no owned mongod/listener or spike temp directory left.

## Boundaries and remaining work

This proves the engine and integration hooks, not real user password login,
consent UI/CSRF, auth-client package API, MCP OAuth gateway or full production
security. User/consent results are explicit fixture interactions; metadata fetch
is a controlled test double. No existing auth e2e scaffold was run: it targets
Hello World at / against an app that has no such route and requires external DB.
There are no existing owner unit .spec.ts suites. Builds are compile evidence,
not regression proof of real cookie login. src/libs were left unchanged.

Atomic issuance needs a replica set; standalone storage is not an acceptable
fallback. Network-ambiguous commit outcome, multi-process failover, request-time
transaction limits, cleanup failure and key rotation require hardening and tests
in actual integration. The ADR records these precisely. CIMD draft-02 hooks are
available but full SSRF/DNS pinning and metadata policy remain next owner work;
no feature 003 AC-001–009 is marked passed by this spike.

Install reported 99 root audit findings (6 low, 23 moderate, 66 high, 4 critical).
This is an install summary for the whole existing dependency tree, not an engine
security review. No broad audit fix or unrelated upgrade was performed.

Next action: implement auth-owner login/consent and durable engine integration
under a separate owner feature, then additive auth-client exports and gateway
resource protection. Existing identity belongs to service-auth; no duplicate
users or foreign database access. Deployment/public routing remains deferred.

Follow-up: real local login/consent and hardened runtime storage are implemented
in [feature 002](../002-oauth-implementation/handoff.md). The evidence above
records the original spike scope.
