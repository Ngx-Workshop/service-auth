# Handoff: Code Maintenance

Status: Implemented and verified locally; external acceptance pending
Updated: 2026-11-22
[Spec](spec.md) · [Plan](plan.md) · [Tasks](tasks.md) · [Audit](audit.md)

## Delivered

- Source-backed audit and characterization before moving account behavior.
- Controller sign-up now delegates the existing sequence to
  AuthenticationService.register. Internal UserMetadataService owns the unchanged
  owner-API upsert, timeout/local URL and best-effort failure semantics. IAM exports,
  cookies, routes/DTOs/roles, token claims, OAuth/social handling and schema remain
  unchanged. No consumer contract regeneration, migration or publication required.
- Safe native structured password-sign-in, role-update and metadata boundary
  events replace identity/body-bearing logs. Locally generated request UUIDs reach
  async domain work; concurrent requests are isolated. Background work outside a
  request has a generated operation ID. Caller IDs are ignored, not trusted or
  forwarded. No secrets, personal content or raw exceptions enter these events.
- Pinned Husky/lint-staged, local staged-only Prettier hook, guarded package-only-safe
  prepare lifecycle, lockfile and ignores. Non-mutating CI formatting/lint gates
  and disposable hook/install fixtures preserve partial staging and block errors.
- Architecture/development/observability docs and local feature records aligned.
  Existing workflow setup and historical feature records were preserved.

## Verified evidence

| Command                                                                                    | Final result                                                 |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| `npm ci`                                                                                   | Developer install/hook setup passed                          |
| `npm test -- --runInBand`                                                                  | 6 suites, 27 tests passed                                    |
| `npm run test:oauth`                                                                       | Service/client builds; 81 OAuth/Mongo tests passed, no skips |
| `npm run test:social`                                                                      | 9 protocol tests passed                                      |
| `npm run test:maintenance`                                                                 | 9 real hook/install/negative-check fixture tests passed      |
| `npm run lint:check`                                                                       | Passed; 16 baseline warnings, 43 original errors suppressed  |
| `npm run format:check`                                                                     | Passed; one exact-content legacy formatting exception        |
| `npm run lint:oauth` / `npm run lint:oauth:spike`                                          | Passed                                                       |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/production -p 'test_*.py'` | 4 passed                                                     |
| `npm audit --omit=dev --json`                                                              | Zero production findings                                     |

The fixture suite executes real disposable commits only, verifies preserved
unstaged/partial changes and ignored generated output, blocks a syntax-error
formatter failure, rejects new lint/format violations without mutation and checks
developer/CI/HUSKY=0/no-Git/production/omit-dev installations with bcrypt usable.
It removes its temporary directories afterward; the real index is not staged.

Legacy diagnostics are deliberately not misrepresented as clean source: the
unbaselined original lint check had 45 errors/16 warnings; 43 errors remain.
ESLint allowances are file/rule counts, not exact-line exemptions, and must not
grow to cover new work. The single pre-existing JWT-config formatting drift is
allowed only at its unchanged digest. Full dev-inclusive install audit reports
37 findings; broad dependency fixes remain outside this task.

## External-owner handoffs and remaining risk

1. **CI/repository maintainer:** local runtime is Node 24.9.0/macOS, while CI/image
   pins Node 22.23.5/Linux. Docker CLI is present but daemon unavailable. Run the
   existing image and hosted validation in a properly authorized review flow.
   Beware the existing main-branch deployment job: do not push/deploy merely to
   validate this task. Package-only/no-Git installs are verified locally, not image
   execution. No current-repository commit, push, publish or deployment was made.
2. **Infrastructure owner nginx-ngx-workshop.io:** after separately authorized
   deployment, confirm JSON receipt/stream labels/retention in Alloy/Grafana and
   correlate a harmless controlled request and metadata failure as described in
   [observability](../../docs/observability.md). Credentials remain host-owned.
   Native JSON compatibility is locally tested; live Grafana receipt is pending.
3. **Existing feature owners:** real provider consent/social production acceptance
   remains the older feature's pending work, not newly completed maintenance
   acceptance. No sibling checkout or production provider calls were used.

## Next action

Review the local changes and baseline policy. Run pinned Linux CI/image checks when
an authorized review workflow is available; later obtain infrastructure-owned
Grafana evidence. T001–T010 are complete for local implementation/evidence/handoff,
with external checks explicitly left unchecked in [tasks.md](tasks.md).
