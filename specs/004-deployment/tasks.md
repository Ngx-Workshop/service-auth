# Auth deployment tasks
Status: Readiness implemented; release tasks remain · 2026-10-12

- [x] P001: Inspect CI/Docker/config/session/storage/legacy browser source and infrastructure records; document findings/limits without secret values.
- [x] P002: Add coordinated spec/plan, proposed client/secrets/Mongo ADRs and handoff; check mapping/links and unchanged deployment assets.
- [x] R001: Implement explicit production HTTPS/trusted-proxy profile while retaining local mode and legacy behavior.
- [x] R002: Require persistent runtime-owned private secret files; reject unsafe production config.
- [x] R003: Validate authenticated TLS MongoDB/schema/transactions in auth and dependency readiness in gateway with isolated regression tests.
- [x] R004: Correct Docker entrypoints/vendor/native dependencies, non-root image, private mounts and exclusions; build locally.
- [x] R005: Replace automatic publication/deployment with validation-only CI gates and candidate evidence; update ADRs and runbooks.

- [x] R006: Perform authorized live read-only deployment preflight; record passes, failures and unverified client/recovery policy in docs/deployment-preflight-2026-10-12.md. Audit complete, release not approved.

- [ ] T001: Confirm domain/cert/proxy/actual client registry, secret owners/GitHub environment controls, live rs0/TLS/backups and recovery targets. Gate release; FR-001/003/005/007–009; AC-001/003/005/007/008.
- [ ] T002: Implement production config/bootstrap/provider/grant secure session and trusted proxy/Host/client-IP handling while preserving local/legacy consumers; test HTTPS/no-local fallback. Depends T001; FR-001–004/010; AC-001–004/008.
- [ ] T003: Implement least-privilege DB runtime and migration split, private replica/TLS readiness/config and transaction/validator/expiry regressions. Depends T001; FR-006/007; AC-001/006.
- [ ] T004: Implement persistent secret config mounts/ownership and Docker exclusions/non-root image; verify restart/rotation and key secrecy in layers/artifacts. Depends T002/003; FR-005; AC-005.
- [ ] T005: Add PR tests with isolated replica set, immutable build/config manifest and separate client publication/manual protected promotion/rollback workflow. Depends T002–004; FR-009; AC-008.
- [ ] T006: Coordinate edge native auth routes/cert/proxy/limits with Nginx owner, preserve SPA/legacy paths; production smoke uses approved client and disposable grant. Depends T001–005; FR-002–004/010; AC-002–004/008.
- [ ] T007: Prove encrypted backup/isolated restore/key rotation/restore grant invalidation and compatibility rollback; agree single-member outage target. Depends T001/003/004; FR-005–008; AC-005–007.
- [ ] T008: After separately authorized rollout, promote auth before private gateway and edge, measure actual public flow/legacy regressions/revocation and record SHA/image/config/rollback evidence. Depends T001–007; FR-009/010; AC-001–008.

Production-readiness implementation is authorized and delivered. T002–T005 have
local implementation evidence; their public acceptance, rotation/recovery and
promotion portions remain unchecked until release work. No checklist triggers a
deployment or publication. Live facts, edge changes, backups and rollout remain
deferred (T001 and T006 onward). See [readiness evidence](../../docs/production-readiness.md).

2026-10-12 preflight: T001 partially verified (hosts/certificate/rs0/current
permissions/backup integrity); actual clients and RPO/RTO remain open. T006/T007
and rollout remain unchecked. Existing remote main workflows still publish/deploy;
local CI changes must be reviewed before any future dispatch.

2026-10-12 user clarification: no production traffic; downtime accepted. Initial
launch retains single-member rs0 without a strict RTO or zero-downtime requirement.
Data-loss policy is not waived. [Recommended ChatGPT registration and recovery
baseline](../../docs/launch-client-and-recovery.md) replace the open availability
question; exact callback/issuer acceptance and recoverable backups remain gates.
No deployment or publication is authorized.

## Authorized production execution — 2026-10-12

The user now authorizes the recommended ChatGPT setup, infrastructure/secret/
MongoDB TLS/scoped-access/recovery remediation, deployment and publication.
Earlier no-deploy/no-publish restrictions are historical and superseded. Downtime
is acceptable; existing shared records/legacy auth and independent keys remain
preserved. No renewed permission is required for the explicitly authorized
release. Record exact versions, images, recovery proof and public smoke evidence.

Execution order: fresh encrypted consistent backup and isolated restore; durable
keys/CA/scoped roles; validated service and private TLS backhaul images; safe CI
and package release; private service rollout; edge/DNS; ChatGPT linking and public
three-tool/revocation/legacy acceptance. Compatibility-mode Mongo TLS preserves
older consumers until their own TLS migration; auth requires verified TLS.

- [ ] X001: Fresh encrypted shared backup, independent escrow and isolated restore proof.
- [ ] X002: Mongo TLS certificates, staged compatible server mode and scoped auth/provision/backup principals.
- [ ] X003: Persistent OAuth keys, exact ChatGPT client, encrypted private backhaul and private-only bindings.
- [ ] X004: Validated versioned images; gated CI/publication and reviewed commits.
- [ ] X005: Activate services/edge/DNS; public SDK tools, revocation, legacy and rollback acceptance.
- [ ] X006: Link private ChatGPT connection and record remaining account-specific constraints.
