# Production-readiness handoff
Status: Services deployed/packages published; ChatGPT three-tool acceptance passed · 2026-10-12

Current evidence and exact remaining action: [production launch](../../docs/production-execution-2026-10-12.md). Historical phase notes below are retained for audit.
[Spec](spec.md) · [Plan](plan.md) · [Tasks](tasks.md) · [Inventory](research.md)

The authorized readiness portion is implemented: explicit production HTTPS/proxy
profiles, persistent read-only secrets, authenticated TLS MongoDB validation in
auth, corrected non-root Docker images and validation-only CI. Local profiles and
legacy authentication remain supported. See the [configuration and verification
runbook](../../docs/production-readiness.md) for exact evidence and limitations.

The [live preflight](../../docs/deployment-preflight-2026-10-12.md) verified the
three hosts, auth certificate, real rs0 access and both historical backup copies.
Release is blocked: MCP DNS/native routes/proxy/backhaul, publicly reachable app
ports, missing OAuth registrations/keys/mounts, Mongo TLS/scoped role/schema,
current encrypted backup/restore proof and remote CI protection need remediation.
Local safe CI replacements are not yet installed on GitHub main. Secret values
were withheld; no running service or infrastructure was changed.

Remaining release work: confirm actual clients/callbacks and live infrastructure;
provision private keys, scoped MongoDB credentials/schema and validated TLS;
configure edge headers/routes, firewall and verified backhaul; prove encrypted
backup/restore and key rotation; obtain separate rollout authorization; then run
public client/legacy/revocation acceptance with compatible image/config rollback.
Do not regenerate production keys or restore the shared database for app rollback.

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

## 2026-11-07 runtime audit repair

The user reported auth deployment run 42405150604 failed. Its validate job stopped
at npm audit --omit=dev --audit-level=high, before tests/build/promotion. Production
remained on service-auth:f1edcbbaf373. The compatible lockfile refresh and narrow
platform-express multer override are documented in ADR 0009. Clean runtime audit
now has zero findings; all 80 OAuth/application/production/client tests, strict
service/client builds and required lint checks passed locally on Node 22.23.3.
Proceed with normal main validation/deployment; no package publication is required.

Production follow-through: fix commit 2afa6a3f9bf85821177dee6401eb4e3fa2399995
passed validation and deployment in
https://github.com/Ngx-Workshop/service-auth/actions/runs/42405890442.
Running image service-auth:2afa6a3f9bf8 has the exact revision label and is running.
Public authorization-server metadata and JWKS return 200 with the canonical issuer.
Public signing-key fingerprint matches the predeployment baseline, confirming the
existing signing keys were preserved. No client package publication was requested
or performed. Postdeployment evidence is kept local to avoid another docs-only rollout.
