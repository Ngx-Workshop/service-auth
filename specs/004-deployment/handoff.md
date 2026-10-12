# Production-readiness handoff
Status: Readiness and live preflight audited; release blocked, deployment/publication deferred · 2026-10-12
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
