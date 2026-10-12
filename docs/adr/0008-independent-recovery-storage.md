# ADR 0008: Separate encrypted recovery storage from asset uploading
Status: Accepted and implemented · 2026-10-12

## Decision

Use the existing DigitalOcean Spaces subscription with a separate private SFO3
bucket, ngx-workshop-oauth-recovery. Generate a dedicated limited-access key for
that bucket only; retain the uploader's independent asset-bucket key unchanged.
Operator credentials stay root-only, outside repositories and application mounts.
Encrypt backups before upload. Keep matching OAuth/JWT/backhaul and private-CA
escrow, with independently accessible workstation decryption material.

The daily backup uses the backup-only Mongo principal, verified TLS, a consistent
oplog archive and checksum/length checks. Anonymous downloads must return403.
Restore only into an isolated owned clone during verification; invalidate restored
OAuth state before reusing any recovered auth database. Application rollback must
never restore shared data or regenerate production keys.

## Evidence and consequences

The dedicated key was denied access to ngx-workshop-assets. Baseline, logical
archive, matching application secrets and CA escrow were uploaded privately.
Physical and logical isolated restoration preserved all21 original users; the
daily timer is enabled. See [launch evidence](../production-execution-2026-10-12.md).
Daily recovery points are demonstrated, not a strict RPO/RTO promise. Initial
single-node downtime is accepted. Monitor job failures, maintain leaf certificate
renewal and take additional pre-change backups. Historical encrypted bootstrap
copies in the asset bucket remain redundant; future backups use the separate key.
