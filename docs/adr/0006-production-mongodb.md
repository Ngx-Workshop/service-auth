# ADR 0006: Reuse private rs0 with auth-scoped access and safe recovery
Status: Accepted and implemented in production; owner ChatGPT sign-in pending · 2026-10-12
Feature: [004 deployment](../../specs/004-deployment/spec.md)

## Context

Existing deployment docs record MongoDB8.0.17 on private10.116.0.2:27017,
authenticated single-member rs0 and existing workshop-viewer accounts. Auth current
workflow enforces shared workshop credentials, while OAuth runtime restricts DB
to loopback and performs collMod/createIndexes. Local OAuth tested transactional
majority issuance against its own replica set; no production topology proof yet.

## Proposed decision

Reuse the existing account database and initialized rs0, preserving users and all
other service data. No identity copy, second OAuth user store, rs.initiate, database
recreation or Mongo version/topology change as a gateway convenience. Explicit
replicaSet=rs0/authSource/current database with auth-specific collection privileges.
Gateway receives no DB credentials or access to OAuth collections.

Replace shared DB-wide workshop role for auth with enumerated privileges on
users and oauth_state/oauth_forms/oauth_revoked only. Controlled provisioning
principal creates indexes/validators; runtime validates them rather than obtaining
dbAdmin for collMod. Tests prove legacy CRUD and OAuth transaction operations work
and unrelated collections/admin operations are denied. Runtime verifies set name,
writable primary/transaction support and schema/key readiness before serving OAuth.
Maintain bounded read/selection/socket/commit timeouts, majority transaction
commit, hashed credentials and record-bound AES256-GCM; no request replay on
unknown commit and no unencrypted fallback.

Private network allowlist and authenticated Mongo are required. Verify current
TLS; stage server/client TLS with certificate validation for this service if
missing, coordinating other consumers rather than changing shared server mode
blindly. Stable private DNS is preferred, but don't reconfigure current replica
member addressing without that separate review; certificate SAN must match the
actual member identities. No invalid-certificate/hostname options. Current
split-horizon IP configuration remains historical inventory, not a template to
repeat. Capture operational TLS/topology facts before release.

Single member supports transactions, not failover or a redundant data copy.
Initial deployment may reuse it only after operator accepts outage/recovery
tolerance and confirms measured backup/restore targets; redundancy expansion
requires separate infrastructure scope. Proposed RPO24h/RTO4h are planning targets.

## Backup, restore and rollback

Schedule encrypted consistent backups with off-host retention and encrypted
matching keys/config escrow; identify accountable operator and run isolated
restore drills. Never assume a live file copy is consistent. Choose supported
Mongo backup tooling appropriate to current rs0, verify actual contents/checksums
and recovery time. The 2026-10-04 stopped shared-db archive is historical, not a
current auth recovery guarantee.

Application rollback restores compatible image/config only and preserves DB
writes/keys. Never rewind the whole shared DB for auth/MCP rollback. Database
incident restore is a separately authorized maintenance operation: close OAuth
issuance/introspection/MCP exposure, validate restored users in isolation, then
invalidate all restored OAuth sessions/codes/tokens/grants/forms/revocation state
before reopening. Old revoked tokens must not become active after a backup rewind;
require fresh login/consent. Preserve restored accounts and assess legacy session
impact separately; no wholesale user/other-service deletion. Recovering other
services in a full shared DB restore requires their owners, not just auth.

## Consequences

Reuse minimizes new operations while honestly retaining single-node downtime
risk. Production needs scoped privileges, migration/readiness changes and proof
of private transport/backup/key recovery; local tests don't satisfy those gates.
No Mongo/credential/backup operation is authorized or performed by this ADR.

References: [MongoDB8 transaction production considerations](https://www.mongodb.com/docs/v8.0/core/transactions-production-consideration/),
[MongoDB replica-set TLS](https://www.mongodb.com/docs/v8.3/core/tls/configure-client-tls-tutorial/).

## Implementation evidence

The readiness subset is implemented and verified locally; see
[production readiness](../production-readiness.md). CI now validates and retains
reviewable candidates only. Secret provisioning, live client registration, edge
configuration, backup/rotation proof and protected promotion remain future release
operations. No publishing or deployment occurred.

## Live preflight — 2026-10-12

[Audit evidence](../deployment-preflight-2026-10-12.md) verifies current hosts,
certificate, authenticated single-member rs0 and historical backup integrity.
Installed production configuration does not yet satisfy this decision; deployment
is blocked by the recorded infrastructure/client/secret/recovery/CI gaps. No
production change or publication occurred.

## Launch-policy clarification

The user accepts downtime because there is no production traffic. Retain the
single-member replica for launch; no strict recovery-time commitment or
zero-downtime deployment is required. Preserve data and keys and prove recovery.
Initial ChatGPT registration is a recommendation awaiting exact client callback
acceptance; see [client/recovery note](../launch-client-and-recovery.md).
Nothing was provisioned, deployed or published.

## Authorized launch evidence — 2026-10-12

Decision implemented in production after explicit user authorization. See [launch evidence](../production-execution-2026-10-12.md) for reviewed commits/images, persistent secrets, verified TLS/scoped storage, actual recovery/public acceptance and successful private plugin creation and pending owner account sign-in. Earlier no-deploy statements describe the historical phase.
