# Deployment preflight — 2026-10-12

> Current status: services deployed and packages published after user authorization.
> See [launch evidence](production-execution-2026-10-12.md). Earlier deferred/preflight
> statements below describe the historical phase; private ChatGPT linking is still open.


**Decision: NOT READY for production OAuth/MCP rollout.**
Live inspection performed approximately 19:57–20:04 UTC. This preflight is complete
as an audit; failed/unknown release gates remain open. Deployment and publication
were not performed.

## Verified live inventory

| Host | Public / private address | Verified state |
| --- | --- | --- |
| HTTPS edge | 167.172.154.106 / 10.116.0.3 | Running nginx container; configuration parses; ~60 GiB free |
| Application | 24.144.98.154 / 10.116.0.4 | ngx-net; running legacy auth and seed MCP containers; ~117 GiB free |
| MongoDB | 167.71.28.197 / 10.116.0.2 | mongod 8.0.17 active; authenticated writable single-member rs0; ~83 GiB free |

SSH used existing cached host keys with StrictHostKeyChecking and batch mode.
The VPC app/DB keys matched the cached public-host keys before connecting. No
new trust entry or credential was installed. Inspection used public DNS/TLS/GET,
SSH status/configuration commands, filtered container inspection, GitHub metadata,
authenticated MongoDB metadata and a read-only aborted transaction.

## Gate results

| ID | Gate | Result / evidence |
| --- | --- | --- |
| PF-001 | Public identity and TLS | PARTIAL: auth.ngx-workshop.io resolves to the edge and verified TLS1.3 succeeds. Certificate SAN covers *.ngx-workshop.io and ngx-workshop.io, valid Sep 28–Dec 27 2026. Certbot timer enabled; last service result success. mcp.ngx-workshop.io A query returns NXDOMAIN. Forced SNI/Host routing to the edge verifies the wildcard certificate but protected-resource discovery returns HTTP500. |
| PF-002 | Native routes / trusted proxy / backhaul | FAIL: auth OAuth/OpenID discovery returns HTTP200 text/html (the SPA), not metadata. Installed nginx lacks native OAuth/discovery/MCP routes and required X-Forwarded-Proto/X-Forwarded-For normalization. Upstreams use HTTP, not verified TLS. Existing /api/mcp-gateway rewrite remains incompatible with native /mcp. |
| PF-003 | Application isolation | FAIL: both containers run with default root user, writable root filesystem, no dropped capabilities, no secret mounts, and ports published on all IPv4/IPv6 interfaces. Workstation TCP checks reach public app ports3000 and3011. UFW is active but DOCKER-USER only returns; current UFW rules do not establish Docker-port isolation. |
| PF-004 | Existing catalog owners | PASS (connectivity only): native document /navigation/sections and coding-labs /published-labs return HTTP200 JSON on app ports3007/3009. Public edge routes return200 JSON too. Current deployed MCP GET /mcp returns404; the new three-tool binary is not installed. No tool flow or production bearer flow was claimed. |
| PF-005 | OAuth clients | UNVERIFIED / NOT INSTALLED: auth has no OAUTH_ENABLED/profile/config mount; no installed approved static/CIMD registry is available. No intended client IDs, CIMD URLs, exact callbacks or approved origins were supplied. Local fixtures are not production registrations. User input requested; no guessed ChatGPT callback or public DCR. |
| PF-006 | Persistent secrets | FAIL for OAuth: no OAuth private config, introspection secret or Mongo CA mount configured. Bounded depth3 searches of the two service checkouts, /etc and /root found no relevant staged private config names. This does not prove files cannot exist elsewhere. Existing service .env files and auth .env.previous are regular root-owned0600 files. Auth legacy JWT is present, at least32 bytes; issuer/audience/positive access TTL/DOMAIN present. Values were withheld and unchanged. Production OAuth JWKS/cookie/AES rings, resource-client secret matching/independence and key escrow remain unverified. |
| PF-007 | MongoDB topology / access | PARTIAL: authenticated hello reports writable rs0 with only10.116.0.2:27017. A snapshot transaction read succeeds and is aborted without record changes. DB binds127.0.0.1/10.116.0.2; UFW permits27017 only from app10.116.0.4. Public DB port is not reachable from this workstation. Single member has no failover. |
| PF-008 | MongoDB TLS / runtime role / schema | FAIL: mongod net config has no TLS; deployed auth URI omits tls and explicit replicaSet. Actual connection succeeds authenticated, using database-wide readWrite on workshop-viewer, including create/drop/index privileges across collections. No oauth_state/oauth_forms/oauth_revoked collections exist. Dedicated auth collection role, separate provisioner, verified CA/SAN and schema/index provisioning are absent from deployed configuration. |
| PF-009 | Backup integrity | PASS (historical archive only): both database and app copies of /var/backups/mongodb-pre-rs0-20261004T171930Z/mongodb-data.tar.gz pass sha256sum against their manifests and gzip integrity. Archive is59,502,501 bytes; directories root-owned0700. DB copy files are0644 inside that private directory. These are the documented stopped-db, pre-rs0 backups from October4; not a current recovery point. |
| PF-010 | Recovery readiness | NOT PROVEN: inspected host timers/cron directories/root crontab show no MongoDB backup scheduler. Archive is plain tar.gz and contains97 members under mongodb, without /etc/mongodb-keyfile or OAuth key/config files. No encryption/key escrow, off-host backup policy, measured isolated restore, restored-grant invalidation proof or confirmed RPO/RTO was available. Copies on app/DB are not evidence of independent offsite retention. Cloud-provider snapshots/backups and storage encryption could not be verified without cloud account access. |
| PF-011 | CI / promotion control | FAIL for installed remote workflow: GitHub main still has publish + deploy jobs in both repos. Auth main SHA f09e24655f4df07e07b3d722a578732da5bb8351; gateway main SHA9c1e0331505e1eebee29e373fe838ce768a9f31e. Both main branches report protected=false; neither repo has an environment. Local validation-only replacements are uncommitted and do not protect the currently installed remote workflows. No workflow was triggered. |
| PF-012 | GitHub secret inventory | PARTIAL: repository and repository-accessible organization secret names/timestamps were inspected. Existing JWT/Mongo/SSH settings are available by name, but new OAuth-specific settings are not listed. GitHub cannot return encrypted secret values, so presence is not validity proof. Global org secret/variable inventory returned403; narrower repository organization-secret listing succeeded. No scope expansion or secret edit. |

Installed auth image:
`sha256:44f2cd45cfb5c44f339d187f7782a181035a88d4e82dd26e250707a042656238`

Installed gateway image:
`sha256:a4cb3cc8ed3579b73238f191e489b771368f326bb6bbfca8cd870b52680a9a57`

Existing remote successful runs establish historical deployment only:
[auth36506473482](https://github.com/Ngx-Workshop/service-auth/actions/runs/36506473482),
[gateway38211719219](https://github.com/Ngx-Workshop/service-mcp-gateway/actions/runs/38211719219).
No application log, account record, password, token, private key, complete Mongo
URI or unfiltered container environment was included in the report.

## Required remediation before release

1. Confirm production client names, IDs/CIMD URLs, exact callbacks and origins,
   secret owner/staging location, RPO/RTO and acceptance of single-member downtime.
   Planning targets24h RPO /4h RTO remain unapproved assumptions.
2. Review and land validation-only CI replacements through a controlled change;
   establish protected release environment/branch controls or a documented manual
   equivalent before future promotion. Do not dispatch the old remote workflows.
3. Stage independent persistent OAuth rings/resource credentials and matching
   gateway secret, owned0600 by runtime UID1000, read-only mounts and encrypted
   escrow. Validate without exposing values or generating keys on startup.
4. Coordinate MongoDB TLS with all existing consumers; certificate identity must
   match actual replica-member names/IPs. Create scoped auth runtime and separate
   provisioner identities, then install/verify additive OAuth validator/indexes.
   Do not reset rs0, copy users or grant broad admin access to runtime.
5. Establish encrypted consistent current backups, independent retention and
   matching key/config escrow. Run a measured isolated restore and rotation drill,
   preserve accounts and invalidate all restored OAuth state before reopening.
   Integrity checks performed here are not a successful restore or RPO guarantee.
6. Prepare DNS/native edge routes, verified backhaul and exact normalized proxy
   policy, limits/no-cache controls, and private-only Docker bindings/firewall
   checks. Preserve auth SPA and legacy API routes. Recheck both IPv4/IPv6 reachability.
7. Obtain separate deployment authorization, then promote compatible image/config
   pairs in auth→private gateway→edge order and verify actual client/three tools,
   revocation, legacy auth and rollback. Infrastructure remediation or provisioning
   above has not been executed by this preflight.

## Scope and limits

No production configuration, DNS, firewall, client registration, secret, MongoDB
schema/role/data or service was changed. No restart, rs initialization, fresh backup,
archive transfer/extraction, restore, NPM publication, image push, commit/push or
workflow dispatch occurred. SSH/HTTP/database inspection creates ordinary access
logs and connection/session activity. Database atomic write issuance and live
backup restoration were not tested; prior isolated implementation tests remain
separate evidence in [production readiness](production-readiness.md).

## User clarification after the audit

The user confirmed no production traffic and acceptance of downtime. Retain
single-member rs0 for launch and remove the proposed four-hour RTO commitment.
No data-loss waiver, deployment or service interruption is authorized. Client
selection needs assistance; recommended first client is a private preregistered
ChatGPT public client, pending exact callback/issuer checks. See
[client and recovery recommendations](launch-client-and-recovery.md).
This resolves the launch availability-policy question, not the failed recovery
proof or infrastructure/client/secret gates above.
