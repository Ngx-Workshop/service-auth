# Auth deployment source inventory
2026-10-12 · Checkout evidence only; live state unverified.

Historical source inventory below predates readiness implementation. Current live
evidence and release blockers: [preflight](../../docs/deployment-preflight-2026-10-12.md).

| Source | Finding / future gap |
| --- | --- |
| .github/workflows/deploy.yml | main and manual trigger, publish auth-client via NPM OIDC then SSH/SCP source deployment as root; private .env.next/cleanup and pinned host fingerprint/actions; no test/protected approval/automatic application rollback gate |
| Workflow URI validation | Forces mongodb://10.116.0.2:27017/workshop-viewer, shared username workshop/authSource; does not require replicaSet=rs0 or auth-specific runtime role |
| Dockerfile | Node 22 Alpine, full install/build, dist/src/main.js, 3000; secrets not mounted; no non-root user/runtime-only stage or digest pin |
| .dockerignore | Excludes env/npmrc but not ignored .oauth-local private config; exclude it before manual Docker builds |
| docker-compose.yml (filename with trailing space) | Existing ngx-auth-service/port3000/ngx-net; workflow separately uses docker run |
| src/oauth/config.mjs/bootstrap/provider | Production rejected, loopback issuer/resource/DB, issuer port compared with PORT; local binding; Host exact issuer; durable 0600 keys already required |
| src/oauth/grants.mjs/interactions.mjs | Session.get secure:false; CSRF exact Origin; socket-address throttling can't distinguish clients behind edge without trusted proxy work |
| src/iam/authentication/authentication.controller.ts | accessToken uses existing DOMAIN, production Secure, HttpOnly/SameSite; preserve browser contract and verify deployed domain separately |
| src/oauth/mongo-adapter.mjs/provider | Auth-owned encrypted/hash-only storage, majority issuance transactions and CAS/replay protections; runtime collMod/createIndexes currently need provisioning split for least privilege |

External inventory needed for coordinated release (facts replicated here for
standalone planning, no sibling runtime dependency): nginx-ngx-workshop.io maps
existing auth.ngx-workshop.io SPA plus /api/auth to 10.116.0.4:3000 and uses mounted
Let's Encrypt certificates. Dedicated proposed MCP hostname can route native /mcp
to existing port3011. Current /api/mcp-gateway rewrite doesn't match native path.
Gateway uses local 0.0.22-local.0 auth-client tarball; vendor must be copied before
Docker npm ci. Both workflows independently deploy on main; CLI dispatch template
is not installed behavior to assume.

service-uploader docs/deployment-2026-10-04.md records MongoDB8.0.17 authenticated
single-member rs0 at10.116.0.2:27017, retained users/shared data and keyfile, with no
failover and a dated stopped-db backup. Reverify live; don't rerun initialization,
restore the old shared archive or assume TLS/backup scheduling exists. Current
OAuth [local evidence](../003-oauth-integration/handoff.md) proves transactions
and key persistence only on owned test replica sets.

Primary references reviewed 2026-10-12:
[oidc-provider9.12.2](https://github.com/panva/node-oidc-provider/blob/v9.12.2/docs/README.md),
[Nginx proxy](https://nginx.org/en/docs/http/ngx_http_proxy_module.html),
[GitHub environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[Mongo8 transactions](https://www.mongodb.com/docs/v8.0/core/transactions-production-consideration/).
No installed cloud secrets, private .env values, SSH/database contents or live certs
were read. Source baseline f09e24655f4df07e07b3d722a578732da5bb8351 contains earlier
code; authorized uncommitted OAuth implementation was inspected and preserved.
