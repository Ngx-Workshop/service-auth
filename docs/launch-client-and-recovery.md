# Initial client and recovery recommendations

> Current status: services deployed and packages published after user authorization.
> See [launch evidence](production-execution-2026-10-12.md). Earlier deferred/preflight
> statements below describe the historical phase; private ChatGPT linking is still open.

2026-10-12 · Preflight follow-up; no deployment or publication

## User-confirmed launch conditions

There is no production traffic and downtime is acceptable. Keep the existing
single-member rs0 for the initial launch; no high-availability expansion or
zero-downtime rollout is needed. Maintenance windows are acceptable, but this
clarification does not authorize a deployment, service interruption or data reset.
Remove the proposed four-hour recovery-time commitment. Measure a future restore
without treating elapsed time as an initial launch SLA. Existing shared records
and keys remain preserved; acceptable data loss has not been specified.

## Recommended initial client

Start with a private ChatGPT connection for the owner, exposing the same three
read-only tools. Use a preregistered public OAuth client and S256 PKCE. This fits
our existing static-client implementation and keeps initial registration small.
These are recommendations, not installed or user-approved registrations.

| Setting | Proposed value / source |
| --- | --- |
| Connection display name | Ngx Workshop |
| Auth client name | Ngx Workshop — ChatGPT |
| Static client ID | ngx-workshop-chatgpt-prod (chosen by us in service-auth and entered unchanged in ChatGPT) |
| User-client token authentication | none; no shared client secret for ChatGPT |
| Scope | catalog:read |
| Resource/server URL | https://mcp.ngx-workshop.io/mcp |
| Issuer | https://auth.ngx-workshop.io |
| Exact redirect | Copy from the specific ChatGPT MCP connection's management page before allowlisting |

The official [authentication guide](https://developers.openai.com/plugins/build/auth)
requires exact callback copying. It documents
`https://chatgpt.com/connector_platform_oauth_redirect` for eligible connections
whose authorization server meets RFC9207 issuer-identification requirements;
otherwise the callback includes a connection-specific identifier. Do not guess
that identifier or allow wildcard callbacks. Its stable CIMD identity is
`https://chatgpt.com/oauth/client.json` under the same eligibility conditions.

Our installed oidc-provider9.12.2 source advertises issuer identification and
adds iss to successful code responses. That is source evidence, not completed
ChatGPT acceptance. Before selecting the stable redirect, verify discovery,
matching protected-resource issuer and both success/error redirect iss behavior,
then compare the connection's displayed callback exactly.

OpenAI [custom MCP instructions](https://developers.openai.com/api/docs/guides/custom-mcp-server)
allow static credentials or CIMD. Use OAuth-only authentication for this service.
CIMD remains supported by our architecture but needs a live OpenAI document
compatibility check: current policy requires singular auth method none, exact
redirect set/name and catalog:read; OpenAI documents plural supported methods and
a legacy singular preference. A fixture pass does not establish compatibility.
Do not relax scope/redirect/SSRF checks to make an unchecked document pass.

We will help with the connection form when the endpoint is available. No public
listing/submission is needed for the initial private connection. Additional AI
clients and native loopback callback policy can be evaluated separately. No
ChatGPT connection, public registration or account-setting change was made here.

## Secret ownership recommendation

Production keys have not been found installed by preflight; the user does not
need to supply key material in chat. During later authorized provisioning, generate
independent production signing/cookie/storage keys and a resource-client secret,
then stage persistent files outside the checkout. Recommended host locations:

- Auth private JSON: /etc/ngx-workshop/oauth/auth/config.json.
- Gateway introspection secret: /etc/ngx-workshop/oauth/gateway/introspection.
- Verified public Mongo CA: /etc/ngx-workshop/oauth/auth/mongo-ca.pem.

Private directories0700 and files0600 must be owned by runtime UID1000 and mounted
read-only. Keep an encrypted, separately accessible recovery copy of OAuth rings,
config versions and Mongo replica keyfile. The gateway resource-client ID may be
ngx-workshop-gateway-prod; its secret is separate from the public ChatGPT client
and does not grant user/tool access. No keys were generated or staged by this note.

## Recovery recommendation

Before infrastructure changes, take a fresh consistent backup of the shared
database and matching configuration/keys, verify integrity, encrypt and keep an
independent recovery copy. Prove restoration in isolation; require fresh OAuth
authorization after restoring OAuth state so revoked grants cannot revive.

For continuing operation, recommend daily encrypted backups (up to24h between
recovery points), plus backups immediately before changes. This is a proposed
retention/cadence policy, not user approval to lose24h of data. The October4
archive is historical and lacks the replica keyfile; it does not satisfy this
new recovery baseline. Avoid promising RPO until scheduled backups and a restore
have been demonstrated. Availability is no longer a launch-policy blocker;
TLS, credentials, network isolation, recoverability and client acceptance remain.
