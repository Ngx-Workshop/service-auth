# Authorized production execution — 2026-10-12

The user authorized deployment and publication after resolving preflight gates.
Initial launch is a private ChatGPT connection, public PKCE client
`ngx-workshop-chatgpt-prod`, exact callback
`https://chatgpt.com/connector_platform_oauth_redirect`, resource
`https://mcp.ngx-workshop.io/mcp`, scope `catalog:read`. No wildcard redirects,
DCR, refresh tokens, or public directory submission.

## Verified recovery and database preparation

Encrypted stopped-database physical baseline: 20261012T212935Z,
183,468,726 ciphertext bytes, checksum retained on DB host. Includes shared
Mongo data, configuration and replica-set key. Independent workstation escrow
outside Git includes ciphertext and separate owner-only decryption material.
Isolated physical restore preserved 21 users and completed in 4.61 seconds.
No live database restoration occurred.

Verified private-CA TLS is active on MongoDB in preferTLS migration mode;
legacy services continue to work. New auth requires verified TLS. Separate
collection-scoped runtime/provisioner principals and backup-only principal exist.
Scoped provisioner successfully installed and validated exact OAuth schema/indexes.
Persistent production cookie, encryption, signing and introspection credentials
were generated once on the application host, never logged or committed.
Legacy JWT configuration was preserved in staged runtime configuration.

## Release behavior

Auth client 0.0.66 adds introspection; existing 0.0.65 public declarations match.
Manual OIDC publication depends on successful validation and committed version.
Pushes and PRs validate; there is no automatic production rollout.
Client builds disable incremental emission because a previously cached build
could otherwise skip files after the output directory was removed.

## Remaining execution gates

CI, encrypted backhaul, recovery scheduling/offsite escrow, public HTTPS rollout,
public OAuth/tool/revocation checks and ChatGPT account linking are pending.
