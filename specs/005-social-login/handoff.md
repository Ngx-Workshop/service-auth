# Google/GitHub production release — 2026-11-09

Status: Deployed; complete real-account sign-in acceptance pending. Apple is disabled
and deferred until the associated primary Apple app registration exists.

## Released components

| Component | Running source revision | Successful workflow |
| --- | --- | --- |
| service-auth | 585a21da13902ff74297cc4e58f1096f2c179e07 | [42723066871](https://github.com/Ngx-Workshop/service-auth/actions/runs/42723066871) |
| nginx-ngx-workshop.io | f722498233e2637168f25efe8c16821d918c87bb | [42723145170](https://github.com/Ngx-Workshop/nginx-ngx-workshop.io/actions/runs/42723145170) |
| app-authentication | 9c5076182bb1642416a2fe19913c322da1121d5b | [42723468962](https://github.com/Ngx-Workshop/app-authentication/actions/runs/42723468962) |

Metadata/admin runtime contracts remain unchanged. Compatibility documentation was
pushed as service-user-metadata 3d93d49 and admin user-management 5a3d88d. Those
changes are documentation-only; they did not trigger unrelated runtime deployment.
Subsequent auth documentation commits do not replace the running image revision.

## Database and credentials

The user explicitly authorized migration, push and deployment after confirming
organization secret access. The existing encrypted off-host recovery service ran
successfully immediately before migration (Result=success, ExecMainStatus=0).

scripts/production/provision-social-login.py ran successfully on the database host,
adding the unique sparse externalIdentities index, social transaction TTL index and
additive collection-scoped runtime/provisioner privileges. No user records, passwords,
JWT keys, OAuth signing keys or existing grants were migrated or reset.

The actual running restricted auth database principal verified both indexes and
inserted/consumed a temporary smoke transaction, which was removed by that check.
Production startup validates the indexes without requesting schema-write privileges.

The auth workflow installed Google/GitHub credentials into protected server-only
social.env (verified mode 0600, root owned), loaded after the persistent runtime env.
Runtime booleans confirmed both providers configured and Apple disabled. No secret
values were printed, committed, put in uploaded image artifacts or delivered to Angular.

## Verification

- Local auth build, 80 OAuth/Mongo integration tests, 12 account tests, 8 social
  protocol/schema tests and 4 credential transfer/install tests passed; OAuth lint,
  workflow YAML parsing and production dependency audit passed (zero findings).
- Auth UI production build and 2 focused ChromeHeadless tests passed. The existing
  500 kB warning budget reports a 558.27 kB initial bundle; it is not a build failure.
- Metadata's 56 tests passed during implementation.
- All three production delivery workflows succeeded. The running auth image label
  equals the release revision above. Live nginx configuration SHA256 equals the
  committed configuration; nginx -t passed on the server.
- Public GET /api/auth/social/providers returns exactly ["google","github"].
- Google/GitHub starts return HTTPS provider redirects with the registered callback,
  client ID, S256 challenge and secure HttpOnly host-only browser-binding cookie.
  Cancellation consumes state, issues no account cookie and returns to the login page.
- Apple start returns 404; beta-host provider API returns 404; an unapproved return
  destination is rejected. Existing OAuth discovery remains healthy (HTTP 200).
- The deployed login and sign-up pages render exactly Google/GitHub buttons. Native
  browser clicks reach Google's sign-in page for ngx-workshop.io and GitHub's sign-in
  page branded NGX Workshop. No provider passwords, consent or account creation were
  submitted by the deployment agent.

## Remaining acceptance and behavior

Use a real provider session to complete consent, new/returning account sign-in,
cross-subdomain cookie use, profile visibility and assigned-role retention. Existing
password accounts can connect Google or GitHub through a one-time password
confirmation. Provider-only accounts continue to use their original provider. Deleting metadata still leaves the auth
identity. The separate catalog OAuth server-rendered password interaction is unchanged.

Previous auth containers/images remain available through the existing promotion
rollback process. Preserve the additive indexes and identities on rollback. Disabling
provider IDs hides the corresponding buttons; do not reset production signing keys.
