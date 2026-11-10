# Google, Apple and GitHub website login

Implemented for https://auth.ngx-workshop.io, using the existing /api/auth/ ingress
rewrite to service-auth. Current rollout enables Google and GitHub only; Apple is
deferred until the primary app registration exists. The browser never receives
client secrets or provider tokens.

## Provider registrations

| Provider | Register this exact callback | Server environment |
| --- | --- | --- |
| Google web OAuth client | https://auth.ngx-workshop.io/api/auth/social/google/callback | SOCIAL_GOOGLE_CLIENT_ID, SOCIAL_GOOGLE_CLIENT_SECRET |
| Apple Services ID | https://auth.ngx-workshop.io/api/auth/social/apple/callback | SOCIAL_APPLE_CLIENT_ID, SOCIAL_APPLE_TEAM_ID, SOCIAL_APPLE_KEY_ID, SOCIAL_APPLE_PRIVATE_KEY |
| GitHub OAuth app | https://auth.ngx-workshop.io/api/auth/social/github/callback | SOCIAL_GITHUB_CLIENT_ID, SOCIAL_GITHUB_CLIENT_SECRET |

Google: configure consent branding/audience and publish or register test users as
appropriate. Request only openid/email. If the console asks for an origin, use
https://auth.ngx-workshop.io.

Apple: enable Sign in with Apple on the primary App ID, associate the web Services
ID with it, register auth.ngx-workshop.io and the HTTPS return URL, and create a
Sign in with Apple key. This requires an Apple Developer account and associated
primary app configuration. The client ID is the Services ID, not the Team ID.
The private key is PKCS#8 PEM; literal backslash-n sequences are accepted. The server
signs a fresh five-minute client secret with ES256; no expiring static Apple secret
needs to be manually renewed. Apple replies through form_post; the secure host-only
transaction cookie uses SameSite=None. Relay emails are valid; do not try to merge
by a person's ordinary email. Configure Apple's email relay senders separately if
sending mail to relay addresses.

GitHub: homepage https://auth.ngx-workshop.io; read:user/user:email scopes support
private primary verified email. Repository access is not requested.

Unset CLIENT_ID disables that provider. A configured ID without its required
credentials prevents startup. Pass secrets through the deployment secret mechanism;
Compose uses its env_file for manual deployments. The production Actions workflow
uses the protected runtime configuration described below. Do not commit them. The UI
queries GET /api/auth/social/providers and displays configured providers only.

## Data and deployment order

1. Back up the auth database. Check for duplicate externalIdentities before creating
   a sparse unique index on users.externalIdentities. Existing accounts omit this
   field. Keep the unique email index. New accounts have no password and role regular.
   Do not disable database validation or run destructive syncIndexes migrations.
2. Run scripts/production/provision-social-login.py on the MongoDB host as the
   existing database operator, before deploying enabled providers. It adds the
   social_login_transactions TTL index, unique sparse users.externalIdentities
   index, and collection-scoped runtime/provisioner privileges. It preserves user
   records and existing grants/indexes. Production startup validates indexes; it
   does not create them using the restricted runtime identity. Expiry is also
   checked at consumption, independent of delayed TTL cleanup.
3. Supply provider credentials; ensure DOMAIN=ngx-workshop.io, the existing JWT
   issuer/audience/secret match consuming services and USER_METADATA_URL is correct.
4. Deploy service-auth and the nginx /api/auth/social/ location (auth host only,
   access logs off, 16k bodies, 30 requests/minute per IP with burst 10, 429 on limit).
   Validate nginx configuration before reload. Apple POST bodies must be forwarded.
5. Deploy app-authentication. Confirm the provider discovery response, then sign up
   and sign in with disposable real provider accounts. Check first and repeated
   login, cancellation, allowed return destinations, cookie availability in beta/admin,
   and profile visibility/role changes in the admin user-management page.

Do not log callback query strings or POST bodies at other ingress layers or APM.
No provider access/refresh token is stored. Transaction state lives for ten minutes;
starting again with the same provider in the same browser replaces its binding.

Account creation/upsert may succeed before a metadata outage. Each later provider
login retries metadata upsert using the same UUID. For Google or GitHub, a verified email matching an existing password account opens
a password confirmation page. The browser-bound confirmation expires after five
minutes and can be submitted once. Successful confirmation connects the provider
to the existing account and signs in with its current UUID and role. Conflicts with
a provider-only account still require the original provider. Deleting a
metadata record in admin continues to leave the auth identity intact.

The metadata service and admin remote require no new runtime DTOs or dependencies.
The separate catalog OAuth server-rendered password interaction remains unchanged.
To roll back, disable provider IDs and redeploy the auth UI/service; preserve accounts
and identities so provider-only users can return after re-enabling providers.

## Local checks

- service-auth: npm run build; npm test -- --runInBand social-login admin-provisioning;
  npm run test:social.
- app-authentication: npm run build; npm test -- --watch=false
  --browsers=ChromeHeadless --include=src/app/social-login.spec.ts.
- service-user-metadata: npm test -- --runInBand.

These checks use local test doubles. Real provider callbacks use the fixed HTTPS
production domain; localhost HTTP is deliberately not presented as a valid Apple test.

## Provider references

- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Apple web configuration](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/)
- [Apple REST API](https://developer.apple.com/documentation/signinwithapplerestapi)
- [GitHub web authorization](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)


## Current production release through GitHub Actions

The organization secrets must be named exactly:

- SOCIAL_GOOGLE_CLIENT_ID
- SOCIAL_GOOGLE_CLIENT_SECRET
- SOCIAL_GITHUB_CLIENT_ID
- SOCIAL_GITHUB_CLIENT_SECRET

In organization Settings → Secrets and variables → Actions, grant service-auth
repository access to all four. The auth frontend and nginx repositories do not need
these provider secrets. Names/access could not be verified from this local session:
the connected GitHub credential cannot list organization secrets (HTTP 403).

On trusted pushes to service-auth/main, the prepared deployment workflow stages the
four values privately after candidate validation, transfers them through the pinned
SSH connection, and installs /etc/ngx-workshop/oauth/auth/social.env with mode 0600.
The existing promotion helper loads runtime.env followed by social.env. Existing
JWT/database configuration is preserved; Docker env-file parsing preserves literal
secret characters without shell evaluation. The extra file explicitly sets
SOCIAL_APPLE_CLIENT_ID empty, so Apple stays disabled even if runtime.env contained
an old value. Credentials are excluded from uploaded candidate artifacts and images;
the transfer file is cleaned after installation. If transfer/promotion is interrupted
before remote cleanup, remove any remaining social-credentials.json in that release
directory as the server operator.

Release order:

1. Confirm the four organization secrets allow service-auth access.
2. Back up the auth database and run the explicit migration on its MongoDB host:
   `python3 provision-social-login.py` using the script from this checkout.
3. Release service-auth; main pushes run validation and deployment automatically.
   workflow_dispatch currently validates/publishes only; it does not deploy auth.
4. Release nginx-ngx-workshop.io's social route and app-authentication's buttons.
5. GET https://auth.ngx-workshop.io/api/auth/social/providers must return
   ["google","github"]. Test new and returning accounts, cancellation, metadata,
   allowed redirects and assigned-role retention. Verify password confirmation for
   a matching existing account and provider-only conflict handling.

Google/GitHub production rollout completed on 2026-11-09. The database migration
and all three delivery workflows succeeded. Public provider discovery, cancellation,
redirect restrictions and browser entry into both provider login pages were verified.
A complete provider-account sign-in and new/returning profile acceptance still need
a real user session; no personal provider credentials were entered for deployment.
See specs/005-social-login/handoff.md for exact release revisions and evidence.
