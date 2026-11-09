# Handoff

Implemented locally across service-auth and app-authentication, with auth-only nginx
social ingress. Metadata/admin compatibility is documented in those repositories;
no runtime contract changes are required there.

Evidence:

- service-auth build passed; complete Jest suite: 12 tests passed.
- New protocol/middleware suite: 8 tests passed, including signed Google/Apple test
  tokens, Apple client-secret signing, GitHub verified email, browser binding,
  expiration, replay, cancellation, conflicts and redirect restrictions.
- app-authentication production build passed with a 558.27 kB initial bundle versus
  the existing 500 kB warning budget. Focused ChromeHeadless social UI suite: 2 passed.
- service-user-metadata complete Jest suite: 56 passed.
- nginx -t passed against a temporary copy using disposable certificates and the
  local mime.types path. Production certificates, backhaul connectivity and browser
  cookies were not tested by that syntax check.
- Whitespace/diff checks passed in all changed repositories.

No deployment, provider registrations, hosted writes or actual provider sign-ins
were performed. New account creation/UUID behavior is unit-tested; real MongoDB
indexes and provider flows still require acceptance. No implicit email account
linking exists: email conflicts require the original sign-in method. The catalog
OAuth password interaction remains separate.

Next: follow docs/social-login.md to register the three callbacks, supply server
credentials and provision database indexes, then deploy auth+ingress+UI and complete
real new/returning provider login, metadata visibility and assigned-role acceptance.


## Google/GitHub-only deployment follow-up

Organization Actions secrets were reported configured by the user. Prepared the
auth deployment workflow to transfer those four secrets as protected server config,
load them after the persistent runtime env file, and explicitly disable Apple.
Added a database-host operator migration for social indexes and scoped privileges;
production now validates indexes instead of requiring runtime schema permissions.
Updated initial role provisioning to match the additive migration. Actual promotion
uses /etc/ngx-workshop/oauth/auth/runtime.env, not Compose's .env.

Validation: 4 credential transfer/install tests passed (private modes, literal
special characters, validation failure, source cleanup and existing-config retention),
8 protocol/schema tests and 12 account tests passed; auth build, focused lint, workflow
YAML parsing and production dependency audit passed (0 production vulnerabilities).
Full deployed migration, SSH credential delivery and live provider sign-in remain
unverified. Organization secret metadata lookup returned HTTP 403; no access scope
was changed. Confirm repository access and exact secret names before release.

Full OAuth/Mongo integration suite: 80/80 passed after restoring the existing
missing-account error response. Production OAuth lint and diff checks passed.
