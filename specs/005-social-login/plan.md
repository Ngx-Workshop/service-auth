# Implementation plan

1. Add optional password and sparse unique multikey `externalIdentities` to auth
   users. One provider-qualified subject maps to one UUID. Keep unique email.
2. Add native ESM social middleware after cookie/body parsers using jose for JWT
   verification and Apple ES256 client secrets. Use fixed provider endpoints and
   callbacks; Mongo stores hashed state/browser binding plus nonce/verifier for ten
   minutes and consumes a callback atomically.
3. Reuse AuthenticationService token generation and idempotent metadata upsert.
   Retry metadata creation on returning sign-in after service outages; do not
   overwrite roles or existing profile values. Metadata failure remains nonblocking,
   matching existing sign-up behavior.
4. Angular discovers configured providers through same-origin /api/auth/social.
   Preserve requested destination between login/sign-up pages. Nest sees /social
   after the existing ingress rewrite. Add auth-only ingress with no access logs,
   request limits and body limits. No new DNS/subdomain is needed.
5. Metadata and admin MFE contracts stay compatible. No provider secrets, tokens,
   or claims are added to metadata contracts or editable profile forms.

No environment secret is written or production account mutated. Deployment requires
indexes, provider-console configuration and HTTPS verification described in the guide.


Current release wiring: Google/GitHub organization secrets enter a separate protected
server env file via trusted deployment, not through the image or frontend. Apple
CLIENT_ID is explicitly empty. A separate database-host operator migration grants
only the additional social collection privileges and provisions indexes; production
startup validates this prerequisite without schema-write privileges.
