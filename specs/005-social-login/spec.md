# Social sign-up and sign-in

Status: Google/GitHub deployed 2026-11-09; Apple deferred by the user.
Complete real-account acceptance remains pending.

The authentication page at https://auth.ngx-workshop.io must let users create an
account and return to it through Google, Apple, or GitHub.

- FR-001: Both login and sign-up offer each configured provider. First successful
  authentication creates a passwordless regular account; later logins reuse its UUID.
- FR-002: Validate provider credentials server-side. Bind expiring, single-use
  authorization state to a host-only browser cookie; validate OIDC nonce and JWT
  signatures/issuer/audience/expiry. Google/GitHub use S256 PKCE. Apple uses form POST.
- FR-003: Require verified email, including private GitHub email and Apple relay email.
  Identify accounts by provider subject, never by mutable usernames or matching emails.
- FR-004: Preserve metadata and admin role management by retaining local UUIDs and
  using the existing JWT and metadata upsert. Default new accounts to regular.
- FR-005: Fail closed on existing email conflicts. Explicit account linking is a
  follow-up, not automatic account merging. Passwordless accounts reject password login.
- FR-006: Redirect only to the exact auth, beta, and admin HTTPS origins. Never put
  session/provider tokens in URLs or retain provider access/refresh tokens.

Acceptance: new account, returning account, assigned role retention, email conflict,
private/relay email, denied consent, invalid/expired/replayed callbacks, wrong browser,
wrong nonce/audience/issuer/expiry, unapproved redirects, disabled providers, and
frontend availability failures are covered by local doubles. Real provider sessions,
real Mongo indexes, deployed ingress and cross-subdomain cookies require production
acceptance with registered credentials.

Scope: the Angular website's existing cookie login. The catalog OAuth engine's
separate server-rendered login/consent, provider linking/unlinking, connected-provider
admin UI, and provider account revocation/deletion are not changed by this feature.
