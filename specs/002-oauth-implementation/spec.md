# Feature 002: Local OAuth authorization server

Implement oidc-provider 9.12.2 as opt-in middleware in the existing Nest service.
Existing cookie JWT routes, guards, roles, sign-out, and auth-client exports retain
existing behavior. Deployment and gateway bearer integration remain deferred.

Acceptance: existing Mongo-backed users authenticate using the shared password
verifier; explicit browser consent names the client, exact MCP resource, and
catalog:read; deny returns access_denied. Browser forms require single-use,
interaction-bound CSRF and same-origin POST, and expire after ten minutes.
Provider-signed cookies protect interactions. Login attempts are bounded.

Only authorization_code with S256 is available. Require an explicit registered
redirect URI and exact resource at authorization and redemption. Access tokens
are opaque, last 600 seconds, and introspection is limited to the configured
resource server with Basic credentials. Codes expire after 60 seconds. Public
clients can revoke their own tokens only. No refresh, password, client credentials,
OIDC ID-token, registration, or dynamic metadata-fetch endpoints in this increment.

Mongo storage uses hashed credentials, authenticated encryption with retained
key IDs, database-enforced expiry checks, TTL cleanup and indexes. Redemption is
atomic: code consumption and token insertion commit before response. Concurrent
redemption has one winner; replay revokes its grant. Unknown commit outcomes retry
only commit, never the request. Startup rejects standalone Mongo and missing or
invalid keys. Secrets must not be logged or checked in.

OAuth configuration requires deliberate local enablement, fixed loopback issuer
and resource, and an isolated local replica set. Production enablement is rejected.
Tests use their own temporary replica set and real application accounts.
