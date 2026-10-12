# Implementation plan

Keep the provider's ESM boundary in packaged Nest assets, with a small typed
bootstrap seam. Install middleware before legacy body parsers and guards, only
for explicit OAuth routes. Reuse AuthenticationService for account lookup and
bcrypt verification; do not accept legacy JWTs as OAuth access tokens.

Supply persistent private JWKS, cookie signing keys and storage key ring from an
owner-only configuration file. Reuse the existing Mongoose connection while
requiring replica-set transactions when OAuth is enabled. Store provider state,
CSRF form records, and grant revocation tombstones in separate OAuth collections.

Validate real HTTP browser flows, database failures and legacy routes using an
isolated Nest application and Mongo replica set. Preserve the original engine
spike as regression evidence. Defer CIMD fetching, gateway resource middleware,
shared auth-client additions, HTTPS/proxy deployment and infrastructure changes.
