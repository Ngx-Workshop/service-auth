# @tmdjr/ngx-auth-client

Legacy Nest cookie/JWT guards, decorators and DTO exports remain available.
The additive local version `0.0.22-local.0` introduces `OAuthIntrospectionClient`,
`OAuthPrincipal` and `OAuthVerificationError` without an MCP dependency.

Construct with explicit `issuer`, `introspectionUrl` (same issuer origin,
`/oauth/introspect`), `resource`, `clientId` and `clientSecret`. HTTPS is required;
`allowLocalHttp: true` permits loopback HTTP for local tests. Issuer/resource URLs
are canonical without trailing slash, credentials, query or fragment. The issuer
is an origin. Credentials authenticate the resource server, not an end user.

`verifyAccessToken(token)` returns an immutable principal after native HTTP
introspection and strict active/Bearer/issuer/audience/subject/client/scope/expiry
validation. It accepts the auth owner's 256-bit opaque access-token profile,
never decodes JWTs, forwards cookies, retries redirects or caches authorization.
Defaults: 3-second total deadline and 64-KiB streamed response cap. Options
`timeoutMs` and `maxResponseBytes` may lower limits (timeout maximum 10 seconds).
Errors carry sanitized categories `invalid_token`, `auth_unavailable`, or
`invalid_auth_response`; callers enforce required scopes separately.

Build from service-auth with `npm run build:ngx-auth-client`, then pack from
`dist/libs/ngx-auth-client`. The gateway consumes a checked-in local tarball;
this version has not been published. Never log raw tokens or introspection secrets.
