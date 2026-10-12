# OAuth integration

Complete the authorized local integration without deployment. Add optional explicit
CIMD registry: exact HTTPS metadata URLs and approved redirect lists. Fetch with
3-second total deadline, 64-KiB cap, valid TLS, pinned public DNS address, rejection
of every private/reserved IPv4/IPv6 answer, no redirects/proxies. Bind identity,
name, redirect/grant/auth metadata to approved policy, revalidate on cached reads.
Browser interaction UI must accept approved metadata clients and preserve CSRF.

Add independent typed introspection client/principal/errors to ngx-auth-client;
legacy exports unchanged. Explicit endpoint/issuer/resource/Basic credentials,
bounded body/deadline, strict active response validation, no JWT decoding/cookies,
redirects or cached authorization. Pin a locally packed additive package in the
gateway without publishing or requiring sibling sources for normal runtime.

Gateway defaults to OAuth; local-public mode must be explicit. Protect every MCP
method before parsing with SDK verification, exact audience/expiry/scopes, public
path-aware discovery and limited preflight. Reject query/cookie-only/duplicate
credentials. Verify real login/consent and both MCP protocol clients against all
three tools and live document/lab services, then immediate token/grant revocation.
