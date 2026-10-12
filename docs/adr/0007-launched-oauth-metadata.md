# ADR 0007: Advertise only launch-supported OAuth capabilities

Status: Accepted · 2026-10-12

The launched static ChatGPT public client permits only catalog:read. oidc-provider
adds openid to its internal scopes even when the configured scope list excludes
it. Advertising that scope causes hosted clients to request identity access that
this launch does not provide (userinfo and ID-token identity are outside scope).

After the engine produces its discovery response, filter the public scope list
to catalog:read on both discovery paths. Limit the engine's client authentication
methods to none (public PKCE client) and client_secret_basic (trusted resource
server introspection). Preserve issuer binding, resource binding, PKCE and every
legacy JWT route. Do not enable OIDC identity, DCR or relax client policy to work
around hosted-client discovery errors.

Tests assert the exact public scopes and methods in local and production-profile
HTTP discovery. Public OAuth and SDK acceptance must pass after promotion.
