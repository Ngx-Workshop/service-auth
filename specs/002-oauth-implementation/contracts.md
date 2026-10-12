# Local OAuth HTTP contracts

| Method   | Path                                    | Contract                                                                                                                   |
| -------- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| GET      | /.well-known/oauth-authorization-server | Fixed issuer and engine-generated metadata; S256, authorization_code only                                                  |
| GET      | /.well-known/openid-configuration       | Engine metadata alias; openid scope and ID-token flows unavailable                                                         |
| GET      | /jwks                                   | Public signing keys only                                                                                                   |
| GET      | /oauth/authorize                        | Registered client/redirect, response_type=code, scope=catalog:read, exact resource, S256 challenge; use state              |
| GET/POST | /oauth/interaction/:uid                 | Signed engine interaction cookie; POST additionally requires Origin=issuer and single-use form CSRF                        |
| POST     | /oauth/token                            | URL-encoded code, client_id, exact redirect_uri/resource, code_verifier, grant_type=authorization_code; no scope parameter |
| POST     | /oauth/introspect                       | Resource-server Basic credentials and token; active principal or active:false; structured JWT rejected 400                 |
| POST     | /oauth/revoke                           | Public client_id and owned token; empty idempotent 200; another client's token remains active                              |
| GET/POST | /oauth/grants                           | Signed OAuth session; account-bound CSRF and same-origin POST; immediate grant revocation                                  |

Successful token response contains opaque access_token, token_type=Bearer,
expires_in=600 and scope=catalog:read; no refresh_token or id_token. An active
introspection response includes active, iss, sub (existing account ID), client_id,
aud (exact MCP resource), scope, token_type, iat, exp. Invalid resource/PKCE/code/
redirect/scope requests return OAuth errors; storage failures release no token.
Commit/storage failure is temporarily_unavailable (503); conflict/replay is
invalid_grant (400). Discovery does not advertise dynamic registration or CIMD.

Legacy REST request, response and cookie contracts are unchanged. OAuth tokens
never validate through legacy cookie endpoints, and legacy JWTs never become
OAuth credentials. Legacy sign-out does not revoke OAuth grants.
