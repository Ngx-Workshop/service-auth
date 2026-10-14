# AI Publisher browser client — production registration

User authorized registration and deployment on 2026-10-12. The production private OAuth registry now adds:

- Client ID: `ngx-workshop-ai-publisher-prod`
- Name: `Ngx Workshop AI Publisher`
- Exact callback: `https://admin.ngx-workshop.io/ai-publisher/console`
- Public authorization-code client; authentication method none, required S256 PKCE, catalog:read, exact resource `https://mcp.ngx-workshop.io/mcp`.
- Access-token lifetime at most 600 seconds; no refresh token, browser client secret or dynamic registration.

`ALLOWED_ORIGINS=https://chatgpt.com,https://admin.ngx-workshop.io` in the auth and gateway production runtime profiles. Existing oidc-provider registered-client CORS permits admin token redemption; consent CSP derives the registered callback origin. Unapproved origin token requests have no allow-origin header. Admin MCP OPTIONS returns 204 with the exact origin; unapproved MCP OPTIONS returns 403.

No source/engine or persistent key changes. Auth image remains `service-auth:c4c0a6b6d266`, gateway remains `service-mcp-gateway:9e6630a2e6e0`. Both recreated through the validated promotion operator using the existing immutable candidates. Existing cookie/JWKS/storage/introspection credentials and original public client records compared equal to the rollback configuration.

Previous private configuration: `/opt/ngx-releases/publisher-oauth-config-20261013T004332Z` on the application host; old containers retained by the promotion operator. Roll back configuration and matching container together; never restore the shared Mongo database for application rollback. Updated encrypted application escrow verified at `ops-recovery/ngx-oauth/20261013T004509Z/application-secrets.tar.gz.gpg` in the dedicated private recovery bucket. Credential denied access to the asset bucket, encrypted object checksum/size verified and anonymous access denied.

Consumer implementation and browser acceptance belong to `mfe-user-journey-admin-ai-publisher/specs/003-console-oauth/handoff.md`. That frontend consumes published MCP contracts and the SDK. Confidential introspection continues through @tmdjr/ngx-auth-client on the gateway; do not bundle that Nest client or its credential into Angular.

## Callback registration update — 2026-10-13

The user reported invalid_redirect_uri after moving the console and authorized the callback update. The live public client ngx-workshop-ai-publisher-prod now also approves the exact https://admin.ngx-workshop.io/mcp-gateway/overview redirect. Retained /ai-publisher/console for rollout compatibility. No other client records, keys, origins, scopes, resource configuration or image changed. The private config was backed up under /opt/ngx-releases/mcp-overview-callback-20261014T001405Z; mounted inode/UID1000/mode0600 preserved. Production loadConfig validation passed, then the existing ngx-auth-service container was restarted and readiness passed.

Live authorization checks after restart: new overview and previous console callback each redirect to the auth sign-in interaction; an unregistered /mcp-gateway/unregistered callback still returns 400 invalid_redirect_uri. This verifies registration acceptance without completing a user sign-in or issuing a token. Encrypted recovery escrow refreshed through the existing application backup operator: ops-recovery/ngx-oauth/20261014T001427Z/application-secrets.tar.gz.gpg; private upload checksum/size and anonymous-access rejection verified.
