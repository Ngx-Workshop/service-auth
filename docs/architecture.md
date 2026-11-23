# Architecture — service-auth

Source inspected: `682a2f8` plus local maintenance changes on 2026-11-22.

## Ownership

Authentication, IAM and OAuth. Keep IAM, OAuth protocol handling and exported auth-client boundaries explicit. Preserve cookies, redirects, issuer/audience, token validation, recovery and local-profile restrictions. Never log tokens, passwords, authorization codes, cookies or OAuth query strings.

## Source map

- `src/app.module.ts`
- `src/bootstrap.ts`
- `src/iam`
- `src/local-admin-development.ts`
- `src/main.ts`
- `src/oauth`
- `src/observability`

`src/app.module.ts` is the application composition root. Inspect feature module
imports/providers/exports, controller decorators and persistence registrations
before proposing a refactor. Directory presence alone does not prove encapsulation.
`src/observability/` provides structured HTTP logging and heartbeat support;
[observability.md](observability.md) records the collector contract and limits.

## External boundaries

Use installed dependencies in `package.json` and actual source imports as the
baseline for HTTP clients, auth and persistence. Inspect source, DTOs and existing
specs for current access/error policy. `test/`, when present, contains integration
configuration; generated artifacts are outputs, not the contract source.

## Verified maintenance boundaries

The [maintenance audit](../specs/006-code-maintenance/audit.md) records the dependency
map, baseline failures and selected findings. AppModule composes configuration,
the root Mongo connection, IAM and operational liveness. IamModule intentionally
registers global authentication/role guards and exports only AuthenticationService
for bootstrap's OAuth/social adapters. Hashing, JWT/config, User persistence and
the new internal UserMetadataService are explicit providers; there is no circular
module flow or duplicate registration.

AuthenticationController retains routes, DTO/guard metadata and cookie transport.
AuthenticationService.register now owns the existing sign-up, password sign-in and
metadata sequence. UserMetadataService owns the metadata owner's HTTP upsert,
unchanged URL selection, 3-second timeout and best-effort warning behavior. It is
not exported and has no access to the metadata service's database.

The native ESM OAuth engine and separately built ngx-auth-client module remain
unchanged. No contract, claim, schema, social-linking policy, cookie, redirect,
recovery or local-admin access behavior changed. This is a bounded maintainability
audit, not certification of all existing code or a security audit.

Generated deployment orchestration is centrally managed by the Node CLI; see [deployment-workflows](deployment-workflows.md).
