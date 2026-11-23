# Constitution — service-auth

Version: 1.0.0 · Adopted: 2026-11-22

These principles guide future changes; adoption does not certify current code.

1. **Own the domain.** This repository owns authentication, iam and oauth. Keep other domains
   behind explicit owner APIs/contracts; never access another service's database.
2. **Use idiomatic NestJS boundaries.** Feature modules group cohesive behavior,
   explicitly import dependencies and export only their public providers.
   Controllers adapt transport and delegate business work. Services own use cases;
   persistence and external integrations stay behind cohesive providers. Prefer
   constructor injection; avoid service locators, accidental globals and circular
   dependencies. Do not create layers or interfaces without a concrete need.
3. **Preserve contracts and access.** Treat routes, DTOs, status/errors, identifiers,
   serialized data, auth and protocol behavior as contracts. Validate runtime input.
   Preserve access policy; no new bypasses. Regenerate owned contracts from source
   for approved API changes and document consumer impact.
4. **Keep operations predictable.** Preserve persistence, timeout, concurrency and
   failure semantics. Reuse native structured logging and existing observability.
   Log safe bounded events, never credentials or user content. Grafana credentials
   and ingestion belong to infrastructure, not this application's logger.
5. **Verify behavior.** Use meaningful regression tests for changed behavior and
   boundaries; mocks are not live integration. Run build, non-mutating lint and
   formatting checks. Record baseline failures, unavailable checks and residual risk.
6. **Keep context local.** Maintain architecture, development commands and feature
   spec/plan/tasks/handoff in this checkout. Do not require sibling repositories.
   Preserve unrelated changes. Update principles intentionally with version/date
   and rationale rather than using the constitution as a task log.

Domain constraint: Keep IAM, OAuth protocol handling and exported auth-client boundaries explicit. Preserve cookies, redirects, issuer/audience, token validation, recovery and local-profile restrictions. Never log tokens, passwords, authorization codes, cookies or OAuth query strings.
