# Agent entry point — service-auth

This repository owns authentication, iam and oauth. Work from this checkout; sibling source is
not required.

Read [.specify/memory/constitution.md](.specify/memory/constitution.md),
[architecture](docs/architecture.md), [development](docs/development.md),
[workflow](.specify/README.md) and the [feature index](specs/README.md) before edits.

- Inspect source and git status; preserve unrelated work and historical specs.
- Keep feature spec, plan, tasks and handoff aligned; mark complete with evidence.
- Preserve public contracts and access policies. Generate contracts from source.
- Keep controllers thin, providers cohesive and module exports intentional.
- Use owner-service APIs; do not couple to another service's collections.
- Keep IAM, OAuth protocol handling and exported auth-client boundaries explicit. Preserve cookies, redirects, issuer/audience, token validation, recovery and local-profile restrictions. Never log tokens, passwords, authorization codes, cookies or OAuth query strings.
- Reuse existing structured logging; read [observability](docs/observability.md).
- Verify changed behavior and distinguish local tests from live integration.
- Resolve routine choices; ask only for consequential missing decisions.

This is a Spec Kit-inspired Markdown setup, not an installed Spec Kit CLI.

## Next task: Code Maintenance

The selected work is [Code Maintenance](specs/006-code-maintenance/spec.md)
(implemented and verified locally; external acceptance pending).
Read its [plan](specs/006-code-maintenance/plan.md), [tasks](specs/006-code-maintenance/tasks.md) and
[handoff](specs/006-code-maintenance/handoff.md). Review recorded evidence; retain older unfinished
feature records without treating them as the next task. The requested work covers
NestJS module/domain boundaries, thin controllers, cohesive services, Prettier
with Husky/lint-staged, CI checks and safe domain logging through existing
observability. T001–T010 are verified locally; pinned Linux image/hosted CI and live
Grafana receipt remain pending. Do not publish or deploy without authorization.

Current deployment policy: [deployment-workflows](docs/deployment-workflows.md). Automatic main delivery verifies/deploys; npm publication is manual only. This supersedes older automatic-publishing instructions.
