# Feature: Code Maintenance

Status: Implemented and verified locally; external acceptance pending
Feature ID: 006-code-maintenance · Selected: 2026-11-22
Repository: service-auth

## Problem and audience

The service needs a deliberate maintainability pass that future maintainers can
verify without changing consumer behavior. The setup audit found native structured
HTTP logs and Prettier already present, but no Husky/lint-staged integration. It
did not certify architecture quality or domain-event coverage.

## Requirements

- **FR-001 — Baseline and scope.** Audit module/provider dependency flow,
  controllers, use cases, persistence, external adapters, validation, configuration,
  error handling and tests. Record concrete findings with paths and priorities
  before edits; implement justified improvements, not a blanket rewrite.
- **FR-002 — NestJS design.** Group cohesive domain behavior in feature modules.
  Controllers handle routing, validation/transport metadata and delegation; business
  decisions and persistence belong in cohesive services/providers. Use explicit
  imports and minimal exports, constructor DI and acyclic dependencies. Avoid
  duplicate provider registrations, service locators, accidental global modules,
  unnecessary `forwardRef`, god services and speculative abstraction layers.
- **FR-003 — Compatibility.** Preserve routes, response/error shapes, DTO behavior,
  authorization, persisted schemas, upstream protocols and failure/concurrency
  semantics. Add regression coverage before moving logic. Record consequential
  changes separately; regenerate owned OpenAPI/contracts if definitions change.
- **FR-004 — Formatting.** Keep the existing Prettier style. Add Husky plus
  lint-staged for supported staged files only, preserve partial staging, update
  manifest/lockfile and use a guarded prepare lifecycle. Add non-mutating
  `format:check` and `lint:check` scripts/gates where missing. Exclude generated
  contracts, build/coverage output and vendored assets explicitly. Verify clean
  CI/Docker installs, including no `.git` and devDependencies omitted. Do not run a
  repository-wide formatting rewrite as an incidental architecture change.
- **FR-005 — Domain observability.** Reuse `src/observability/observability.ts` and
  native NestJS contextual `Logger` calls with structured objects, compatible with
  the installed version. Add bounded stable event names, outcome, duration and
  safe operation/correlation IDs for meaningful use-case and upstream boundaries.
  Existing request middleware generates an ID but does not by itself establish
  async domain context or cross-service tracing; implement/test propagation where
  useful, validate any incoming ID, and document limits. Preserve JSON output,
  existing collector field structure, log levels, health exclusions and HTTP logs.
  Avoid duplicate errors, per-item noise and misleading trace claims. Never log
  secrets, cookies, tokens, bodies, queries, private content or raw upstream errors.
  No Grafana credentials/SDK or direct ingestion belongs in application code.
- **FR-006 — Evidence and handoff.** Run meaningful regressions, build,
  non-mutating lint and formatting checks; document baseline failures and blocked
  checks honestly. Update architecture/development/observability docs and handoff.

## Service-specific scope

Owner: Authentication, IAM and OAuth. Keep IAM, OAuth protocol handling and exported auth-client boundaries explicit. Preserve cookies, redirects, issuer/audience, token validation, recovery and local-profile restrictions. Never log tokens, passwords, authorization codes, cookies or OAuth query strings.

## Acceptance scenarios

- **AC-001:** A maintainer can explain module ownership and provider dependencies
  from a source-backed audit; justified refactors leave controllers thin and
  preserve observable success, invalid input, authorization and failure behavior.
- **AC-002:** Committing a deliberately misformatted staged supported file formats
  it. Unstaged changes, including a partially staged file, remain intact. Hook
  failures block commit. CI rejects a formatting violation without modifying files.
- **AC-003:** Clean developer installation enables hooks; CI, a Docker-style
  package-only/no-Git install and production installation without devDependencies
  do not fail because of hook setup. Record actual commands and results.
- **AC-004:** Representative successful and failed operations emit parseable
  structured events with correct level/context and useful safe correlation.
  Canary secrets/content are absent, concurrent requests do not share context,
  health polls stay quiet and HTTP logging remains covered by regression tests.
- **AC-005:** Required local checks pass or documented pre-existing failures and
  unavailable prerequisites are clearly separated. Handoff distinguishes local
  JSON/collector compatibility from actual live Grafana receipt.

## Non-goals and constraints

No unrelated feature completion, framework/runtime upgrades, forced RxJS/Promise
migration, blanket clean-architecture rewrite, data migration, publication or
deployment. Work within this checkout. External systems use doubles/disposable
fixtures for tests. A live Grafana check is recorded as pending when unavailable;
it must not be represented as completed local verification.
