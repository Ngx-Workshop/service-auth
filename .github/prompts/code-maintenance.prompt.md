---
description: Implement the next Code Maintenance specification in this repository
agent: agent
---

Implement this repository's next **Code Maintenance** task.

Read AGENTS.md, .specify/memory/constitution.md, .specify/README.md,
docs/architecture.md, docs/development.md, docs/observability.md and the Code
Maintenance spec/plan/tasks/handoff linked as next in specs/README.md.

Start at T001: inspect git status and source, establish actual check baselines,
and record concrete findings and an implementation plan. Then implement the
ordered tasks through verification and handoff without stopping after the audit.
Preserve unrelated work, public contracts, persisted data and access policies.

Keep NestJS modules aligned with domain boundaries, controllers thin, services
cohesive, provider exports intentional and dependency flow acyclic. Prefer the
smallest useful refactor; do not add speculative layers or migrate async patterns.
Install Prettier staged-file formatting with Husky/lint-staged, a safe prepare
lifecycle, lockfile updates and a non-mutating CI formatting gate. Verify partial
staging and Docker/CI/production installs; do not reformat unrelated source.

Add safe structured domain logs using the existing NestJS logger/observability
pipeline. Preserve HTTP logging/health behavior, correlate with request/run IDs
where appropriate, test redaction/failure logs and avoid duplicate/noisy events.
Never log credentials, user content or unbounded payloads; do not add app-held
Grafana tokens or replace the collector. Document live Grafana checks separately.

Run meaningful regression tests, build, non-mutating lint and formatting checks.
Update task checkboxes, context docs and handoff with actual evidence, baseline
failures and blocked integration checks. Do not mark unverified work complete.
Leave changes ready for review; do not commit, push, publish or deploy unless asked.
