# Specification-driven implementation workflow

This repository uses a lightweight Markdown workflow inspired by GitHub Spec Kit.
It works in a standalone VS Code checkout with Copilot. No CLI, extension or slash
command installation is required.

1. Read [AGENTS.md](../AGENTS.md), the [constitution](memory/constitution.md),
   [architecture](../docs/architecture.md), [development](../docs/development.md)
   and the [feature index](../specs/README.md). The index explicitly names next work.
2. Specify observable requirements and acceptance cases in `specs/NNN-name/spec.md`.
3. Inspect source and dependencies, record affected paths, compatibility, risks and
   verification in `plan.md`. Check each applicable constitution principle.
4. Write ordered checkbox tasks with stable IDs and acceptance references in
   `tasks.md`. Resolve routine choices and record consequential unknowns.
5. Implement authorized tasks, update checkboxes only with evidence, and run checks.
   Preserve unrelated work and previous feature records. Missing external systems
   are verification limits, not reasons to invent successful integration results.
6. Update `handoff.md`, context docs and the feature index with actual results,
   external owner actions and next steps. Local generation is not publication.

Use [templates](templates/) for new work. Allocate the next unused numeric folder;
the greatest number is not automatically the active feature. Keep a feature's
spec, plan, tasks and handoff together. Small mechanical/docs fixes need only a
concise change and verification record. The workflow does not impose additional
approval steps for work the user has already authorized.
