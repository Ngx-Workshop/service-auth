# Tasks: <feature>

Spec: [spec.md](spec.md)
Plan: [plan.md](plan.md)
Updated: <date>

Only check a task off when its expected result is achieved and evidence exists.
Replace placeholders with actual paths/checks. Add tasks as needed; remove phases
that do not apply. Unchecked external tasks remain visible in the handoff.

## Local implementation

- [ ] T001 — <Implement behavior> in <paths>. Covers FR-001 / AC-001.
      Depends on: <none/task ID>. Verify: <check and expected outcome>.
- [ ] T002 — <Add/update meaningful behavior tests> in <test paths>.
      Covers AC-001. Depends on: T001. Verify: <command and expected outcome>.

## Integration and documentation

- [ ] T003 — <Review/regenerate affected contracts or integration artifacts>.
      Depends on: <IDs>. Verify: <compatibility check or N/A rationale>.
- [ ] T004 — Update affected context docs and record final verification in
      [handoff.md](handoff.md). Depends on: <IDs>. Verify: acceptance coverage.

## External work, if needed

- [ ] X001 — Owner: <repository>. Required change: <contract/behavior>.
      Blocks: <specific task/scenario, or none>. Acceptance: <check>.
      Status/evidence: <pending, delivered version, or verified result>.

## Progress and evidence

| Task | Result or blocker                          | Evidence                         |
| ---- | ------------------------------------------ | -------------------------------- |
| T001 | <Not started/in progress/complete/blocked> | <Command result, file, or check> |
