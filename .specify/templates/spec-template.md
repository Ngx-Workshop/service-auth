# Feature: <name>

Status: Draft
Feature ID: <NNN-short-name>
Created: <date>
Updated: <date>
Request/source: <user request, issue, or local reference>

## Problem and audience

<Who needs what outcome, and why does the current behavior fall short?>

## Scope

In scope:

- <Behavior this repository will deliver>

Out of scope:

- <Explicit boundaries>

## Current behavior and evidence

<Relevant source paths; distinguish observed code from behavior actually tested.>

## User scenarios and acceptance

### AC-001 — <scenario>

- Given <initial state>
- When <action>
- Then <observable outcome>
- Covers: FR-001
- Priority: <required/optional>

<Add relevant invalid-input, access-denied, empty, error, and recovery scenarios.
Mark irrelevant categories N/A with a reason.>

## Functional requirements

- FR-001: <Testable requirement, without prematurely choosing implementation>

## Quality requirements

<Applicable accessibility, latency, data integrity, security, compatibility, and
operational constraints. Use measurable targets when they matter.>

## Data and external boundaries

<Owned data, consumed/produced contracts, actors/access levels, external owners,
and what must remain compatible. Do not assume another checkout is available.>

## Success criteria

<Observable completion criteria and how each can be checked. State whether host,
gateway, or other service integration is within the acceptance scope.>

## Assumptions and unresolved decisions

| ID    | Assumption or question                                         | Impact           | Resolution/evidence                       |
| ----- | -------------------------------------------------------------- | ---------------- | ----------------------------------------- |
| Q-001 | <Question or assumption; NEEDS CLARIFICATION if consequential> | <Affected scope> | <Answer, accepted assumption, or pending> |
