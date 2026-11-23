# Feature: Deployment workflow management

Status: Implemented locally

FR-001: Verify main merges/pushes and pull requests. Deploy main only after
verification, without requiring npm publication. FR-002: Publish only through an
explicit manual main run selecting operation=publish; manual publishing must not
deploy. FR-003: Use the central CLI profile `service-auth` and generated YAML with
local profile identity. Preserve runtime configuration, cleanup and rollback.
FR-004: Commit/push this authorized policy update; do not query deployment status.
