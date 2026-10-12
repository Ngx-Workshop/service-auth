# OAuth engine spike
Status: Complete (spike scope) · 2026-10-12

Prove an engine for service-auth before implementing production OAuth routes.
This is an isolated test harness, not a change to the existing login service.

- FR-001: Pin a maintained engine and record version, license, runtime/module compatibility and alternatives from primary sources.
- FR-002: Real HTTP code flow with PKCE S256; reject missing/plain/wrong verifier, replay and expired code; prove subject/client separation.
- FR-003: Bind a single configured MCP resource in authorization and token requests; reject wrong/missing resource and scope escalation.
- FR-004: Authenticated introspection and client/token/grant revocation; prove inactive expired/revoked/unknown token and resource isolation.
- FR-005: Real isolated MongoDB adapter, hashed opaque-token/code lookup, explicit expiry, durable restart behavior, atomic concurrent consumption and storage-failure behavior; identify any unfulfilled atomic issuance requirement.
- FR-006: Prove Nest/CommonJS mount seam and identity interaction hook without duplicating users or wiring experimental routes into AppModule.
- FR-007: Record proven engine behavior versus application policy/adapter work, including metadata-client support; no implied full OAuth rollout, auth-client package change, publication or deployment.

Acceptance: executable opt-in test exits nonzero on a failed scenario, uses real
engine HTTP and real isolated MongoDB, closes sockets/DB resources and deletes
only its newly created test database. No existing user/catalog records changed.
Storage limitations are blockers to unqualified engine acceptance, not hidden by
in-memory adapters or weakened concurrency tests.
