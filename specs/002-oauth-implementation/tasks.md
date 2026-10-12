# Implementation checklist

- [x] Package oidc-provider as a runtime dependency through the native ESM boundary.
- [x] Opt-in validated local configuration and fail-closed startup policy.
- [x] Reuse existing Mongo accounts and password verification; real browser login.
- [x] Explicit client/resource/scope consent and denial.
- [x] Interaction-bound single-use CSRF, input limits, security headers and throttling.
- [x] Encrypted, hashed, indexed Mongo state with replica-set transactions and expiry.
- [x] Atomic redemption, concurrent/replay handling and bounded commit-only retries.
- [x] Discovery, code/token, Basic introspection, owner-bound token revocation.
- [x] Authenticated browser grant management and durable revocation tombstones.
- [x] Actual application HTTP/storage and legacy auth regression tests.
- [x] ADR, local configuration generator, runbook and handoff.

Deferred: dynamic metadata client HTTPS resolution; auth-client additive OAuth
exports; gateway bearer integration and three-tool OAuth integration; deployment.
