# Auth architecture decisions

- [0001 — OAuth engine recommendation](0001-oauth-engine.md): executable local spike passed; engine selected; see ADR 0002 for the local application integration.

- [0002 — Local OAuth implementation](0002-local-oauth-implementation.md): accepted for local use; deployment deferred.

- [0003 — Approved CIMD and additive introspection](0003-oauth-cimd-introspection.md): accepted and verified locally; deployment deferred.

Deployment decisions proposed for future implementation:

- [0004 — Public HTTPS and verified clients](0004-public-oauth-clients.md)
- [0005 — Production secrets and rotation](0005-production-secrets.md)
- [0006 — Private rs0 and safe recovery](0006-production-mongodb.md)

[Deployment handoff](../../specs/004-deployment/handoff.md) records limits and
unchecked implementation/release tasks. No deployment is authorized by these ADRs.

- [0007: Launch-supported OAuth metadata](0007-launched-oauth-metadata.md)

Production decisions are implemented after user authorization; see [actual launch evidence](../production-execution-2026-10-12.md). Private ChatGPT linking remains open.

- [0008 — Independent encrypted recovery storage](0008-independent-recovery-storage.md)
