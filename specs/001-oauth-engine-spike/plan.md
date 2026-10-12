# Spike plan
Status: Complete (spike scope) · 2026-10-12

Compare node-oauth/oauth2-server and oidc-provider using primary docs/source.
Start with oidc-provider because resource indicators, introspection and revocation
are native capabilities. Pin as dev-only; keep executable ESM harness outside
runtime src. Use its adapter and interaction hooks with Nest on loopback and an
isolated MongoDB database named auth_oauth_spike_<random>. Verify over real HTTP,
not direct fake token issuance. Identity in the spike is a fixed test subject via
interaction hook, explicitly not proof of real password login/consent UI.

Inspect adapter consumption semantics before selecting storage architecture.
Test expiry, restart, concurrent replay, hashes and grant removal against MongoDB.
Record any need for a transactional topology/response buffering before claiming
atomic issuance. Keep service-auth src and auth-client library unchanged. Update
gateway T001 only to the extent supported by actual evidence.
