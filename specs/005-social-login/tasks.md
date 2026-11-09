# Tasks

- [x] T001 Inspect all four account/profile paths and existing HTTPS ingress.
- [x] T002 Add passwordless provider accounts, UUID reuse and collision handling.
- [x] T003 Add Google/Apple/GitHub authorization and validated callbacks.
- [x] T004 Add shared provider buttons to login/sign-up and preserve destination.
- [x] T005 Add ingress logging/body/rate restrictions and configuration guide.
- [x] T006 Verify provider protocol, browser binding, replay, account and UI tests.
- [ ] T007 Register each provider, provision credentials/indexes, deploy and verify
  real provider consent, returning sign-in, cross-subdomain cookies and admin visibility.

- [x] T008 Wire organization Google/GitHub secrets through private server config and
  force Apple disabled; verify local credential transfer/install behavior.
- [x] T009 Prepare additive database-host migration and production index validation.
- [ ] T010 Execute production migration and release Google/GitHub; confirm discovery
  and live provider acceptance. Apple rollout is explicitly deferred by the user.
