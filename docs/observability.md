# Service logging and heartbeat

This service uses native NestJS 11 `ConsoleLogger` JSON output to stdout/stderr, with `Logger` context for application events. No Angular logger or application-held Grafana credential is used. HTTP logs contain generated request ID, method, route template, status and duration; bodies, cookies, authorization headers, concrete identifiers and query strings are not logged by the middleware. Health polling is excluded from access logs. Avoid embedding secrets or personal search text in domain log messages.

## Maintenance domain events

AuthenticationService emits `auth_password_sign_in` and `auth_role_update`;
the internal UserMetadataService emits `user_metadata_upsert`. Payloads contain
only event, outcome, generated operationId, optional generated requestId and
durationMs. Success is `log`, authentication rejection is `warn`, unexpected
account/storage/token-signing failure is `error`. A missing role-update account
remains the existing null response and logs `not_found`, not a fabricated success.
Metadata remains best-effort: one `warn`/`failure` is emitted before returning,
without re-logging a raw axios error. No account IDs, emails, roles, passwords,
provider subjects, tokens, cookies, body/query data or exception text are recorded.

HTTP middleware runs downstream async work in AsyncLocalStorage. It always
generates its own UUID and ignores incoming X-Request-ID (valid or invalid);
there is no trust in caller-supplied correlation content. Access records and
domain events share this local ID. Concurrent requests remain isolated; operations
started outside a request have only operationId. Work launched inside a request
inherits its context for its async lifetime. IDs are not automatically forwarded
to upstream services, and this does not claim distributed tracing. Domain and
HTTP error records describe different boundaries, not repeated raw exceptions.
GET/HEAD health polls do not create context or domain/access events.

The installed ConsoleLogger emits structured payloads under `message`, for example:

```json
{
  "level": "warn",
  "context": "UserMetadataService",
  "message": {
    "event": "user_metadata_upsert",
    "outcome": "failure",
    "operationId": "00000000-0000-4000-8000-000000000001",
    "requestId": "00000000-0000-4000-8000-000000000002",
    "durationMs": 3001
  }
}
```

This illustrative fragment omits native timestamp/pid fields. Local tests parse
the actual logger output, assert levels/context/outcome and exclude canary secrets
from returned values and thrown errors. Keep IDs as JSON fields, not Loki labels.
With the infrastructure owner's existing stream selector, useful LogQL filters are:

```logql
{service_name="ngx-auth-service"} | json event="message.event", outcome="message.outcome" | event="user_metadata_upsert" | outcome="failure"
{service_name="ngx-auth-service"} | json requestId="message.requestId" | requestId="<locally-generated-request-id>"
```

The stream label must be confirmed by the collector owner; these expressions
describe the locally verified JSON field placement, not a live query result.
After an authorized deployment, infrastructure owner `nginx-ngx-workshop.io`
should verify receipt, retention and label selection in Grafana/Alloy, then correlate
a harmless controlled request and metadata failure. No live Grafana check was
performed for this maintenance task and no ingestion credential was requested.

`GET /health` and HEAD return the anonymous operational Terminus heartbeat with `status: ok` and `heartbeat: up`, plus `Cache-Control: no-store`. This is liveness only; it does not claim MongoDB or upstream readiness. Existing business-route authentication remains enforced. The gateway's exact read-only heartbeat is the only exception to its normalized proxy-envelope requirement. The operational endpoint is excluded from business Swagger/contracts where that service generates them.

Docker probes `/health` every 30 seconds. Deployments bound each container's local JSON log files to 10 MiB × 3. Host Alloy discovers active service names and ships logs and private HTTP heartbeat probe metrics to Grafana Cloud stack `ivorytoffee195`. Collector configuration/dashboard lives in infrastructure owner `nginx-ngx-workshop.io/ops/grafana`; its ingestion token remains host-owned, scoped to logs/metrics write, and requires account authorization before activation. No production credential belongs in this repository.

Validation on 2026-11-21: the isolated observability HTTP suite passed (5 scenarios), build passed, Linux-targeted lockfile dry run passed. Guarded services additionally passed the anonymous-heartbeat/protected-business-route HTTP test. Gateway production ingress e2e passed (51 scenarios), including exact-path/method heartbeat boundaries. Gateway and publisher lint passed. Full existing unit suites passed except Backstage's unchanged Octokit ESM test-loader failure, reproduced on its pre-change HEAD. Uploader tests pass under its documented `npm test` command; its 10 optional cases remain skipped. Publisher persistence e2e cases require the isolated Mongo URI and remain skipped when unavailable. These are local checks, not evidence of Grafana ingestion or live deployment.
