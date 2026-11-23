# Handoff

The workflow now separates automatic verification/deployment from explicit manual
publication. Source transport steps and service-specific rollback/configuration
were preserved; uploader gateway proof applies to manual deployment only.
[Policy and update commands](../../docs/deployment-workflows.md).

Local YAML/event/dependency policy and prior-deployment-step comparisons passed.
CLI tests cover main/PR/manual event gates, safe local application and drift. This
is not an application refactor or evidence of successful production deployment.
No deployment status endpoint, Actions run result or production health endpoint was
queried. Commit/push delivery evidence is recorded separately after completion.
