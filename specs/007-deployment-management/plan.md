# Plan

Baseline HEAD: `f7906d0bd8590b571bec98f538756fae77b1b9ce`. Audit found jobs validate, deploy, publish;
deploy prerequisites were `validate`.
Use the central Node CLI policy and reviewed service-specific job profile. Separate
validation from publication, make deploy need validate only, preserve transport
steps and existing contract/version semantics. Main-only guards protect mutation;
OIDC write permission belongs only to manual publish. Preserve domain/access rules;
no application/schema changes. Verify YAML parsing, event gates, source transport
comparison and CLI drift check. No live deployment verification is requested.
