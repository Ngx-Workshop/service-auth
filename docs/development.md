# Development — service-auth

Baseline: `682a2f8` on 2026-11-22. Use `package-lock.json` and `npm ci`; inspect the
Dockerfile and CI for the supported Node runtime. Do not upgrade NestJS/Node as
an incidental maintenance change.

## Existing npm scripts

| Script                  | Command                                                                                                                                                                                                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build`                 | `nest build`                                                                                                                                                                                                                                                                                            |
| `build:ngx-auth-client` | `nest build ngx-auth-client && cp libs/ngx-auth-client/package.json dist/libs/ngx-auth-client/package.json && cp libs/ngx-auth-client/README.md dist/libs/ngx-auth-client/README.md`                                                                                                                    |
| `format`                | `prettier --write "src/**/*.ts" "test/**/*.ts" "libs/**/*.ts"`                                                                                                                                                                                                                                          |
| `start`                 | `nest start`                                                                                                                                                                                                                                                                                            |
| `start:dev`             | `nest start --watch`                                                                                                                                                                                                                                                                                    |
| `start:debug`           | `nest start --debug --watch`                                                                                                                                                                                                                                                                            |
| `start:prod`            | `node dist/src/main.js`                                                                                                                                                                                                                                                                                 |
| `lint`                  | `eslint "{src,apps,libs,test}/**/*.ts" --fix`                                                                                                                                                                                                                                                           |
| `test`                  | `jest`                                                                                                                                                                                                                                                                                                  |
| `test:watch`            | `jest --watch`                                                                                                                                                                                                                                                                                          |
| `test:cov`              | `jest --coverage`                                                                                                                                                                                                                                                                                       |
| `test:debug`            | `node --inspect-brk -r tsconfig-paths/register -r ts-node/register node_modules/.bin/jest --runInBand`                                                                                                                                                                                                  |
| `test:e2e`              | `jest --config ./test/jest-e2e.json`                                                                                                                                                                                                                                                                    |
| `test:oauth:spike`      | `node --test --test-concurrency=1 spikes/oauth-engine/engine.test.mjs`                                                                                                                                                                                                                                  |
| `lint:oauth:spike`      | `eslint --config spikes/oauth-engine/eslint.config.mjs spikes/oauth-engine/*.mjs`                                                                                                                                                                                                                       |
| `test:oauth`            | `npm run build && npm run build:ngx-auth-client && node --test --test-concurrency=1 test/oauth/*.test.mjs`                                                                                                                                                                                              |
| `lint:oauth`            | `eslint --config test/oauth/eslint.config.mjs src/oauth/*.mjs test/oauth/*.mjs scripts/oauth-local-config.mjs scripts/oauth-mongo-provision.mjs && eslint src/bootstrap.ts src/main.ts`                                                                                                                 |
| `oauth:local:config`    | `node scripts/oauth-local-config.mjs`                                                                                                                                                                                                                                                                   |
| `oauth:mongo:provision` | `node scripts/oauth-mongo-provision.mjs`                                                                                                                                                                                                                                                                |
| `start:admin-local`     | `AUTH_ADMIN_LOCAL_DEV=true NODE_ENV=development OAUTH_ENABLED=false RUNTIME_PROFILE=local MONGODB_URI=mongodb://127.0.0.1:27017/auth_users_local PORT=3005 JWT_SECRET=isolated-local-provisioning-development-only JWT_ISSUER=http://127.0.0.1:3005 JWT_AUDIENCE=ngx-workshop-local nest start --watch` |
| `test:social`           | `node --test test/social/*.test.mjs`                                                                                                                                                                                                                                                                    |

## Maintenance checks and hooks

- `npm run lint:check`: non-mutating TypeScript ESLint with the reviewed native
  `eslint-suppressions.json` baseline. 43 pre-existing errors remain suppressed
  by file/rule counts; 16 existing warnings remain visible. No new-file violations
  are exempt. Count-based suppression is not proof that an edited legacy file has
  no new issue: review those files and prune allowances when fixing existing errors.
  Do not grow this baseline to accept new code.
- `npm run format:check`: non-mutating Prettier API check for owned TypeScript,
  maintenance JS/config, workflow YAML, maintained context docs and feature 006.
  The sole legacy TypeScript drift, `src/iam/config/jwt.config.ts`, is allowed only
  at its recorded exact SHA256 in `scripts/maintenance/format-baseline.json`.
  Editing that file invalidates the exception; format it and remove the baseline
  on its next functional change. Historical specs/assets and unrelated JS are
  not a newly imposed repository-wide formatting baseline.
- `npm run test:maintenance`: disposable Git/install fixtures; tests real hooks,
  partial staging, ignored generated artifacts, negative formatting checks and
  full/package-only/no-dev installations. Uses the cache populated by `npm ci`
  with `--offline`; no network fallback during commit.

Pinned Husky 9.1.7 / lint-staged 16.2.7 are developer dependencies compatible with
the Node 22 image. `npm ci` enables `.husky/pre-commit` in a developer Git checkout.
The hook calls local lint-staged with explicit root configuration, formats only
staged supported TS/JS/JSON/Markdown/YAML files and uses the default stash/partial
staging protection. Do not add `git add` or disable hiding partial changes.
`.prettierignore` excludes generated contracts, vendored/public assets, lockfile,
build/coverage and private runtime directories consistently for hook/check.

The self-contained manifest `prepare` skips hook setup for CI, `HUSKY=0`,
production, `--omit=dev` or no `.git`; it does not disable dependency lifecycle
scripts or silently swallow developer hook failures. Docker still copies only
package manifests before `npm ci`. CI runs the formatting/lint/fixture gates
before the existing protocol, unit, social and image checks.

## Runtime and verification

Inspect configuration reads in `src/`, Docker and workflow files for required
environment variables; never print or commit `.env` credentials. Use existing
local-development documentation and isolated data where available. Read
[observability.md](observability.md), existing security/deployment docs and previous
feature specs before touching runtime behavior.

Maintenance local evidence is recorded in the
[handoff](../specs/006-code-maintenance/handoff.md). The local Node 24 runtime differs
from pinned Node 22 CI; local package-only installation is not a Docker image
execution claim. Docker daemon and live Grafana acceptance remain external checks.
Do not use paid provider calls or production writes as tests.

Deployment and npm publication now follow [deployment-workflows](deployment-workflows.md).
