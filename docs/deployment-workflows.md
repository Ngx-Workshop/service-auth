# Deployment workflow policy

This repository uses the central Node CLI profile `service-auth` under
`cli-ngx-workshop-node/src/templates/deployment/`. That external repository owns
policy/rendering; its source is not required for normal development here.
`.ngx-workshop/deployment.json` identifies this profile. Generated deploy.yml is
excluded from Prettier; use the CLI's `workflows --check` to detect generated drift.

| Trigger                           | Verify | Deploy             | Publish                                                 |
| --------------------------------- | ------ | ------------------ | ------------------------------------------------------- |
| PR targeting main                 | Yes    | No                 | No                                                      |
| Push/merge to main                | Yes    | After verification | No                                                      |
| Manual operation=verify (default) | Yes    | No                 | No                                                      |
| Manual operation=deploy on main   | Yes    | After verification | No                                                      |
| Manual operation=publish on main  | Yes    | No                 | After verification, if this service publishes a package |
| Manual on another branch          | Yes    | No                 | No                                                      |

Use GitHub Run workflow on main and select `publish` for npm publication. The BFF
has no npm package/job. Configure trusted publishing for the existing package and
workflow. Existing package versioning and runtime transport/rollback policies stay
in effect. Standalone validate.yml, where present, remains callable/manually runnable;
deploy.yml owns automatic verification. Publication never gates deployment.

From the central Node CLI checkout run `npm run build`, then
`node bin/ngx-workshop.js workflows --workspace /path/to/workspace --targets service-auth`
to audit. Add `--apply --dry-run` to preview, `--apply --yes` to write, or `--check`
for a failing drift check. These operations only inspect/edit local files; review,
commit and push explicitly. Change the central profile/policy rather than editing
this generated workflow. Updates propagate through reviewed consumer commits,
not automatically from the CLI branch. This policy supersedes older instructions
that coupled npm publication and deployment.

Local checks validated YAML, event/job policy and preserved deployment transport.
No deployment status/health or live Grafana receipt was checked for this rollout.
