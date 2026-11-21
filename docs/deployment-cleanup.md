# Deployment storage cleanup

After the replacement passes its existing readiness check, `.github/workflows/deploy.yml` runs `scripts/cleanup-deployment.py` with the exact container and image repository. Failed deployment checks skip cleanup, retaining existing recovery behavior. Successful deployments remove this service's stopped rollback containers and superseded image tags. After success, an older version must be rebuilt/redeployed rather than restarted from a retained rollback container.

The helper never force-removes images, prunes volumes or deletes host secrets. Docker protects images referenced by other containers. Running image IDs and unrelated repositories/containers are retained, including on-demand Coding Labs runner images. Cleanup errors fail the job without triggering rollback of a healthy replacement.

Unused build cache older than 24 hours is pruned with `--keep-storage 1GB`; recent/in-use cache remains available for concurrent deployments. Only generated local `node_modules`, `dist`, image/source transfer archives and obsolete `.env.previous`/`.env.next` are removed. Live `.env`, runtime files under `/etc`, data volumes and small deployment scripts/evidence are preserved. CI artifact retention remains unchanged.

Verification (2026-11-21): three isolated cleanup tests pass; workflow YAML parsing and all shell blocks pass `bash -n`. Run `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_cleanup_deployment.py`. Tests use Docker doubles; main pushes still run normal service validation and deployment. Gateway/publisher existing deployment suites also pass (6/12 tests); auth production helper suite passes (4 tests). API code and dependencies are unchanged.
