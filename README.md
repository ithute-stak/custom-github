# Custom GitHub

A local-first CI/CD and controlled deployment platform.

GitHub remains the source of truth for repositories. This project runs on the operator's PC, synchronizes selected GitHub repositories, executes CI pipelines locally, and only enables **Deploy Latest** for the exact latest commit when its required checks have passed.

## Core rule

Production VPS servers do **not** build source code. They will receive pre-built, tested release artifacts/containers from the local control plane.

## MVP flow

1. Register a GitHub repository.
2. Sync/fetch its latest branch commit locally.
3. Run the local pipeline.
4. Mark the exact commit as green only when every required step passes.
5. Enable **Deploy Latest** only when `latest GitHub SHA == latest green SHA`.
6. Create an approved deployment request for that immutable SHA/image.
7. The next stage will add the VPS deployment agent, resource checks, health checks, rollback, and cleanup policy.

## What is implemented in the first MVP

- Local browser dashboard.
- SQLite state database.
- Register selected GitHub repositories.
- Clone once, then fetch/reset on later syncs.
- Automatic basic pipeline detection for Node, Python, .NET, and Docker projects.
- Pipeline history with exact commit SHA.
- Docker build tag tied to project and commit SHA.
- A hard green-build deployment gate.
- **Deploy Latest** button that cannot approve an untested/failed latest commit.
- Deployment request table ready for the remote agent stage.

## Run locally

The native mode is the recommended MVP mode because it can use the Git credentials and developer tools already installed on your PC.

```bash
bash scripts/start-local.sh
```

Then open:

```text
http://127.0.0.1:8787
```

Before registering private repositories, make sure normal Git HTTPS access to GitHub already works on the PC (for example through your existing Git credential helper or GitHub CLI authentication).

## Local runner requirements

The current MVP executes detected tools directly on the local PC. Install only the runtimes required by the repositories you intend to test:

- `git`
- Node.js / npm for Node or Next.js projects
- Python for Python projects
- .NET SDK for .NET projects
- Docker for Docker image builds

A later runner stage will isolate builds in dedicated worker containers so dependencies and untrusted build processes do not share the control-plane process.

## Docker/Compose note

`Dockerfile` and `compose.yaml` package the dashboard/control plane, but native mode is preferred for the first iteration. The container image intentionally does not attempt to contain every possible Node, Python, .NET, and Docker build toolchain.

## Safety boundary

The current **Deploy Latest** action creates an approved deployment request only. It does not yet connect to a VPS. We will add VPS credentials, resource thresholds, health checks, image transfer, rollback, and retention rules in a separate stage rather than putting production access into the first prototype.

## Planned deployment checks

Before the remote deployment agent is allowed to release anything, it should require:

- latest commit is green;
- no other deployment is active for the application;
- VPS disk usage is below the configured threshold;
- VPS memory headroom is sufficient;
- release image/artifact exists locally;
- database backup policy has passed when required;
- health check is configured;
- previous release is retained for rollback.

## Development branch

The first implementation is developed under `feature/control-plane-mvp` and should be reviewed through a pull request before merging into `main`.
