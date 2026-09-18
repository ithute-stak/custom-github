# Custom GitHub

A local-first CI/CD and controlled deployment platform.

GitHub remains the source of truth for repositories. This project runs on the operator's PC, synchronizes selected GitHub repositories, executes CI pipelines locally, builds immutable Docker images locally, checks production VPS capacity, and only enables **Deploy Latest** for the exact latest commit when its required checks have passed.

## Core rule

Production VPS servers do **not** build source code.

They receive pre-built, tested Docker images from the local control plane and activate them with Docker Compose using `--no-build`.

## Current flow

1. Register a GitHub repository.
2. Sync/fetch its latest branch commit locally.
3. Run the local pipeline.
4. Build a Docker image tagged to the exact commit SHA.
5. Mark that exact commit green only when every required step passes.
6. Register a production VPS and SSH identity path.
7. Configure the project's Compose directory/service, health URL and resource requirements.
8. Enable **Deploy Latest** only when the latest GitHub SHA has a green Docker image and a deployment target.
9. Check VPS disk, memory, Docker and Compose availability.
10. Stream the already-built image directly to the VPS over SSH.
11. Generate a tiny Compose override containing only the selected immutable image.
12. Activate it with `docker compose ... up -d --no-build`.
13. Health-check the application.
14. Automatically roll back to the previous image if the health check fails.
15. Keep the current and immediate previous project images while removing older images for that project only.

## Implemented

- Local browser dashboard.
- SQLite state database.
- GitHub repository registration and synchronization.
- Clone-once/fetch-later local workspaces.
- Basic automatic pipeline detection for Node, Python, .NET and Docker projects.
- Exact commit-SHA pipeline history.
- Docker image tags tied to project + commit SHA.
- Hard latest-green deployment gate.
- Production VPS registry.
- SSH identity-path configuration without storing private key contents.
- Live VPS capacity checks.
- Per-project deployment targets.
- Disk and memory deployment thresholds.
- Minimum free RAM/disk requirements per project.
- One active deployment per VPS.
- Background deployment execution.
- Direct `docker save | ssh docker load` image streaming.
- Docker Compose activation with a generated override and `--no-build`.
- Existing production `.env` files remain untouched.
- Repeated HTTP health verification.
- Automatic rollback on failed deployment health.
- Project-scoped Docker image retention.
- Deployment history and logs.
- Audit-event history.
- Local verification script and safety-focused regression tests.

## Verify the local machine first

Before starting the dashboard or connecting any VPS, run:

```bash
bash scripts/verify-local.sh
```

This verifies the required local tools, Docker daemon access, Python compilation and the control-plane test suite.

Only continue to production configuration when this command is green.

## Run locally

Native mode is recommended because the local control plane needs access to your existing Git credentials, Docker daemon, runtimes and SSH keys.

```bash
bash scripts/start-local.sh
```

Open:

```text
http://127.0.0.1:8787
```

Before registering private repositories, make sure normal Git HTTPS access to GitHub already works on the PC, for example through your existing Git credential helper or GitHub CLI authentication.

## Local runner requirements

Install the tools required by the repositories you intend to test:

- `git`
- Node.js / npm for Node or Next.js projects
- Python for Python projects
- .NET SDK for .NET projects
- Docker for image builds and image export
- OpenSSH client for production deployment

The current runner executes repository commands directly on the local PC. A later hardening stage will isolate builds in dedicated runner containers or VMs.

## Production VPS requirements

The controlled deployment worker expects:

- Linux VPS
- SSH access using a dedicated deployment user/key
- Docker Engine
- Docker Compose v2
- a pre-existing production Compose directory
- an application Compose file already present there
- no requirement to build application source on the VPS
- a health endpoint reachable from the control-plane PC

See [`docs/DEPLOYMENT_CONTRACT.md`](docs/DEPLOYMENT_CONTRACT.md) before connecting a production server.

## Compose override design

Your existing application Compose configuration can stay intact. Custom GitHub writes only:

```text
.custom-github.override.yaml
.custom-github.release
```

For example, the generated override is equivalent to:

```yaml
services:
  app:
    image: custom-github/loanhub:0123456789ab
```

Then the controller activates it with:

```bash
docker compose \
  -f compose.yaml \
  -f .custom-github.override.yaml \
  up -d --no-build app
```

This means Custom GitHub can change the deployed image without replacing the application's normal `.env` file.

## Disk-protection policy

The platform does **not** call broad destructive commands such as `docker system prune -a --volumes` during deployment.

After a successful release it only considers tags belonging to the exact project repository, for example:

```text
custom-github/loanhub:aaaaaaaaaaaa
custom-github/loanhub:bbbbbbbbbbbb
custom-github/loanhub:cccccccccccc
```

It retains:

- the currently deployed image;
- the immediate previous rollback image.

Older images for that project are removed when Docker says they are safe to remove. Volumes and unrelated application images are never targeted by this retention step.

## Deployment states

```text
queued
preflight
transferring
deploying
health-check
success
failed
rolled-back
rollback-failed
```

A deployment marked `rolled-back` means the attempted release failed but the previous release was restored and passed its health check.

A deployment marked `rollback-failed` requires operator attention.

## Important security boundary

Keep the dashboard bound to localhost (`127.0.0.1`) until authentication and CSRF protection are implemented.

Do not use a personal/root SSH key for automated deployment. Use a dedicated deployment key and read the Docker privilege warning in the deployment contract.

## Still to harden before broad production use

- isolated build runners instead of executing project code in the API process;
- manual rollback button and release browser;
- backup hooks before database/schema migrations;
- encrypted secret management;
- authentication/authorization;
- live streaming logs and job cancellation;
- signed artifact provenance;
- dedicated restricted deployment agent/rootless container runtime;
- queue controls for multiple runner machines.

## Development branch

The current implementation is developed under `feature/control-plane-mvp` and is reviewed through PR #1 before merging into `main`.
