# Production deployment contract

Custom GitHub deliberately separates **build infrastructure** from **runtime infrastructure**.

The local PC is allowed to fetch source, install dependencies, run tests and build images. A production VPS is only allowed to receive and run an immutable image that has already passed the local pipeline.

## Required production pattern

A production Compose service must use an image variable and must not contain a `build:` section for the application being controlled by Custom GitHub.

```yaml
services:
  app:
    image: ${CUSTOM_GITHUB_IMAGE:?CUSTOM_GITHUB_IMAGE is required}
    restart: unless-stopped
    mem_limit: 1g
    cpus: 1.0
    ports:
      - "127.0.0.1:8080:8080"
```

Custom GitHub writes only this release metadata file in the configured Compose directory:

```text
.custom-github.env
```

Its content is intentionally small:

```dotenv
CUSTOM_GITHUB_IMAGE=custom-github/loanhub:0123456789ab
```

The deployment command uses:

```bash
docker compose --env-file .custom-github.env -f compose.yaml up -d --no-build app
```

`--no-build` is a hard architectural boundary. A production release must fail rather than silently build source code on the VPS.

## SSH account

Use a dedicated account, for example:

```text
deploy
```

Use a dedicated SSH key on the local control-plane PC. The database stores only the path to that key, such as:

```text
~/.ssh/custom_github_deploy
```

Custom GitHub does **not** store the private-key contents in SQLite.

The private key should remain readable only by its owner:

```bash
chmod 600 ~/.ssh/custom_github_deploy
```

### Docker privilege warning

Membership in the normal Docker group is effectively highly privileged on a Linux host. For an initial private deployment server this can be acceptable when the `deploy` key is tightly protected, but the stronger long-term design is a rootless Docker/Podman deployment agent or a narrowly scoped privileged helper.

Do not reuse a personal/root SSH key for the control plane.

## VPS prerequisites

The registered VPS currently requires:

- Linux with `/proc/meminfo` and `df`.
- OpenSSH server.
- Docker Engine.
- Docker Compose v2 (`docker compose`).
- The configured Compose directory already present on the VPS.
- The application Compose file already present on the VPS.
- Network reachability from the local PC to the VPS SSH port.
- A health endpoint reachable from the local PC.

The VPS does **not** require a Git checkout of the application.

## Deployment preflight

Before an image is sent, the control plane checks the VPS and blocks deployment when any configured safety rule fails.

Current gates include:

- Docker is available.
- Docker Compose v2 is available.
- disk usage is below the server threshold;
- memory usage is below the server threshold;
- minimum free memory for the project is available;
- minimum free disk for the project is available;
- no other Custom GitHub deployment is active on that server;
- the exact latest GitHub SHA has a successful local pipeline;
- that exact successful pipeline produced a Docker image;
- a deployment target and health URL are configured.

## Image transfer

Images are streamed directly from local Docker to the VPS Docker daemon:

```text
local docker save IMAGE
        |
        | SSH stream
        v
remote docker load
```

This avoids Git clones, package installations, Docker build caches and source-build artifacts on production.

## Health verification and automatic rollback

Before activating the new release, Custom GitHub reads the previous image from `.custom-github.env` and records it in deployment history.

After the new image is activated, the configured health URL is checked repeatedly. If the release does not become healthy, the controller attempts to reactivate the previous image and checks health again.

Deployment states include:

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

A `rollback-failed` state requires operator attention and must never be presented as a successful release.

## Persistent data

Application databases and uploaded files must use named volumes, bind mounts, or external services that are independent of the application image.

Custom GitHub must never automatically prune application volumes.

Example:

```yaml
services:
  postgres:
    image: postgres:17
    volumes:
      - loanhub_postgres:/var/lib/postgresql/data

volumes:
  loanhub_postgres:
```

The application image can therefore change or roll back without replacing the database volume.

## Next hardening stages

Before broad production use, the platform should add:

1. dedicated isolated runner containers/VMs rather than executing repository code in the API process;
2. database backup hooks before schema-changing deployments;
3. manual rollback controls;
4. image-retention policy that preserves the current and previous releases;
5. deploy-user/agent hardening so Docker access is narrowly scoped;
6. authentication and CSRF protection before the dashboard is exposed beyond localhost;
7. encrypted secret management;
8. WebSocket/server-sent live job logs;
9. deployment cancellation and queue controls;
10. signed release provenance and artifact hashes.
