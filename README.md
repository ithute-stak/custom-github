# Custom GitHub

Custom GitHub is a local-first Linux infrastructure, CI/CD, deployment and VPS operations control plane.

GitHub remains the source of truth for repositories. Custom GitHub synchronizes repositories, runs verification, builds immutable Docker images away from production, deploys tested releases, manages Linux VPS infrastructure, monitors health, protects secrets, verifies backups and can optionally use a restricted VPS Agent for continuous telemetry and structured operations.

## Core production rules

1. Production VPS servers do **not** build application source.
2. Releases are tied to exact Git commit SHAs.
3. Production receives pre-built images and activates them with Docker Compose `--no-build`.
4. Existing production `.env` files are not replaced by deployment.
5. Destructive infrastructure operations require explicit confirmation and are audited.
6. Docker volumes are not removed by routine cleanup.
7. The browser control plane stays on loopback; remote access is provided through an HTTPS reverse proxy.
8. SSH remains the break-glass recovery channel even when VPS Agents are enrolled.

## Major capabilities

### CI/CD and releases

- GitHub repository registration and synchronization
- clone-once/fetch-later local workspaces
- Node, Python, .NET and Docker pipeline detection
- exact commit-SHA pipeline history
- immutable project/SHA Docker images
- latest-green deployment gate
- VPS capacity checks before deployment
- direct `docker save | ssh docker load` image transfer
- Compose override activation with `--no-build`
- health checks and automatic rollback
- current + previous release retention
- deployment, operation and audit history

### VPS management

- live CPU, RAM, disk, uptime and Docker state
- file manager with List/Tile views and live folder disk usage
- protected create/edit/move/permission/delete operations
- Docker containers, images, logs, storage and cleanup
- systemd service management
- process management
- journal/system logs
- network/listening-port inspection
- interactive SSH terminal
- database manager for PostgreSQL/PostGIS, MySQL and MariaDB
- package/OS update management
- Linux users, sudo groups and SSH public keys
- UFW firewall administration
- managed cron jobs

### Production applications

LoanHub and Ithute have application-aware dashboards built from the production Docker contract.

- LoanHub: 5 expected long-running services
- Ithute: 22 expected long-running services
- live service/image state
- expected vs missing/stopped/wrong-image containers
- aggregate container resources
- deployment and backup context
- guarded application restart
- non-approved workload detection

### Security

- Owner bootstrap
- authenticated sessions
- RBAC: Owner, Admin, Developer, Operator, Viewer
- TOTP MFA
- same-origin/CSRF controls
- protected terminal WebSocket access
- Security Center
- encrypted Secrets Vault using Fernet authenticated encryption
- vault master key stored separately from SQLite
- live VPS security scanner
- effective SSH-policy checks
- privileged-container and Docker-socket exposure checks
- public database/cache port checks
- Fail2ban management
- unattended-upgrades and unsafe `/etc` permission checks

### Monitoring and incidents

- live CPU from `/proc/stat`
- live memory from `/proc/meminfo`
- root disk from `df`
- load average
- network counters
- Docker running/total and restart state
- failed systemd services
- reboot-required state
- timestamped metric history
- configurable alert thresholds
- persistent incidents with `new -> acknowledged -> resolved`
- automatic incident resolution when the live condition clears

### Backup and disaster recovery

- profile-based path backups
- Docker-volume backups
- PostgreSQL/PostGIS dumps
- MySQL/MariaDB dumps
- manifests and retention
- component-level restore with typed confirmation
- off-site SSH/rsync targets
- post-transfer byte verification
- off-site retention constrained to Custom-GitHub-owned target paths
- recovery drill that verifies every artifact in the latest successful manifest with `tar -tzf`, `gzip -t` or non-empty-file verification
- Production Readiness page combining security, MFA, backup freshness, recovery drill, off-site copy, incidents, VPS Agent and live production-contract evidence

### Multi-VPS Fleet

- named server groups
- concurrent live fleet health/capacity inspection
- aggregate RAM/disk/container/service state
- guarded group service restart
- connectivity-critical SSH/network/firewall services blocked from fleet restart

## VPS Agent

The optional VPS Agent is a restricted execution plane for continuous management.

It uses:

- one-time enrollment tokens
- long-lived random agent tokens stored only as SHA-256 hashes in the control-plane database
- agent-side credential state with mode `0600`
- HTTPS-only control-plane communication except loopback development
- periodic live telemetry
- structured command queue

The initial command allowlist is deliberately small:

```text
agent.ping
service.start
service.stop
service.restart
container.start
container.stop
container.restart
```

SSH, networking and firewall services are blocked from Agent service actions. The Agent does not accept arbitrary shell commands.

Install it on a VPS from the repository checkout with:

```bash
sudo bash agent/install.sh https://control.example.com <one-time-enrollment-token>
```

Create the one-time token from **VPS Agents** in the control plane.

## Verify locally

Before starting or pulling production infrastructure into the workflow:

```bash
bash scripts/verify-local.sh
```

This verifies required tools, Docker access, Python compilation, shell scripts and the regression suite.

## Local mode

Local mode is the default and safest starting point:

```bash
bash scripts/start-local.sh
```

Open:

```text
http://127.0.0.1:8787
```

The local launcher deliberately binds only to `127.0.0.1`.

## Remote production control-plane mode

Do not bind Uvicorn directly to the public internet.

Remote mode requires:

- an existing bootstrapped Owner
- authentication enabled
- at least one Owner/Admin with MFA enabled
- an HTTPS public URL
- an HTTPS reverse proxy
- explicit trusted hostnames

Example environment:

```bash
export CUSTOM_GITHUB_PUBLIC_URL=https://control.example.com
export CUSTOM_GITHUB_TRUSTED_HOSTS=control.example.com
export CUSTOM_GITHUB_FORWARDED_ALLOW_IPS=127.0.0.1
bash scripts/start-production.sh
```

`start-production.sh` still binds Uvicorn to `127.0.0.1`. Your reverse proxy terminates HTTPS and forwards to the loopback listener.

Remote mode refuses startup if security, an active Owner or privileged MFA are missing.

## Production-readiness workflow

For each production VPS:

1. Verify the local control plane with `scripts/verify-local.sh`.
2. Create the Owner account and enable MFA.
3. Run the VPS Security Scanner.
4. Verify the application production contract.
5. Create a local backup profile and complete a successful backup.
6. Configure and test an off-site target.
7. Sync a successful backup off-site.
8. Run **Production Readiness -> Verify latest backup**.
9. Resolve critical incidents.
10. Optionally enroll the VPS Agent.
11. Require the Production Readiness page to show no failed checks before treating the recovery posture as complete.

## Deployment contract

See [`docs/DEPLOYMENT_CONTRACT.md`](docs/DEPLOYMENT_CONTRACT.md) before connecting production infrastructure.

The platform never intentionally replaces a production `.env` during release activation and never performs broad `docker system prune -a --volumes` cleanup as part of deployment.

## Current trust boundaries

Custom GitHub is powerful infrastructure software. A user with sufficient RBAC permissions can modify files, databases, containers and services on registered servers. Keep the control plane itself patched and backed up, protect the vault master key separately, retain emergency SSH access, and keep at least one verified off-site backup outside the production VPS.

The current VPS Agent is intentionally narrower than SSH. Expanding Agent privileges should be done by adding structured, validated operations rather than arbitrary command execution.

## Development branch

The complete control-plane implementation is developed on `feature/control-plane-mvp` and remains reviewed through PR #1 before final merge to `main`.
