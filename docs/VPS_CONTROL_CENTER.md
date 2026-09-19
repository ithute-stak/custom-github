# VPS Control Center

Custom GitHub now has a VPS management surface in addition to its repository, pipeline and deployment control plane.

## Open the workspace

1. Start the platform with `bash scripts/start-local.sh`.
2. Open `http://127.0.0.1:8787`.
3. Register a production server if one is not already configured.
4. Use **Open VPS Manager** on the server card.

The server workspace is also available directly at `/vps/<server-id>`.

## Current management modules

### Overview

The overview performs a live SSH inspection and displays:

- hostname, operating system, kernel and architecture;
- uptime and reboot-required state;
- CPU count and load;
- memory use and free memory;
- disk use and free disk;
- Docker and Compose versions;
- running/total container counts;
- failed systemd service count.

The UI distinguishes `online`, `degraded` and `offline` states.

### Events and operations

Server actions are not treated as opaque button clicks. The platform records operations with these fields:

- queued/running/success/failed state;
- percentage progress;
- human-readable status message;
- result/error data;
- created, started and finished timestamps.

Server events are delivered to the browser over Server-Sent Events (SSE). The Activity screen and toast system update without requiring a page reload.

### Files

The file manager can:

- browse any absolute path available to the SSH user;
- create files and directories;
- read and edit UTF-8 text files up to the browser-editor safety limit;
- write files atomically through a temporary file;
- rename or move paths;
- change permissions and owner/group where privileges allow;
- move deleted items to `$HOME/.custom-github-trash` by default;
- perform explicit permanent deletion when the exact path is confirmed.

Destructive operations against critical top-level Linux paths such as `/`, `/etc`, `/usr`, `/var`, `/home`, `/root`, `/boot` and `/var/lib/docker` are blocked by the API. Files inside those directories can still be managed when the operator has access.

### Docker

The Docker workspace provides:

- container inventory;
- image inventory;
- container logs;
- start, stop, restart, pause and unpause operations;
- controlled container removal;
- read-only Docker storage inspection.

Background Docker actions appear in the operation/event system.

### Services

The systemd workspace lists service units and supports start, stop, restart, reload, enable and disable operations.

Privileged operations run directly when the registered SSH user is root. Otherwise they use non-interactive `sudo -n`, so the platform never prompts for or stores a sudo password.

### Processes

The process workspace lists PID, parent PID, owner, CPU, memory, state, elapsed time and command. Operators can send a controlled set of signals (`TERM`, `KILL`, `HUP`, `INT`). PID 1 is explicitly protected by the API.

### Logs

The log workspace reads `journalctl` with line, service and priority filters. It is read-only.

### Network

The network workspace exposes:

- interface/address state;
- routing table;
- listening TCP/UDP sockets and owning processes where visible.

### Terminal

The terminal is a real interactive SSH PTY bridged to the browser through a WebSocket. It uses the same registered host, port, SSH user and identity-file configuration as controlled deployments.

Terminal open and close events are written to the audit/event history. Shell contents are not recorded as an audit log in this initial version.

## Security boundary

The current control plane remains **local-first** and native mode binds only to `127.0.0.1`. Do not expose it publicly yet.

Before any internet-facing deployment, add at minimum:

- authentication and MFA;
- role-based authorization;
- CSRF protection for browser actions;
- encrypted secret/key references;
- origin restrictions for WebSockets and SSE;
- session expiry and re-authentication for destructive actions;
- more granular sudo policy or a restricted VPS agent;
- backups/snapshots before high-risk system changes.

## Architecture direction

The current release remains agentless and uses OpenSSH because the existing deployment controller already has a hardened connection model and operators can use servers without installing new software.

A later phase can introduce a small restricted VPS agent for structured metrics, file transfer, long-running jobs and finer-grained privileges while retaining SSH for installation, recovery and interactive terminal access.
