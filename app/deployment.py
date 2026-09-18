from __future__ import annotations

import os
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable


ACTIVE_DEPLOYMENT_STATES = {
    "queued",
    "preflight",
    "transferring",
    "deploying",
    "health-check",
}


def _ssh_options(server: dict[str, Any]) -> list[str]:
    options = [
        "-p",
        str(server["port"]),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    identity_file = (server.get("identity_file") or "").strip()
    if identity_file:
        identity = Path(os.path.expanduser(identity_file)).resolve()
        if not identity.exists():
            raise RuntimeError(f"SSH identity file does not exist: {identity}")
        options.extend(["-i", str(identity)])
    return options


def _ssh_target(server: dict[str, Any]) -> str:
    return f"{server['ssh_user']}@{server['host']}"


def ssh_command(
    server: dict[str, Any],
    command: str,
    *,
    timeout: int = 120,
) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            ["ssh", *_ssh_options(server), _ssh_target(server), command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout
    except FileNotFoundError:
        return 127, "Required executable not found: ssh"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return 124, stdout + "\nSSH command timed out."


def inspect_server(server: dict[str, Any]) -> dict[str, Any]:
    script = r"""
set -eu
mem_total_kb=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
mem_available_kb=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
disk_total_kb=$(df -Pk / | awk 'NR==2 {print $2}')
disk_available_kb=$(df -Pk / | awk 'NR==2 {print $4}')
disk_used_percent=$(df -Pk / | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
load_1=$(awk '{print $1}' /proc/loadavg)
cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)
docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
compose_version=$(docker compose version --short 2>/dev/null || true)
printf 'mem_total_kb=%s\n' "$mem_total_kb"
printf 'mem_available_kb=%s\n' "$mem_available_kb"
printf 'disk_total_kb=%s\n' "$disk_total_kb"
printf 'disk_available_kb=%s\n' "$disk_available_kb"
printf 'disk_used_percent=%s\n' "$disk_used_percent"
printf 'load_1=%s\n' "$load_1"
printf 'cpu_count=%s\n' "$cpu_count"
printf 'docker_version=%s\n' "$docker_version"
printf 'compose_version=%s\n' "$compose_version"
""".strip()
    code, output = ssh_command(server, script, timeout=30)
    if code != 0:
        raise RuntimeError(f"VPS inspection failed: {output[-3000:]}")

    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

    if not values.get("docker_version"):
        raise RuntimeError("Docker is not available on the target VPS.")
    if not values.get("compose_version"):
        raise RuntimeError("Docker Compose v2 is not available on the target VPS.")

    mem_total_mb = int(values["mem_total_kb"]) // 1024
    mem_available_mb = int(values["mem_available_kb"]) // 1024
    disk_total_mb = int(values["disk_total_kb"]) // 1024
    disk_available_mb = int(values["disk_available_kb"]) // 1024
    memory_used_percent = round(100 * (1 - mem_available_mb / max(mem_total_mb, 1)), 1)

    return {
        "mem_total_mb": mem_total_mb,
        "mem_available_mb": mem_available_mb,
        "memory_used_percent": memory_used_percent,
        "disk_total_mb": disk_total_mb,
        "disk_available_mb": disk_available_mb,
        "disk_used_percent": int(values["disk_used_percent"]),
        "load_1": float(values["load_1"]),
        "cpu_count": int(values["cpu_count"]),
        "docker_version": values["docker_version"],
        "compose_version": values["compose_version"],
    }


def capacity_gate(
    metrics: dict[str, Any],
    server: dict[str, Any],
    target: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if metrics["disk_used_percent"] >= int(server["max_disk_percent"]):
        failures.append(
            f"Disk usage is {metrics['disk_used_percent']}% (limit {server['max_disk_percent']}%)."
        )
    if metrics["memory_used_percent"] >= float(server["max_memory_percent"]):
        failures.append(
            f"Memory usage is {metrics['memory_used_percent']}% (limit {server['max_memory_percent']}%)."
        )
    if metrics["mem_available_mb"] < int(target["required_memory_mb"]):
        failures.append(
            f"Only {metrics['mem_available_mb']} MB memory available; deployment requires "
            f"{target['required_memory_mb']} MB."
        )
    if metrics["disk_available_mb"] < int(target["required_disk_mb"]):
        failures.append(
            f"Only {metrics['disk_available_mb']} MB disk available; deployment requires "
            f"{target['required_disk_mb']} MB."
        )
    return failures


def transfer_docker_image(server: dict[str, Any], image_tag: str) -> str:
    """Stream an already-built local Docker image directly to the VPS over SSH."""
    try:
        local = subprocess.Popen(
            ["docker", "save", image_tag],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker is not installed on the local runner.") from exc

    assert local.stdout is not None
    remote = subprocess.Popen(
        ["ssh", *_ssh_options(server), _ssh_target(server), "docker load"],
        stdin=local.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
    )
    local.stdout.close()
    remote_bytes, _ = remote.communicate()
    local_stderr = local.stderr.read() if local.stderr else b""
    local_code = local.wait()
    remote_output = remote_bytes.decode(errors="replace") if remote_bytes else ""

    if local_code != 0:
        raise RuntimeError(f"docker save failed: {local_stderr.decode(errors='replace')[-3000:]}")
    if remote.returncode != 0:
        raise RuntimeError(f"docker load on VPS failed: {remote_output[-3000:]}")
    return remote_output


def _compose_command(target: dict[str, Any], image_tag: str) -> str:
    compose_dir = shlex.quote(target["compose_dir"])
    compose_file = shlex.quote(target["compose_file"])
    service_name = shlex.quote(target["service_name"])
    env_key = target["image_env_key"]
    env_file = ".custom-github.env"
    quoted_image = shlex.quote(image_tag)
    return (
        "set -eu; "
        f"cd {compose_dir}; "
        f"printf '%s\\n' {shlex.quote(env_key + '=' + image_tag)} > {env_file}; "
        f"docker compose --env-file {env_file} -f {compose_file} up -d --no-build {service_name}; "
        f"docker compose --env-file {env_file} -f {compose_file} ps {service_name}"
    )


def read_previous_image(server: dict[str, Any], target: dict[str, Any]) -> str | None:
    compose_dir = shlex.quote(target["compose_dir"])
    env_key = shlex.quote(target["image_env_key"])
    command = (
        "set -eu; "
        f"cd {compose_dir}; "
        "if [ -f .custom-github.env ]; then "
        f"grep -E '^{target['image_env_key']}=' .custom-github.env | tail -n1 | cut -d= -f2- || true; "
        "fi"
    )
    code, output = ssh_command(server, command, timeout=20)
    if code != 0:
        raise RuntimeError(f"Unable to read current release metadata: {output[-2000:]}")
    value = output.strip()
    return value or None


def activate_release(server: dict[str, Any], target: dict[str, Any], image_tag: str) -> str:
    code, output = ssh_command(server, _compose_command(target, image_tag), timeout=180)
    if code != 0:
        raise RuntimeError(f"Compose deployment failed: {output[-4000:]}")
    return output


def check_health(url: str, attempts: int = 12, delay_seconds: float = 5.0) -> None:
    last_error = "no response"
    for _ in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "custom-github-health/1.0"})
            with urllib.request.urlopen(request, timeout=8) as response:
                if 200 <= response.status < 400:
                    return
                last_error = f"HTTP {response.status}"
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_error = str(exc)
        time.sleep(delay_seconds)
    raise RuntimeError(f"Health check failed after {attempts} attempts: {last_error}")


def execute_deployment(
    *,
    server: dict[str, Any],
    target: dict[str, Any],
    image_tag: str,
    set_status: Callable[[str, str], None],
    set_previous_image: Callable[[str | None], None],
    append_log: Callable[[str], None],
) -> None:
    previous_image: str | None = None
    try:
        set_status("preflight", "Checking target VPS capacity")
        metrics = inspect_server(server)
        append_log(f"Preflight metrics: {metrics}")
        failures = capacity_gate(metrics, server, target)
        if failures:
            raise RuntimeError("Deployment blocked by capacity policy: " + " ".join(failures))

        previous_image = read_previous_image(server, target)
        set_previous_image(previous_image)
        if previous_image:
            append_log(f"Previous release: {previous_image}")

        set_status("transferring", "Streaming immutable Docker image to VPS")
        append_log(transfer_docker_image(server, image_tag))

        set_status("deploying", "Activating release with Docker Compose --no-build")
        append_log(activate_release(server, target, image_tag))

        set_status("health-check", f"Checking {target['health_url']}")
        check_health(target["health_url"])
        append_log("Health check passed.")
        set_status("success", "Deployment completed successfully")
    except Exception as exc:
        append_log(f"ERROR: {exc}")
        if previous_image:
            try:
                append_log(f"Attempting automatic rollback to {previous_image}.")
                activate_release(server, target, previous_image)
                check_health(target["health_url"], attempts=8, delay_seconds=3)
                append_log("Rollback health check passed.")
                set_status("rolled-back", f"Deployment failed and rollback succeeded: {exc}")
                return
            except Exception as rollback_exc:
                append_log(f"ROLLBACK ERROR: {rollback_exc}")
                set_status("rollback-failed", f"Deployment failed; rollback also failed: {rollback_exc}")
                return
        set_status("failed", str(exc))
