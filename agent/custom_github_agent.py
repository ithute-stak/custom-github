#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

AGENT_VERSION = "0.1.0"
PROTOCOL_VERSION = 1
SERVICE_RE = re.compile(r"^[A-Za-z0-9@_.:-]+(?:\.service)?$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
BLOCKED_SERVICES = {
    "ssh", "sshd", "ssh.service", "sshd.service", "networking", "networking.service",
    "systemd-networkd", "systemd-networkd.service", "ufw", "ufw.service", "firewalld", "firewalld.service",
}

CONTROL_URL = os.environ.get("CG_CONTROL_URL", "").rstrip("/")
ENROLLMENT_TOKEN = os.environ.get("CG_ENROLLMENT_TOKEN", "").strip()
STATE_PATH = Path(os.environ.get("CG_AGENT_STATE", "/var/lib/custom-github-agent/state.json"))
HEARTBEAT_SECONDS = max(10, min(int(os.environ.get("CG_HEARTBEAT_SECONDS", "30")), 300))
TIMEOUT = max(5, min(int(os.environ.get("CG_HTTP_TIMEOUT", "20")), 120))


def log(message: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), message, flush=True)


def _control_url_ok(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return True
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return True
    return False


def _request(path: str, *, method: str = "GET", token: str | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if not _control_url_ok(CONTROL_URL):
        raise RuntimeError("CG_CONTROL_URL must use HTTPS unless it points to loopback")
    headers = {"Accept": "application/json", "User-Agent": f"custom-github-agent/{AGENT_VERSION}"}
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(CONTROL_URL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            raw = response.read(1_000_000)
    except urllib.error.HTTPError as exc:
        body = exc.read(20_000).decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Control plane unavailable: {exc.reason}") from exc
    try:
        return json.loads(raw.decode("utf-8")) if raw else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError("Control plane returned invalid JSON") from exc


def _load_state() -> dict[str, Any]:
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as exc:
        raise RuntimeError(f"Unable to read agent state: {exc}") from exc


def _save_state(state: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_PATH)
    os.chmod(STATE_PATH, 0o600)


def _run(argv: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        completed = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        return completed.returncode, completed.stdout[-20_000:]
    except FileNotFoundError:
        return 127, f"Executable not found: {argv[0]}"
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return 124, output[-20_000:] + "\nCommand timed out"


def _cpu_percent() -> float | None:
    def snap() -> tuple[int, int] | None:
        try:
            fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]
            values = [int(x) for x in fields]
            total = sum(values)
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            return total, idle
        except Exception:
            return None
    a = snap()
    time.sleep(0.15)
    b = snap()
    if not a or not b:
        return None
    total = b[0] - a[0]
    idle = b[1] - a[1]
    if total <= 0:
        return None
    return round(100.0 * (1.0 - idle / total), 1)


def _memory_percent() -> float | None:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, _, rest = line.partition(":")
            if key in {"MemTotal", "MemAvailable"}:
                values[key] = int(rest.strip().split()[0])
        total = values["MemTotal"]
        available = values["MemAvailable"]
        return round(100.0 * (1.0 - available / max(total, 1)), 1)
    except Exception:
        return None


def _disk_percent() -> float | None:
    try:
        usage = shutil.disk_usage("/")
        return round(100.0 * usage.used / max(usage.total, 1), 1)
    except Exception:
        return None


def _load_1() -> float | None:
    try:
        return round(os.getloadavg()[0], 2)
    except Exception:
        return None


def _docker_counts() -> tuple[int | None, int | None]:
    code, output = _run(["docker", "ps", "-aq"], 15)
    if code != 0:
        return None, None
    all_ids = [line for line in output.splitlines() if line.strip()]
    code, output = _run(["docker", "ps", "-q"], 15)
    if code != 0:
        return None, len(all_ids)
    running = [line for line in output.splitlines() if line.strip()]
    return len(running), len(all_ids)


def _failed_services() -> int | None:
    code, output = _run(["systemctl", "--failed", "--type=service", "--no-legend", "--plain"], 15)
    if code not in {0, 1}:
        return None
    return len([line for line in output.splitlines() if line.strip()])


def collect_metrics() -> dict[str, Any]:
    running, total = _docker_counts()
    metrics: dict[str, Any] = {
        "cpu_percent": _cpu_percent(),
        "memory_percent": _memory_percent(),
        "disk_percent": _disk_percent(),
        "load_1": _load_1(),
        "containers_running": running,
        "containers_total": total,
        "failed_services": _failed_services(),
        "cpu_count": os.cpu_count(),
        "uptime_seconds": None,
    }
    try:
        metrics["uptime_seconds"] = int(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]))
    except Exception:
        pass
    return metrics


def enroll() -> dict[str, Any]:
    if not ENROLLMENT_TOKEN:
        raise RuntimeError("Agent is not enrolled and CG_ENROLLMENT_TOKEN is missing")
    payload = {
        "enrollment_token": ENROLLMENT_TOKEN,
        "agent_version": AGENT_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
    }
    response = _request("/auth/agent/v1/enroll", method="POST", payload=payload)
    if not response.get("agent_token") or not response.get("agent_id"):
        raise RuntimeError("Enrollment response did not contain agent credentials")
    state = {
        "agent_id": response["agent_id"],
        "agent_token": response["agent_token"],
        "protocol_version": response.get("protocol_version", PROTOCOL_VERSION),
        "enrolled_at": time.time(),
    }
    _save_state(state)
    log(f"enrolled as {state['agent_id']}")
    return state


def heartbeat(state: dict[str, Any]) -> None:
    _request(
        "/auth/agent/v1/heartbeat",
        method="POST",
        token=state["agent_token"],
        payload={
            "agent_version": AGENT_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "metrics": collect_metrics(),
        },
    )


def _normalize_service(unit: str) -> str:
    if not SERVICE_RE.fullmatch(unit):
        raise RuntimeError("Invalid service name")
    normalized = unit if unit.endswith(".service") else unit + ".service"
    if unit in BLOCKED_SERVICES or normalized in BLOCKED_SERVICES:
        raise RuntimeError("Connectivity-critical service is blocked")
    return normalized


def execute_command(command: dict[str, Any]) -> tuple[bool, dict[str, Any], str | None]:
    kind = str(command.get("kind", ""))
    payload = command.get("payload") or {}
    if kind == "agent.ping":
        return True, {"pong": True, "agent_version": AGENT_VERSION, "hostname": socket.gethostname()}, None
    if kind in {"service.restart", "service.start", "service.stop"}:
        try:
            unit = _normalize_service(str(payload.get("unit", "")))
        except RuntimeError as exc:
            return False, {}, str(exc)
        action = kind.split(".", 1)[1]
        code, output = _run(["systemctl", action, unit], 120)
        return code == 0, {"unit": unit, "action": action, "output": output[-8000:]}, None if code == 0 else output[-8000:]
    if kind in {"container.restart", "container.start", "container.stop"}:
        container = str(payload.get("container", ""))
        if not CONTAINER_RE.fullmatch(container):
            return False, {}, "Invalid container name or id"
        action = kind.split(".", 1)[1]
        code, output = _run(["docker", action, container], 180)
        return code == 0, {"container": container, "action": action, "output": output[-8000:]}, None if code == 0 else output[-8000:]
    return False, {}, "Unsupported structured command"


def poll_and_execute(state: dict[str, Any]) -> None:
    response = _request("/auth/agent/v1/commands", token=state["agent_token"])
    command = response.get("command")
    if not command:
        return
    cid = int(command["id"])
    ok, result, error = execute_command(command)
    try:
        _request(
            "/auth/agent/v1/results",
            method="POST",
            token=state["agent_token"],
            payload={"command_id": cid, "ok": ok, "result": result, "error": error},
        )
    except Exception as exc:
        log(f"unable to report command {cid} result: {exc}")
        raise


def main() -> int:
    if not CONTROL_URL:
        log("CG_CONTROL_URL is required")
        return 2
    if not _control_url_ok(CONTROL_URL):
        log("CG_CONTROL_URL must use HTTPS unless it points to loopback")
        return 2
    state = _load_state()
    if not state.get("agent_token"):
        state = enroll()
    failures = 0
    while True:
        started = time.monotonic()
        try:
            heartbeat(state)
            poll_and_execute(state)
            failures = 0
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            failures += 1
            log(f"cycle failed ({failures}): {exc}")
            if "401" in str(exc):
                log("agent credential rejected; re-enrollment is required")
        elapsed = time.monotonic() - started
        backoff = min(300, HEARTBEAT_SECONDS * max(1, min(failures, 5)))
        time.sleep(max(1, backoff - elapsed))


if __name__ == "__main__":
    raise SystemExit(main())
