from __future__ import annotations

import asyncio
import base64
import fcntl
import json
import os
import posixpath
import pty
import re
import shlex
import signal
import sqlite3
import struct
import subprocess
import termios
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.deployment import inspect_server, ssh_command


MAX_EDITOR_BYTES = 512 * 1024
MAX_LOG_LINES = 2000
PROTECTED_DELETE_PATHS = {
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/lib",
    "/lib64",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
    "/var/lib/docker",
}
SERVICE_ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable"}
CONTAINER_ACTIONS = {"start", "stop", "restart", "pause", "unpause", "remove"}
PROCESS_SIGNALS = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL, "HUP": signal.SIGHUP, "INT": signal.SIGINT}


class FileCreate(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    kind: str = Field(pattern=r"^(file|directory)$")


class FileWrite(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    content: str = Field(max_length=MAX_EDITOR_BYTES)


class FileMove(BaseModel):
    source: str = Field(min_length=1, max_length=4096)
    destination: str = Field(min_length=1, max_length=4096)
    overwrite: bool = False


class FileDelete(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    permanent: bool = False
    confirm_path: str | None = Field(default=None, max_length=4096)


class FileMetadata(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    mode: str | None = Field(default=None, pattern=r"^[0-7]{3,4}$")
    owner: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    group: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")


class ServiceAction(BaseModel):
    action: str = Field(pattern=r"^(start|stop|restart|reload|enable|disable)$")


class ContainerAction(BaseModel):
    action: str = Field(pattern=r"^(start|stop|restart|pause|unpause|remove)$")
    force: bool = False


class ProcessAction(BaseModel):
    signal: str = Field(default="TERM", pattern=r"^(TERM|KILL|HUP|INT)$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_remote_path(path: str) -> str:
    if "\x00" in path:
        raise HTTPException(status_code=400, detail="Path contains an invalid NUL character")
    if not path.startswith("/"):
        raise HTTPException(status_code=400, detail="VPS paths must be absolute")
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid absolute path")
    return normalized


def deletion_is_protected(path: str) -> bool:
    return normalize_remote_path(path) in PROTECTED_DELETE_PATHS


def _validate_unit(unit: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9@_.:-]+(?:\.service)?", unit):
        raise HTTPException(status_code=400, detail="Invalid systemd service name")
    return unit if unit.endswith(".service") else f"{unit}.service"


def _validate_container(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise HTTPException(status_code=400, detail="Invalid Docker container name or id")
    return value


def _validate_pid(pid: int) -> int:
    if pid <= 1 or pid > 2_147_483_647:
        raise HTTPException(status_code=400, detail="Refusing to signal this PID")
    return pid


def _run_remote(server: dict[str, Any], command: str, timeout: int = 60) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        message = output.strip()[-4000:] or f"Remote command failed with exit code {code}"
        raise RuntimeError(message)
    return output


def _sudo(command: str) -> str:
    return f"if [ \"$(id -u)\" -eq 0 ]; then {command}; else sudo -n {command}; fi"


def _decode_name(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8", errors="replace")


def install_vps_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
    app_root: Path,
) -> None:
    """Attach the VPS management surface to the existing control-plane app."""

    dashboard_path = app_root / "app" / "static" / "vps.html"

    def init_vps_db() -> None:
        with db_factory() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS server_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    message TEXT,
                    result_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    FOREIGN KEY(server_id) REFERENCES servers(id)
                );

                CREATE TABLE IF NOT EXISTS server_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    data_json TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(server_id) REFERENCES servers(id)
                );

                CREATE INDEX IF NOT EXISTS idx_server_operations_server
                    ON server_operations(server_id, id DESC);
                CREATE INDEX IF NOT EXISTS idx_server_events_server
                    ON server_events(server_id, id DESC);
                """
            )

    @app.on_event("startup")
    def startup_vps_management() -> None:
        init_vps_db()

    def emit_event(
        server_id: int,
        category: str,
        severity: str,
        title: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> int:
        with db_factory() as connection:
            cursor = connection.execute(
                """
                INSERT INTO server_events(server_id, category, severity, title, message, data_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    server_id,
                    category,
                    severity,
                    title[:240],
                    message[:4000],
                    json.dumps(data) if data is not None else None,
                    utc_now(),
                ),
            )
            return int(cursor.lastrowid)

    def create_operation(server_id: int, kind: str, title: str, message: str = "Queued") -> int:
        with db_factory() as connection:
            cursor = connection.execute(
                """
                INSERT INTO server_operations(server_id, kind, title, status, progress, message, created_at)
                VALUES (?, ?, ?, 'queued', 0, ?, ?)
                """,
                (server_id, kind, title[:240], message[:2000], utc_now()),
            )
            operation_id = int(cursor.lastrowid)
        emit_event(server_id, "operation", "info", title, message, {"operation_id": operation_id, "status": "queued"})
        return operation_id

    def update_operation(
        operation_id: int,
        *,
        status: str,
        progress: int,
        message: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        now = utc_now()
        with db_factory() as connection:
            operation = connection.execute(
                "SELECT server_id, title FROM server_operations WHERE id = ?", (operation_id,)
            ).fetchone()
            if not operation:
                return
            started_at = now if status == "running" else None
            finished_at = now if status in {"success", "failed", "cancelled"} else None
            connection.execute(
                """
                UPDATE server_operations
                SET status = ?, progress = ?, message = ?, result_json = ?, error = ?,
                    started_at = COALESCE(started_at, ?), finished_at = COALESCE(?, finished_at)
                WHERE id = ?
                """,
                (
                    status,
                    max(0, min(progress, 100)),
                    message[:2000],
                    json.dumps(result) if result is not None else None,
                    error[:4000] if error else None,
                    started_at,
                    finished_at,
                    operation_id,
                ),
            )
        severity = "success" if status == "success" else "error" if status == "failed" else "info"
        emit_event(
            int(operation["server_id"]),
            "operation",
            severity,
            str(operation["title"]),
            message,
            {"operation_id": operation_id, "status": status, "progress": progress},
        )

    def run_operation(
        operation_id: int,
        server_id: int,
        event_type: str,
        audit_message: str,
        action: Callable[[], dict[str, Any] | None],
    ) -> None:
        update_operation(operation_id, status="running", progress=15, message="Connecting to VPS")
        try:
            result = action() or {}
            update_operation(operation_id, status="success", progress=100, message="Completed successfully", result=result)
            audit_fn(event_type, "server", server_id, audit_message)
        except Exception as exc:  # background tasks must always settle their operation record
            message = str(exc) or exc.__class__.__name__
            update_operation(operation_id, status="failed", progress=100, message="Operation failed", error=message)
            audit_fn(f"{event_type}.failed", "server", server_id, f"{audit_message}: {message[:1000]}")

    def operation_response(operation_id: int) -> dict[str, Any]:
        return {"operation_id": operation_id, "status": "queued"}

    @app.get("/vps/{server_id}", response_class=HTMLResponse)
    def vps_dashboard(server_id: int) -> str:
        server_lookup(server_id)
        return dashboard_path.read_text(encoding="utf-8")

    @app.get("/api/vps/servers/{server_id}/state")
    def server_state(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        try:
            metrics = inspect_server(server)
            details_output = _run_remote(
                server,
                """
set -eu
printf 'hostname=%s\\n' "$(hostname)"
printf 'kernel=%s\\n' "$(uname -sr)"
printf 'architecture=%s\\n' "$(uname -m)"
printf 'uptime_seconds=%s\\n' "$(cut -d. -f1 /proc/uptime)"
printf 'os_name=%s\\n' "$(. /etc/os-release 2>/dev/null && printf '%s' \"${PRETTY_NAME:-Linux}\" || printf Linux)"
printf 'containers_running=%s\\n' "$(docker ps -q 2>/dev/null | wc -l)"
printf 'containers_total=%s\\n' "$(docker ps -aq 2>/dev/null | wc -l)"
printf 'failed_services=%s\\n' "$(systemctl --failed --type=service --no-legend 2>/dev/null | wc -l)"
printf 'reboot_required=%s\\n' "$([ -f /var/run/reboot-required ] && printf yes || printf no)"
""".strip(),
                timeout=30,
            )
            details: dict[str, str] = {}
            for line in details_output.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    details[key] = value
            state = "degraded" if int(details.get("failed_services", "0") or "0") > 0 else "online"
            return {
                "status": state,
                "server": {
                    "id": server["id"],
                    "name": server["name"],
                    "host": server["host"],
                    "port": server["port"],
                    "ssh_user": server["ssh_user"],
                },
                "metrics": metrics,
                "system": {
                    **details,
                    "uptime_seconds": int(details.get("uptime_seconds", "0") or "0"),
                    "containers_running": int(details.get("containers_running", "0") or "0"),
                    "containers_total": int(details.get("containers_total", "0") or "0"),
                    "failed_services": int(details.get("failed_services", "0") or "0"),
                    "reboot_required": details.get("reboot_required") == "yes",
                },
                "checked_at": utc_now(),
            }
        except Exception as exc:
            emit_event(server_id, "server", "error", "Server unreachable", str(exc))
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/operations")
    def list_operations(server_id: int, limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            rows = connection.execute(
                "SELECT * FROM server_operations WHERE server_id = ? ORDER BY id DESC LIMIT ?",
                (server_id, limit),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if item.get("result_json"):
                item["result"] = json.loads(item.pop("result_json"))
            else:
                item.pop("result_json", None)
                item["result"] = None
            result.append(item)
        return result

    @app.get("/api/vps/operations/{operation_id}")
    def get_operation(operation_id: int) -> dict[str, Any]:
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM server_operations WHERE id = ?", (operation_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Operation not found")
        item = dict(row)
        if item.get("result_json"):
            item["result"] = json.loads(item.pop("result_json"))
        else:
            item.pop("result_json", None)
            item["result"] = None
        return item

    @app.get("/api/vps/servers/{server_id}/events")
    def list_events(server_id: int, limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            rows = connection.execute(
                "SELECT * FROM server_events WHERE server_id = ? ORDER BY id DESC LIMIT ?",
                (server_id, limit),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if item.get("data_json"):
                item["data"] = json.loads(item.pop("data_json"))
            else:
                item.pop("data_json", None)
                item["data"] = None
            result.append(item)
        return result

    @app.get("/api/vps/servers/{server_id}/events/stream")
    async def event_stream(server_id: int, after_id: int = Query(default=0, ge=0)) -> StreamingResponse:
        server_lookup(server_id)

        async def generate():
            last_id = after_id
            while True:
                with db_factory() as connection:
                    rows = connection.execute(
                        "SELECT * FROM server_events WHERE server_id = ? AND id > ? ORDER BY id ASC LIMIT 100",
                        (server_id, last_id),
                    ).fetchall()
                if rows:
                    for row in rows:
                        item = dict(row)
                        last_id = int(item["id"])
                        if item.get("data_json"):
                            item["data"] = json.loads(item.pop("data_json"))
                        else:
                            item.pop("data_json", None)
                            item["data"] = None
                        yield f"id: {last_id}\nevent: server-event\ndata: {json.dumps(item)}\n\n"
                else:
                    yield ": keepalive\n\n"
                await asyncio.sleep(1.5)

        return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.get("/api/vps/servers/{server_id}/files")
    def list_files(server_id: int, path: str = Query(default="/")) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(path)
        quoted = shlex.quote(normalized)
        script = f"""
set -eu
path={quoted}
[ -d "$path" ] || {{ printf 'Not a directory: %s\\n' "$path" >&2; exit 44; }}
printf '__DIR__\\t%s\\t%s\\n' "$(stat -c '%a' -- "$path")" "$(stat -c '%U:%G' -- "$path")"
while IFS= read -r -d '' item; do
  name64=$(basename -- "$item" | base64 -w0)
  if [ -L "$item" ]; then kind=link; elif [ -d "$item" ]; then kind=directory; elif [ -f "$item" ]; then kind=file; else kind=other; fi
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \
    "$name64" "$kind" "$(stat -c '%s' -- "$item")" "$(stat -c '%A' -- "$item")" \
    "$(stat -c '%a' -- "$item")" "$(stat -c '%U' -- "$item")" "$(stat -c '%G' -- "$item")" "$(stat -c '%Y' -- "$item")"
done < <(find "$path" -mindepth 1 -maxdepth 1 -print0)
""".strip()
        try:
            output = _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=45)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        entries: list[dict[str, Any]] = []
        directory_meta: dict[str, Any] = {}
        for line in output.splitlines():
            parts = line.split("\t")
            if parts and parts[0] == "__DIR__" and len(parts) >= 3:
                directory_meta = {"mode": parts[1], "owner": parts[2]}
                continue
            if len(parts) != 8:
                continue
            name = _decode_name(parts[0])
            entries.append(
                {
                    "name": name,
                    "path": posixpath.join(normalized.rstrip("/") or "/", name),
                    "kind": parts[1],
                    "size": int(parts[2] or 0),
                    "permissions": parts[3],
                    "mode": parts[4],
                    "owner": parts[5],
                    "group": parts[6],
                    "modified_at": int(float(parts[7] or 0)),
                }
            )
        entries.sort(key=lambda item: (item["kind"] != "directory", item["name"].lower()))
        return {
            "path": normalized,
            "parent": None if normalized == "/" else posixpath.dirname(normalized) or "/",
            "directory": directory_meta,
            "entries": entries,
        }

    @app.get("/api/vps/servers/{server_id}/file")
    def read_file(server_id: int, path: str) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(path)
        quoted = shlex.quote(normalized)
        script = f"""
set -eu
path={quoted}
[ -f "$path" ] || {{ printf 'Not a regular file: %s\\n' "$path" >&2; exit 44; }}
size=$(stat -c '%s' -- "$path")
[ "$size" -le {MAX_EDITOR_BYTES} ] || {{ printf 'File is too large for browser editing (%s bytes).\\n' "$size" >&2; exit 45; }}
mime=$(command -v file >/dev/null 2>&1 && file -b --mime-type -- "$path" || printf application/octet-stream)
printf '__META__\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$size" "$mime" "$(stat -c '%a' -- "$path")" "$(stat -c '%U' -- "$path")" "$(stat -c '%G' -- "$path")"
base64 -w0 -- "$path"
""".strip()
        try:
            output = _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=30)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        first_line, _, encoded = output.partition("\n")
        meta = first_line.split("\t")
        if len(meta) != 6 or meta[0] != "__META__":
            raise HTTPException(status_code=502, detail="Unexpected VPS file response")
        raw = base64.b64decode(encoded.strip().encode("ascii")) if encoded.strip() else b""
        mime = meta[2]
        textual = mime.startswith("text/") or mime in {
            "application/json",
            "application/javascript",
            "application/xml",
            "application/x-yaml",
            "application/yaml",
        }
        content: str | None = None
        if textual or b"\x00" not in raw:
            try:
                content = raw.decode("utf-8")
                textual = True
            except UnicodeDecodeError:
                textual = False
        return {
            "path": normalized,
            "size": int(meta[1]),
            "mime": mime,
            "mode": meta[3],
            "owner": meta[4],
            "group": meta[5],
            "editable": textual,
            "content": content if textual else None,
        }

    @app.put("/api/vps/servers/{server_id}/file")
    def write_file(server_id: int, payload: FileWrite) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(payload.path)
        data = payload.content.encode("utf-8")
        if len(data) > MAX_EDITOR_BYTES:
            raise HTTPException(status_code=413, detail=f"Browser editor limit is {MAX_EDITOR_BYTES} bytes")
        encoded = base64.b64encode(data).decode("ascii")
        path_q = shlex.quote(normalized)
        encoded_q = shlex.quote(encoded)
        script = f"""
set -eu
path={path_q}
parent=$(dirname -- "$path")
[ -d "$parent" ] || {{ printf 'Parent directory does not exist.\\n' >&2; exit 44; }}
tmp="${{path}}.custom-github.tmp.$$"
trap 'rm -f -- "$tmp"' EXIT
printf '%s' {encoded_q} | base64 -d > "$tmp"
if [ -e "$path" ]; then
  chmod --reference="$path" "$tmp"
  chown --reference="$path" "$tmp" 2>/dev/null || true
else
  chmod 0644 "$tmp"
fi
mv -f -- "$tmp" "$path"
trap - EXIT
""".strip()
        try:
            _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=45)
        except RuntimeError as exc:
            emit_event(server_id, "filesystem", "error", "File save failed", f"{normalized}: {exc}")
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.file.saved", "server", server_id, normalized)
        emit_event(server_id, "filesystem", "success", "File saved", normalized)
        return {"status": "saved", "path": normalized, "bytes": len(data)}

    @app.post("/api/vps/servers/{server_id}/files", status_code=201)
    def create_file_or_directory(server_id: int, payload: FileCreate) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(payload.path)
        path_q = shlex.quote(normalized)
        command = f"mkdir -- {path_q}" if payload.kind == "directory" else f"( umask 022; : > {path_q} )"
        try:
            _run_remote(server, f"set -eu; [ ! -e {path_q} ] || {{ echo 'Path already exists' >&2; exit 46; }}; {command}")
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn(f"vps.{payload.kind}.created", "server", server_id, normalized)
        emit_event(server_id, "filesystem", "success", f"{payload.kind.title()} created", normalized)
        return {"status": "created", "path": normalized, "kind": payload.kind}

    @app.post("/api/vps/servers/{server_id}/files/move")
    def move_file(server_id: int, payload: FileMove) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        source = normalize_remote_path(payload.source)
        destination = normalize_remote_path(payload.destination)
        if source == "/" or deletion_is_protected(source):
            raise HTTPException(status_code=409, detail="This top-level system path cannot be moved")
        source_q = shlex.quote(source)
        destination_q = shlex.quote(destination)
        overwrite_guard = "" if payload.overwrite else f"[ ! -e {destination_q} ] || {{ echo 'Destination exists' >&2; exit 46; }}; "
        try:
            _run_remote(server, f"set -eu; {overwrite_guard}mv -- {source_q} {destination_q}", timeout=60)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.file.moved", "server", server_id, f"{source} -> {destination}")
        emit_event(server_id, "filesystem", "success", "Path moved", f"{source} → {destination}")
        return {"status": "moved", "source": source, "destination": destination}

    @app.post("/api/vps/servers/{server_id}/files/delete")
    def delete_file(server_id: int, payload: FileDelete) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(payload.path)
        if deletion_is_protected(normalized):
            raise HTTPException(status_code=409, detail="Deleting this protected top-level system path is blocked")
        if payload.permanent and payload.confirm_path != normalized:
            raise HTTPException(status_code=400, detail="Permanent deletion requires confirm_path to exactly match the target")
        path_q = shlex.quote(normalized)
        if payload.permanent:
            command = f"rm -rf -- {path_q}"
            status = "deleted"
        else:
            base = posixpath.basename(normalized) or "item"
            command = (
                "trash=\"$HOME/.custom-github-trash\"; mkdir -p -- \"$trash\"; "
                f"dest=\"$trash/$(date +%Y%m%d-%H%M%S)-$$-{shlex.quote(base)}\"; mv -- {path_q} \"$dest\"; printf '%s' \"$dest\""
            )
            status = "trashed"
        try:
            output = _run_remote(server, f"set -eu; [ -e {path_q} ] || [ -L {path_q} ] || {{ echo 'Path not found' >&2; exit 44; }}; {command}")
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn(f"vps.file.{status}", "server", server_id, normalized)
        emit_event(server_id, "filesystem", "warning" if payload.permanent else "info", f"Path {status}", normalized)
        return {"status": status, "path": normalized, "trash_path": output.strip() or None}

    @app.patch("/api/vps/servers/{server_id}/files/metadata")
    def update_file_metadata(server_id: int, payload: FileMetadata) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        normalized = normalize_remote_path(payload.path)
        path_q = shlex.quote(normalized)
        commands: list[str] = []
        if payload.mode:
            commands.append(f"chmod {shlex.quote(payload.mode)} -- {path_q}")
        if payload.owner or payload.group:
            owner_group = f"{payload.owner or ''}:{payload.group or ''}"
            commands.append(_sudo(f"chown {shlex.quote(owner_group)} -- {path_q}"))
        if not commands:
            raise HTTPException(status_code=400, detail="Provide mode, owner, or group")
        try:
            _run_remote(server, "set -eu; " + "; ".join(commands))
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.file.metadata", "server", server_id, normalized)
        emit_event(server_id, "filesystem", "success", "File metadata updated", normalized)
        return {"status": "updated", "path": normalized}

    @app.get("/api/vps/servers/{server_id}/docker/containers")
    def docker_containers(server_id: int) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id))
        try:
            output = _run_remote(server, "docker ps -a --no-trunc --format '{{json .}}'", timeout=30)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        rows: list[dict[str, Any]] = []
        for line in output.splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    @app.get("/api/vps/servers/{server_id}/docker/images")
    def docker_images(server_id: int) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id))
        try:
            output = _run_remote(server, "docker image ls -a --no-trunc --format '{{json .}}'", timeout=30)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        rows: list[dict[str, Any]] = []
        for line in output.splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    @app.get("/api/vps/servers/{server_id}/docker/storage")
    def docker_storage(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        try:
            output = _run_remote(server, "docker system df", timeout=30)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"raw": output}

    @app.get("/api/vps/servers/{server_id}/docker/containers/{container}/logs")
    def docker_logs(
        server_id: int,
        container: str,
        lines: int = Query(default=300, ge=1, le=MAX_LOG_LINES),
    ) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        target = _validate_container(container)
        try:
            output = _run_remote(server, f"docker logs --tail {lines} --timestamps {shlex.quote(target)} 2>&1", timeout=45)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"container": target, "lines": lines, "logs": output}

    @app.post("/api/vps/servers/{server_id}/docker/containers/{container}/action", status_code=202)
    def docker_action(
        server_id: int,
        container: str,
        payload: ContainerAction,
        background_tasks: BackgroundTasks,
    ) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        target = _validate_container(container)
        action = payload.action
        if action not in CONTAINER_ACTIONS:
            raise HTTPException(status_code=400, detail="Unsupported container action")
        title = f"{action.title()} container {target}"
        operation_id = create_operation(server_id, "docker.container", title)

        def task() -> dict[str, Any]:
            force = " -f" if action == "remove" and payload.force else ""
            command = f"docker rm{force} {shlex.quote(target)}" if action == "remove" else f"docker {action} {shlex.quote(target)}"
            output = _run_remote(server, command, timeout=120)
            return {"output": output.strip(), "container": target, "action": action}

        background_tasks.add_task(
            run_operation,
            operation_id,
            server_id,
            "vps.docker.container.action",
            f"{action} {target}",
            task,
        )
        return operation_response(operation_id)

    @app.get("/api/vps/servers/{server_id}/services")
    def services(server_id: int) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id))
        command = "systemctl list-units --type=service --all --no-legend --plain --no-pager | head -n 500"
        try:
            output = _run_remote(server, command, timeout=30)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        rows: list[dict[str, Any]] = []
        for line in output.splitlines():
            parts = line.strip().split(None, 4)
            if len(parts) >= 4:
                rows.append(
                    {
                        "unit": parts[0],
                        "load": parts[1],
                        "active": parts[2],
                        "sub": parts[3],
                        "description": parts[4] if len(parts) > 4 else "",
                    }
                )
        return rows

    @app.post("/api/vps/servers/{server_id}/services/{unit}/action", status_code=202)
    def service_action(
        server_id: int,
        unit: str,
        payload: ServiceAction,
        background_tasks: BackgroundTasks,
    ) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        service = _validate_unit(unit)
        action = payload.action
        if action not in SERVICE_ACTIONS:
            raise HTTPException(status_code=400, detail="Unsupported service action")
        operation_id = create_operation(server_id, "systemd", f"{action.title()} {service}")

        def task() -> dict[str, Any]:
            output = _run_remote(server, _sudo(f"systemctl {action} {shlex.quote(service)}"), timeout=120)
            status_output = _run_remote(
                server,
                f"systemctl show {shlex.quote(service)} --property=ActiveState,SubState --no-pager",
                timeout=20,
            )
            return {"output": output.strip(), "state": status_output.strip(), "service": service, "action": action}

        background_tasks.add_task(
            run_operation,
            operation_id,
            server_id,
            "vps.service.action",
            f"{action} {service}",
            task,
        )
        return operation_response(operation_id)

    @app.get("/api/vps/servers/{server_id}/processes")
    def processes(server_id: int, limit: int = Query(default=250, ge=20, le=1000)) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id))
        command = f"ps -eo pid=,ppid=,user=,pcpu=,pmem=,stat=,etimes=,comm=,args= --sort=-pcpu | head -n {limit + 1}"
        try:
            output = _run_remote(server, command, timeout=30)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        rows: list[dict[str, Any]] = []
        for line in output.splitlines():
            parts = line.strip().split(None, 8)
            if len(parts) < 8:
                continue
            rows.append(
                {
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]),
                    "user": parts[2],
                    "cpu": float(parts[3]),
                    "memory": float(parts[4]),
                    "state": parts[5],
                    "elapsed_seconds": int(parts[6]),
                    "command": parts[7],
                    "args": parts[8] if len(parts) > 8 else parts[7],
                }
            )
        return rows

    @app.post("/api/vps/servers/{server_id}/processes/{pid}/signal", status_code=202)
    def signal_process(
        server_id: int,
        pid: int,
        payload: ProcessAction,
        background_tasks: BackgroundTasks,
    ) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        target_pid = _validate_pid(pid)
        signal_name = payload.signal
        signal_number = PROCESS_SIGNALS[signal_name]
        operation_id = create_operation(server_id, "process", f"Send {signal_name} to PID {target_pid}")

        def task() -> dict[str, Any]:
            _run_remote(server, _sudo(f"kill -{signal_number} {target_pid}"), timeout=30)
            return {"pid": target_pid, "signal": signal_name}

        background_tasks.add_task(
            run_operation,
            operation_id,
            server_id,
            "vps.process.signal",
            f"{signal_name} PID {target_pid}",
            task,
        )
        return operation_response(operation_id)

    @app.get("/api/vps/servers/{server_id}/logs")
    def system_logs(
        server_id: int,
        unit: str | None = Query(default=None, max_length=180),
        priority: str | None = Query(default=None, pattern=r"^(emerg|alert|crit|err|warning|notice|info|debug|0|1|2|3|4|5|6|7)$"),
        lines: int = Query(default=300, ge=1, le=MAX_LOG_LINES),
    ) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        args = ["journalctl", "--no-pager", "--output=short-iso", "-n", str(lines)]
        if unit:
            args.extend(["-u", _validate_unit(unit)])
        if priority:
            args.extend(["-p", priority])
        command = " ".join(shlex.quote(value) for value in args)
        try:
            output = _run_remote(server, command, timeout=45)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"unit": unit, "priority": priority, "lines": lines, "logs": output}

    @app.get("/api/vps/servers/{server_id}/network")
    def network(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        script = """
set -eu
printf '%s\\n' '__ADDR__'
ip -brief address 2>/dev/null || true
printf '%s\\n' '__ROUTE__'
ip route 2>/dev/null || true
printf '%s\\n' '__LISTEN__'
ss -lntupH 2>/dev/null || true
""".strip()
        try:
            output = _run_remote(server, script, timeout=30)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        section = None
        result: dict[str, list[str]] = {"addresses": [], "routes": [], "listening": []}
        mapping = {"__ADDR__": "addresses", "__ROUTE__": "routes", "__LISTEN__": "listening"}
        for line in output.splitlines():
            if line in mapping:
                section = mapping[line]
            elif section and line.strip():
                result[section].append(line)
        return result

    def terminal_ssh_argv(server: dict[str, Any]) -> list[str]:
        args = [
            "ssh",
            "-tt",
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
            args.extend(["-i", str(identity)])
        args.append(f"{server['ssh_user']}@{server['host']}")
        return args

    @app.websocket("/api/vps/servers/{server_id}/terminal/ws")
    async def terminal_socket(websocket: WebSocket, server_id: int) -> None:
        await websocket.accept()
        try:
            server = dict(server_lookup(server_id))
            argv = terminal_ssh_argv(server)
        except Exception as exc:
            await websocket.send_json({"type": "error", "message": str(exc)})
            await websocket.close(code=1011)
            return

        master_fd, slave_fd = pty.openpty()
        process: subprocess.Popen[bytes] | None = None
        audit_fn("vps.terminal.opened", "server", server_id, f"Terminal session to {server['name']}")
        emit_event(server_id, "terminal", "info", "Terminal opened", f"{server['ssh_user']}@{server['host']}")

        try:
            process = subprocess.Popen(
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                start_new_session=True,
                close_fds=True,
            )
            os.close(slave_fd)
            slave_fd = -1

            async def reader() -> None:
                while True:
                    try:
                        data = await asyncio.to_thread(os.read, master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    await websocket.send_json({"type": "output", "data": data.decode("utf-8", errors="replace")})

            async def writer() -> None:
                while True:
                    message = await websocket.receive_json()
                    kind = message.get("type")
                    if kind == "input":
                        data = str(message.get("data", "")).encode("utf-8", errors="replace")
                        if data:
                            await asyncio.to_thread(os.write, master_fd, data)
                    elif kind == "resize":
                        cols = max(20, min(int(message.get("cols", 120)), 400))
                        rows = max(5, min(int(message.get("rows", 36)), 200))
                        winsize = struct.pack("HHHH", rows, cols, 0, 0)
                        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)

            reader_task = asyncio.create_task(reader())
            writer_task = asyncio.create_task(writer())
            done, pending = await asyncio.wait({reader_task, writer_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                try:
                    await task
                except WebSocketDisconnect:
                    pass
                except asyncio.CancelledError:
                    pass
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            try:
                await websocket.send_json({"type": "error", "message": str(exc)})
            except Exception:
                pass
        finally:
            if slave_fd >= 0:
                try:
                    os.close(slave_fd)
                except OSError:
                    pass
            try:
                os.close(master_fd)
            except OSError:
                pass
            if process and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    await asyncio.to_thread(process.wait, 3)
                except Exception:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except Exception:
                        pass
            audit_fn("vps.terminal.closed", "server", server_id, f"Terminal session closed for {server['name']}")
            emit_event(server_id, "terminal", "info", "Terminal closed", server["name"])
