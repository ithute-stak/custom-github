from __future__ import annotations

import json
import re
import shlex
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, model_validator

from app.deployment import inspect_server, ssh_command
from app.docker_cleanup import _docker_snapshot, _parse_snapshot


class MaintenanceSettings(BaseModel):
    warn_disk_percent: int = Field(default=80, ge=50, le=95)
    critical_disk_percent: int = Field(default=90, ge=55, le=98)
    warn_memory_percent: int = Field(default=85, ge=50, le=98)
    retention_releases: int = Field(default=2, ge=1, le=10)
    auto_cleanup_enabled: bool = False
    auto_cleanup_threshold_percent: int = Field(default=88, ge=60, le=98)
    auto_cleanup_build_cache: bool = True
    journal_retention_days: int = Field(default=14, ge=1, le=365)
    temp_retention_days: int = Field(default=7, ge=1, le=365)
    trash_retention_days: int = Field(default=30, ge=1, le=365)
    rotated_log_retention_days: int = Field(default=14, ge=1, le=365)
    schedule_enabled: bool = False
    schedule_weekday: int = Field(default=6, ge=0, le=6)
    schedule_hour: int = Field(default=3, ge=0, le=23)
    backup_watch_path: str | None = Field(default=None, max_length=4096)
    backup_max_age_hours: int = Field(default=48, ge=1, le=8760)

    @model_validator(mode="after")
    def validate_thresholds(self) -> "MaintenanceSettings":
        if self.critical_disk_percent <= self.warn_disk_percent:
            raise ValueError("critical_disk_percent must be greater than warn_disk_percent")
        if self.auto_cleanup_threshold_percent < self.warn_disk_percent:
            raise ValueError("auto_cleanup_threshold_percent must be at least warn_disk_percent")
        if self.backup_watch_path and not self.backup_watch_path.startswith("/"):
            raise ValueError("backup_watch_path must be an absolute path")
        return self


class CleanupRequest(BaseModel):
    confirm: bool = False
    docker_images: bool = True
    build_cache: bool = False
    apt_cache: bool = False
    journal: bool = False
    temp_files: bool = False
    trash: bool = False
    rotated_logs: bool = False


class LogCleanupRequest(BaseModel):
    confirm: bool = False
    journal: bool = True
    rotated_logs: bool = True
    docker_logs: list[str] = Field(default_factory=list, max_length=100)
    journal_retention_days: int = Field(default=14, ge=1, le=365)
    rotated_log_retention_days: int = Field(default=14, ge=1, le=365)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_remote(server: dict[str, Any], command: str, timeout: int = 120) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(output.strip()[-4000:] or f"Remote command failed with exit code {code}")
    return output


def _sudo(command: str) -> str:
    return f'if [ "$(id -u)" -eq 0 ]; then {command}; else sudo -n {command}; fi'


def _human_bytes_to_int(text: str) -> int:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?)(?:i?B)?", text, flags=re.I)
    if not match:
        return 0
    value = float(match.group(1))
    unit = match.group(2).upper()
    power = {"": 0, "K": 1, "M": 2, "G": 3, "T": 4, "P": 5, "E": 6}.get(unit, 0)
    return int(value * (1024**power))


def _deployment_protected_tags(connection: sqlite3.Connection, server_id: int, retention: int) -> set[str]:
    rows = connection.execute(
        """
        SELECT project_id, image_tag, previous_image
        FROM deployments
        WHERE server_id = ?
        ORDER BY project_id ASC, id DESC
        """,
        (server_id,),
    ).fetchall()
    protected: set[str] = set()
    seen: dict[int, int] = {}
    for row in rows:
        project_id = int(row["project_id"])
        count = seen.get(project_id, 0)
        if count >= retention:
            continue
        seen[project_id] = count + 1
        image = (row["image_tag"] or "").strip()
        previous = (row["previous_image"] or "").strip()
        if image:
            protected.add(image)
        if previous:
            protected.add(previous)
    return protected


def _parse_disk_analysis(output: str) -> dict[str, Any]:
    section: str | None = None
    result: dict[str, Any] = {
        "filesystem": {},
        "top_directories": [],
        "special": {},
        "largest_files": [],
        "journal_raw": "",
    }
    markers = {
        "__DF__": "df",
        "__TOP__": "top",
        "__SPECIAL__": "special",
        "__LARGEST__": "largest",
        "__JOURNAL__": "journal",
    }
    for raw in output.splitlines():
        if raw in markers:
            section = markers[raw]
            continue
        if section == "df":
            parts = raw.split("\t")
            if len(parts) == 5 and parts[0].isdigit():
                result["filesystem"] = {
                    "total_bytes": int(parts[0]),
                    "used_bytes": int(parts[1]),
                    "available_bytes": int(parts[2]),
                    "used_percent": int(parts[3].rstrip("%")),
                    "mountpoint": parts[4],
                }
        elif section == "top":
            parts = raw.split("\t", 1)
            if len(parts) == 2 and parts[0].isdigit():
                result["top_directories"].append({"bytes": int(parts[0]), "path": parts[1]})
        elif section == "special":
            parts = raw.split("\t", 1)
            if len(parts) == 2 and parts[1].isdigit():
                result["special"][parts[0]] = int(parts[1])
        elif section == "largest":
            parts = raw.split("\t", 1)
            if len(parts) == 2 and parts[0].isdigit():
                result["largest_files"].append({"bytes": int(parts[0]), "path": parts[1]})
        elif section == "journal":
            result["journal_raw"] += raw + "\n"
    result["journal_raw"] = result["journal_raw"].strip()
    result["top_directories"].sort(key=lambda item: item["bytes"], reverse=True)
    result["largest_files"].sort(key=lambda item: item["bytes"], reverse=True)
    result["largest_files"] = result["largest_files"][:25]
    return result


def _disk_analysis(server: dict[str, Any]) -> dict[str, Any]:
    script = r"""
set -u
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@" 2>/dev/null || "$@" 2>/dev/null; fi; }
printf '%s\n' '__DF__'
df -B1 -P / | awk 'NR==2 {print $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6}'
printf '%s\n' '__TOP__'
for p in /var /home /opt /srv /usr /tmp /root; do
  [ -e "$p" ] || continue
  as_root du -sx -B1 "$p" 2>/dev/null | awk '{print $1 "\t" $2}' || true
done
printf '%s\n' '__SPECIAL__'
for spec in "logs:/var/log" "apt:/var/cache/apt/archives" "docker:/var/lib/docker" "trash:$HOME/.custom-github-trash"; do
  key=${spec%%:*}; path=${spec#*:}
  if [ -e "$path" ]; then
    bytes=$(as_root du -sx -B1 "$path" 2>/dev/null | awk '{print $1}' | head -1)
    printf '%s\t%s\n' "$key" "${bytes:-0}"
  else
    printf '%s\t0\n' "$key"
  fi
done
printf '%s\n' '__LARGEST__'
for base in /var/log /opt /home /srv; do
  [ -e "$base" ] || continue
  as_root find "$base" -xdev -type f -printf '%s\t%p\n' 2>/dev/null || true
done | sort -nr | head -n 25
printf '%s\n' '__JOURNAL__'
journalctl --disk-usage 2>/dev/null || true
""".strip()
    return _parse_disk_analysis(_run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=180))


def _cleanup_preview(server: dict[str, Any], settings: dict[str, Any], protected_tags: set[str]) -> dict[str, Any]:
    docker = _parse_snapshot(_docker_snapshot(server), protected_tags)
    temp_days = int(settings["temp_retention_days"])
    trash_days = int(settings["trash_retention_days"])
    rotated_days = int(settings["rotated_log_retention_days"])
    script = f"""
set -u
as_root() {{ if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@" 2>/dev/null || "$@" 2>/dev/null; fi; }}
sum_find() {{
  path="$1"; days="$2"
  if [ -e "$path" ]; then
    as_root find "$path" -xdev -type f -mtime "+$days" -printf '%s\\n' 2>/dev/null | awk '{{s+=$1}} END {{print s+0}}'
  else
    printf '0\\n'
  fi
}}
apt_bytes=$(as_root du -sx -B1 /var/cache/apt/archives 2>/dev/null | awk '{{print $1}}' | head -1)
printf 'apt_cache\\t%s\\n' "${{apt_bytes:-0}}"
printf 'temp_files\\t%s\\n' "$(sum_find /tmp {temp_days})"
printf 'trash\\t%s\\n' "$(sum_find "$HOME/.custom-github-trash" {trash_days})"
rotated=$(as_root find /var/log -xdev -type f -mtime "+{rotated_days}" \\( -name '*.gz' -o -name '*.1' -o -name '*.old' \\) -printf '%s\\n' 2>/dev/null | awk '{{s+=$1}} END {{print s+0}}')
printf 'rotated_logs\\t%s\\n' "${{rotated:-0}}"
printf '__JOURNAL__\\n'
journalctl --disk-usage 2>/dev/null || true
""".strip()
    output = _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=90)
    categories: dict[str, int] = {}
    journal_raw = ""
    in_journal = False
    for line in output.splitlines():
        if line == "__JOURNAL__":
            in_journal = True
            continue
        if in_journal:
            journal_raw += line + "\n"
        else:
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[1].isdigit():
                categories[parts[0]] = int(parts[1])
    categories["journal"] = _human_bytes_to_int(journal_raw)
    categories["docker_images"] = int(docker["estimated_reclaimable_bytes"])
    return {
        "categories": categories,
        "estimated_reclaimable_bytes": sum(categories.values()),
        "docker": docker,
        "journal_raw": journal_raw.strip(),
        "note": "Estimates can overstate actual reclaimed disk when Docker layers are shared.",
    }


def _log_storage(server: dict[str, Any]) -> dict[str, Any]:
    script = r"""
set -u
printf '%s\n' '__CONTAINERS__'
for id in $(docker ps -aq); do
  name=$(docker inspect --format '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
  log=$(docker inspect --format '{{.LogPath}}' "$id" 2>/dev/null)
  driver=$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$id" 2>/dev/null)
  bytes=0
  [ -n "$log" ] && [ -e "$log" ] && bytes=$(stat -c '%s' "$log" 2>/dev/null || printf 0)
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$name" "$driver" "${bytes:-0}" "$log"
done
printf '%s\n' '__VARLOG__'
for p in /var/log/*; do
  [ -e "$p" ] || continue
  bytes=$(du -sx -B1 "$p" 2>/dev/null | awk '{print $1}' | head -1)
  printf '%s\t%s\n' "${bytes:-0}" "$p"
done
printf '%s\n' '__JOURNAL__'
journalctl --disk-usage 2>/dev/null || true
""".strip()
    output = _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=90)
    section = None
    containers: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    journal_raw = ""
    for line in output.splitlines():
        if line == "__CONTAINERS__":
            section = "containers"
            continue
        if line == "__VARLOG__":
            section = "varlog"
            continue
        if line == "__JOURNAL__":
            section = "journal"
            continue
        if section == "containers":
            parts = line.split("\t", 4)
            if len(parts) == 5:
                containers.append({"id": parts[0], "name": parts[1], "driver": parts[2], "bytes": int(parts[3] or 0), "path": parts[4]})
        elif section == "varlog":
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[0].isdigit():
                files.append({"bytes": int(parts[0]), "path": parts[1]})
        elif section == "journal":
            journal_raw += line + "\n"
    containers.sort(key=lambda item: item["bytes"], reverse=True)
    files.sort(key=lambda item: item["bytes"], reverse=True)
    return {"containers": containers, "var_log": files, "journal_raw": journal_raw.strip(), "journal_bytes": _human_bytes_to_int(journal_raw)}


def _container_stats(server: dict[str, Any]) -> list[dict[str, Any]]:
    stats = []
    for line in _run_remote(server, "docker stats --no-stream --format '{{json .}}'", timeout=45).splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            stats.append(item)
    inspect_script = r"""
ids=$(docker ps -aq)
[ -n "$ids" ] || exit 0
docker inspect --format '{{.Id}}\t{{.Name}}\t{{.RestartCount}}\t{{.State.Status}}' $ids 2>/dev/null
""".strip()
    metadata: dict[str, dict[str, Any]] = {}
    for line in _run_remote(server, f"bash -lc {shlex.quote(inspect_script)}", timeout=45).splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            metadata[parts[1].lstrip("/")] = {"id": parts[0], "restart_count": int(parts[2] or 0), "state": parts[3]}
    for item in stats:
        name = str(item.get("Name") or item.get("Container") or "")
        item.update(metadata.get(name, {}))
    return stats


def _health_snapshot(server: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    metrics = inspect_server(server)
    script = r"""
set -u
printf 'failed_services=%s\n' "$(systemctl --failed --type=service --no-legend 2>/dev/null | wc -l)"
printf 'reboot_required=%s\n' "$([ -f /var/run/reboot-required ] && printf yes || printf no)"
printf '%s\n' '__RESTARTS__'
for id in $(docker ps -aq); do
  docker inspect --format '{{.Name}}\t{{.RestartCount}}\t{{.State.Status}}' "$id" 2>/dev/null || true
done
printf '%s\n' '__CERTS__'
for cert in /etc/letsencrypt/live/*/fullchain.pem; do
  [ -f "$cert" ] || continue
  name=$(basename "$(dirname "$cert")")
  end=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2-)
  epoch=$(date -d "$end" +%s 2>/dev/null || printf 0)
  printf '%s\t%s\n' "$name" "$epoch"
done
""".strip()
    output = _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=60)
    failed_services = 0
    reboot_required = False
    section = None
    restarts: list[dict[str, Any]] = []
    certificates: list[dict[str, Any]] = []
    now_epoch = int(time.time())
    for line in output.splitlines():
        if line.startswith("failed_services="):
            failed_services = int(line.split("=", 1)[1] or 0)
        elif line.startswith("reboot_required="):
            reboot_required = line.split("=", 1)[1] == "yes"
        elif line == "__RESTARTS__":
            section = "restarts"
        elif line == "__CERTS__":
            section = "certs"
        elif section == "restarts":
            parts = line.split("\t")
            if len(parts) >= 3:
                restarts.append({"name": parts[0].lstrip("/"), "restart_count": int(parts[1] or 0), "state": parts[2]})
        elif section == "certs":
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[1].isdigit():
                expiry = int(parts[1])
                certificates.append({"name": parts[0], "expires_epoch": expiry, "days_remaining": int((expiry - now_epoch) / 86400)})

    backup: dict[str, Any] | None = None
    backup_path = settings.get("backup_watch_path")
    if backup_path:
        quoted = shlex.quote(str(backup_path))
        backup_script = f"path={quoted}; if [ -e \"$path\" ]; then find \"$path\" -type f -printf '%T@\\t%p\\n' 2>/dev/null | sort -nr | head -1; fi"
        raw = _run_remote(server, f"bash -lc {shlex.quote(backup_script)}", timeout=45).strip()
        if raw:
            ts, _, path = raw.partition("\t")
            try:
                epoch = float(ts)
            except ValueError:
                epoch = 0.0
            backup = {"path": path, "age_hours": round(max(0.0, (time.time() - epoch) / 3600), 1), "max_age_hours": int(settings["backup_max_age_hours"])}
        else:
            backup = {"path": None, "age_hours": None, "max_age_hours": int(settings["backup_max_age_hours"])}

    alerts: list[dict[str, str]] = []
    score = 100
    disk = int(metrics["disk_used_percent"])
    mem = float(metrics["memory_used_percent"])
    load_per_cpu = float(metrics["load_1"]) / max(int(metrics["cpu_count"]), 1)
    if disk >= int(settings["critical_disk_percent"]):
        score -= 35
        alerts.append({"severity": "critical", "title": "Disk critically full", "message": f"Root disk is {disk}% used."})
    elif disk >= int(settings["warn_disk_percent"]):
        score -= 15
        alerts.append({"severity": "warning", "title": "Disk usage high", "message": f"Root disk is {disk}% used."})
    if mem >= float(settings["warn_memory_percent"]):
        score -= 15
        alerts.append({"severity": "warning", "title": "Memory usage high", "message": f"Memory is {mem:.1f}% used."})
    if load_per_cpu >= 1.5:
        score -= 15
        alerts.append({"severity": "warning", "title": "CPU load high", "message": f"1-minute load per CPU is {load_per_cpu:.2f}."})
    elif load_per_cpu >= 1.0:
        score -= 8
        alerts.append({"severity": "info", "title": "CPU load elevated", "message": f"1-minute load per CPU is {load_per_cpu:.2f}."})
    if failed_services:
        score -= min(20, failed_services * 5)
        alerts.append({"severity": "critical" if failed_services >= 3 else "warning", "title": "Failed services", "message": f"{failed_services} systemd service(s) failed."})
    if reboot_required:
        score -= 5
        alerts.append({"severity": "info", "title": "Reboot required", "message": "The operating system reports a pending reboot."})
    noisy = [row for row in restarts if int(row["restart_count"]) >= 5]
    if noisy:
        score -= min(15, len(noisy) * 5)
        alerts.append({"severity": "warning", "title": "Container restart activity", "message": f"{len(noisy)} container(s) have restarted at least 5 times."})
    expiring = [cert for cert in certificates if cert["days_remaining"] <= 30]
    if expiring:
        worst = min(cert["days_remaining"] for cert in expiring)
        score -= 15 if worst <= 7 else 5
        alerts.append({"severity": "critical" if worst <= 7 else "warning", "title": "SSL certificate expiry", "message": f"A certificate expires in {worst} day(s)."})
    if backup is not None:
        age = backup.get("age_hours")
        max_age = int(backup["max_age_hours"])
        if age is None or float(age) > max_age:
            score -= 15
            alerts.append({"severity": "warning", "title": "Backup is stale or missing", "message": f"No backup newer than {max_age} hour(s) was found in the configured backup path."})
    score = max(0, min(100, score))
    state = "healthy" if score >= 90 else "attention" if score >= 70 else "critical"
    return {
        "score": score,
        "state": state,
        "alerts": alerts,
        "metrics": metrics,
        "failed_services": failed_services,
        "reboot_required": reboot_required,
        "containers": restarts,
        "certificates": certificates,
        "backup": backup,
        "checked_at": _utc_now(),
    }


def install_maintenance_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
    app_root: Path,
) -> None:
    page_path = app_root / "app" / "static" / "maintenance.html"
    scheduler_started = False
    scheduler_lock = threading.Lock()

    def init_db() -> None:
        with db_factory() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS server_maintenance_settings (
                    server_id INTEGER PRIMARY KEY,
                    warn_disk_percent INTEGER NOT NULL DEFAULT 80,
                    critical_disk_percent INTEGER NOT NULL DEFAULT 90,
                    warn_memory_percent INTEGER NOT NULL DEFAULT 85,
                    retention_releases INTEGER NOT NULL DEFAULT 2,
                    auto_cleanup_enabled INTEGER NOT NULL DEFAULT 0,
                    auto_cleanup_threshold_percent INTEGER NOT NULL DEFAULT 88,
                    auto_cleanup_build_cache INTEGER NOT NULL DEFAULT 1,
                    journal_retention_days INTEGER NOT NULL DEFAULT 14,
                    temp_retention_days INTEGER NOT NULL DEFAULT 7,
                    trash_retention_days INTEGER NOT NULL DEFAULT 30,
                    rotated_log_retention_days INTEGER NOT NULL DEFAULT 14,
                    schedule_enabled INTEGER NOT NULL DEFAULT 0,
                    schedule_weekday INTEGER NOT NULL DEFAULT 6,
                    schedule_hour INTEGER NOT NULL DEFAULT 3,
                    backup_watch_path TEXT,
                    backup_max_age_hours INTEGER NOT NULL DEFAULT 48,
                    last_scheduled_run_at TEXT,
                    last_auto_cleanup_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(server_id) REFERENCES servers(id)
                );
                CREATE TABLE IF NOT EXISTS server_metric_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    disk_used_percent REAL NOT NULL,
                    disk_available_mb INTEGER NOT NULL,
                    memory_used_percent REAL NOT NULL,
                    memory_available_mb INTEGER NOT NULL,
                    load_1 REAL NOT NULL,
                    cpu_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(server_id) REFERENCES servers(id)
                );
                CREATE INDEX IF NOT EXISTS idx_server_metric_samples ON server_metric_samples(server_id, id DESC);
                """
            )

    def ensure_settings(server_id: int) -> dict[str, Any]:
        server_lookup(server_id)
        now = _utc_now()
        with db_factory() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO server_maintenance_settings(server_id, created_at, updated_at) VALUES (?, ?, ?)",
                (server_id, now, now),
            )
            row = connection.execute("SELECT * FROM server_maintenance_settings WHERE server_id = ?", (server_id,)).fetchone()
        assert row is not None
        item = dict(row)
        for key in ("auto_cleanup_enabled", "auto_cleanup_build_cache", "schedule_enabled"):
            item[key] = bool(item[key])
        return item

    def save_settings(server_id: int, payload: MaintenanceSettings) -> dict[str, Any]:
        ensure_settings(server_id)
        data = payload.model_dump()
        with db_factory() as connection:
            connection.execute(
                """
                UPDATE server_maintenance_settings
                SET warn_disk_percent=?, critical_disk_percent=?, warn_memory_percent=?, retention_releases=?,
                    auto_cleanup_enabled=?, auto_cleanup_threshold_percent=?, auto_cleanup_build_cache=?,
                    journal_retention_days=?, temp_retention_days=?, trash_retention_days=?, rotated_log_retention_days=?,
                    schedule_enabled=?, schedule_weekday=?, schedule_hour=?, backup_watch_path=?, backup_max_age_hours=?, updated_at=?
                WHERE server_id=?
                """,
                (
                    data["warn_disk_percent"], data["critical_disk_percent"], data["warn_memory_percent"], data["retention_releases"],
                    int(data["auto_cleanup_enabled"]), data["auto_cleanup_threshold_percent"], int(data["auto_cleanup_build_cache"]),
                    data["journal_retention_days"], data["temp_retention_days"], data["trash_retention_days"], data["rotated_log_retention_days"],
                    int(data["schedule_enabled"]), data["schedule_weekday"], data["schedule_hour"], data["backup_watch_path"],
                    data["backup_max_age_hours"], _utc_now(), server_id,
                ),
            )
        audit_fn("vps.maintenance.settings", "server", server_id, "Updated VPS maintenance settings")
        return ensure_settings(server_id)

    def protected_tags(server_id: int) -> set[str]:
        settings = ensure_settings(server_id)
        with db_factory() as connection:
            return _deployment_protected_tags(connection, server_id, int(settings["retention_releases"]))

    def emit_event(server_id: int, severity: str, title: str, message: str, data: dict[str, Any] | None = None) -> None:
        with db_factory() as connection:
            connection.execute(
                "INSERT INTO server_events(server_id, category, severity, title, message, data_json, created_at) VALUES (?, 'maintenance', ?, ?, ?, ?, ?)",
                (server_id, severity, title[:240], message[:4000], json.dumps(data) if data else None, _utc_now()),
            )

    def create_operation(server_id: int, title: str, kind: str = "maintenance.cleanup") -> int:
        with db_factory() as connection:
            cursor = connection.execute(
                "INSERT INTO server_operations(server_id, kind, title, status, progress, message, created_at) VALUES (?, ?, ?, 'queued', 0, 'Queued', ?)",
                (server_id, kind, title[:240], _utc_now()),
            )
            operation_id = int(cursor.lastrowid)
        emit_event(server_id, "info", title, "Queued", {"operation_id": operation_id, "status": "queued"})
        return operation_id

    def update_operation(operation_id: int, server_id: int, *, status: str, progress: int, message: str, result: dict[str, Any] | None = None, error: str | None = None) -> None:
        now = _utc_now()
        with db_factory() as connection:
            connection.execute(
                """
                UPDATE server_operations SET status=?, progress=?, message=?, result_json=?, error=?,
                    started_at=COALESCE(started_at, ?), finished_at=CASE WHEN ? IN ('success','failed') THEN ? ELSE finished_at END
                WHERE id=?
                """,
                (status, max(0, min(progress, 100)), message[:2000], json.dumps(result) if result is not None else None,
                 error[:4000] if error else None, now if status == "running" else None, status, now, operation_id),
            )
        severity = "success" if status == "success" else "error" if status == "failed" else "info"
        emit_event(server_id, severity, "Maintenance operation", message, {"operation_id": operation_id, "status": status, "progress": progress})

    def record_sample(server_id: int, metrics: dict[str, Any]) -> None:
        with db_factory() as connection:
            last = connection.execute("SELECT created_at FROM server_metric_samples WHERE server_id=? ORDER BY id DESC LIMIT 1", (server_id,)).fetchone()
            if last:
                try:
                    if datetime.now(timezone.utc) - datetime.fromisoformat(last["created_at"]) < timedelta(minutes=5):
                        return
                except Exception:
                    pass
            connection.execute(
                """
                INSERT INTO server_metric_samples(server_id, disk_used_percent, disk_available_mb, memory_used_percent,
                    memory_available_mb, load_1, cpu_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (server_id, float(metrics["disk_used_percent"]), int(metrics["disk_available_mb"]), float(metrics["memory_used_percent"]),
                 int(metrics["mem_available_mb"]), float(metrics["load_1"]), int(metrics["cpu_count"]), _utc_now()),
            )

    def cleanup_job(server_id: int, request: CleanupRequest, operation_id: int) -> None:
        server = dict(server_lookup(server_id))
        settings = ensure_settings(server_id)
        try:
            update_operation(operation_id, server_id, status="running", progress=5, message="Analyzing cleanup candidates")
            analysis = _cleanup_preview(server, settings, protected_tags(server_id))
            removed_images: list[str] = []
            skipped_images: list[dict[str, str]] = []
            actions: list[str] = []
            if request.docker_images:
                candidates = analysis["docker"]["candidates"]
                update_operation(operation_id, server_id, status="running", progress=20, message=f"Removing {len(candidates)} unused Docker image(s)")
                for item in candidates:
                    image_id = str(item["id"])
                    code, output = ssh_command(server, f"docker image rm {shlex.quote(image_id)}", timeout=120)
                    if code == 0:
                        removed_images.append(image_id)
                    else:
                        skipped_images.append({"id": image_id, "reason": output.strip()[-1200:]})
                actions.append(f"docker images: {len(removed_images)} removed")
            if request.build_cache:
                update_operation(operation_id, server_id, status="running", progress=40, message="Cleaning old Docker build cache")
                _run_remote(server, "docker builder prune -af --filter until=168h", timeout=300)
                actions.append("Docker build cache")
            if request.apt_cache:
                update_operation(operation_id, server_id, status="running", progress=55, message="Cleaning APT package cache")
                _run_remote(server, _sudo("apt-get clean"), timeout=180)
                actions.append("APT cache")
            if request.journal:
                days = int(settings["journal_retention_days"])
                update_operation(operation_id, server_id, status="running", progress=65, message=f"Vacuuming journal older than {days} days")
                _run_remote(server, _sudo(f"journalctl --vacuum-time={days}d"), timeout=180)
                actions.append(f"journal > {days}d")
            if request.temp_files:
                days = int(settings["temp_retention_days"])
                update_operation(operation_id, server_id, status="running", progress=75, message=f"Removing /tmp files older than {days} days")
                _run_remote(server, _sudo(f"find /tmp -xdev -type f -mtime +{days} -delete"), timeout=180)
                actions.append(f"/tmp files > {days}d")
            if request.trash:
                days = int(settings["trash_retention_days"])
                update_operation(operation_id, server_id, status="running", progress=85, message=f"Emptying Custom GitHub trash older than {days} days")
                command = f'if [ -d "$HOME/.custom-github-trash" ]; then find "$HOME/.custom-github-trash" -xdev -type f -mtime +{days} -delete; find "$HOME/.custom-github-trash" -xdev -type d -empty -delete 2>/dev/null || true; fi'
                _run_remote(server, f"bash -lc {shlex.quote(command)}", timeout=180)
                actions.append(f"Custom GitHub trash > {days}d")
            if request.rotated_logs:
                days = int(settings["rotated_log_retention_days"])
                inner = f"find /var/log -xdev -type f -mtime +{days} \\( -name '*.gz' -o -name '*.1' -o -name '*.old' \\) -delete"
                _run_remote(server, _sudo(inner), timeout=180)
                actions.append(f"rotated logs > {days}d")
            after = _cleanup_preview(server, settings, protected_tags(server_id))
            result = {"actions": actions, "removed_images": removed_images, "skipped_images": skipped_images,
                      "before_estimated_bytes": analysis["estimated_reclaimable_bytes"], "after_estimated_bytes": after["estimated_reclaimable_bytes"]}
            update_operation(operation_id, server_id, status="success", progress=100, message="Maintenance cleanup completed", result=result)
            audit_fn("vps.maintenance.cleanup", "server", server_id, "; ".join(actions) or "No cleanup categories selected")
        except Exception as exc:
            message = str(exc) or exc.__class__.__name__
            update_operation(operation_id, server_id, status="failed", progress=100, message="Maintenance cleanup failed", error=message)
            audit_fn("vps.maintenance.cleanup.failed", "server", server_id, message[:1000])

    def maybe_auto_cleanup(server_id: int, settings: dict[str, Any]) -> None:
        if not settings["auto_cleanup_enabled"]:
            return
        server = dict(server_lookup(server_id))
        metrics = inspect_server(server)
        record_sample(server_id, metrics)
        if int(metrics["disk_used_percent"]) < int(settings["auto_cleanup_threshold_percent"]):
            return
        last_raw = settings.get("last_auto_cleanup_at")
        if last_raw:
            try:
                if datetime.now(timezone.utc) - datetime.fromisoformat(last_raw) < timedelta(hours=6):
                    return
            except Exception:
                pass
        with db_factory() as connection:
            connection.execute("UPDATE server_maintenance_settings SET last_auto_cleanup_at=?, updated_at=? WHERE server_id=?", (_utc_now(), _utc_now(), server_id))
        operation_id = create_operation(server_id, "Automatic disk-pressure cleanup", "maintenance.auto_cleanup")
        cleanup_job(server_id, CleanupRequest(confirm=True, docker_images=True, build_cache=bool(settings["auto_cleanup_build_cache"]),
                    apt_cache=True, journal=True, trash=True, rotated_logs=True), operation_id)

    def maybe_scheduled(server_id: int, settings: dict[str, Any], local_now: datetime) -> None:
        if not settings["schedule_enabled"]:
            return
        if local_now.weekday() != int(settings["schedule_weekday"]) or local_now.hour != int(settings["schedule_hour"]):
            return
        last_raw = settings.get("last_scheduled_run_at")
        if last_raw:
            try:
                if datetime.fromisoformat(last_raw).astimezone().date() == local_now.date():
                    return
            except Exception:
                pass
        with db_factory() as connection:
            connection.execute("UPDATE server_maintenance_settings SET last_scheduled_run_at=?, updated_at=? WHERE server_id=?", (_utc_now(), _utc_now(), server_id))
        operation_id = create_operation(server_id, "Scheduled VPS maintenance", "maintenance.scheduled")
        cleanup_job(server_id, CleanupRequest(confirm=True, docker_images=True, build_cache=True, apt_cache=True,
                    journal=True, temp_files=True, trash=True, rotated_logs=True), operation_id)

    def scheduler_loop() -> None:
        while True:
            try:
                local_now = datetime.now().astimezone()
                with db_factory() as connection:
                    rows = connection.execute("SELECT server_id FROM server_maintenance_settings").fetchall()
                for row in rows:
                    server_id = int(row["server_id"])
                    try:
                        settings = ensure_settings(server_id)
                        with db_factory() as connection:
                            last = connection.execute("SELECT created_at FROM server_metric_samples WHERE server_id=? ORDER BY id DESC LIMIT 1", (server_id,)).fetchone()
                        should_sample = True
                        if last:
                            try:
                                should_sample = datetime.now(timezone.utc) - datetime.fromisoformat(last["created_at"]) >= timedelta(minutes=55)
                            except Exception:
                                pass
                        if should_sample:
                            record_sample(server_id, inspect_server(dict(server_lookup(server_id))))
                        maybe_auto_cleanup(server_id, settings)
                        maybe_scheduled(server_id, settings, local_now)
                    except Exception as exc:
                        emit_event(server_id, "error", "Maintenance scheduler error", str(exc))
            except Exception:
                pass
            time.sleep(60)

    @app.on_event("startup")
    def startup_maintenance() -> None:
        nonlocal scheduler_started
        init_db()
        with scheduler_lock:
            if not scheduler_started:
                scheduler_started = True
                threading.Thread(target=scheduler_loop, name="custom-github-maintenance", daemon=True).start()

    @app.get("/vps/{server_id}/maintenance", response_class=HTMLResponse, include_in_schema=False)
    def maintenance_page(server_id: int) -> str:
        server_lookup(server_id)
        return page_path.read_text(encoding="utf-8")

    @app.get("/api/vps/servers/{server_id}/maintenance/settings")
    def get_settings(server_id: int) -> dict[str, Any]:
        return ensure_settings(server_id)

    @app.put("/api/vps/servers/{server_id}/maintenance/settings")
    def update_settings(server_id: int, payload: MaintenanceSettings) -> dict[str, Any]:
        return save_settings(server_id, payload)

    @app.get("/api/vps/servers/{server_id}/maintenance/disk")
    def disk_analyzer(server_id: int) -> dict[str, Any]:
        try:
            return _disk_analysis(dict(server_lookup(server_id)))
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/maintenance/cleanup/preview")
    def cleanup_preview(server_id: int) -> dict[str, Any]:
        settings = ensure_settings(server_id)
        try:
            return _cleanup_preview(dict(server_lookup(server_id)), settings, protected_tags(server_id))
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.post("/api/vps/servers/{server_id}/maintenance/cleanup", status_code=202)
    def cleanup(server_id: int, payload: CleanupRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        if not payload.confirm:
            raise HTTPException(status_code=400, detail="Maintenance cleanup requires explicit confirmation")
        server_lookup(server_id)
        if not any((payload.docker_images, payload.build_cache, payload.apt_cache, payload.journal, payload.temp_files, payload.trash, payload.rotated_logs)):
            raise HTTPException(status_code=400, detail="Select at least one cleanup category")
        operation_id = create_operation(server_id, "Smart storage cleanup")
        background_tasks.add_task(cleanup_job, server_id, payload, operation_id)
        return {"operation_id": operation_id, "status": "queued"}

    @app.get("/api/vps/servers/{server_id}/maintenance/containers")
    def container_resources(server_id: int) -> list[dict[str, Any]]:
        try:
            return _container_stats(dict(server_lookup(server_id)))
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/maintenance/logs")
    def log_storage(server_id: int) -> dict[str, Any]:
        try:
            return _log_storage(dict(server_lookup(server_id)))
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.post("/api/vps/servers/{server_id}/maintenance/logs/cleanup", status_code=202)
    def cleanup_logs(server_id: int, payload: LogCleanupRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        if not payload.confirm:
            raise HTTPException(status_code=400, detail="Log cleanup requires explicit confirmation")
        server = dict(server_lookup(server_id))
        operation_id = create_operation(server_id, "Log cleanup", "maintenance.logs")

        def task() -> None:
            try:
                update_operation(operation_id, server_id, status="running", progress=10, message="Cleaning selected logs")
                actions: list[str] = []
                if payload.journal:
                    _run_remote(server, _sudo(f"journalctl --vacuum-time={int(payload.journal_retention_days)}d"), timeout=180)
                    actions.append("system journal")
                if payload.rotated_logs:
                    days = int(payload.rotated_log_retention_days)
                    inner = f"find /var/log -xdev -type f -mtime +{days} \\( -name '*.gz' -o -name '*.1' -o -name '*.old' \\) -delete"
                    _run_remote(server, _sudo(inner), timeout=180)
                    actions.append("rotated logs")
                for name in payload.docker_logs:
                    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
                        raise RuntimeError(f"Invalid Docker container name: {name}")
                    path = _run_remote(server, f"docker inspect --format '{{{{.LogPath}}}}' {shlex.quote(name)}", timeout=30).strip()
                    if path:
                        _run_remote(server, _sudo(f"truncate -s 0 -- {shlex.quote(path)}"), timeout=60)
                        actions.append(f"container log {name}")
                after = _log_storage(server)
                update_operation(operation_id, server_id, status="success", progress=100, message="Log cleanup completed", result={"actions": actions, "after": after})
                audit_fn("vps.maintenance.logs", "server", server_id, "; ".join(actions) or "No log changes")
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                update_operation(operation_id, server_id, status="failed", progress=100, message="Log cleanup failed", error=message)
                audit_fn("vps.maintenance.logs.failed", "server", server_id, message[:1000])

        background_tasks.add_task(task)
        return {"operation_id": operation_id, "status": "queued"}

    @app.get("/api/vps/servers/{server_id}/maintenance/health")
    def health(server_id: int) -> dict[str, Any]:
        settings = ensure_settings(server_id)
        try:
            result = _health_snapshot(dict(server_lookup(server_id)), settings)
            record_sample(server_id, result["metrics"])
            return result
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/maintenance/history")
    def history(server_id: int, limit: int = Query(default=168, ge=1, le=2000)) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            rows = connection.execute("SELECT * FROM server_metric_samples WHERE server_id=? ORDER BY id DESC LIMIT ?", (server_id, limit)).fetchall()
        return [dict(row) for row in reversed(rows)]

    @app.post("/api/vps/servers/{server_id}/maintenance/sample")
    def sample_now(server_id: int) -> dict[str, Any]:
        try:
            metrics = inspect_server(dict(server_lookup(server_id)))
            record_sample(server_id, metrics)
            return {"status": "recorded", "metrics": metrics, "recorded_at": _utc_now()}
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.post("/api/vps/servers/{server_id}/maintenance/run", status_code=202)
    def run_now(server_id: int, background_tasks: BackgroundTasks) -> dict[str, Any]:
        server_lookup(server_id)
        operation_id = create_operation(server_id, "Manual scheduled-maintenance run", "maintenance.manual")
        request = CleanupRequest(confirm=True, docker_images=True, build_cache=True, apt_cache=True, journal=True,
                                 temp_files=True, trash=True, rotated_logs=True)
        background_tasks.add_task(cleanup_job, server_id, request, operation_id)
        return {"operation_id": operation_id, "status": "queued"}


__all__ = [
    "CleanupRequest",
    "LogCleanupRequest",
    "MaintenanceSettings",
    "_deployment_protected_tags",
    "_human_bytes_to_int",
    "_parse_disk_analysis",
    "install_maintenance_routes",
]
