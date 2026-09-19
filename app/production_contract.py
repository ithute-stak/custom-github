from __future__ import annotations

import json
import shlex
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ssh_command


# Hardcoded from the production deployment contracts in:
# - ithute-stak/LoanHub compose.yaml + deploy-production.yml
# - ithute-stak/ithute compose.production.yml, compose.backup.yml,
#   compose.telemetry.yml and their deployment workflows.
#
# Keys are (Docker Compose project, Docker Compose service).
APPROVED_RUNNING: dict[tuple[str, str], tuple[str, ...]] = {
    # LoanHub: five steady-state services.
    ("loanhub", "db"): ("postgres:16-alpine",),
    ("loanhub", "redis"): ("redis:7-alpine",),
    ("loanhub", "backend"): ("loanhub-backend:",),
    ("loanhub", "maintenance"): ("loanhub-backend:",),
    ("loanhub", "frontend"): ("loanhub-frontend:",),

    # Ithute core production stack: sixteen services.
    ("ithute", "ithute-app-db"): ("postgres:16-alpine",),
    ("ithute", "ithute-app-redis"): ("redis:7-alpine",),
    ("ithute", "ithute-app-rspamd-redis"): ("redis:7-alpine",),
    ("ithute", "ithute-app-api"): ("ithute-app-api:",),
    ("ithute", "ithute-web"): ("ithute-web:",),
    ("ithute", "ithute-auth-db"): ("postgres:16-alpine",),
    ("ithute", "ithute-auth"): ("ithute-auth:",),
    ("ithute", "ithute-auth-push-event-worker"): ("ithute-auth:",),
    ("ithute", "ithute-push-db"): ("postgres:16-alpine",),
    ("ithute", "ithute-push"): ("ithute-push:",),
    ("ithute", "ithute-push-worker"): ("ithute-push:",),
    ("ithute", "ithute-realtime-db"): ("postgres:16-alpine",),
    ("ithute", "ithute-realtime-redis"): ("redis:7-alpine",),
    ("ithute", "ithute-realtime"): ("ithute-realtime:",),
    ("ithute", "ithute-dns"): ("powerdns/pdns-auth-49:4.9.17",),
    ("ithute", "caddy"): ("caddy:2.11.4-alpine",),

    # Ithute backup assurance: three services.
    ("ithute", "ithute-backup"): ("postgres:16-alpine",),
    ("ithute", "ithute-restore-drill-db"): ("postgres:16-alpine",),
    ("ithute", "ithute-restore-drill"): ("postgres:16-alpine",),

    # Ithute private telemetry: three services.
    ("ithute", "prometheus"): ("prom/prometheus:v2.55.1",),
    ("ithute", "ithute-node-exporter"): ("prom/node-exporter:v1.8.2",),
    ("ithute", "ithute-cadvisor"): ("gcr.io/cadvisor/cadvisor:v0.49.2",),
}

# LoanHub migrations are intentionally one-shot. They are allowed to exist/run during
# deployment but are not part of the expected steady-state running count.
APPROVED_TRANSIENT: dict[tuple[str, str], tuple[str, ...]] = {
    ("loanhub", "migrate"): ("loanhub-backend:",),
}

EXPECTED_RUNNING_COUNT = len(APPROVED_RUNNING)  # 27
CONFIRM_TEXT = "DELETE NON-APPROVED CONTAINERS"


class CleanupRequest(BaseModel):
    confirm: str = Field(min_length=1, max_length=80)
    remove_unused_images: bool = True


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def image_matches(image: str, allowed: tuple[str, ...]) -> bool:
    for pattern in allowed:
        if pattern.endswith(":"):
            if image.startswith(pattern) and len(image) > len(pattern):
                return True
        elif image == pattern:
            return True
    return False


def classify_container(row: dict[str, str]) -> dict[str, Any]:
    project = (row.get("compose_project") or "").strip()
    service = (row.get("compose_service") or "").strip()
    image = (row.get("image") or "").strip()
    key = (project, service)

    if key in APPROVED_RUNNING:
        valid_image = image_matches(image, APPROVED_RUNNING[key])
        return {
            **row,
            "classification": "approved" if valid_image else "image-mismatch",
            "approved": valid_image,
            "expected_running": True,
            "reason": "Production contract match" if valid_image else "Approved service is using an unexpected image",
            "allowed_images": list(APPROVED_RUNNING[key]),
        }
    if key in APPROVED_TRANSIENT:
        valid_image = image_matches(image, APPROVED_TRANSIENT[key])
        return {
            **row,
            "classification": "approved-transient" if valid_image else "image-mismatch",
            "approved": valid_image,
            "expected_running": False,
            "reason": "Approved transient deployment service" if valid_image else "Transient service is using an unexpected image",
            "allowed_images": list(APPROVED_TRANSIENT[key]),
        }
    return {
        **row,
        "classification": "non-approved",
        "approved": False,
        "expected_running": False,
        "reason": "Not present in the hardcoded LoanHub/Ithute production contract",
        "allowed_images": [],
    }


def parse_inventory(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in output.splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 8:
            continue
        container_id, name, image, project, service, status, state, created = parts[:8]
        rows.append(
            classify_container(
                {
                    "id": container_id,
                    "name": name.lstrip("/"),
                    "image": image,
                    "compose_project": project if project not in {"<no value>", "<nil>"} else "",
                    "compose_service": service if service not in {"<no value>", "<nil>"} else "",
                    "status": status,
                    "state": state,
                    "created": created,
                }
            )
        )
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    running = [row for row in rows if row.get("state") == "running"]
    approved_running = [row for row in running if row.get("classification") == "approved"]
    transient_running = [row for row in running if row.get("classification") == "approved-transient"]
    non_approved_running = [row for row in running if not row.get("approved")]
    non_approved_all = [row for row in rows if not row.get("approved")]

    present_keys = {
        (row.get("compose_project") or "", row.get("compose_service") or "")
        for row in approved_running
    }
    missing = []
    for (project, service), images in APPROVED_RUNNING.items():
        if (project, service) not in present_keys:
            missing.append({"compose_project": project, "compose_service": service, "allowed_images": list(images)})

    return {
        "expected_running": EXPECTED_RUNNING_COUNT,
        "actual_running": len(running),
        "approved_running": len(approved_running),
        "transient_running": len(transient_running),
        "non_approved_running": len(non_approved_running),
        "non_approved_total": len(non_approved_all),
        "missing_expected": len(missing),
        "missing": missing,
        "approved": [row for row in rows if row.get("approved")],
        "non_approved": non_approved_all,
        "containers": rows,
        "contract": {
            "loanhub_expected": 5,
            "ithute_core_expected": 16,
            "ithute_backup_expected": 3,
            "ithute_telemetry_expected": 3,
            "total_expected": EXPECTED_RUNNING_COUNT,
        },
        "note": "Cleanup never removes Docker volumes. LoanHub migrate is approved as transient but is not part of the 27 steady-state containers.",
    }


def _inventory_command() -> str:
    return r"""
docker ps -a --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.Status}}\t{{.State}}\t{{.CreatedAt}}'
""".strip()


def _inspect(server: dict[str, Any]) -> dict[str, Any]:
    code, output = ssh_command(server, _inventory_command(), timeout=45)
    if code != 0:
        raise RuntimeError(output.strip()[-4000:] or "Unable to inspect Docker containers")
    return summarize(parse_inventory(output))


def install_production_contract_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
    app_root: Path,
) -> None:
    page_path = app_root / "app" / "static" / "production-contract.html"

    def ensure_operation_tables() -> None:
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
                """
            )

    def create_operation(server_id: int, title: str) -> int:
        ensure_operation_tables()
        now = utc_now()
        with db_factory() as connection:
            cursor = connection.execute(
                "INSERT INTO server_operations(server_id,kind,title,status,progress,message,created_at) VALUES(?,?,?,'queued',0,?,?)",
                (server_id, "production-contract.cleanup", title, "Waiting for cleanup worker", now),
            )
            operation_id = int(cursor.lastrowid)
            connection.execute(
                "INSERT INTO server_events(server_id,category,severity,title,message,data_json,created_at) VALUES(?,?,?,?,?,?,?)",
                (server_id, "docker", "warning", title, "Cleanup queued", json.dumps({"operation_id": operation_id}), now),
            )
        return operation_id

    def set_operation(operation_id: int, server_id: int, status: str, progress: int, message: str, result: dict[str, Any] | None = None, error: str | None = None) -> None:
        now = utc_now()
        with db_factory() as connection:
            connection.execute(
                """
                UPDATE server_operations
                   SET status=?, progress=?, message=?, result_json=?, error=?,
                       started_at=COALESCE(started_at, ?),
                       finished_at=CASE WHEN ? IN ('success','failed') THEN ? ELSE finished_at END
                 WHERE id=?
                """,
                (
                    status,
                    max(0, min(progress, 100)),
                    message[:2000],
                    json.dumps(result) if result is not None else None,
                    error[:4000] if error else None,
                    now if status == "running" else None,
                    status,
                    now,
                    operation_id,
                ),
            )
            connection.execute(
                "INSERT INTO server_events(server_id,category,severity,title,message,data_json,created_at) VALUES(?,?,?,?,?,?,?)",
                (
                    server_id,
                    "docker",
                    "success" if status == "success" else "error" if status == "failed" else "info",
                    "Production contract cleanup",
                    message[:4000],
                    json.dumps({"operation_id": operation_id, "status": status, "progress": progress}),
                    now,
                ),
            )

    def cleanup_task(operation_id: int, server_id: int, remove_unused_images: bool) -> None:
        try:
            server = dict(server_lookup(server_id))
            set_operation(operation_id, server_id, "running", 10, "Auditing production containers")
            before = _inspect(server)
            candidates = before["non_approved"]
            if not candidates:
                set_operation(operation_id, server_id, "success", 100, "No non-approved containers found", result=before)
                return

            ids = [str(row["id"]) for row in candidates]
            images = sorted({str(row["image"]) for row in candidates if row.get("image")})
            set_operation(operation_id, server_id, "running", 35, f"Removing {len(ids)} non-approved container(s)")
            quoted_ids = " ".join(shlex.quote(value) for value in ids)
            command = f"docker rm -f {quoted_ids}"
            code, output = ssh_command(server, command, timeout=180)
            if code != 0:
                raise RuntimeError(output.strip()[-4000:] or "Unable to remove non-approved containers")

            removed_images: list[str] = []
            if remove_unused_images and images:
                set_operation(operation_id, server_id, "running", 70, "Removing candidate images that are no longer referenced")
                for image in images:
                    q = shlex.quote(image)
                    # Docker itself refuses image removal while another container references it.
                    code, _ = ssh_command(server, f"docker image rm {q} >/dev/null 2>&1 || true", timeout=60)
                    if code == 0:
                        removed_images.append(image)

            after = _inspect(server)
            result = {
                "removed_containers": [row["name"] for row in candidates],
                "candidate_images": images,
                "after": after,
            }
            set_operation(operation_id, server_id, "success", 100, f"Removed {len(candidates)} non-approved container(s); volumes were untouched", result=result)
            audit_fn(
                "production-contract.cleanup",
                "server",
                server_id,
                f"Removed non-approved containers: {', '.join(result['removed_containers'])}; Docker volumes untouched",
            )
        except Exception as exc:
            message = str(exc) or exc.__class__.__name__
            set_operation(operation_id, server_id, "failed", 100, "Cleanup failed", error=message)
            audit_fn("production-contract.cleanup.failed", "server", server_id, message[:1000])

    @app.get("/vps/{server_id}/production-contract", response_class=HTMLResponse, include_in_schema=False)
    def production_contract_page(server_id: int) -> str:
        server_lookup(server_id)
        return page_path.read_text(encoding="utf-8")

    @app.get("/api/vps/servers/{server_id}/production-contract")
    def production_contract(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        try:
            result = _inspect(server)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        result["server_id"] = server_id
        result["server_name"] = server["name"]
        return result

    @app.post("/api/vps/servers/{server_id}/production-contract/cleanup", status_code=202)
    def cleanup_non_approved(server_id: int, payload: CleanupRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        server_lookup(server_id)
        if payload.confirm != CONFIRM_TEXT:
            raise HTTPException(status_code=409, detail=f"Type exactly: {CONFIRM_TEXT}")
        preview = _inspect(dict(server_lookup(server_id)))
        if not preview["non_approved"]:
            return {"status": "nothing-to-do", "message": "No non-approved containers found", "preview": preview}
        operation_id = create_operation(server_id, "Remove non-approved Docker workloads")
        background_tasks.add_task(cleanup_task, operation_id, server_id, payload.remove_unused_images)
        return {
            "status": "queued",
            "operation_id": operation_id,
            "candidate_count": preview["non_approved_total"],
            "candidate_names": [row["name"] for row in preview["non_approved"]],
            "message": "Cleanup queued. Docker volumes will not be removed.",
        }


__all__ = [
    "APPROVED_RUNNING",
    "APPROVED_TRANSIENT",
    "EXPECTED_RUNNING_COUNT",
    "CONFIRM_TEXT",
    "classify_container",
    "parse_inventory",
    "summarize",
    "install_production_contract_routes",
]
