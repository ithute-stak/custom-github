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


class DockerCleanupRequest(BaseModel):
    confirm: bool = False
    clean_build_cache: bool = False
    build_cache_older_than_hours: int = Field(default=168, ge=1, le=8760)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_remote(server: dict[str, Any], command: str, timeout: int = 120) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(output.strip()[-4000:] or f"Remote command failed with exit code {code}")
    return output


def _deployment_protected_tags(connection: sqlite3.Connection, server_id: int) -> set[str]:
    """Protect recent current/rollback images for every project deployed to this VPS.

    We intentionally keep two deployment records per project. This is slightly conservative,
    but prevents a general Docker cleanup from destroying the image needed for a rollback.
    """
    rows = connection.execute(
        """
        SELECT project_id, image_tag, previous_image, status
        FROM deployments
        WHERE server_id = ?
        ORDER BY project_id ASC, id DESC
        """,
        (server_id,),
    ).fetchall()
    protected: set[str] = set()
    seen_per_project: dict[int, int] = {}
    for row in rows:
        project_id = int(row["project_id"])
        count = seen_per_project.get(project_id, 0)
        if count >= 2:
            continue
        seen_per_project[project_id] = count + 1
        image_tag = (row["image_tag"] or "").strip()
        previous_image = (row["previous_image"] or "").strip()
        if image_tag:
            protected.add(image_tag)
        if previous_image:
            protected.add(previous_image)
    return protected


def _docker_snapshot(server: dict[str, Any]) -> str:
    script = r"""
set -eu
printf '%s\n' '__IMAGES__'
docker image ls -a --no-trunc --format '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}'
printf '%s\n' '__SIZES__'
for id in $(docker image ls -aq --no-trunc | sort -u); do
  docker image inspect "$id" --format '{{.Id}}\t{{.Size}}' 2>/dev/null || true
done
printf '%s\n' '__CONTAINER_IMAGES__'
ids=$(docker ps -aq)
if [ -n "$ids" ]; then
  docker inspect --format '{{.Image}}' $ids 2>/dev/null || true
fi
printf '%s\n' '__SYSTEM_DF__'
docker system df 2>/dev/null || true
""".strip()
    return _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=90)


def _parse_snapshot(output: str, protected_tags: set[str]) -> dict[str, Any]:
    section: str | None = None
    image_rows: list[tuple[str, str, str, str]] = []
    sizes: dict[str, int] = {}
    container_image_ids: set[str] = set()
    system_df: list[str] = []

    for raw in output.splitlines():
        line = raw.rstrip("\n")
        if line in {"__IMAGES__", "__SIZES__", "__CONTAINER_IMAGES__", "__SYSTEM_DF__"}:
            section = line
            continue
        if section == "__IMAGES__":
            parts = line.split("\t", 3)
            if len(parts) == 4:
                image_rows.append((parts[0], parts[1], parts[2], parts[3]))
        elif section == "__SIZES__":
            parts = line.split("\t", 1)
            if len(parts) == 2:
                try:
                    sizes[parts[0]] = int(parts[1])
                except ValueError:
                    pass
        elif section == "__CONTAINER_IMAGES__":
            value = line.strip()
            if value:
                container_image_ids.add(value)
        elif section == "__SYSTEM_DF__":
            system_df.append(line)

    images: dict[str, dict[str, Any]] = {}
    for image_id, repository, tag, created_at in image_rows:
        item = images.setdefault(
            image_id,
            {
                "id": image_id,
                "size_bytes": sizes.get(image_id, 0),
                "created_at": created_at,
                "tags": [],
                "protected_by_container": image_id in container_image_ids,
                "protected_by_deployment": False,
            },
        )
        if repository != "<none>" and tag != "<none>":
            full_tag = f"{repository}:{tag}"
            item["tags"].append(full_tag)
            if full_tag in protected_tags:
                item["protected_by_deployment"] = True

    # Some Docker versions may list an inspect ID with a sha256 prefix while image ls
    # produces the same value; normalize container references defensively.
    for image_id, item in images.items():
        if any(ref == image_id or ref.endswith(image_id) or image_id.endswith(ref) for ref in container_image_ids):
            item["protected_by_container"] = True

    removable: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    for item in images.values():
        item["tags"] = sorted(set(item["tags"]))
        reasons: list[str] = []
        if item["protected_by_container"]:
            reasons.append("referenced by a container")
        if item["protected_by_deployment"]:
            reasons.append("kept for deployment/rollback")
        item["protection_reasons"] = reasons
        if reasons:
            protected.append(item)
        else:
            removable.append(item)

    removable.sort(key=lambda item: item["size_bytes"], reverse=True)
    protected.sort(key=lambda item: item["size_bytes"], reverse=True)
    return {
        "total_images": len(images),
        "candidate_images": len(removable),
        "protected_images": len(protected),
        "estimated_reclaimable_bytes": sum(int(item["size_bytes"]) for item in removable),
        "candidates": removable,
        "protected": protected,
        "protected_deployment_tags": sorted(protected_tags),
        "system_df": "\n".join(system_df).strip(),
        "note": "Estimated image bytes can overstate true reclaimed disk because Docker layers may be shared.",
    }


def install_docker_cleanup_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
    app_root: Path,
) -> None:
    page_path = app_root / "app" / "static" / "docker-cleanup.html"

    def protected_tags(server_id: int) -> set[str]:
        with db_factory() as connection:
            return _deployment_protected_tags(connection, server_id)

    def preview(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        return _parse_snapshot(_docker_snapshot(server), protected_tags(server_id))

    def emit_event(server_id: int, severity: str, title: str, message: str, data: dict[str, Any] | None = None) -> None:
        with db_factory() as connection:
            connection.execute(
                """
                INSERT INTO server_events(server_id, category, severity, title, message, data_json, created_at)
                VALUES (?, 'docker', ?, ?, ?, ?, ?)
                """,
                (server_id, severity, title[:240], message[:4000], json.dumps(data) if data else None, _utc_now()),
            )

    def create_operation(server_id: int) -> int:
        now = _utc_now()
        with db_factory() as connection:
            cursor = connection.execute(
                """
                INSERT INTO server_operations(server_id, kind, title, status, progress, message, created_at)
                VALUES (?, 'docker.cleanup', 'Clean unused Docker data', 'queued', 0, 'Queued', ?)
                """,
                (server_id, now),
            )
            operation_id = int(cursor.lastrowid)
        emit_event(server_id, "info", "Docker cleanup queued", "Waiting to analyze safe cleanup candidates", {"operation_id": operation_id, "status": "queued"})
        return operation_id

    def update_operation(
        operation_id: int,
        server_id: int,
        *,
        status: str,
        progress: int,
        message: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        now = _utc_now()
        with db_factory() as connection:
            connection.execute(
                """
                UPDATE server_operations
                SET status = ?, progress = ?, message = ?, result_json = ?, error = ?,
                    started_at = COALESCE(started_at, ?),
                    finished_at = CASE WHEN ? IN ('success','failed') THEN ? ELSE finished_at END
                WHERE id = ?
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
        severity = "success" if status == "success" else "error" if status == "failed" else "info"
        emit_event(server_id, severity, "Docker cleanup", message, {"operation_id": operation_id, "status": status, "progress": progress})

    @app.get("/vps/{server_id}/docker-cleanup", response_class=HTMLResponse, include_in_schema=False)
    def docker_cleanup_page(server_id: int) -> str:
        server_lookup(server_id)
        return page_path.read_text(encoding="utf-8")

    @app.get("/api/vps/servers/{server_id}/docker/cleanup/preview")
    def docker_cleanup_preview(server_id: int) -> dict[str, Any]:
        try:
            return preview(server_id)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.post("/api/vps/servers/{server_id}/docker/cleanup", status_code=202)
    def docker_cleanup(
        server_id: int,
        payload: DockerCleanupRequest,
        background_tasks: BackgroundTasks,
    ) -> dict[str, Any]:
        if not payload.confirm:
            raise HTTPException(status_code=400, detail="Docker cleanup requires explicit confirmation")
        server = dict(server_lookup(server_id))
        operation_id = create_operation(server_id)

        def task() -> None:
            try:
                update_operation(operation_id, server_id, status="running", progress=10, message="Analyzing Docker images")
                analysis = _parse_snapshot(_docker_snapshot(server), protected_tags(server_id))
                candidates = analysis["candidates"]
                update_operation(
                    operation_id,
                    server_id,
                    status="running",
                    progress=30,
                    message=f"Removing {len(candidates)} unused image(s)",
                )
                removed: list[str] = []
                skipped: list[dict[str, str]] = []
                for item in candidates:
                    image_id = str(item["id"])
                    code, output = ssh_command(server, f"docker image rm {shlex.quote(image_id)}", timeout=120)
                    if code == 0:
                        removed.append(image_id)
                    else:
                        skipped.append({"id": image_id, "reason": output.strip()[-1200:]})

                cache_output = ""
                if payload.clean_build_cache:
                    update_operation(operation_id, server_id, status="running", progress=75, message="Cleaning old Docker build cache")
                    hours = int(payload.build_cache_older_than_hours)
                    cache_output = _run_remote(
                        server,
                        f"docker builder prune -af --filter {shlex.quote(f'until={hours}h')}",
                        timeout=300,
                    )

                after = _parse_snapshot(_docker_snapshot(server), protected_tags(server_id))
                result = {
                    "removed_images": removed,
                    "removed_count": len(removed),
                    "skipped": skipped,
                    "build_cache_cleaned": payload.clean_build_cache,
                    "build_cache_output": cache_output[-4000:],
                    "before": {
                        "candidate_images": analysis["candidate_images"],
                        "estimated_reclaimable_bytes": analysis["estimated_reclaimable_bytes"],
                    },
                    "after": {
                        "candidate_images": after["candidate_images"],
                        "estimated_reclaimable_bytes": after["estimated_reclaimable_bytes"],
                        "system_df": after["system_df"],
                    },
                }
                update_operation(operation_id, server_id, status="success", progress=100, message=f"Cleanup complete: removed {len(removed)} image(s)", result=result)
                audit_fn("vps.docker.cleanup", "server", server_id, f"Removed {len(removed)} unused Docker image(s); build cache={'yes' if payload.clean_build_cache else 'no'}")
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                update_operation(operation_id, server_id, status="failed", progress=100, message="Docker cleanup failed", error=message)
                audit_fn("vps.docker.cleanup.failed", "server", server_id, message[:1000])

        background_tasks.add_task(task)
        return {"operation_id": operation_id, "status": "queued"}


__all__ = [
    "DockerCleanupRequest",
    "_deployment_protected_tags",
    "_parse_snapshot",
    "install_docker_cleanup_routes",
]
