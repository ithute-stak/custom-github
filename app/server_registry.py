from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


class ServerUnregister(BaseModel):
    confirm_name: str = Field(min_length=1, max_length=80)


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return bool(row)


def _identity_state(identity_file: str | None) -> dict[str, Any]:
    if not identity_file:
        return {"configured": False, "exists": False, "path": None, "state": "not-configured"}
    expanded = os.path.expanduser(identity_file)
    exists = os.path.isfile(expanded)
    return {
        "configured": True,
        "exists": exists,
        "path": identity_file,
        "expanded_path": expanded,
        "state": "ready" if exists else "missing",
    }


def install_server_registry_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
    app_root: Path,
) -> None:
    page_path = app_root / "app" / "static" / "server-registry.html"

    @app.get("/server-registry", response_class=HTMLResponse, include_in_schema=False)
    def server_registry_page() -> str:
        return page_path.read_text(encoding="utf-8")

    @app.get("/api/server-registry")
    def server_registry() -> list[dict[str, Any]]:
        with db_factory() as connection:
            servers = connection.execute("SELECT * FROM servers ORDER BY name").fetchall()
            result: list[dict[str, Any]] = []
            for server in servers:
                server_id = int(server["id"])
                target_count = connection.execute(
                    "SELECT COUNT(*) FROM deployment_targets WHERE server_id = ?", (server_id,)
                ).fetchone()[0]
                deployment_count = connection.execute(
                    "SELECT COUNT(*) FROM deployments WHERE server_id = ?", (server_id,)
                ).fetchone()[0]
                project_names = [
                    row[0]
                    for row in connection.execute(
                        """
                        SELECT p.name
                        FROM deployment_targets t
                        JOIN projects p ON p.id = t.project_id
                        WHERE t.server_id = ?
                        ORDER BY p.name
                        """,
                        (server_id,),
                    ).fetchall()
                ]
                result.append(
                    {
                        **dict(server),
                        "identity": _identity_state(server["identity_file"]),
                        "deployment_target_count": int(target_count),
                        "deployment_count": int(deployment_count),
                        "projects": project_names,
                        "can_unregister": int(target_count) == 0 and int(deployment_count) == 0,
                    }
                )
        return result

    @app.delete("/api/server-registry/{server_id}")
    def unregister_server(server_id: int, payload: ServerUnregister) -> dict[str, Any]:
        server = server_lookup(server_id)
        name = str(server["name"])
        if payload.confirm_name != name:
            raise HTTPException(status_code=400, detail="confirm_name must exactly match the server name")

        with db_factory() as connection:
            target_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM deployment_targets WHERE server_id = ?", (server_id,)
                ).fetchone()[0]
            )
            deployment_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM deployments WHERE server_id = ?", (server_id,)
                ).fetchone()[0]
            )
            if target_count:
                raise HTTPException(
                    status_code=409,
                    detail=f"Server still has {target_count} deployment target(s). Reassign or remove those targets first.",
                )
            if deployment_count:
                raise HTTPException(
                    status_code=409,
                    detail=f"Server has {deployment_count} deployment history record(s). It is retained to preserve audit history.",
                )

            # These are local control-plane records only. No SSH command is executed and
            # no remote server, container, image, volume, file or service is changed.
            for table in (
                "server_operations",
                "server_events",
                "server_metric_samples",
                "server_maintenance_settings",
            ):
                if _table_exists(connection, table):
                    connection.execute(f"DELETE FROM {table} WHERE server_id = ?", (server_id,))
            try:
                connection.execute("DELETE FROM servers WHERE id = ?", (server_id,))
            except sqlite3.IntegrityError as exc:
                raise HTTPException(
                    status_code=409,
                    detail="This server is still referenced by control-plane data and cannot be unregistered safely.",
                ) from exc

        audit_fn("server.unregistered", "server", server_id, f"Unregistered stale VPS entry {name}")
        return {
            "status": "unregistered",
            "server_id": server_id,
            "name": name,
            "remote_changes": False,
        }


__all__ = ["_identity_state", "_table_exists", "install_server_registry_routes"]
