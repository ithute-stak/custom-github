from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI

from app.isolated_runner import RunnerError, run_pipeline_isolated


def install_isolated_pipeline_route(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    project_lookup: Callable[[int], sqlite3.Row],
    sync_fn: Callable[[sqlite3.Row], str],
    git_sha_fn: Callable[[Path], str],
    detect_pipeline_fn: Callable[[Path, str], list[tuple[str, list[str]]]],
    audit_fn: Callable[[str, str, int | None, str], None],
    runs_root: Path,
    utc_now_fn: Callable[[], str],
) -> None:
    # Replace the legacy route that executed repository commands directly in the API process.
    for route in list(app.router.routes):
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == "/api/projects/{project_id}/pipeline" and "POST" in methods:
            app.router.routes.remove(route)

    @app.post("/api/projects/{project_id}/pipeline")
    def isolated_pipeline(project_id: int) -> dict[str, Any]:
        project = project_lookup(project_id)
        path = Path(project["workspace_path"])
        if not path.exists():
            sync_fn(project)
            project = project_lookup(project_id)
            path = Path(project["workspace_path"])

        commit_sha = git_sha_fn(path)
        image_tag = f"custom-github/{str(project['name']).lower()}:{commit_sha[:12]}"
        started = utc_now_fn()
        try:
            overall, results, logs, built_image = run_pipeline_isolated(
                project_name=str(project["name"]),
                source_path=path,
                commit_sha=commit_sha,
                image_tag=image_tag,
                steps=detect_pipeline_fn(path, image_tag),
                runs_root=runs_root,
            )
        except RunnerError as exc:
            overall = "failed"
            results = [{"name": "isolated runner preflight", "status": "failed", "exit_code": 1, "runner": "docker", "command": ["docker", "info"]}]
            logs = [str(exc)]
            built_image = None

        finished = utc_now_fn()
        with db_factory() as connection:
            cursor = connection.execute(
                "INSERT INTO pipeline_runs(project_id,commit_sha,status,image_tag,steps_json,logs,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?)",
                (project_id, commit_sha, overall, built_image, json.dumps(results), "\n\n".join(logs), started, finished),
            )
            run_id = int(cursor.lastrowid)
        audit_fn("pipeline.finished", "pipeline", run_id, f"{project['name']} {commit_sha[:12]}: {overall} (isolated)")
        return {
            "id": run_id,
            "project_id": project_id,
            "commit_sha": commit_sha,
            "status": overall,
            "image_tag": built_image,
            "steps": results,
            "started_at": started,
            "finished_at": finished,
            "execution": "isolated-docker-runner",
        }
