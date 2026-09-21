from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ACTIVE_DEPLOYMENT_STATES, execute_deployment, inspect_server

APP_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("CUSTOM_GITHUB_DATA_DIR", APP_ROOT / "data"))
WORKSPACE_ROOT = Path(os.getenv("CUSTOM_GITHUB_WORKSPACE_ROOT", DATA_DIR / "workspaces"))
DB_PATH = DATA_DIR / "custom-github.db"
DASHBOARD_PATH = APP_ROOT / "app" / "static" / "index.html"

DATA_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Custom GitHub Control Plane", version="0.2.0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def init_db() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                github_url TEXT NOT NULL,
                branch TEXT NOT NULL DEFAULT 'main',
                workspace_path TEXT NOT NULL,
                latest_sha TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pipeline_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                commit_sha TEXT NOT NULL,
                status TEXT NOT NULL,
                image_tag TEXT,
                steps_json TEXT NOT NULL,
                logs TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS deployment_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                commit_sha TEXT NOT NULL,
                image_tag TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                ssh_user TEXT NOT NULL DEFAULT 'deploy',
                identity_file TEXT,
                max_disk_percent INTEGER NOT NULL DEFAULT 80,
                max_memory_percent INTEGER NOT NULL DEFAULT 85,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS deployment_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL UNIQUE,
                server_id INTEGER NOT NULL,
                compose_dir TEXT NOT NULL,
                compose_file TEXT NOT NULL DEFAULT 'compose.yaml',
                service_name TEXT NOT NULL,
                image_env_key TEXT NOT NULL DEFAULT 'CUSTOM_GITHUB_IMAGE',
                health_url TEXT NOT NULL,
                required_memory_mb INTEGER NOT NULL DEFAULT 512,
                required_disk_mb INTEGER NOT NULL DEFAULT 2048,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id),
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );

            CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                server_id INTEGER NOT NULL,
                commit_sha TEXT NOT NULL,
                image_tag TEXT NOT NULL,
                previous_image TEXT,
                status TEXT NOT NULL,
                status_message TEXT,
                logs TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                FOREIGN KEY(project_id) REFERENCES projects(id),
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_pipeline_project ON pipeline_runs(project_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_deployments_project ON deployments(project_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_deployments_server ON deployments(server_id, id DESC);
            """
        )
        pipeline_columns = {row[1] for row in connection.execute("PRAGMA table_info(pipeline_runs)").fetchall()}
        if "image_tag" not in pipeline_columns:
            connection.execute("ALTER TABLE pipeline_runs ADD COLUMN image_tag TEXT")
        request_columns = {row[1] for row in connection.execute("PRAGMA table_info(deployment_requests)").fetchall()}
        if "image_tag" not in request_columns:
            connection.execute("ALTER TABLE deployment_requests ADD COLUMN image_tag TEXT")


@app.on_event("startup")
def startup() -> None:
    init_db()


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    github_url: str
    branch: str = Field(default="main", min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._/-]+$")


class ServerCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    host: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._:-]+$")
    port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(default="deploy", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    identity_file: str | None = Field(default=None, max_length=500)
    max_disk_percent: int = Field(default=80, ge=40, le=95)
    max_memory_percent: int = Field(default=85, ge=40, le=95)


class DeploymentTargetCreate(BaseModel):
    server_id: int = Field(gt=0)
    compose_dir: str = Field(min_length=2, max_length=500, pattern=r"^/[A-Za-z0-9._/-]+$")
    compose_file: str = Field(default="compose.yaml", min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._/-]+$")
    service_name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._-]+$")
    image_env_key: str = Field(default="CUSTOM_GITHUB_IMAGE", pattern=r"^[A-Z][A-Z0-9_]{1,80}$")
    health_url: str = Field(min_length=8, max_length=500)
    required_memory_mb: int = Field(default=512, ge=64, le=262144)
    required_disk_mb: int = Field(default=2048, ge=128, le=1048576)


def audit(event_type: str, entity_type: str, entity_id: int | None, message: str) -> None:
    with db() as connection:
        connection.execute(
            "INSERT INTO audit_events(event_type, entity_type, entity_id, message, created_at) VALUES (?, ?, ?, ?, ?)",
            (event_type, entity_type, entity_id, message[:4000], utc_now()),
        )


def validate_github_url(url: str) -> None:
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", url):
        raise HTTPException(status_code=400, detail="Only HTTPS github.com repository URLs are allowed.")


def validate_health_url(url: str) -> None:
    if not re.fullmatch(r"https?://[^\s]+", url):
        raise HTTPException(status_code=400, detail="Health URL must begin with http:// or https://")


def project_or_404(project_id: int) -> sqlite3.Row:
    with db() as connection:
        row = connection.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return row


def server_or_404(server_id: int) -> sqlite3.Row:
    with db() as connection:
        row = connection.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Server not found")
    return row


def target_or_404(project_id: int) -> sqlite3.Row:
    with db() as connection:
        row = connection.execute("SELECT * FROM deployment_targets WHERE project_id = ?", (project_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=409, detail="Configure a deployment target before deploying")
    return row


def run(cmd: list[str], cwd: Path, timeout: int = 1800) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env={**os.environ, "CI": "true"},
        )
        return completed.returncode, completed.stdout
    except FileNotFoundError:
        return 127, f"Required executable not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return 124, stdout + "\nCommand timed out."


def git_sha(path: Path) -> str:
    code, output = run(["git", "rev-parse", "HEAD"], path, timeout=30)
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Unable to read repository SHA: {output[-1000:]}")
    return output.strip()


def sync_project(project: sqlite3.Row) -> str:
    path = Path(project["workspace_path"])
    url = project["github_url"]
    branch = project["branch"]

    if not path.exists():
        code, output = run(
            ["git", "clone", "--branch", branch, "--single-branch", url, str(path)],
            WORKSPACE_ROOT,
            timeout=1800,
        )
        if code != 0:
            raise HTTPException(status_code=400, detail=f"Clone failed: {output[-3000:]}")
    else:
        code, output = run(["git", "fetch", "origin", branch, "--prune"], path, timeout=900)
        if code != 0:
            raise HTTPException(status_code=400, detail=f"Fetch failed: {output[-3000:]}")
        code, output = run(["git", "checkout", branch], path, timeout=60)
        if code != 0:
            raise HTTPException(status_code=400, detail=f"Checkout failed: {output[-3000:]}")
        code, output = run(["git", "reset", "--hard", f"origin/{branch}"], path, timeout=60)
        if code != 0:
            raise HTTPException(status_code=400, detail=f"Reset failed: {output[-3000:]}")

    sha = git_sha(path)
    with db() as connection:
        connection.execute(
            "UPDATE projects SET latest_sha = ?, updated_at = ? WHERE id = ?",
            (sha, utc_now(), project["id"]),
        )
    audit("repository.synced", "project", project["id"], f"Synced {project['name']} to {sha}")
    return sha


def detect_pipeline(path: Path, image_tag: str) -> list[tuple[str, list[str]]]:
    steps: list[tuple[str, list[str]]] = []

    if (path / "package-lock.json").exists():
        steps.extend(
            [
                ("npm install", ["npm", "ci"]),
                ("npm test", ["npm", "test", "--if-present"]),
                ("npm build", ["npm", "run", "build", "--if-present"]),
            ]
        )
    elif (path / "package.json").exists():
        steps.extend(
            [
                ("npm install", ["npm", "install"]),
                ("npm test", ["npm", "test", "--if-present"]),
                ("npm build", ["npm", "run", "build", "--if-present"]),
            ]
        )

    if (path / "pyproject.toml").exists() or (path / "requirements.txt").exists():
        steps.append(("python compile", ["python", "-m", "compileall", "-q", "."]))
        if (path / "tests").exists():
            steps.append(("pytest", ["python", "-m", "pytest", "-q"]))

    if any(path.glob("*.sln")) or any(path.glob("*.csproj")):
        steps.append(("dotnet test", ["dotnet", "test", "--nologo"]))

    if (path / "Dockerfile").exists():
        steps.append(("docker build", ["docker", "build", "-t", image_tag, "."]))

    if not steps:
        steps.append(("repository validation", ["git", "status", "--short"]))

    return steps


def run_pipeline(project: sqlite3.Row) -> dict[str, Any]:
    path = Path(project["workspace_path"])
    if not path.exists():
        sync_project(project)
        project = project_or_404(project["id"])

    commit_sha = git_sha(path)
    image_tag = f"custom-github/{project['name'].lower()}:{commit_sha[:12]}"
    started = utc_now()
    results: list[dict[str, Any]] = []
    combined_logs: list[str] = []
    overall = "success"

    for label, command in detect_pipeline(path, image_tag):
        code, output = run(command, path)
        results.append(
            {
                "name": label,
                "command": command,
                "exit_code": code,
                "status": "success" if code == 0 else "failed",
            }
        )
        combined_logs.append(f"$ {' '.join(command)}\n{output}")
        if code != 0:
            overall = "failed"
            break

    finished = utc_now()
    built_image = image_tag if (path / "Dockerfile").exists() and overall == "success" else None
    with db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO pipeline_runs(project_id, commit_sha, status, image_tag, steps_json, logs, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project["id"],
                commit_sha,
                overall,
                built_image,
                json.dumps(results),
                "\n\n".join(combined_logs),
                started,
                finished,
            ),
        )
        run_id = cursor.lastrowid
    audit("pipeline.finished", "pipeline", run_id, f"{project['name']} {commit_sha[:12]}: {overall}")

    return {
        "id": run_id,
        "project_id": project["id"],
        "commit_sha": commit_sha,
        "status": overall,
        "image_tag": built_image,
        "steps": results,
        "started_at": started,
        "finished_at": finished,
    }


def deployment_row_or_404(deployment_id: int) -> sqlite3.Row:
    with db() as connection:
        row = connection.execute("SELECT * FROM deployments WHERE id = ?", (deployment_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return row


def update_deployment_status(deployment_id: int, status: str, message: str) -> None:
    finished_at = utc_now() if status not in ACTIVE_DEPLOYMENT_STATES else None
    started_at = utc_now() if status == "preflight" else None
    with db() as connection:
        if started_at:
            connection.execute(
                "UPDATE deployments SET status = ?, status_message = ?, started_at = COALESCE(started_at, ?) WHERE id = ?",
                (status, message[:2000], started_at, deployment_id),
            )
        elif finished_at:
            connection.execute(
                "UPDATE deployments SET status = ?, status_message = ?, finished_at = ? WHERE id = ?",
                (status, message[:2000], finished_at, deployment_id),
            )
        else:
            connection.execute(
                "UPDATE deployments SET status = ?, status_message = ? WHERE id = ?",
                (status, message[:2000], deployment_id),
            )
    audit("deployment.status", "deployment", deployment_id, f"{status}: {message}")


def append_deployment_log(deployment_id: int, message: str) -> None:
    clean = message[-12000:]
    with db() as connection:
        connection.execute(
            "UPDATE deployments SET logs = logs || ? WHERE id = ?",
            (f"[{utc_now()}] {clean}\n", deployment_id),
        )


def set_previous_image(deployment_id: int, image: str | None) -> None:
    with db() as connection:
        connection.execute("UPDATE deployments SET previous_image = ? WHERE id = ?", (image, deployment_id))


def run_deployment_task(deployment_id: int) -> None:
    with db() as connection:
        deployment = connection.execute("SELECT * FROM deployments WHERE id = ?", (deployment_id,)).fetchone()
        if not deployment:
            return
        server = connection.execute("SELECT * FROM servers WHERE id = ?", (deployment["server_id"],)).fetchone()
        target = connection.execute(
            "SELECT * FROM deployment_targets WHERE project_id = ?", (deployment["project_id"],)
        ).fetchone()
    if not server or not target:
        update_deployment_status(deployment_id, "failed", "Server or deployment target no longer exists")
        return

    execute_deployment(
        server=dict(server),
        target=dict(target),
        image_tag=deployment["image_tag"],
        set_status=lambda status, message: update_deployment_status(deployment_id, status, message),
        set_previous_image=lambda image: set_previous_image(deployment_id, image),
        append_log=lambda message: append_deployment_log(deployment_id, message),
    )


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_PATH.read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "custom-github-control-plane", "version": "0.2.0"}


@app.get("/api/projects")
def list_projects() -> list[dict[str, Any]]:
    with db() as connection:
        projects = connection.execute("SELECT * FROM projects ORDER BY name").fetchall()
        result: list[dict[str, Any]] = []
        for project in projects:
            latest_run = connection.execute(
                "SELECT * FROM pipeline_runs WHERE project_id = ? ORDER BY id DESC LIMIT 1",
                (project["id"],),
            ).fetchone()
            latest_green = connection.execute(
                "SELECT * FROM pipeline_runs WHERE project_id = ? AND status = 'success' ORDER BY id DESC LIMIT 1",
                (project["id"],),
            ).fetchone()
            target = connection.execute(
                """
                SELECT dt.*, s.name AS server_name
                FROM deployment_targets dt
                JOIN servers s ON s.id = dt.server_id
                WHERE dt.project_id = ?
                """,
                (project["id"],),
            ).fetchone()
            latest_deployment = connection.execute(
                "SELECT * FROM deployments WHERE project_id = ? ORDER BY id DESC LIMIT 1",
                (project["id"],),
            ).fetchone()
            exact_green = bool(latest_green and latest_green["commit_sha"] == project["latest_sha"])
            result.append(
                {
                    **dict(project),
                    "latest_run": dict(latest_run) if latest_run else None,
                    "latest_green_sha": latest_green["commit_sha"] if latest_green else None,
                    "latest_green_image": latest_green["image_tag"] if latest_green else None,
                    "target": dict(target) if target else None,
                    "latest_deployment": dict(latest_deployment) if latest_deployment else None,
                    "deployable": bool(exact_green and latest_green["image_tag"] and target),
                }
            )
    return result


@app.post("/api/projects", status_code=201)
def create_project(payload: ProjectCreate) -> dict[str, Any]:
    validate_github_url(payload.github_url)
    path = WORKSPACE_ROOT / payload.name
    now = utc_now()
    try:
        with db() as connection:
            cursor = connection.execute(
                """
                INSERT INTO projects(name, github_url, branch, workspace_path, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (payload.name, payload.github_url, payload.branch, str(path), now, now),
            )
            project_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="A project with that name already exists")
    audit("project.created", "project", project_id, f"Registered {payload.github_url}")
    return dict(project_or_404(project_id))


@app.post("/api/projects/{project_id}/sync")
def sync(project_id: int) -> dict[str, str]:
    project = project_or_404(project_id)
    sha = sync_project(project)
    return {"status": "synced", "commit_sha": sha}


@app.post("/api/projects/{project_id}/pipeline")
def pipeline(project_id: int) -> dict[str, Any]:
    project = project_or_404(project_id)
    return run_pipeline(project)


@app.get("/api/projects/{project_id}/pipeline/latest")
def latest_pipeline(project_id: int) -> dict[str, Any]:
    project_or_404(project_id)
    with db() as connection:
        row = connection.execute(
            "SELECT * FROM pipeline_runs WHERE project_id = ? ORDER BY id DESC LIMIT 1",
            (project_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="No pipeline run yet")
    data = dict(row)
    data["steps"] = json.loads(data.pop("steps_json"))
    return data


@app.get("/api/servers")
def list_servers() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM servers ORDER BY name").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/servers", status_code=201)
def create_server(payload: ServerCreate) -> dict[str, Any]:
    now = utc_now()
    try:
        with db() as connection:
            cursor = connection.execute(
                """
                INSERT INTO servers(name, host, port, ssh_user, identity_file, max_disk_percent, max_memory_percent, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.name,
                    payload.host,
                    payload.port,
                    payload.ssh_user,
                    payload.identity_file,
                    payload.max_disk_percent,
                    payload.max_memory_percent,
                    now,
                    now,
                ),
            )
            server_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="A server with that name already exists")
    audit("server.created", "server", server_id, f"Registered {payload.ssh_user}@{payload.host}:{payload.port}")
    return dict(server_or_404(server_id))


@app.post("/api/servers/{server_id}/check")
def check_server(server_id: int) -> dict[str, Any]:
    server = server_or_404(server_id)
    try:
        metrics = inspect_server(dict(server))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    audit("server.checked", "server", server_id, f"Capacity check: {metrics}")
    return {"status": "online", "metrics": metrics}


@app.put("/api/projects/{project_id}/deployment-target")
def configure_deployment_target(project_id: int, payload: DeploymentTargetCreate) -> dict[str, Any]:
    project_or_404(project_id)
    server_or_404(payload.server_id)
    validate_health_url(payload.health_url)
    now = utc_now()
    with db() as connection:
        connection.execute(
            """
            INSERT INTO deployment_targets(
                project_id, server_id, compose_dir, compose_file, service_name,
                image_env_key, health_url, required_memory_mb, required_disk_mb,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id) DO UPDATE SET
                server_id = excluded.server_id,
                compose_dir = excluded.compose_dir,
                compose_file = excluded.compose_file,
                service_name = excluded.service_name,
                image_env_key = excluded.image_env_key,
                health_url = excluded.health_url,
                required_memory_mb = excluded.required_memory_mb,
                required_disk_mb = excluded.required_disk_mb,
                updated_at = excluded.updated_at
            """,
            (
                project_id,
                payload.server_id,
                payload.compose_dir,
                payload.compose_file,
                payload.service_name,
                payload.image_env_key,
                payload.health_url,
                payload.required_memory_mb,
                payload.required_disk_mb,
                now,
                now,
            ),
        )
        row = connection.execute("SELECT * FROM deployment_targets WHERE project_id = ?", (project_id,)).fetchone()
    audit("target.configured", "project", project_id, f"Deployment target server #{payload.server_id}")
    return dict(row)


@app.post("/api/projects/{project_id}/deploy-latest", status_code=202)
def deploy_latest(project_id: int, background_tasks: BackgroundTasks) -> dict[str, Any]:
    project = project_or_404(project_id)
    target = target_or_404(project_id)
    if not project["latest_sha"]:
        raise HTTPException(status_code=409, detail="Sync the project before deployment")

    with db() as connection:
        green = connection.execute(
            """
            SELECT * FROM pipeline_runs
            WHERE project_id = ? AND status = 'success' AND commit_sha = ?
            ORDER BY id DESC LIMIT 1
            """,
            (project_id, project["latest_sha"]),
        ).fetchone()
        if not green:
            raise HTTPException(status_code=409, detail="Latest commit is not green. Deployment blocked.")
        if not green["image_tag"]:
            raise HTTPException(status_code=409, detail="Latest green pipeline did not produce a Docker image.")

        placeholders = ",".join("?" for _ in ACTIVE_DEPLOYMENT_STATES)
        active = connection.execute(
            f"SELECT id FROM deployments WHERE server_id = ? AND status IN ({placeholders}) LIMIT 1",
            (target["server_id"], *sorted(ACTIVE_DEPLOYMENT_STATES)),
        ).fetchone()
        if active:
            raise HTTPException(
                status_code=409,
                detail=f"Deployment #{active['id']} is already active on this server. Wait for it to finish.",
            )

        cursor = connection.execute(
            """
            INSERT INTO deployments(project_id, server_id, commit_sha, image_tag, status, status_message, created_at)
            VALUES (?, ?, ?, ?, 'queued', 'Waiting for local deployment worker', ?)
            """,
            (project_id, target["server_id"], project["latest_sha"], green["image_tag"], utc_now()),
        )
        deployment_id = cursor.lastrowid

    audit(
        "deployment.queued",
        "deployment",
        deployment_id,
        f"{project['name']} {project['latest_sha'][:12]} -> server #{target['server_id']}",
    )
    background_tasks.add_task(run_deployment_task, deployment_id)
    return {
        "deployment_id": deployment_id,
        "status": "queued",
        "commit_sha": project["latest_sha"],
        "image_tag": green["image_tag"],
        "message": "Latest green immutable image queued for controlled VPS deployment.",
    }


@app.get("/api/deployments")
def list_deployments(limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 200))
    with db() as connection:
        rows = connection.execute(
            """
            SELECT d.*, p.name AS project_name, s.name AS server_name
            FROM deployments d
            JOIN projects p ON p.id = d.project_id
            JOIN servers s ON s.id = d.server_id
            ORDER BY d.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/deployments/{deployment_id}")
def get_deployment(deployment_id: int) -> dict[str, Any]:
    return dict(deployment_row_or_404(deployment_id))


@app.get("/api/audit")
def list_audit(limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    with db() as connection:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]
