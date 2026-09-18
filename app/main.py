from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

APP_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("CUSTOM_GITHUB_DATA_DIR", APP_ROOT / "data"))
WORKSPACE_ROOT = Path(os.getenv("CUSTOM_GITHUB_WORKSPACE_ROOT", DATA_DIR / "workspaces"))
DB_PATH = DATA_DIR / "custom-github.db"
DASHBOARD_PATH = APP_ROOT / "app" / "static" / "index.html"

DATA_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Custom GitHub Control Plane", version="0.1.0")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
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
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(pipeline_runs)").fetchall()}
        if "image_tag" not in columns:
            connection.execute("ALTER TABLE pipeline_runs ADD COLUMN image_tag TEXT")
        deployment_columns = {row[1] for row in connection.execute("PRAGMA table_info(deployment_requests)").fetchall()}
        if "image_tag" not in deployment_columns:
            connection.execute("ALTER TABLE deployment_requests ADD COLUMN image_tag TEXT")


@app.on_event("startup")
def startup() -> None:
    init_db()


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    github_url: str
    branch: str = Field(default="main", min_length=1, max_length=120)


def validate_github_url(url: str) -> None:
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", url):
        raise HTTPException(status_code=400, detail="Only HTTPS github.com repository URLs are allowed in the MVP.")


def project_or_404(project_id: int) -> sqlite3.Row:
    with db() as connection:
        row = connection.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
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
    return sha


def detect_pipeline(path: Path, image_tag: str) -> list[tuple[str, list[str]]]:
    steps: list[tuple[str, list[str]]] = []

    if (path / "package-lock.json").exists():
        steps.append(("npm install", ["npm", "ci"]))
        steps.append(("npm test", ["npm", "test", "--if-present"]))
        steps.append(("npm build", ["npm", "run", "build", "--if-present"]))
    elif (path / "package.json").exists():
        steps.append(("npm install", ["npm", "install"]))
        steps.append(("npm test", ["npm", "test", "--if-present"]))
        steps.append(("npm build", ["npm", "run", "build", "--if-present"]))

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
        results.append({"name": label, "command": command, "exit_code": code, "status": "success" if code == 0 else "failed"})
        combined_logs.append(f"$ {' '.join(command)}\n{output}")
        if code != 0:
            overall = "failed"
            break

    finished = utc_now()
    with db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO pipeline_runs(project_id, commit_sha, status, image_tag, steps_json, logs, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (project["id"], commit_sha, overall, image_tag if (path / "Dockerfile").exists() and overall == "success" else None, json.dumps(results), "\n\n".join(combined_logs), started, finished),
        )
        run_id = cursor.lastrowid

    return {"id": run_id, "project_id": project["id"], "commit_sha": commit_sha, "status": overall, "image_tag": image_tag if (path / "Dockerfile").exists() and overall == "success" else None, "steps": results, "started_at": started, "finished_at": finished}


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_PATH.read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "custom-github-control-plane"}


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
            result.append(
                {
                    **dict(project),
                    "latest_run": dict(latest_run) if latest_run else None,
                    "latest_green_sha": latest_green["commit_sha"] if latest_green else None,
                    "deployable": bool(latest_green and latest_green["commit_sha"] == project["latest_sha"]),
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


@app.post("/api/projects/{project_id}/deploy-latest", status_code=202)
def deploy_latest(project_id: int) -> dict[str, Any]:
    project = project_or_404(project_id)
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
        cursor = connection.execute(
            "INSERT INTO deployment_requests(project_id, commit_sha, image_tag, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (project_id, project["latest_sha"], green["image_tag"], "awaiting-deployment-agent", utc_now()),
        )
        deployment_id = cursor.lastrowid

    return {
        "deployment_id": deployment_id,
        "status": "awaiting-deployment-agent",
        "commit_sha": project["latest_sha"],
        "image_tag": green["image_tag"],
        "message": "Latest green commit approved. The remote VPS deployment agent is the next implementation stage.",
    }
