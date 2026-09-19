from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.github_operations import GitHubAPIError, inspect_local_repository, install_github_operations_routes, parse_github_repository
from app.platform import app as platform_app


def test_parse_github_repository() -> None:
    assert parse_github_repository("https://github.com/ithute-stak/custom-github") == ("ithute-stak", "custom-github")
    assert parse_github_repository("https://github.com/ithute-stak/custom-github.git") == ("ithute-stak", "custom-github")
    for value in ["git@github.com:ithute-stak/custom-github.git", "https://gitlab.com/a/b", "https://github.com/a/b/extra"]:
        try:
            parse_github_repository(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected invalid GitHub URL: {value}")


def test_local_repository_state_is_read_only(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (repo / "README.md").write_text("changed\n", encoding="utf-8")
    project = {"workspace_path": str(repo), "branch": "main"}
    state = inspect_local_repository(project)
    assert state["exists"] is True
    assert state["branch"] == "main"
    assert len(state["head_sha"]) == 40
    assert state["dirty_files"] == 1
    # Inspection must not reset or clean the working tree.
    assert (repo / "README.md").read_text(encoding="utf-8") == "changed\n"


class FakeGitHubAPI:
    fail = False

    def __init__(self):
        self.rate = {"limit": "5000", "remaining": "4990", "reset": "0", "resource": "core"}

    def get(self, path: str):
        if self.fail:
            raise GitHubAPIError(503, "simulated outage")
        if path.endswith("/branches?per_page=50"):
            return [{"name": "main", "commit": {"sha": "a" * 40}, "protected": True}]
        if "/commits?" in path:
            return [{"sha": "a" * 40, "html_url": "https://github.com/o/r/commit/a", "commit": {"message": "Initial", "author": {"name": "Tester", "date": "2026-09-19T00:00:00Z"}}, "author": {"login": "tester"}}]
        if path.endswith("/pulls?state=open&per_page=25"):
            return [{"number": 7, "title": "Improve", "draft": False, "user": {"login": "tester"}, "head": {"ref": "feature"}, "base": {"ref": "main"}, "updated_at": "2026-09-19T00:00:00Z", "html_url": "https://github.com/o/r/pull/7"}]
        if path.endswith("/actions/runs?per_page=25"):
            return {"workflow_runs": [{"id": 9, "name": "CI", "event": "push", "head_branch": "main", "head_sha": "a" * 40, "status": "completed", "conclusion": "success", "run_number": 3, "created_at": "2026-09-19T00:00:00Z", "updated_at": "2026-09-19T00:01:00Z", "html_url": "https://github.com/o/r/actions/runs/9"}]}
        if path.endswith("/releases?per_page=10"):
            return []
        return {"id": 1, "full_name": "o/r", "private": False, "archived": False, "disabled": False, "default_branch": "main", "description": "test", "language": "Python", "visibility": "public", "open_issues_count": 1, "forks_count": 0, "stargazers_count": 0, "size": 42, "updated_at": "2026-09-19T00:00:00Z", "pushed_at": "2026-09-19T00:00:00Z", "html_url": "https://github.com/o/r"}


def _mini_app(tmp_path: Path):
    db_path = tmp_path / "github.db"

    def db_factory():
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    with db_factory() as connection:
        connection.executescript(
            """
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                github_url TEXT NOT NULL,
                branch TEXT NOT NULL,
                workspace_path TEXT NOT NULL,
                latest_sha TEXT
            );
            INSERT INTO projects(name,github_url,branch,workspace_path,latest_sha)
            VALUES('demo','https://github.com/o/r','main','/tmp/not-cloned',NULL);
            """
        )

    def lookup(project_id: int):
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Project not found")
        return row

    audit_events: list[tuple] = []
    app = FastAPI()
    install_github_operations_routes(
        app,
        db_factory=db_factory,
        project_lookup=lookup,
        audit_fn=lambda *args: audit_events.append(args),
        api_factory=FakeGitHubAPI,
    )
    return app, audit_events


def test_live_snapshot_and_stale_fallback(tmp_path: Path) -> None:
    FakeGitHubAPI.fail = False
    app, audit_events = _mini_app(tmp_path)
    client = TestClient(app)
    live = client.get("/api/projects/1/github/overview?refresh=true")
    assert live.status_code == 200, live.text
    payload = live.json()
    assert payload["source"] == "live"
    assert payload["stale"] is False
    assert payload["repository"]["full_name"] == "o/r"
    assert payload["branches"][0]["protected"] is True
    assert payload["workflow_runs"][0]["conclusion"] == "success"
    assert audit_events

    FakeGitHubAPI.fail = True
    stale = client.get("/api/projects/1/github/overview?refresh=true")
    assert stale.status_code == 200, stale.text
    cached = stale.json()
    assert cached["source"] == "cache"
    assert cached["stale"] is True
    assert "simulated outage" in cached["refresh_error"]
    assert cached["repository"]["full_name"] == "o/r"
    FakeGitHubAPI.fail = False


def test_status_never_returns_token(tmp_path: Path, monkeypatch) -> None:
    app, _ = _mini_app(tmp_path)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_TOKEN", "ghp_super_secret_value")
    payload = TestClient(app).get("/api/github/status").json()
    assert payload["token_configured"] is True
    assert payload["credential_storage"] == "environment"
    assert "ghp_super_secret_value" not in str(payload)


def test_platform_github_routes_are_unique() -> None:
    paths = [getattr(route, "path", "") for route in platform_app.router.routes]
    expected = {
        "/github",
        "/projects/{project_id}/github",
        "/api/github/status",
        "/api/github/projects",
        "/api/projects/{project_id}/github/overview",
    }
    for path in expected:
        assert paths.count(path) == 1
