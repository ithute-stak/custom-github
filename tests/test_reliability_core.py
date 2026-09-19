from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

from app.isolated_runner import _container_command, _kind
from app.platform import app as platform_app


def test_pipeline_executable_steps_are_classified_for_isolation(tmp_path: Path) -> None:
    assert _kind("npm test", ["npm", "test"]) == "node"
    assert _kind("pytest", ["python", "-m", "pytest", "-q"]) == "python"
    assert _kind("dotnet test", ["dotnet", "test"]) == "dotnet"
    assert _kind("docker build", ["docker", "build", "-t", "x", "."]) == "docker-build"
    assert _kind("repository validation", ["git", "status", "--short"]) == "safe-host"
    argv = _container_command("python", tmp_path, ["python", "-m", "compileall", "-q", "."])
    joined = " ".join(argv)
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges:true" in joined
    assert "/var/run/docker.sock" not in joined


def test_legacy_pipeline_route_is_replaced_once() -> None:
    routes = [route for route in platform_app.router.routes if getattr(route, "path", "") == "/api/projects/{project_id}/pipeline"]
    assert len(routes) == 1
    assert "POST" in (getattr(routes[0], "methods", None) or set())


def test_reliability_routes_are_unique() -> None:
    paths = [getattr(route, "path", "") for route in platform_app.router.routes]
    expected = {
        "/reliability",
        "/projects/{project_id}/reliability",
        "/api/projects/{project_id}/releases",
        "/api/projects/{project_id}/releases/{pipeline_id}/rollback",
        "/api/projects/{project_id}/drift",
        "/api/projects/{project_id}/drift/baseline",
        "/api/projects/{project_id}/dr-rehearsals",
    }
    assert expected.issubset(set(paths))
    for path in expected:
        assert paths.count(path) == 1


def test_postgres_migration_is_dry_run_by_default(tmp_path: Path) -> None:
    db_path = tmp_path / "control.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE demo(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE)")
    connection.execute("INSERT INTO demo(name) VALUES('one')")
    connection.commit()
    connection.close()
    script = Path(__file__).resolve().parents[1] / "scripts" / "migrate-control-db-to-postgres.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--sqlite", str(db_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout
    assert "demo: 1" in completed.stdout
    assert "DRY RUN ONLY" in completed.stdout
