from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import uuid
from pathlib import Path

import psycopg
import pytest

from app.control_db import CompatRow, PostgresCompatConnection, _split_sql


DSN = os.getenv("CUSTOM_GITHUB_TEST_POSTGRES_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="PostgreSQL CI service is not configured")
ROOT = Path(__file__).resolve().parents[1]


def _schema() -> str:
    return "cg_test_" + uuid.uuid4().hex[:12]


def _drop(schema: str) -> None:
    with psycopg.connect(DSN, autocommit=True) as raw:
        with raw.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def _run_python(code: str, env: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def test_compat_row_supports_sqlite_style_access() -> None:
    row = CompatRow(["id", "name"], (7, "alpha"))
    assert row[0] == 7
    assert row["id"] == 7
    assert row["name"] == "alpha"
    assert dict(row) == {"id": 7, "name": "alpha"}


def test_split_sql_preserves_semicolon_inside_literal() -> None:
    statements = _split_sql("CREATE TABLE a(x TEXT); INSERT INTO a(x) VALUES('x;y');")
    assert len(statements) == 2
    assert "x;y" in statements[1]


def test_postgres_compat_executes_core_sqlite_patterns() -> None:
    schema = _schema()
    with psycopg.connect(DSN, autocommit=True) as raw:
        with raw.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    try:
        with PostgresCompatConnection(DSN, schema) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS parent (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS child (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_id INTEGER NOT NULL,
                    label TEXT NOT NULL,
                    FOREIGN KEY(parent_id) REFERENCES parent(id)
                );
                """
            )
            cursor = connection.execute("INSERT INTO parent(name) VALUES (?)", ("alpha",))
            assert cursor.lastrowid == 1
            duplicate = connection.execute("INSERT OR IGNORE INTO parent(name) VALUES (?)", ("alpha",))
            assert duplicate.lastrowid is None
            child = connection.execute("INSERT INTO child(parent_id,label) VALUES (?,?)", (1, "first"))
            assert child.lastrowid == 1

            row = connection.execute("SELECT id,name FROM parent WHERE id=?", (1,)).fetchone()
            assert row is not None
            assert row[0] == 1
            assert row["name"] == "alpha"
            assert dict(row) == {"id": 1, "name": "alpha"}

            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                ("parent",),
            ).fetchone()
            assert exists is not None

            columns = connection.execute("PRAGMA table_info(parent)").fetchall()
            by_name = {row["name"]: row for row in columns}
            assert by_name["id"]["pk"] == 1
            assert by_name["name"]["notnull"] == 1

            with pytest.raises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO child(parent_id,label) VALUES (?,?)", (999, "bad"))
            assert connection.execute("SELECT COUNT(*) AS c FROM child").fetchone()["c"] == 1
    finally:
        _drop(schema)


def test_full_platform_boots_and_writes_against_postgres() -> None:
    schema = _schema()
    data_dir = Path(tempfile.mkdtemp(prefix="cg-postgres-runtime-"))
    code = """
    from fastapi.testclient import TestClient
    from app.platform import app
    with TestClient(app) as client:
        status = client.get('/api/control-plane/database')
        assert status.status_code == 200, status.text
        assert status.json()['backend'] == 'postgres'
        created = client.post('/api/projects', json={
            'name': 'pg-smoke',
            'github_url': 'https://github.com/ithute-stak/pg-smoke.git',
            'branch': 'main',
        })
        assert created.status_code == 201, created.text
        projects = client.get('/api/projects')
        assert projects.status_code == 200, projects.text
        assert any(p['name'] == 'pg-smoke' for p in projects.json())
    """
    env = {
        **os.environ,
        "CUSTOM_GITHUB_DB_BACKEND": "postgres",
        "CUSTOM_GITHUB_POSTGRES_DSN": DSN,
        "CUSTOM_GITHUB_POSTGRES_SCHEMA": schema,
        "CUSTOM_GITHUB_POSTGRES_ALLOW_EMPTY": "1",
        "CUSTOM_GITHUB_DATA_DIR": str(data_dir),
        "CUSTOM_GITHUB_WORKSPACE_ROOT": str(data_dir / "workspaces"),
    }
    try:
        completed = _run_python(code, env)
        assert completed.returncode == 0, completed.stdout
    finally:
        _drop(schema)


def test_sqlite_to_postgres_migration_then_runtime_preserves_data() -> None:
    schema = _schema()
    data_dir = Path(tempfile.mkdtemp(prefix="cg-sqlite-source-"))
    sqlite_env = {
        **os.environ,
        "CUSTOM_GITHUB_DB_BACKEND": "sqlite",
        "CUSTOM_GITHUB_DATA_DIR": str(data_dir),
        "CUSTOM_GITHUB_WORKSPACE_ROOT": str(data_dir / "workspaces"),
    }
    create_code = """
    from fastapi.testclient import TestClient
    from app.platform import app
    with TestClient(app) as client:
        response = client.post('/api/projects', json={
            'name': 'migration-survivor',
            'github_url': 'https://github.com/ithute-stak/migration-survivor.git',
            'branch': 'main',
        })
        assert response.status_code == 201, response.text
        assert client.get('/api/control-plane/database').json()['backend'] == 'sqlite'
    """
    source = _run_python(create_code, sqlite_env)
    assert source.returncode == 0, source.stdout
    sqlite_db = data_dir / "custom-github.db"
    assert sqlite_db.exists()

    try:
        migration = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "migrate-control-db-to-postgres.py"),
                "--sqlite", str(sqlite_db),
                "--dsn", DSN,
                "--schema", schema,
                "--apply",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
        assert migration.returncode == 0, migration.stdout
        assert "MIGRATION VERIFIED" in migration.stdout

        postgres_env = {
            **os.environ,
            "CUSTOM_GITHUB_DB_BACKEND": "postgres",
            "CUSTOM_GITHUB_POSTGRES_DSN": DSN,
            "CUSTOM_GITHUB_POSTGRES_SCHEMA": schema,
            "CUSTOM_GITHUB_DATA_DIR": str(data_dir / "postgres-runtime"),
            "CUSTOM_GITHUB_WORKSPACE_ROOT": str(data_dir / "postgres-runtime" / "workspaces"),
        }
        verify_code = """
        from fastapi.testclient import TestClient
        from app.platform import app
        with TestClient(app) as client:
            state = client.get('/api/control-plane/database')
            assert state.status_code == 200, state.text
            assert state.json()['backend'] == 'postgres'
            projects = client.get('/api/projects')
            assert projects.status_code == 200, projects.text
            matches = [p for p in projects.json() if p['name'] == 'migration-survivor']
            assert len(matches) == 1, projects.json()
        """
        verified = _run_python(verify_code, postgres_env)
        assert verified.returncode == 0, verified.stdout
    finally:
        _drop(schema)
