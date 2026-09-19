from __future__ import annotations

import os
import sqlite3
import uuid

import psycopg
import pytest

from app.control_db import CompatRow, PostgresCompatConnection, _split_sql


DSN = os.getenv("CUSTOM_GITHUB_TEST_POSTGRES_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="PostgreSQL CI service is not configured")


def _schema() -> str:
    return "cg_test_" + uuid.uuid4().hex[:12]


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
            # A mapped integrity error must not poison the rest of the transaction.
            assert connection.execute("SELECT COUNT(*) AS c FROM child").fetchone()["c"] == 1
    finally:
        with psycopg.connect(DSN, autocommit=True) as raw:
            with raw.cursor() as cur:
                cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
