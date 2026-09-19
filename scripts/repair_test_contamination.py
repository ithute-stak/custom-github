from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "custom-github.db"

SERVER_FIXTURES = {
    ("test-production", "192.0.2.20"),
    ("gate-server", "192.0.2.30"),
    ("vps-ui-test", "192.0.2.50"),
}
PROJECT_FIXTURES = {
    ("gate-test", "https://github.com/ithute-stak/gate-test.git"),
}


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def detect(connection: sqlite3.Connection) -> dict[str, list[sqlite3.Row]]:
    connection.row_factory = sqlite3.Row
    servers: list[sqlite3.Row] = []
    projects: list[sqlite3.Row] = []
    if table_exists(connection, "servers"):
        for row in connection.execute("SELECT * FROM servers ORDER BY id"):
            if (str(row["name"]), str(row["host"])) in SERVER_FIXTURES:
                servers.append(row)
    if table_exists(connection, "projects"):
        for row in connection.execute("SELECT * FROM projects ORDER BY id"):
            if (str(row["name"]), str(row["github_url"])) in PROJECT_FIXTURES:
                projects.append(row)
    return {"servers": servers, "projects": projects}


def delete_by_server(connection: sqlite3.Connection, server_id: int) -> None:
    for table in (
        "server_events",
        "server_operations",
        "server_metric_samples",
        "maintenance_settings",
    ):
        if table_exists(connection, table):
            connection.execute(f"DELETE FROM {table} WHERE server_id = ?", (server_id,))

    if table_exists(connection, "deployments"):
        connection.execute("DELETE FROM deployments WHERE server_id = ?", (server_id,))
    if table_exists(connection, "deployment_targets"):
        connection.execute("DELETE FROM deployment_targets WHERE server_id = ?", (server_id,))
    connection.execute("DELETE FROM servers WHERE id = ?", (server_id,))


def delete_by_project(connection: sqlite3.Connection, project_id: int) -> None:
    if table_exists(connection, "deployments"):
        connection.execute("DELETE FROM deployments WHERE project_id = ?", (project_id,))
    if table_exists(connection, "deployment_requests"):
        connection.execute("DELETE FROM deployment_requests WHERE project_id = ?", (project_id,))
    if table_exists(connection, "pipeline_runs"):
        connection.execute("DELETE FROM pipeline_runs WHERE project_id = ?", (project_id,))
    if table_exists(connection, "deployment_targets"):
        connection.execute("DELETE FROM deployment_targets WHERE project_id = ?", (project_id,))
    connection.execute("DELETE FROM projects WHERE id = ?", (project_id,))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect or remove known Custom GitHub pytest fixtures leaked into the live local database."
    )
    parser.add_argument("--apply", action="store_true", help="Actually remove exact known test fixtures")
    parser.add_argument("--db", type=Path, default=DB_PATH, help="SQLite database path")
    args = parser.parse_args()

    db_path = args.db.expanduser().resolve()
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        return 1

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    found = detect(connection)

    print(f"Database: {db_path}")
    print(f"Known leaked test servers: {len(found['servers'])}")
    for row in found["servers"]:
        print(f"  server #{row['id']}: {row['name']} -> {row['host']}")
    print(f"Known leaked test projects: {len(found['projects'])}")
    for row in found["projects"]:
        print(f"  project #{row['id']}: {row['name']} -> {row['github_url']}")

    if not found["servers"] and not found["projects"]:
        print("No known leaked pytest fixtures found. Nothing to repair.")
        return 0

    if not args.apply:
        print("Dry run only. Re-run with --apply to remove only the exact fixtures listed above.")
        return 0

    for row in found["projects"]:
        delete_by_project(connection, int(row["id"]))
    for row in found["servers"]:
        delete_by_server(connection, int(row["id"]))
    connection.commit()

    remaining = detect(connection)
    print("Repair applied.")
    print(f"Remaining known test servers: {len(remaining['servers'])}")
    print(f"Remaining known test projects: {len(remaining['projects'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
