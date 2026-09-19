import sqlite3
from pathlib import Path

from scripts.repair_test_contamination import detect, delete_by_project, delete_by_server


def _db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE projects(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            github_url TEXT NOT NULL,
            branch TEXT NOT NULL,
            workspace_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE servers(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            ssh_user TEXT NOT NULL,
            identity_file TEXT,
            max_disk_percent INTEGER NOT NULL,
            max_memory_percent INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE deployment_targets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL UNIQUE,
            server_id INTEGER NOT NULL,
            compose_dir TEXT NOT NULL,
            compose_file TEXT NOT NULL,
            service_name TEXT NOT NULL,
            image_env_key TEXT NOT NULL,
            health_url TEXT NOT NULL,
            required_memory_mb INTEGER NOT NULL,
            required_disk_mb INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(server_id) REFERENCES servers(id)
        );
        CREATE TABLE pipeline_runs(
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
        CREATE TABLE deployment_requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            commit_sha TEXT NOT NULL,
            image_tag TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        );
        CREATE TABLE deployments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            commit_sha TEXT NOT NULL,
            image_tag TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(server_id) REFERENCES servers(id)
        );
        """
    )
    return connection


def test_repair_targets_only_exact_known_test_fixtures(tmp_path: Path) -> None:
    connection = _db(tmp_path / "state.db")
    now = "2026-09-19T00:00:00+00:00"
    connection.execute(
        "INSERT INTO projects(name,github_url,branch,workspace_path,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        ("loanhub", "https://github.com/ithute-stak/loanhub.git", "main", "/real/loanhub", now, now),
    )
    gate_project = connection.execute(
        "INSERT INTO projects(name,github_url,branch,workspace_path,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        ("gate-test", "https://github.com/ithute-stak/gate-test.git", "main", "/tmp/gate-test", now, now),
    ).lastrowid
    real_server = connection.execute(
        "INSERT INTO servers(name,host,port,ssh_user,max_disk_percent,max_memory_percent,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        ("selemela", "203.0.113.10", 22, "administrator", 80, 85, now, now),
    ).lastrowid
    gate_server = connection.execute(
        "INSERT INTO servers(name,host,port,ssh_user,max_disk_percent,max_memory_percent,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        ("gate-server", "192.0.2.30", 22, "deploy", 80, 85, now, now),
    ).lastrowid
    connection.execute(
        "INSERT INTO servers(name,host,port,ssh_user,max_disk_percent,max_memory_percent,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        ("looks-similar", "192.0.2.30", 22, "deploy", 80, 85, now, now),
    )
    connection.execute(
        "INSERT INTO deployment_targets(project_id,server_id,compose_dir,compose_file,service_name,image_env_key,health_url,required_memory_mb,required_disk_mb,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (gate_project, gate_server, "/opt/apps/gate-test", "compose.yaml", "gate-test", "CUSTOM_GITHUB_IMAGE", "https://example.test/health", 512, 2048, now, now),
    )
    connection.commit()

    found = detect(connection)
    assert [row["name"] for row in found["servers"]] == ["gate-server"]
    assert [row["name"] for row in found["projects"]] == ["gate-test"]

    delete_by_project(connection, int(gate_project))
    delete_by_server(connection, int(gate_server))
    connection.commit()

    assert connection.execute("SELECT COUNT(*) FROM projects WHERE name='loanhub'").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM projects WHERE name='gate-test'").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM servers WHERE id=?", (real_server,)).fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM servers WHERE name='looks-similar'").fetchone()[0] == 1
    assert connection.execute("SELECT COUNT(*) FROM servers WHERE name='gate-server'").fetchone()[0] == 0
