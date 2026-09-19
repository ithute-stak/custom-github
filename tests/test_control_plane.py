import os
from pathlib import Path

from fastapi.testclient import TestClient

from app.deployment import _compose_command, capacity_gate
from app.main import APP_ROOT, DATA_DIR, WORKSPACE_ROOT, app, db, init_db, utc_now


init_db()
client = TestClient(app)


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "0.2.0"


def test_dashboard_loads_production_controls() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Deploy Latest" in response.text
    assert "Add production VPS" in response.text
    assert "Check VPS" in response.text


def test_rejects_non_github_repository() -> None:
    response = client.post(
        "/api/projects",
        json={"name": "unsafe", "github_url": "https://example.com/repo.git", "branch": "main"},
    )
    assert response.status_code == 400


def test_registers_server_without_storing_private_key_contents() -> None:
    response = client.post(
        "/api/servers",
        json={
            "name": "test-production",
            "host": "192.0.2.20",
            "ssh_user": "deploy",
            "identity_file": "~/.ssh/custom_github_test",
            "max_disk_percent": 80,
            "max_memory_percent": 85,
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["identity_file"] == "~/.ssh/custom_github_test"
    assert "PRIVATE KEY" not in str(body)


def test_capacity_gate_blocks_unsafe_vps() -> None:
    metrics = {
        "disk_used_percent": 86,
        "memory_used_percent": 91.0,
        "mem_available_mb": 256,
        "disk_available_mb": 700,
    }
    server = {"max_disk_percent": 80, "max_memory_percent": 85}
    target = {"required_memory_mb": 512, "required_disk_mb": 2048}
    failures = capacity_gate(metrics, server, target)
    assert len(failures) == 4
    assert any("Disk usage" in failure for failure in failures)
    assert any("Memory usage" in failure for failure in failures)


def test_compose_activation_uses_override_and_never_builds() -> None:
    target = {
        "compose_dir": "/opt/apps/loanhub",
        "compose_file": "compose.yaml",
        "service_name": "api",
    }
    command = _compose_command(target, "custom-github/loanhub:abc123def456")
    assert ".custom-github.override.yaml" in command
    assert ".custom-github.release" in command
    assert "--no-build" in command
    assert "--env-file" not in command
    assert "docker build" not in command
    assert "git " not in command


def test_deploy_latest_requires_exact_green_docker_image() -> None:
    now = utc_now()
    with db() as connection:
        project_id = connection.execute(
            """
            INSERT INTO projects(name, github_url, branch, workspace_path, latest_sha, created_at, updated_at)
            VALUES ('gate-test', 'https://github.com/ithute-stak/gate-test.git', 'main', '/tmp/gate-test', 'abc123', ?, ?)
            """,
            (now, now),
        ).lastrowid
        server_id = connection.execute(
            """
            INSERT INTO servers(name, host, port, ssh_user, max_disk_percent, max_memory_percent, created_at, updated_at)
            VALUES ('gate-server', '192.0.2.30', 22, 'deploy', 80, 85, ?, ?)
            """,
            (now, now),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO deployment_targets(
                project_id, server_id, compose_dir, compose_file, service_name,
                image_env_key, health_url, required_memory_mb, required_disk_mb,
                created_at, updated_at
            ) VALUES (?, ?, '/opt/apps/gate-test', 'compose.yaml', 'gate-test', 'CUSTOM_GITHUB_IMAGE',
                      'https://gate.example.test/health', 512, 2048, ?, ?)
            """,
            (project_id, server_id, now, now),
        )
        connection.execute(
            """
            INSERT INTO pipeline_runs(project_id, commit_sha, status, image_tag, steps_json, logs, started_at, finished_at)
            VALUES (?, 'abc123', 'success', NULL, '[]', '', ?, ?)
            """,
            (project_id, now, now),
        )

    response = client.post(f"/api/projects/{project_id}/deploy-latest")
    assert response.status_code == 409
    assert "Docker image" in response.json()["detail"]


def test_target_rejects_non_http_health_url() -> None:
    projects = client.get("/api/projects").json()
    project_id = next(project["id"] for project in projects if project["name"] == "gate-test")
    servers = client.get("/api/servers").json()
    server_id = next(server["id"] for server in servers if server["name"] == "gate-server")
    response = client.put(
        f"/api/projects/{project_id}/deployment-target",
        json={
            "server_id": server_id,
            "compose_dir": "/opt/apps/gate-test",
            "compose_file": "compose.yaml",
            "service_name": "gate-test",
            "health_url": "file:///etc/passwd",
            "required_memory_mb": 512,
            "required_disk_mb": 2048,
        },
    )
    assert response.status_code == 400


def test_data_paths_are_session_isolated_from_operator_state() -> None:
    configured_data = Path(os.environ["CUSTOM_GITHUB_DATA_DIR"]).resolve()
    configured_workspaces = Path(os.environ["CUSTOM_GITHUB_WORKSPACE_ROOT"]).resolve()
    assert DATA_DIR.resolve() == configured_data
    assert WORKSPACE_ROOT.resolve() == configured_workspaces
    assert DATA_DIR.resolve() != (APP_ROOT / "data").resolve()
    assert "custom-github-pytest-" in configured_data.parent.name
