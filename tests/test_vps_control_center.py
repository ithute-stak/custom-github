import os
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import db, init_db, utc_now
from app.platform import app
from app.vps import deletion_is_protected, normalize_remote_path


init_db()


def ensure_server() -> int:
    now = utc_now()
    with db() as connection:
        row = connection.execute("SELECT id FROM servers WHERE name = 'vps-ui-test'").fetchone()
        if row:
            return int(row["id"])
        return int(
            connection.execute(
                """
                INSERT INTO servers(name, host, port, ssh_user, identity_file,
                                    max_disk_percent, max_memory_percent, created_at, updated_at)
                VALUES ('vps-ui-test', '192.0.2.50', 22, 'deploy', NULL, 80, 85, ?, ?)
                """,
                (now, now),
            ).lastrowid
        )


def test_vps_workspace_route_and_event_tables() -> None:
    server_id = ensure_server()
    with TestClient(app) as client:
        response = client.get(f"/vps/{server_id}")
        assert response.status_code == 200
        assert "VPS Control Center" in response.text
        assert "Remote filesystem" in response.text
        assert "SSH terminal" in response.text

        operations = client.get(f"/api/vps/servers/{server_id}/operations")
        events = client.get(f"/api/vps/servers/{server_id}/events")
        assert operations.status_code == 200
        assert events.status_code == 200
        assert isinstance(operations.json(), list)
        assert isinstance(events.json(), list)


def test_remote_paths_are_normalized_and_system_roots_are_protected() -> None:
    assert normalize_remote_path("/opt/apps/../loanhub") == "/opt/loanhub"
    assert deletion_is_protected("/")
    assert deletion_is_protected("/etc")
    assert deletion_is_protected("/var/lib/docker")
    assert not deletion_is_protected("/etc/nginx/sites-enabled/loanhub.conf")


def test_relative_remote_paths_are_rejected() -> None:
    try:
        normalize_remote_path("etc/passwd")
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400
    else:
        raise AssertionError("relative VPS path should be rejected")


def test_protected_delete_is_blocked_before_any_ssh_action() -> None:
    server_id = ensure_server()
    with TestClient(app) as client:
        response = client.post(
            f"/api/vps/servers/{server_id}/files/delete",
            json={"path": "/etc", "permanent": True, "confirm_path": "/etc"},
        )
    assert response.status_code == 409
    assert "protected" in response.json()["detail"].lower()


def test_invalid_service_name_is_rejected_before_background_operation() -> None:
    server_id = ensure_server()
    with TestClient(app) as client:
        response = client.post(
            f"/api/vps/servers/{server_id}/services/nginx;rm/action",
            json={"action": "restart"},
        )
    assert response.status_code == 400


def test_platform_entrypoint_is_used_by_local_start_script() -> None:
    script = Path("scripts/start-local.sh").read_text(encoding="utf-8")
    assert "app.platform:app" in script
    assert "--host 127.0.0.1" in script


def test_management_routes_remain_local_first() -> None:
    assert os.environ.get("CUSTOM_GITHUB_DATA_DIR")
    route_paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/vps/{server_id}" in route_paths
    assert "/api/vps/servers/{server_id}/files" in route_paths
    assert "/api/vps/servers/{server_id}/docker/containers" in route_paths
    assert "/api/vps/servers/{server_id}/services" in route_paths
    assert "/api/vps/servers/{server_id}/processes" in route_paths
    assert "/api/vps/servers/{server_id}/logs" in route_paths
