import sqlite3

import pytest
from pydantic import ValidationError

from app.maintenance import (
    MaintenanceSettings,
    _deployment_protected_tags,
    _human_bytes_to_int,
    _parse_disk_analysis,
)
from app.platform import app


def test_human_byte_parser_understands_journal_units() -> None:
    assert _human_bytes_to_int("Archived and active journals take up 3.2G in the file system.") == int(3.2 * 1024**3)
    assert _human_bytes_to_int("12.5M") == int(12.5 * 1024**2)
    assert _human_bytes_to_int("no size here") == 0


def test_disk_analysis_parser_sorts_largest_consumers() -> None:
    payload = """
__DF__
1000\t800\t200\t80%\t/
__TOP__
400\t/var
200\t/opt
__SPECIAL__
docker\t300
logs\t100
apt\t20
trash\t10
__LARGEST__
50\t/var/log/a.log
200\t/opt/app/big.bin
__JOURNAL__
Archived and active journals take up 64.0M in the file system.
""".strip()
    result = _parse_disk_analysis(payload)
    assert result["filesystem"]["used_percent"] == 80
    assert result["top_directories"][0] == {"bytes": 400, "path": "/var"}
    assert result["largest_files"][0]["path"] == "/opt/app/big.bin"
    assert result["special"]["docker"] == 300


def test_maintenance_thresholds_are_ordered() -> None:
    with pytest.raises(ValidationError):
        MaintenanceSettings(warn_disk_percent=90, critical_disk_percent=85)
    with pytest.raises(ValidationError):
        MaintenanceSettings(warn_disk_percent=85, critical_disk_percent=90, auto_cleanup_threshold_percent=80)
    with pytest.raises(ValidationError):
        MaintenanceSettings(backup_watch_path="relative/backups")


def test_release_retention_protects_configured_number_per_project() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE deployments(
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            image_tag TEXT,
            previous_image TEXT
        );
        INSERT INTO deployments VALUES(1, 1, 9, 'app:v1', NULL);
        INSERT INTO deployments VALUES(2, 1, 9, 'app:v2', 'app:v1');
        INSERT INTO deployments VALUES(3, 1, 9, 'app:v3', 'app:v2');
        INSERT INTO deployments VALUES(4, 2, 9, 'api:a1', NULL);
        INSERT INTO deployments VALUES(5, 2, 9, 'api:a2', 'api:a1');
        """
    )
    keep_one = _deployment_protected_tags(connection, 9, 1)
    keep_two = _deployment_protected_tags(connection, 9, 2)
    assert {'app:v3', 'app:v2', 'api:a2', 'api:a1'} <= keep_one
    assert 'app:v1' not in keep_one
    assert {'app:v3', 'app:v2', 'app:v1', 'api:a2', 'api:a1'} <= keep_two


def test_maintenance_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    expected = {
        "/vps/{server_id}/maintenance",
        "/api/vps/servers/{server_id}/maintenance/settings",
        "/api/vps/servers/{server_id}/maintenance/disk",
        "/api/vps/servers/{server_id}/maintenance/cleanup/preview",
        "/api/vps/servers/{server_id}/maintenance/cleanup",
        "/api/vps/servers/{server_id}/maintenance/containers",
        "/api/vps/servers/{server_id}/maintenance/logs",
        "/api/vps/servers/{server_id}/maintenance/health",
        "/api/vps/servers/{server_id}/maintenance/history",
        "/api/vps/servers/{server_id}/maintenance/run",
    }
    assert expected <= paths
