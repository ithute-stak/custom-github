import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.backup_manager import BackupProfileCreate, _path
from app.domain_manager import _domain, _upstream
from app.platform import app
from app.security import ROLE_LEVEL, _password_hash, _password_ok, _totp, _totp_ok, _required_role


def test_password_hash_round_trip_and_wrong_password() -> None:
    salt, digest = _password_hash("correct horse battery staple")
    assert _password_ok("correct horse battery staple", salt, digest)
    assert not _password_ok("wrong password", salt, digest)


def test_totp_accepts_current_counter_and_rejects_bad_code() -> None:
    secret = "JBSWY3DPEHPK3PXP"
    now = 1_700_000_000
    code = _totp(secret, now // 30)
    assert _totp_ok(secret, code, now=now)
    assert not _totp_ok(secret, "000000" if code != "000000" else "111111", now=now)


def test_rbac_levels_and_sensitive_route_requirements() -> None:
    assert ROLE_LEVEL["owner"] > ROLE_LEVEL["admin"] > ROLE_LEVEL["developer"] > ROLE_LEVEL["operator"] > ROLE_LEVEL["viewer"]
    assert _required_role("/api/vps/servers/1/domains/nginx", "POST") == "admin"
    assert _required_role("/api/vps/servers/1/backups/runs/4/restore", "POST") == "admin"
    assert _required_role("/api/vps/servers/1/file", "PUT") == "developer"
    assert _required_role("/api/vps/servers/1/docker/containers/x/action", "POST") == "operator"


def test_domain_and_upstream_validation() -> None:
    assert _domain("Api.Example.COM.") == "api.example.com"
    assert _upstream("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert _upstream("http://loanhub-backend:8000/api") == "http://loanhub-backend:8000/api"
    with pytest.raises(HTTPException):
        _domain("not a domain")
    with pytest.raises(HTTPException):
        _upstream("file:///etc/passwd")


def test_backup_paths_reject_root_and_virtual_filesystems() -> None:
    assert _path("/opt/loanhub/") == "/opt/loanhub"
    for unsafe in ["/", "/proc", "/sys", "/dev", "/run", "relative/path"]:
        with pytest.raises(ValueError):
            _path(unsafe)


def test_backup_profile_requires_valid_source_shapes() -> None:
    profile = BackupProfileCreate(
        name="production",
        paths=["/opt/loanhub"],
        volumes=["loanhub_db_data"],
        database_containers=["loanhub-db-1"],
    )
    assert profile.paths == ["/opt/loanhub"]
    assert profile.retention_count == 7
    with pytest.raises(Exception):
        BackupProfileCreate(name="bad", paths=["/opt/app"], volumes=["bad volume"])


def test_prebootstrap_security_mutations_are_blocked() -> None:
    with TestClient(app) as client:
        state = client.get("/auth/status").json()
        assert state["users"] == 0
        response = client.post(
            "/api/security/users",
            json={
                "username": "bypass",
                "display_name": "Should Not Exist",
                "password": "this-is-a-long-password",
                "role": "owner",
            },
        )
        assert response.status_code == 409
        assert "bootstrap" in response.json()["detail"].lower()


def test_expansion_routes_are_registered_once() -> None:
    paths = [getattr(route, "path", "") for route in app.router.routes]
    expected = {
        "/security",
        "/auth/login",
        "/auth/bootstrap",
        "/api/security/me",
        "/vps/{server_id}/domains",
        "/api/vps/servers/{server_id}/domains",
        "/api/vps/servers/{server_id}/domains/nginx",
        "/api/vps/servers/{server_id}/ssl/issue",
        "/vps/{server_id}/backups",
        "/api/vps/servers/{server_id}/backups/profiles",
        "/api/vps/servers/{server_id}/backups/runs/{run_id}/restore",
        "/api/vps/servers/{server_id}/terminal/ws",
    }
    assert expected.issubset(set(paths))
    assert paths.count("/api/vps/servers/{server_id}/terminal/ws") == 1
