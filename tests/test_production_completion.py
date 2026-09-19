from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.agent_control import _hash, _validate_command
from app.main import app, db, utc_now
from app.platform import app as platform_app
from app.remote_hardening import _truthy


def _server(name: str) -> int:
    now = utc_now()
    with db() as connection:
        cursor = connection.execute(
            "INSERT INTO servers(name,host,port,ssh_user,identity_file,max_disk_percent,max_memory_percent,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (name, "192.0.2.91", 22, "deploy", None, 80, 85, now, now),
        )
        return int(cursor.lastrowid)


def test_agent_command_allowlist_blocks_connectivity_services() -> None:
    assert _validate_command("agent.ping", {}) == {}
    assert _validate_command("service.restart", {"unit": "nginx"}) == {"unit": "nginx.service"}
    assert _validate_command("container.restart", {"container": "loanhub-backend-1"}) == {"container": "loanhub-backend-1"}
    with pytest.raises(HTTPException):
        _validate_command("service.restart", {"unit": "sshd"})
    with pytest.raises(HTTPException):
        _validate_command("shell.run", {"command": "id"})


def test_agent_transport_enrollment_heartbeat_command_result_cycle() -> None:
    server_id = _server("agent-transport-test")
    enrollment = "enroll_" + secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    with db() as connection:
        connection.execute(
            "INSERT INTO agent_enrollment_tokens(server_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)",
            (server_id, _hash(enrollment), expires, utc_now()),
        )

    client = TestClient(platform_app)
    response = client.post(
        "/auth/agent/v1/enroll",
        json={
            "enrollment_token": enrollment,
            "agent_version": "test-agent",
            "protocol_version": 1,
            "hostname": "agent-test-host",
            "platform": "Linux test",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    agent_id = body["agent_id"]
    token = body["agent_token"]

    reused = client.post(
        "/auth/agent/v1/enroll",
        json={
            "enrollment_token": enrollment,
            "agent_version": "test-agent",
            "protocol_version": 1,
            "hostname": "agent-test-host",
            "platform": "Linux test",
        },
    )
    assert reused.status_code == 401

    heartbeat = client.post(
        "/auth/agent/v1/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_version": "test-agent",
            "protocol_version": 1,
            "hostname": "agent-test-host",
            "platform": "Linux test",
            "metrics": {
                "cpu_percent": 12.5,
                "memory_percent": 33.1,
                "disk_percent": 44.2,
                "load_1": 0.4,
                "containers_running": 27,
                "containers_total": 27,
                "failed_services": 0,
            },
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text

    with db() as connection:
        agent = connection.execute("SELECT * FROM vps_agents WHERE agent_id=?", (agent_id,)).fetchone()
        assert agent is not None
        cursor = connection.execute(
            "INSERT INTO agent_commands(agent_id,kind,payload_json,status,created_at) VALUES(?,?,?,'queued',?)",
            (agent["id"], "agent.ping", "{}", utc_now()),
        )
        command_id = int(cursor.lastrowid)

    polled = client.get("/auth/agent/v1/commands", headers={"Authorization": f"Bearer {token}"})
    assert polled.status_code == 200
    assert polled.json()["command"]["id"] == command_id
    assert polled.json()["command"]["kind"] == "agent.ping"

    settled = client.post(
        "/auth/agent/v1/results",
        headers={"Authorization": f"Bearer {token}"},
        json={"command_id": command_id, "ok": True, "result": {"pong": True}, "error": None},
    )
    assert settled.status_code == 200
    with db() as connection:
        row = connection.execute("SELECT * FROM agent_commands WHERE id=?", (command_id,)).fetchone()
        assert row["status"] == "success"
        sample = connection.execute("SELECT * FROM agent_metric_samples WHERE agent_id=? ORDER BY id DESC LIMIT 1", (agent["id"],)).fetchone()
        assert sample is not None
        assert sample["containers_running"] == 27


def test_production_completion_routes_are_registered() -> None:
    paths = [getattr(route, "path", "") for route in platform_app.router.routes]
    expected = {
        "/agents",
        "/api/agents",
        "/api/agents/enrollment/{server_id}",
        "/auth/agent/v1/enroll",
        "/auth/agent/v1/heartbeat",
        "/auth/agent/v1/commands",
        "/auth/agent/v1/results",
        "/vps/{server_id}/readiness",
        "/api/vps/servers/{server_id}/readiness",
        "/api/vps/servers/{server_id}/recovery-drills",
    }
    assert expected.issubset(set(paths))
    assert paths.count("/auth/agent/v1/enroll") == 1


def test_remote_mode_truthy_parser() -> None:
    assert _truthy("1")
    assert _truthy("YES")
    assert _truthy("true")
    assert not _truthy("")
    assert not _truthy("0")
