from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request

from app.agent_control import (
    AGENT_PROTOCOL_VERSION,
    AGENT_TOKEN_BYTES,
    CommandResult,
    EnrollmentRequest,
    HeartbeatRequest,
    _agent_from_request,
    _hash,
    _now,
)


def install_agent_transport_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    @app.post("/auth/agent/v1/enroll", status_code=201)
    def enroll(payload: EnrollmentRequest, request: Request) -> dict[str, Any]:
        if payload.protocol_version != AGENT_PROTOCOL_VERSION:
            raise HTTPException(status_code=409, detail=f"Agent protocol {AGENT_PROTOCOL_VERSION} required")
        now_dt = datetime.now(timezone.utc)
        with db_factory() as connection:
            enrollment = connection.execute(
                "SELECT * FROM agent_enrollment_tokens WHERE token_hash=? AND used_at IS NULL",
                (_hash(payload.enrollment_token),),
            ).fetchone()
            if not enrollment:
                raise HTTPException(status_code=401, detail="Unknown or already-used enrollment token")
            try:
                expires = datetime.fromisoformat(enrollment["expires_at"])
            except Exception as exc:
                raise HTTPException(status_code=401, detail="Invalid enrollment token") from exc
            if expires <= now_dt:
                raise HTTPException(status_code=401, detail="Enrollment token expired")
            raw_agent_token = secrets.token_urlsafe(AGENT_TOKEN_BYTES)
            agent_id = "cga_" + secrets.token_urlsafe(12)
            now = _now()
            remote = request.client.host if request.client else ""
            existing = connection.execute("SELECT id FROM vps_agents WHERE server_id=?", (enrollment["server_id"],)).fetchone()
            if existing:
                connection.execute(
                    "UPDATE vps_agents SET agent_id=?,token_hash=?,protocol_version=?,agent_version=?,hostname=?,platform=?,last_seen_at=?,last_ip=?,revoked_at=NULL,updated_at=? WHERE id=?",
                    (agent_id, _hash(raw_agent_token), payload.protocol_version, payload.agent_version, payload.hostname, payload.platform, now, remote, now, existing["id"]),
                )
            else:
                connection.execute(
                    "INSERT INTO vps_agents(server_id,agent_id,token_hash,protocol_version,agent_version,hostname,platform,last_seen_at,last_ip,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (enrollment["server_id"], agent_id, _hash(raw_agent_token), payload.protocol_version, payload.agent_version, payload.hostname, payload.platform, now, remote, now, now),
                )
            connection.execute("UPDATE agent_enrollment_tokens SET used_at=? WHERE id=?", (now, enrollment["id"]))
        audit_fn("agent.enrolled", "server", int(enrollment["server_id"]), f"VPS agent enrolled as {agent_id}")
        return {"agent_id": agent_id, "agent_token": raw_agent_token, "protocol_version": AGENT_PROTOCOL_VERSION, "heartbeat_seconds": 30}

    @app.post("/auth/agent/v1/heartbeat")
    def heartbeat(payload: HeartbeatRequest, request: Request) -> dict[str, Any]:
        agent = _agent_from_request(db_factory, request)
        if payload.protocol_version != AGENT_PROTOCOL_VERSION:
            raise HTTPException(status_code=409, detail=f"Agent protocol {AGENT_PROTOCOL_VERSION} required")
        metrics = payload.metrics
        def num(name: str) -> float | None:
            try:
                value = metrics.get(name)
                return float(value) if value is not None else None
            except (TypeError, ValueError):
                return None
        def integer(name: str) -> int | None:
            try:
                value = metrics.get(name)
                return int(value) if value is not None else None
            except (TypeError, ValueError):
                return None
        now = _now()
        remote = request.client.host if request.client else ""
        with db_factory() as connection:
            connection.execute(
                "UPDATE vps_agents SET protocol_version=?,agent_version=?,hostname=?,platform=?,last_seen_at=?,last_ip=?,updated_at=? WHERE id=?",
                (payload.protocol_version, payload.agent_version, payload.hostname, payload.platform, now, remote, now, agent["id"]),
            )
            connection.execute(
                "INSERT INTO agent_metric_samples(agent_id,cpu_percent,memory_percent,disk_percent,load_1,containers_running,containers_total,failed_services,payload_json,sampled_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (agent["id"], num("cpu_percent"), num("memory_percent"), num("disk_percent"), num("load_1"), integer("containers_running"), integer("containers_total"), integer("failed_services"), json.dumps(metrics)[:20000], now),
            )
            connection.execute(
                "DELETE FROM agent_metric_samples WHERE agent_id=? AND id NOT IN (SELECT id FROM agent_metric_samples WHERE agent_id=? ORDER BY id DESC LIMIT 2880)",
                (agent["id"], agent["id"]),
            )
        return {"ok": True, "server_time": now, "next_heartbeat_seconds": 30}

    @app.get("/auth/agent/v1/commands")
    def commands(request: Request) -> dict[str, Any]:
        agent = _agent_from_request(db_factory, request)
        now = _now()
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM agent_commands WHERE agent_id=? AND status='queued' ORDER BY id LIMIT 1", (agent["id"],)).fetchone()
            if not row:
                return {"command": None}
            changed = connection.execute("UPDATE agent_commands SET status='running',claimed_at=? WHERE id=? AND status='queued'", (now, row["id"])).rowcount
            if not changed:
                return {"command": None}
        return {"command": {"id": row["id"], "kind": row["kind"], "payload": json.loads(row["payload_json"])}}

    @app.post("/auth/agent/v1/results")
    def result(payload: CommandResult, request: Request) -> dict[str, Any]:
        agent = _agent_from_request(db_factory, request)
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM agent_commands WHERE id=? AND agent_id=?", (payload.command_id, agent["id"])).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Agent command not found")
            if row["status"] not in {"running", "queued"}:
                raise HTTPException(status_code=409, detail="Agent command already settled")
            connection.execute(
                "UPDATE agent_commands SET status=?,result_json=?,error=?,finished_at=? WHERE id=?",
                ("success" if payload.ok else "failed", json.dumps(payload.result)[:20000], (payload.error or "")[:8000] or None, _now(), payload.command_id),
            )
        return {"ok": True}
