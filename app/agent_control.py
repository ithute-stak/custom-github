from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

AGENT_PROTOCOL_VERSION = 1
AGENT_TOKEN_BYTES = 32
ENROLLMENT_MINUTES = 15
SERVICE_RE = re.compile(r"^[A-Za-z0-9@_.:-]+(?:\.service)?$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
BLOCKED_SERVICES = {
    "ssh", "sshd", "ssh.service", "sshd.service", "networking", "networking.service",
    "systemd-networkd", "systemd-networkd.service", "ufw", "ufw.service", "firewalld", "firewalld.service",
}
COMMAND_KINDS = {"agent.ping", "service.restart", "service.start", "service.stop", "container.restart", "container.start", "container.stop"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _future(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _init_db(db_factory: Callable[[], sqlite3.Connection]) -> None:
    with db_factory() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );
            CREATE TABLE IF NOT EXISTS vps_agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL UNIQUE,
                agent_id TEXT NOT NULL UNIQUE,
                token_hash TEXT NOT NULL UNIQUE,
                protocol_version INTEGER NOT NULL,
                agent_version TEXT NOT NULL,
                hostname TEXT,
                platform TEXT,
                last_seen_at TEXT,
                last_ip TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );
            CREATE TABLE IF NOT EXISTS agent_metric_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                load_1 REAL,
                containers_running INTEGER,
                containers_total INTEGER,
                failed_services INTEGER,
                payload_json TEXT,
                sampled_at TEXT NOT NULL,
                FOREIGN KEY(agent_id) REFERENCES vps_agents(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS agent_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                claimed_at TEXT,
                finished_at TEXT,
                FOREIGN KEY(agent_id) REFERENCES vps_agents(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent ON agent_metric_samples(agent_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_agent_commands_agent ON agent_commands(agent_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_agent_commands_queue ON agent_commands(agent_id, status, id);
            """
        )


class EnrollmentRequest(BaseModel):
    enrollment_token: str = Field(min_length=20, max_length=256)
    agent_version: str = Field(min_length=1, max_length=80)
    protocol_version: int = Field(default=AGENT_PROTOCOL_VERSION, ge=1, le=20)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(default="linux", min_length=1, max_length=255)


class HeartbeatRequest(BaseModel):
    agent_version: str = Field(min_length=1, max_length=80)
    protocol_version: int = Field(default=AGENT_PROTOCOL_VERSION, ge=1, le=20)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(default="linux", min_length=1, max_length=255)
    metrics: dict[str, Any] = Field(default_factory=dict)


class CommandResult(BaseModel):
    command_id: int = Field(ge=1)
    ok: bool
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=8000)


class QueueCommand(BaseModel):
    kind: str = Field(min_length=1, max_length=80)
    payload: dict[str, Any] = Field(default_factory=dict)


class RevokeAgent(BaseModel):
    confirm: str = Field(min_length=1, max_length=200)


def _remote_addr(request: Request) -> str:
    return request.client.host if request.client else ""


def _agent_from_request(db_factory: Callable[[], sqlite3.Connection], request: Request) -> sqlite3.Row:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Agent bearer token required")
    raw = auth[7:].strip()
    if len(raw) < 20:
        raise HTTPException(status_code=401, detail="Invalid agent bearer token")
    with db_factory() as connection:
        row = connection.execute(
            "SELECT * FROM vps_agents WHERE token_hash=? AND revoked_at IS NULL",
            (_hash(raw),),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Unknown or revoked agent")
    return row


def _validate_command(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    if kind not in COMMAND_KINDS:
        raise HTTPException(status_code=400, detail="Unsupported structured agent command")
    if kind == "agent.ping":
        return {}
    if kind.startswith("service."):
        unit = str(payload.get("unit", "")).strip()
        if not SERVICE_RE.fullmatch(unit):
            raise HTTPException(status_code=400, detail="Invalid systemd service")
        normalized = unit if unit.endswith(".service") else f"{unit}.service"
        if unit in BLOCKED_SERVICES or normalized in BLOCKED_SERVICES:
            raise HTTPException(status_code=409, detail="Connectivity-critical services are blocked from agent actions")
        return {"unit": normalized}
    if kind.startswith("container."):
        container = str(payload.get("container", "")).strip()
        if not CONTAINER_RE.fullmatch(container):
            raise HTTPException(status_code=400, detail="Invalid Docker container name or id")
        return {"container": container}
    raise HTTPException(status_code=400, detail="Unsupported structured agent command")


def install_agent_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    _init_db(db_factory)

    @app.get("/agents", response_class=HTMLResponse, include_in_schema=False)
    def agent_page() -> str:
        return AGENT_HTML

    @app.get("/api/agents")
    def list_agents() -> list[dict[str, Any]]:
        with db_factory() as connection:
            rows = connection.execute(
                """
                SELECT a.*, s.name server_name, s.host server_host,
                       (SELECT sampled_at FROM agent_metric_samples m WHERE m.agent_id=a.id ORDER BY m.id DESC LIMIT 1) sampled_at,
                       (SELECT payload_json FROM agent_metric_samples m WHERE m.agent_id=a.id ORDER BY m.id DESC LIMIT 1) metric_payload
                FROM vps_agents a JOIN servers s ON s.id=a.server_id ORDER BY s.name
                """
            ).fetchall()
        now = datetime.now(timezone.utc)
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            last_seen = None
            try:
                last_seen = datetime.fromisoformat(item["last_seen_at"]) if item.get("last_seen_at") else None
            except Exception:
                pass
            age = (now - last_seen).total_seconds() if last_seen else None
            item["online"] = bool(age is not None and age <= 90 and not item.get("revoked_at"))
            item["last_seen_seconds"] = int(age) if age is not None else None
            item["metrics"] = json.loads(item.pop("metric_payload")) if item.get("metric_payload") else None
            item.pop("token_hash", None)
            result.append(item)
        return result

    @app.post("/api/agents/enrollment/{server_id}", status_code=201)
    def create_enrollment(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        raw = secrets.token_urlsafe(36)
        now = _now()
        expires = _future(ENROLLMENT_MINUTES)
        with db_factory() as connection:
            connection.execute(
                "UPDATE agent_enrollment_tokens SET used_at=? WHERE server_id=? AND used_at IS NULL",
                (now, server_id),
            )
            cursor = connection.execute(
                "INSERT INTO agent_enrollment_tokens(server_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)",
                (server_id, _hash(raw), expires, now),
            )
            enrollment_id = int(cursor.lastrowid)
        audit_fn("agent.enrollment.created", "server", server_id, f"Created one-time VPS agent enrollment for {server['name']}")
        return {
            "enrollment_id": enrollment_id,
            "server_id": server_id,
            "server_name": server["name"],
            "enrollment_token": raw,
            "expires_at": expires,
            "note": "This token is shown once and expires after 15 minutes.",
        }

    @app.post("/agent/v1/enroll", status_code=201)
    def enroll(payload: EnrollmentRequest, request: Request) -> dict[str, Any]:
        if payload.protocol_version != AGENT_PROTOCOL_VERSION:
            raise HTTPException(status_code=409, detail=f"Agent protocol {AGENT_PROTOCOL_VERSION} required")
        now_dt = datetime.now(timezone.utc)
        token_hash = _hash(payload.enrollment_token)
        with db_factory() as connection:
            enrollment = connection.execute(
                "SELECT * FROM agent_enrollment_tokens WHERE token_hash=? AND used_at IS NULL",
                (token_hash,),
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
            existing = connection.execute("SELECT id FROM vps_agents WHERE server_id=?", (enrollment["server_id"],)).fetchone()
            if existing:
                connection.execute(
                    """UPDATE vps_agents SET agent_id=?,token_hash=?,protocol_version=?,agent_version=?,hostname=?,platform=?,last_seen_at=?,last_ip=?,revoked_at=NULL,updated_at=? WHERE id=?""",
                    (agent_id, _hash(raw_agent_token), payload.protocol_version, payload.agent_version, payload.hostname, payload.platform, now, _remote_addr(request), now, existing["id"]),
                )
                db_agent_id = int(existing["id"])
            else:
                cursor = connection.execute(
                    """INSERT INTO vps_agents(server_id,agent_id,token_hash,protocol_version,agent_version,hostname,platform,last_seen_at,last_ip,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (enrollment["server_id"], agent_id, _hash(raw_agent_token), payload.protocol_version, payload.agent_version, payload.hostname, payload.platform, now, _remote_addr(request), now, now),
                )
                db_agent_id = int(cursor.lastrowid)
            connection.execute("UPDATE agent_enrollment_tokens SET used_at=? WHERE id=?", (now, enrollment["id"]))
        audit_fn("agent.enrolled", "server", int(enrollment["server_id"]), f"VPS agent enrolled as {agent_id}")
        return {
            "agent_id": agent_id,
            "agent_token": raw_agent_token,
            "protocol_version": AGENT_PROTOCOL_VERSION,
            "heartbeat_seconds": 30,
            "db_agent_id": db_agent_id,
        }

    @app.post("/agent/v1/heartbeat")
    def heartbeat(payload: HeartbeatRequest, request: Request) -> dict[str, Any]:
        agent = _agent_from_request(db_factory, request)
        if payload.protocol_version != AGENT_PROTOCOL_VERSION:
            raise HTTPException(status_code=409, detail=f"Agent protocol {AGENT_PROTOCOL_VERSION} required")
        m = payload.metrics
        def num(name: str) -> float | None:
            value = m.get(name)
            try:
                return float(value) if value is not None else None
            except (TypeError, ValueError):
                return None
        def integer(name: str) -> int | None:
            value = m.get(name)
            try:
                return int(value) if value is not None else None
            except (TypeError, ValueError):
                return None
        now = _now()
        with db_factory() as connection:
            connection.execute(
                "UPDATE vps_agents SET protocol_version=?,agent_version=?,hostname=?,platform=?,last_seen_at=?,last_ip=?,updated_at=? WHERE id=?",
                (payload.protocol_version, payload.agent_version, payload.hostname, payload.platform, now, _remote_addr(request), now, agent["id"]),
            )
            connection.execute(
                """INSERT INTO agent_metric_samples(agent_id,cpu_percent,memory_percent,disk_percent,load_1,containers_running,containers_total,failed_services,payload_json,sampled_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (agent["id"], num("cpu_percent"), num("memory_percent"), num("disk_percent"), num("load_1"), integer("containers_running"), integer("containers_total"), integer("failed_services"), json.dumps(m)[:20000], now),
            )
            connection.execute(
                "DELETE FROM agent_metric_samples WHERE agent_id=? AND id NOT IN (SELECT id FROM agent_metric_samples WHERE agent_id=? ORDER BY id DESC LIMIT 2880)",
                (agent["id"], agent["id"]),
            )
        return {"ok": True, "server_time": now, "next_heartbeat_seconds": 30}

    @app.get("/agent/v1/commands")
    def poll_commands(request: Request) -> dict[str, Any]:
        agent = _agent_from_request(db_factory, request)
        now = _now()
        with db_factory() as connection:
            row = connection.execute(
                "SELECT * FROM agent_commands WHERE agent_id=? AND status='queued' ORDER BY id LIMIT 1",
                (agent["id"],),
            ).fetchone()
            if not row:
                return {"command": None}
            changed = connection.execute(
                "UPDATE agent_commands SET status='running',claimed_at=? WHERE id=? AND status='queued'",
                (now, row["id"]),
            ).rowcount
            if not changed:
                return {"command": None}
        return {"command": {"id": row["id"], "kind": row["kind"], "payload": json.loads(row["payload_json"])}}

    @app.post("/agent/v1/results")
    def command_result(payload: CommandResult, request: Request) -> dict[str, Any]:
        agent = _agent_from_request(db_factory, request)
        now = _now()
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM agent_commands WHERE id=? AND agent_id=?", (payload.command_id, agent["id"])).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Agent command not found")
            if row["status"] not in {"running", "queued"}:
                raise HTTPException(status_code=409, detail="Agent command already settled")
            connection.execute(
                "UPDATE agent_commands SET status=?,result_json=?,error=?,finished_at=? WHERE id=?",
                ("success" if payload.ok else "failed", json.dumps(payload.result)[:20000], (payload.error or "")[:8000] or None, now, payload.command_id),
            )
        return {"ok": True}

    @app.get("/api/agents/{agent_id}/commands")
    def command_history(agent_id: str) -> list[dict[str, Any]]:
        with db_factory() as connection:
            agent = connection.execute("SELECT * FROM vps_agents WHERE agent_id=?", (agent_id,)).fetchone()
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            rows = connection.execute("SELECT * FROM agent_commands WHERE agent_id=? ORDER BY id DESC LIMIT 100", (agent["id"],)).fetchall()
        result=[]
        for row in rows:
            item=dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            item["result"] = json.loads(item.pop("result_json")) if item.get("result_json") else None
            result.append(item)
        return result

    @app.post("/api/agents/{agent_id}/commands", status_code=202)
    def queue_command(agent_id: str, payload: QueueCommand) -> dict[str, Any]:
        clean = _validate_command(payload.kind, payload.payload)
        with db_factory() as connection:
            agent = connection.execute("SELECT * FROM vps_agents WHERE agent_id=? AND revoked_at IS NULL", (agent_id,)).fetchone()
            if not agent:
                raise HTTPException(status_code=404, detail="Active agent not found")
            cursor = connection.execute(
                "INSERT INTO agent_commands(agent_id,kind,payload_json,status,created_at) VALUES(?,?,?,'queued',?)",
                (agent["id"], payload.kind, json.dumps(clean), _now()),
            )
            command_id = int(cursor.lastrowid)
        audit_fn("agent.command.queued", "server", int(agent["server_id"]), f"Queued {payload.kind} for agent {agent_id}")
        return {"command_id": command_id, "status": "queued", "kind": payload.kind, "payload": clean}

    @app.delete("/api/agents/{agent_id}")
    def revoke_agent(agent_id: str, payload: RevokeAgent) -> dict[str, Any]:
        if payload.confirm != f"REVOKE {agent_id}":
            raise HTTPException(status_code=400, detail=f"Type exactly: REVOKE {agent_id}")
        with db_factory() as connection:
            agent = connection.execute("SELECT * FROM vps_agents WHERE agent_id=?", (agent_id,)).fetchone()
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            connection.execute("UPDATE vps_agents SET revoked_at=?,updated_at=? WHERE id=?", (_now(), _now(), agent["id"]))
        audit_fn("agent.revoked", "server", int(agent["server_id"]), f"Revoked VPS agent {agent_id}")
        return {"revoked": True, "agent_id": agent_id}


AGENT_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>VPS Agents</title><style>body{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}.wrap{max-width:1250px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.card{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:16px;margin:12px 0}.btn{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 12px;text-decoration:none;cursor:pointer}.good{color:#69dda4}.bad{color:#ff707c}.muted{color:#93a4bb}code{color:#9cc4ff}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-top:1px solid #26364c;text-align:left}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>CONTROL PLANE</div><h1>VPS Agents</h1><div class='muted'>Restricted continuous telemetry and structured operations. SSH remains the break-glass path.</div></div><a class='btn' href='/'>Control Center</a></div><div class='card'><h2>Enrollment</h2><p class='muted'>Create a one-time token for a registered VPS, then configure the agent with this control-plane URL. Enrollment tokens expire after 15 minutes.</p><div class='row'><input id='sid' placeholder='Server ID' style='padding:9px;border-radius:8px;border:1px solid #34465e;background:#08101d;color:white'><button class='btn' onclick='enroll()'>Create enrollment token</button></div><pre id='token' style='white-space:pre-wrap'></pre></div><div class='card'><div class='top'><h2>Enrolled agents</h2><button class='btn' onclick='load()'>Refresh</button></div><div style='overflow:auto'><table><thead><tr><th>Server</th><th>Agent</th><th>Status</th><th>Last seen</th><th>Metrics</th><th>Action</th></tr></thead><tbody id='rows'><tr><td colspan='6'>Loading…</td></tr></tbody></table></div></div></div><script>function e(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function api(p,o={}){const r=await fetch(p,{headers:{'Content-Type':'application/json',...(o.headers||{})},...o});const t=await r.text();let d={};try{d=t?JSON.parse(t):{}}catch{d={detail:t}}if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);return d}async function load(){const x=await api('/api/agents');rows.innerHTML=x.length?x.map(a=>`<tr><td><b>${e(a.server_name)}</b><div class='muted'>${e(a.server_host)}</div></td><td><code>${e(a.agent_id)}</code><div class='muted'>${e(a.agent_version)}</div></td><td class='${a.online?'good':'bad'}'>${a.online?'ONLINE':a.revoked_at?'REVOKED':'OFFLINE'}</td><td>${a.last_seen_seconds==null?'never':e(a.last_seen_seconds+'s ago')}</td><td>${a.metrics?`CPU ${e(a.metrics.cpu_percent??'—')}% · RAM ${e(a.metrics.memory_percent??'—')}% · Disk ${e(a.metrics.disk_percent??'—')}%`:'—'}</td><td><button class='btn' onclick="ping('${e(a.agent_id)}')">Ping</button></td></tr>`).join(''):`<tr><td colspan='6'>No enrolled agents.</td></tr>`}async function enroll(){try{const d=await api('/api/agents/enrollment/'+encodeURIComponent(sid.value),{method:'POST'});token.textContent=`ONE-TIME TOKEN (expires ${d.expires_at})\n${d.enrollment_token}\n\nUse this only on the matching VPS.`}catch(x){alert(x.message)}}async function ping(id){try{await api('/api/agents/'+encodeURIComponent(id)+'/commands',{method:'POST',body:JSON.stringify({kind:'agent.ping',payload:{}})});alert('Ping queued')}catch(x){alert(x.message)}}load();</script></body></html>"""
