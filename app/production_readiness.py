from __future__ import annotations

import json
import posixpath
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ssh_command
from app.production_contract import _inspect as inspect_production_contract


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_hours(value: str | None) -> float | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
    except Exception:
        return None


def _table(connection: sqlite3.Connection, name: str) -> bool:
    return bool(connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone())


def _check(key: str, title: str, status: str, message: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"key": key, "title": title, "status": status, "message": message, "evidence": evidence or {}}


class DrillRequest(BaseModel):
    confirm: str = Field(min_length=1, max_length=200)


def install_readiness_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    with db_factory() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS recovery_drills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                backup_run_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                checked_artifacts INTEGER NOT NULL DEFAULT 0,
                details_json TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(server_id) REFERENCES servers(id)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_recovery_drills_server ON recovery_drills(server_id,id DESC)")

    def readiness(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        checks: list[dict[str, Any]] = []
        with db_factory() as connection:
            if _table(connection, "security_settings") and _table(connection, "security_users"):
                settings = connection.execute("SELECT * FROM security_settings WHERE id=1").fetchone()
                owner_count = int(connection.execute("SELECT COUNT(*) FROM security_users WHERE active=1 AND role='owner'").fetchone()[0])
                mfa_admins = int(connection.execute("SELECT COUNT(*) FROM security_users WHERE active=1 AND role IN ('owner','admin') AND mfa_enabled=1").fetchone()[0])
                enabled = bool(settings and settings["enabled"])
                checks.append(_check("security", "Authentication & ownership", "pass" if enabled and owner_count else "fail", f"Security {'enabled' if enabled else 'disabled'} · {owner_count} active Owner(s)", {"mfa_admins": mfa_admins}))
                checks.append(_check("mfa", "Privileged MFA", "pass" if mfa_admins else "warn", f"{mfa_admins} Owner/Admin account(s) have MFA enabled"))
            else:
                checks.append(_check("security", "Authentication & ownership", "fail", "Security tables are not initialized"))

            latest_backup = None
            if _table(connection, "backup_runs") and _table(connection, "backup_profiles"):
                latest_backup = connection.execute(
                    "SELECT r.*,p.name profile_name FROM backup_runs r JOIN backup_profiles p ON p.id=r.profile_id WHERE r.server_id=? AND r.status='success' ORDER BY COALESCE(r.finished_at,r.created_at) DESC LIMIT 1",
                    (server_id,),
                ).fetchone()
            if latest_backup:
                age = _age_hours(latest_backup["finished_at"] or latest_backup["created_at"])
                checks.append(_check("backup", "Local recovery backup", "pass" if age is not None and age <= 48 else "warn", f"Latest successful backup: {latest_backup['profile_name']} · {age if age is not None else 'unknown'}h old", {"run_id": latest_backup["id"], "bytes": latest_backup["bytes"]}))
            else:
                checks.append(_check("backup", "Local recovery backup", "fail", "No successful backup run exists for this VPS"))

            latest_drill = connection.execute("SELECT * FROM recovery_drills WHERE server_id=? ORDER BY id DESC LIMIT 1", (server_id,)).fetchone()
            if latest_drill:
                age = _age_hours(latest_drill["finished_at"] or latest_drill["created_at"])
                status = "pass" if latest_drill["status"] == "success" and age is not None and age <= 168 else "warn" if latest_drill["status"] == "success" else "fail"
                checks.append(_check("drill", "Backup integrity drill", status, f"Last drill {latest_drill['status']} · {age if age is not None else 'unknown'}h old · {latest_drill['checked_artifacts']} artifact(s)", {"drill_id": latest_drill["id"]}))
            else:
                checks.append(_check("drill", "Backup integrity drill", "warn", "No recovery integrity drill has been recorded yet"))

            if _table(connection, "offsite_backup_targets") and _table(connection, "offsite_backup_transfers"):
                target_count = int(connection.execute("SELECT COUNT(*) FROM offsite_backup_targets WHERE server_id=? AND active=1", (server_id,)).fetchone()[0])
                transfer = connection.execute("SELECT * FROM offsite_backup_transfers WHERE server_id=? AND status='success' ORDER BY COALESCE(finished_at,created_at) DESC LIMIT 1", (server_id,)).fetchone()
                transfer_age = _age_hours(transfer["finished_at"] or transfer["created_at"]) if transfer else None
                offsite_status = "pass" if target_count and transfer and transfer_age is not None and transfer_age <= 72 else "warn" if target_count else "fail"
                message = f"{target_count} active target(s)"
                if transfer:
                    message += f" · latest successful transfer {transfer_age}h old"
                else:
                    message += " · no successful off-site transfer"
                checks.append(_check("offsite", "Off-site recovery copy", offsite_status, message))
            else:
                checks.append(_check("offsite", "Off-site recovery copy", "fail", "Off-site backup capability is not initialized"))

            if _table(connection, "vps_agents"):
                agent = connection.execute("SELECT * FROM vps_agents WHERE server_id=? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1", (server_id,)).fetchone()
                if agent:
                    age_seconds = None
                    try:
                        age_seconds = int((datetime.now(timezone.utc) - datetime.fromisoformat(agent["last_seen_at"])).total_seconds()) if agent["last_seen_at"] else None
                    except Exception:
                        pass
                    checks.append(_check("agent", "VPS Agent", "pass" if age_seconds is not None and age_seconds <= 90 else "warn", f"Agent {agent['agent_id']} · last seen {age_seconds if age_seconds is not None else 'unknown'}s ago", {"agent_id": agent["agent_id"]}))
                else:
                    checks.append(_check("agent", "VPS Agent", "warn", "No active VPS Agent enrolled; SSH fallback remains available"))
            else:
                checks.append(_check("agent", "VPS Agent", "warn", "VPS Agent capability is not initialized"))

            if _table(connection, "incidents"):
                critical = int(connection.execute("SELECT COUNT(*) FROM incidents WHERE server_id=? AND severity='critical' AND status!='resolved'", (server_id,)).fetchone()[0])
                active = int(connection.execute("SELECT COUNT(*) FROM incidents WHERE server_id=? AND status!='resolved'", (server_id,)).fetchone()[0])
                checks.append(_check("incidents", "Active infrastructure incidents", "pass" if critical == 0 else "fail", f"{critical} critical · {active} total active", {"critical": critical, "active": active}))

        try:
            contract = inspect_production_contract(server)
            missing = int(contract.get("missing_expected", 0))
            extra = int(contract.get("non_approved_running", 0))
            checks.append(_check("contract", "Production workload contract", "pass" if missing == 0 and extra == 0 else "fail", f"{contract.get('approved_running',0)}/{contract.get('expected_running',0)} approved running · {missing} missing · {extra} non-approved running", {"missing": contract.get("missing", [])[:10]}))
        except Exception as exc:
            checks.append(_check("connectivity", "Live VPS verification", "fail", f"Unable to verify live production state: {str(exc)[:500]}"))

        failures = sum(1 for item in checks if item["status"] == "fail")
        warnings = sum(1 for item in checks if item["status"] == "warn")
        overall = "blocked" if failures else "attention" if warnings else "ready"
        return {"server_id": server_id, "server_name": server["name"], "overall": overall, "failures": failures, "warnings": warnings, "checks": checks, "checked_at": _now()}

    @app.get("/vps/{server_id}/readiness", response_class=HTMLResponse, include_in_schema=False)
    def page(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        return READINESS_HTML.replace("__SERVER_ID__", str(server_id)).replace("__SERVER_NAME__", str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/readiness")
    def api_readiness(server_id: int) -> dict[str, Any]:
        return readiness(server_id)

    @app.get("/api/vps/servers/{server_id}/recovery-drills")
    def drill_history(server_id: int) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            rows = connection.execute("SELECT * FROM recovery_drills WHERE server_id=? ORDER BY id DESC LIMIT 50", (server_id,)).fetchall()
        result=[]
        for row in rows:
            item=dict(row)
            item["details"] = json.loads(item.pop("details_json")) if item.get("details_json") else []
            result.append(item)
        return result

    @app.post("/api/vps/servers/{server_id}/recovery-drills", status_code=201)
    def run_drill(server_id: int, payload: DrillRequest, request: Request) -> dict[str, Any]:
        user = getattr(request.state, "security_user", None)
        if user and str(user["role"]) not in {"owner", "admin"}:
            raise HTTPException(status_code=403, detail="Admin role required")
        server = dict(server_lookup(server_id))
        expected = f"VERIFY BACKUP {server['name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected}")
        with db_factory() as connection:
            if not _table(connection, "backup_runs"):
                raise HTTPException(status_code=409, detail="Backup system is not initialized")
            run = connection.execute("SELECT * FROM backup_runs WHERE server_id=? AND status='success' AND remote_path IS NOT NULL ORDER BY COALESCE(finished_at,created_at) DESC LIMIT 1", (server_id,)).fetchone()
            if not run:
                raise HTTPException(status_code=409, detail="No successful backup run is available")
            cursor = connection.execute("INSERT INTO recovery_drills(server_id,backup_run_id,status,created_at) VALUES(?,?,'running',?)", (server_id, run["id"], _now()))
            drill_id = int(cursor.lastrowid)
        try:
            manifest = json.loads(run["manifest_json"] or "[]")
            if not manifest:
                raise RuntimeError("Backup manifest is empty")
            remote_root = posixpath.normpath(str(run["remote_path"]))
            details: list[dict[str, Any]] = []
            for artifact in manifest:
                rel = str(artifact.get("file", ""))
                if not rel or rel.startswith("/") or ".." in rel.split("/"):
                    raise RuntimeError(f"Unsafe artifact path in manifest: {rel}")
                full = posixpath.join(remote_root, rel)
                kind = str(artifact.get("type", ""))
                if rel.endswith(".tar.gz"):
                    command = f"test -s {shlex.quote(full)} && tar -tzf {shlex.quote(full)} >/dev/null"
                elif rel.endswith(".sql.gz") or rel.endswith(".gz"):
                    command = f"test -s {shlex.quote(full)} && gzip -t {shlex.quote(full)}"
                else:
                    command = f"test -s {shlex.quote(full)}"
                code, output = ssh_command(server, command, timeout=600)
                ok = code == 0
                details.append({"type": kind, "name": artifact.get("name"), "file": rel, "ok": ok, "output": output.strip()[-1000:]})
                if not ok:
                    raise RuntimeError(f"Integrity check failed for {rel}: {output.strip()[-1200:]}")
            finished = _now()
            with db_factory() as connection:
                connection.execute("UPDATE recovery_drills SET status='success',checked_artifacts=?,details_json=?,finished_at=? WHERE id=?", (len(details), json.dumps(details), finished, drill_id))
            audit_fn("recovery.drill.success", "server", server_id, f"Verified {len(details)} artifact(s) from backup run {run['id']}")
            return {"drill_id": drill_id, "status": "success", "backup_run_id": run["id"], "checked_artifacts": len(details), "details": details, "finished_at": finished}
        except Exception as exc:
            finished = _now()
            with db_factory() as connection:
                connection.execute("UPDATE recovery_drills SET status='failed',error=?,finished_at=? WHERE id=?", (str(exc)[:8000], finished, drill_id))
            audit_fn("recovery.drill.failed", "server", server_id, f"Backup integrity drill failed: {str(exc)[:1000]}")
            raise HTTPException(status_code=502, detail=str(exc)) from exc


READINESS_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Production Readiness</title><style>body{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}.wrap{max-width:1180px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.card{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:17px;margin:12px 0}.btn{background:#1c2a3d;color:white;border:1px solid #34465e;border-radius:9px;padding:9px 13px;text-decoration:none;cursor:pointer}.muted{color:#93a4bb}.pass{color:#69dda4}.warn{color:#ffd76e}.fail,.blocked{color:#ff707c}.ready{color:#69dda4}.attention{color:#ffd76e}.big{font-size:30px;font-weight:800}.check{display:grid;grid-template-columns:160px 1fr 110px;gap:12px;border-top:1px solid #26364c;padding:13px 0}@media(max-width:700px){.check{grid-template-columns:1fr}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>PRODUCTION / __SERVER_NAME__</div><h1>Readiness & Recovery Verification</h1><div class='muted'>Evidence-based checks across security, backups, off-site copies, incidents, agents and the live production workload contract.</div></div><a class='btn' href='/vps/__SERVER_ID__'>VPS Manager</a></div><div class='card'><div class='row'><div><div class='muted'>OVERALL</div><div id='overall' class='big'>Checking…</div></div><div><button class='btn' onclick='load()'>Refresh evidence</button> <button class='btn' onclick='drill()'>Verify latest backup</button></div></div></div><div id='checks' class='card'>Loading…</div><div class='card'><h2>Recovery drill history</h2><div id='history'>Loading…</div></div></div><script>const sid=__SERVER_ID__;function e(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function api(p,o={}){const r=await fetch(p,{headers:{'Content-Type':'application/json',...(o.headers||{})},...o});const t=await r.text();let d={};try{d=t?JSON.parse(t):{}}catch{d={detail:t}}if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);return d}async function load(){try{const d=await api(`/api/vps/servers/${sid}/readiness`);overall.className=`big ${d.overall}`;overall.textContent=d.overall.toUpperCase();checks.innerHTML=d.checks.map(x=>`<div class='check'><b>${e(x.title)}</b><div>${e(x.message)}</div><b class='${e(x.status)}'>${e(x.status.toUpperCase())}</b></div>`).join('');const h=await api(`/api/vps/servers/${sid}/recovery-drills`);history.innerHTML=h.length?h.map(x=>`<p><b class='${x.status==='success'?'pass':'fail'}'>${e(x.status.toUpperCase())}</b> · ${e(x.checked_artifacts)} artifact(s) · ${e(x.finished_at||x.created_at)}</p>`).join(''):'No drills yet.'}catch(x){checks.innerHTML=`<span class='fail'>${e(x.message)}</span>`}}async function drill(){const name='__SERVER_NAME__';const phrase=`VERIFY BACKUP ${name}`;const c=prompt(`Type exactly: ${phrase}`);if(c!==phrase)return;try{const d=await api(`/api/vps/servers/${sid}/recovery-drills`,{method:'POST',body:JSON.stringify({confirm:c})});alert(`Verified ${d.checked_artifacts} artifact(s)`);load()}catch(x){alert(x.message)}}load();</script></body></html>"""
