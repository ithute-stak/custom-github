from __future__ import annotations

import concurrent.futures
import html
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import inspect_server, ssh_command

GROUP_RE = re.compile(r"^[A-Za-z0-9._-]{2,80}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9@_.:-]+(?:\.service)?$")
BLOCKED_BULK_SERVICES = {"ssh", "sshd", "networking", "network-manager", "networkmanager", "systemd-networkd", "ufw", "firewalld"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _admin(request: Request) -> None:
    user = getattr(request.state, "security_user", None)
    if user and str(user["role"]) not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Admin role required")


class GroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    description: str = Field(default="", max_length=300)


class MemberAdd(BaseModel):
    server_id: int = Field(gt=0)


class BulkServiceRestart(BaseModel):
    service: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9@_.:-]+(?:\.service)?$")
    confirm: str = Field(min_length=1, max_length=220)


def _normalize_unit(value: str) -> str:
    value = value.strip()
    if not UNIT_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid systemd unit name")
    base = value[:-8] if value.endswith(".service") else value
    if base.lower() in BLOCKED_BULK_SERVICES:
        raise HTTPException(status_code=400, detail=f"Bulk restart of {base} is blocked to protect fleet connectivity")
    return value if value.endswith(".service") else value + ".service"


def install_fleet_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    def init_db() -> None:
        with db_factory() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS fleet_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS fleet_group_members (
                    group_id INTEGER NOT NULL,
                    server_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(group_id,server_id),
                    FOREIGN KEY(group_id) REFERENCES fleet_groups(id) ON DELETE CASCADE,
                    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_fleet_members_server ON fleet_group_members(server_id,group_id);
                """
            )

    @app.on_event("startup")
    def startup_fleet() -> None:
        init_db()

    def group_or_404(group_id: int) -> dict[str, Any]:
        init_db()
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM fleet_groups WHERE id=?", (group_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Fleet group not found")
        return dict(row)

    def members(group_id: int) -> list[dict[str, Any]]:
        with db_factory() as connection:
            rows = connection.execute(
                "SELECT s.* FROM servers s JOIN fleet_group_members m ON m.server_id=s.id WHERE m.group_id=? ORDER BY s.name",
                (group_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    @app.get("/fleet", response_class=HTMLResponse, include_in_schema=False)
    def fleet_page() -> str:
        return _page()

    @app.get("/api/fleet/servers")
    def all_servers() -> list[dict[str, Any]]:
        with db_factory() as connection:
            rows = connection.execute("SELECT id,name,host,port,ssh_user,max_disk_percent,max_memory_percent FROM servers ORDER BY name").fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/fleet/groups")
    def groups() -> list[dict[str, Any]]:
        init_db()
        with db_factory() as connection:
            rows = connection.execute(
                "SELECT g.*,COUNT(m.server_id) member_count FROM fleet_groups g LEFT JOIN fleet_group_members m ON m.group_id=g.id GROUP BY g.id ORDER BY g.name"
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/fleet/groups", status_code=201)
    def create_group(payload: GroupCreate, request: Request) -> dict[str, Any]:
        _admin(request)
        init_db()
        now = _now()
        try:
            with db_factory() as connection:
                cursor = connection.execute("INSERT INTO fleet_groups(name,description,created_at,updated_at) VALUES(?,?,?,?)", (payload.name,payload.description,now,now))
                group_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Fleet group name already exists") from exc
        audit_fn("fleet.group.created", "fleet_group", group_id, f"Created fleet group {payload.name}")
        return group_or_404(group_id)

    @app.delete("/api/fleet/groups/{group_id}")
    def delete_group(group_id: int, request: Request) -> dict[str, Any]:
        _admin(request)
        group = group_or_404(group_id)
        with db_factory() as connection:
            connection.execute("DELETE FROM fleet_groups WHERE id=?", (group_id,))
        audit_fn("fleet.group.deleted", "fleet_group", group_id, f"Deleted fleet group {group['name']}; VPS registrations preserved")
        return {"deleted": True, "servers_preserved": True}

    @app.get("/api/fleet/groups/{group_id}/members")
    def group_members(group_id: int) -> list[dict[str, Any]]:
        group_or_404(group_id)
        return members(group_id)

    @app.post("/api/fleet/groups/{group_id}/members", status_code=201)
    def add_member(group_id: int, payload: MemberAdd, request: Request) -> dict[str, Any]:
        _admin(request)
        group = group_or_404(group_id)
        server = dict(server_lookup(payload.server_id))
        with db_factory() as connection:
            connection.execute("INSERT OR IGNORE INTO fleet_group_members(group_id,server_id,created_at) VALUES(?,?,?)", (group_id,payload.server_id,_now()))
        audit_fn("fleet.member.added", "server", payload.server_id, f"Added {server['name']} to fleet group {group['name']}")
        return {"added": True, "group_id": group_id, "server_id": payload.server_id}

    @app.delete("/api/fleet/groups/{group_id}/members/{server_id}")
    def remove_member(group_id: int, server_id: int, request: Request) -> dict[str, Any]:
        _admin(request)
        group = group_or_404(group_id)
        server = dict(server_lookup(server_id))
        with db_factory() as connection:
            connection.execute("DELETE FROM fleet_group_members WHERE group_id=? AND server_id=?", (group_id,server_id))
        audit_fn("fleet.member.removed", "server", server_id, f"Removed {server['name']} from fleet group {group['name']}")
        return {"removed": True}

    def inspect_one(server: dict[str, Any]) -> dict[str, Any]:
        try:
            metrics = inspect_server(server)
            code, output = ssh_command(server, "printf 'hostname=%s\\n' \"$(hostname)\"; printf 'containers=%s\\n' \"$(docker ps -q 2>/dev/null | wc -l)\"; printf 'failed=%s\\n' \"$(systemctl --failed --type=service --no-legend 2>/dev/null | wc -l)\"", timeout=25)
            details: dict[str, str] = {}
            if code == 0:
                for line in output.splitlines():
                    if "=" in line:
                        k,v=line.split("=",1);details[k]=v
            return {"id":server["id"],"name":server["name"],"host":server["host"],"status":"online","metrics":metrics,"hostname":details.get("hostname"),"containers":int(details.get("containers","0") or 0),"failed_services":int(details.get("failed","0") or 0),"checked_at":_now()}
        except Exception as exc:
            return {"id":server["id"],"name":server["name"],"host":server["host"],"status":"offline","error":str(exc),"checked_at":_now()}

    @app.get("/api/fleet/groups/{group_id}/state")
    def group_state(group_id: int) -> dict[str, Any]:
        group = group_or_404(group_id)
        server_rows = members(group_id)
        if not server_rows:
            return {"group":group,"servers":[],"summary":{"total":0,"online":0,"offline":0},"checked_at":_now()}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8,len(server_rows))) as executor:
            results = list(executor.map(inspect_one, server_rows))
        online = [r for r in results if r["status"] == "online"]
        summary = {
            "total": len(results),
            "online": len(online),
            "offline": len(results)-len(online),
            "containers": sum(int(r.get("containers",0)) for r in online),
            "failed_services": sum(int(r.get("failed_services",0)) for r in online),
            "total_memory_mb": sum(int(r["metrics"]["mem_total_mb"]) for r in online),
            "available_memory_mb": sum(int(r["metrics"]["mem_available_mb"]) for r in online),
            "total_disk_mb": sum(int(r["metrics"]["disk_total_mb"]) for r in online),
            "available_disk_mb": sum(int(r["metrics"]["disk_available_mb"]) for r in online),
        }
        return {"group":group,"servers":results,"summary":summary,"checked_at":_now(),"source":"live SSH inspection on every group member"}

    @app.post("/api/fleet/groups/{group_id}/restart-service")
    def bulk_restart(group_id: int, payload: BulkServiceRestart, request: Request) -> dict[str, Any]:
        _admin(request)
        group = group_or_404(group_id)
        unit = _normalize_unit(payload.service)
        expected = f"RESTART {unit} ON {group['name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected}")
        server_rows = members(group_id)
        if not server_rows:
            raise HTTPException(status_code=409, detail="Fleet group has no servers")

        def restart_one(server: dict[str, Any]) -> dict[str, Any]:
            command = f"sudo -n systemctl restart {shlex.quote(unit)} && systemctl is-active {shlex.quote(unit)}"
            code, output = ssh_command(server, command, timeout=120)
            return {"server_id":server["id"],"server":server["name"],"ok":code==0,"output":output.strip()[-2000:]}

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6,len(server_rows))) as executor:
            results = list(executor.map(restart_one, server_rows))
        succeeded = sum(1 for item in results if item["ok"])
        audit_fn("fleet.service.restart", "fleet_group", group_id, f"Restarted {unit} on fleet group {group['name']}: {succeeded}/{len(results)} succeeded")
        return {"group":group["name"],"service":unit,"succeeded":succeeded,"failed":len(results)-succeeded,"results":results,"checked_at":_now()}


def _page() -> str:
    return """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Fleet</title><style>body{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}.wrap{max-width:1320px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap}.grid{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-top:18px}.panel{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:18px}.muted{color:#93a4bb}.btn{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;cursor:pointer;text-decoration:none}.primary{background:#2878ff}input,select{background:#08101d;color:#fff;border:1px solid #34465e;border-radius:8px;padding:8px}.group{border-top:1px solid #26364c;padding:11px 0;cursor:pointer}.server{display:grid;grid-template-columns:1.2fr .7fr .7fr .7fr .7fr .7fr;gap:9px;border-top:1px solid #26364c;padding:11px 0}.online{color:#69dda4}.offline{color:#ff707c}@media(max-width:900px){.grid{grid-template-columns:1fr}.server{grid-template-columns:1fr 1fr}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>CUSTOM GITHUB / INFRASTRUCTURE</div><h1>Multi-VPS Fleet</h1><div class='muted'>Group servers, compare live capacity, and run guarded fleet operations.</div></div><a class='btn' href='/'>Control Center</a></div><div class='grid'><div class='panel'><h2>Groups</h2><div class='row'><input id='gname' placeholder='production'><button class='btn primary' onclick='createGroup()'>Create</button></div><div id='groups'></div><h3>Add VPS to selected group</h3><select id='server'></select><button class='btn' onclick='addMember()'>Add server</button></div><div class='panel'><div class='top'><div><h2 id='title'>Select a group</h2><div id='summary' class='muted'></div></div><button class='btn' onclick='refreshState()'>Refresh live state</button></div><div id='servers'></div><div style='margin-top:20px'><h3>Guarded bulk service restart</h3><div class='row' style='justify-content:flex-start'><input id='service' placeholder='fail2ban'><button class='btn' onclick='restartService()'>Restart across group</button></div><div class='muted'>SSH/network/firewall services are blocked from this bulk action.</div></div></div></div></div><script>const $=id=>document.getElementById(id);let selected=null,groups=[],allServers=[];function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function api(u,o={}){const r=await fetch(u,{...o,headers:{'content-type':'application/json',...(o.headers||{})}});const x=await r.json().catch(()=>({}));if(!r.ok)throw Error(x.detail||r.statusText);return x}async function load(){[groups,allServers]=await Promise.all([api('/api/fleet/groups'),api('/api/fleet/servers')]);$('groups').innerHTML=groups.length?groups.map(g=>`<div class='group' onclick='selectGroup(${g.id})'><b>${esc(g.name)}</b><div class='muted'>${g.member_count} VPS · ${esc(g.description)}</div></div>`).join(''):'<p class="muted">No groups yet.</p>';$('server').innerHTML=allServers.map(s=>`<option value='${s.id}'>${esc(s.name)} · ${esc(s.host)}</option>`).join('');if(selected)await refreshState()}async function createGroup(){try{await api('/api/fleet/groups',{method:'POST',body:JSON.stringify({name:$('gname').value,description:''})});$('gname').value='';await load()}catch(e){alert(e.message)}}async function selectGroup(id){selected=id;await refreshState()}async function addMember(){if(!selected)return alert('Select a group first');try{await api(`/api/fleet/groups/${selected}/members`,{method:'POST',body:JSON.stringify({server_id:Number($('server').value)})});await load()}catch(e){alert(e.message)}}async function refreshState(){if(!selected)return;try{$('servers').innerHTML='<p class="muted">Inspecting every VPS…</p>';const x=await api(`/api/fleet/groups/${selected}/state`);$('title').textContent=x.group.name;$('summary').textContent=`${x.summary.online}/${x.summary.total} online · ${x.summary.containers||0} containers · ${x.summary.failed_services||0} failed services · checked ${new Date(x.checked_at).toLocaleString()}`;$('servers').innerHTML=x.servers.map(s=>`<div class='server'><div><b>${esc(s.name)}</b><div class='muted'>${esc(s.host)}</div></div><b class='${esc(s.status)}'>${esc(s.status)}</b><span>${s.metrics?('RAM '+s.metrics.memory_used_percent+'%'):'—'}</span><span>${s.metrics?('Disk '+s.metrics.disk_used_percent+'%'):'—'}</span><span>${s.metrics?('Load '+s.metrics.load_1):'—'}</span><span>${s.status==='online'?(s.containers+' containers'):esc(s.error||'')}</span></div>`).join('')||'<p class="muted">No servers in this group.</p>'}catch(e){$('servers').innerHTML=`<p class='offline'>${esc(e.message)}</p>`}}async function restartService(){if(!selected)return alert('Select a group first');const g=groups.find(x=>x.id===selected);let service=$('service').value.trim();if(!service)return;const unit=service.endsWith('.service')?service:service+'.service';const confirm=prompt(`This affects every VPS in ${g.name}. Type: RESTART ${unit} ON ${g.name}`);if(!confirm)return;try{const x=await api(`/api/fleet/groups/${selected}/restart-service`,{method:'POST',body:JSON.stringify({service,confirm})});alert(`${x.succeeded} succeeded; ${x.failed} failed`);await refreshState()}catch(e){alert(e.message)}}load()</script></body></html>"""
