from __future__ import annotations

import html
import posixpath
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator

from app.deployment import ssh_command

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,120}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_remote_path(value: str) -> str:
    if not value.startswith("/") or "\x00" in value:
        raise ValueError("Remote backup path must be absolute")
    normalized = posixpath.normpath(value)
    if normalized in {"/", "/etc", "/usr", "/var", "/home", "/root"}:
        raise ValueError("Choose a dedicated backup subdirectory, not a system root directory")
    return normalized


def _safe_identity(value: str) -> str:
    if not value.startswith("/") or "\x00" in value:
        raise ValueError("Identity file must be an absolute path on the source VPS")
    return posixpath.normpath(value)


def _admin(request: Request) -> None:
    user = getattr(request.state, "security_user", None)
    if user and str(user["role"]) not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Admin role required")


class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120, pattern=r"^[A-Za-z0-9._-]+$")
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    remote_path: str = Field(min_length=2, max_length=500)
    identity_file: str = Field(min_length=2, max_length=500)
    retention_count: int = Field(default=14, ge=1, le=180)

    @field_validator("remote_path")
    @classmethod
    def valid_remote_path(cls, value: str) -> str:
        return _safe_remote_path(value.strip())

    @field_validator("identity_file")
    @classmethod
    def valid_identity(cls, value: str) -> str:
        return _safe_identity(value.strip())


class ConfirmDelete(BaseModel):
    confirm: str = Field(min_length=1, max_length=180)


def install_offsite_backup_routes(
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
                CREATE TABLE IF NOT EXISTS offsite_backup_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    ssh_user TEXT NOT NULL,
                    remote_path TEXT NOT NULL,
                    identity_file TEXT NOT NULL,
                    retention_count INTEGER NOT NULL DEFAULT 14,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(server_id, name),
                    FOREIGN KEY(server_id) REFERENCES servers(id)
                );
                CREATE TABLE IF NOT EXISTS offsite_backup_transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    backup_run_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    destination TEXT,
                    bytes INTEGER,
                    message TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    UNIQUE(target_id, backup_run_id),
                    FOREIGN KEY(server_id) REFERENCES servers(id),
                    FOREIGN KEY(target_id) REFERENCES offsite_backup_targets(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_offsite_targets_server ON offsite_backup_targets(server_id,id DESC);
                CREATE INDEX IF NOT EXISTS idx_offsite_transfers_server ON offsite_backup_transfers(server_id,id DESC);
                """
            )

    @app.on_event("startup")
    def startup_offsite() -> None:
        init_db()

    def target_or_404(server_id: int, target_id: int) -> dict[str, Any]:
        init_db()
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM offsite_backup_targets WHERE id=? AND server_id=?", (target_id, server_id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Off-site backup target not found")
        item = dict(row)
        item["active"] = bool(item["active"])
        return item

    def source_ssh(target: dict[str, Any]) -> str:
        return " ".join(
            [
                "ssh",
                "-p", str(target["port"]),
                "-i", shlex.quote(str(target["identity_file"])),
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=accept-new",
                shlex.quote(f"{target['ssh_user']}@{target['host']}"),
            ]
        )

    def check_target(source: dict[str, Any], target: dict[str, Any]) -> str:
        destination = _safe_remote_path(str(target["remote_path"]))
        identity = _safe_identity(str(target["identity_file"]))
        precheck = f"test -r {shlex.quote(identity)} || {{ echo 'Identity file is not readable on source VPS: {identity}'; exit 31; }}; command -v rsync >/dev/null || {{ echo 'rsync is not installed on source VPS'; exit 32; }}"
        code, out = ssh_command(source, precheck, timeout=20)
        if code != 0:
            raise RuntimeError(out.strip()[-3000:] or "Source VPS is not ready for off-site rsync")
        remote_cmd = f"mkdir -p {shlex.quote(destination)} && test -w {shlex.quote(destination)} && printf READY"
        command = source_ssh(target) + " " + shlex.quote(remote_cmd)
        code, output = ssh_command(source, command, timeout=30)
        if code != 0 or "READY" not in output:
            raise RuntimeError(output.strip()[-4000:] or "Unable to write to off-site backup target")
        return output.strip()

    @app.get("/vps/{server_id}/offsite-backups", response_class=HTMLResponse, include_in_schema=False)
    def page(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        return _page(server_id, str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/offsite/targets")
    def targets(server_id: int) -> list[dict[str, Any]]:
        server_lookup(server_id)
        init_db()
        with db_factory() as connection:
            rows = connection.execute("SELECT * FROM offsite_backup_targets WHERE server_id=? ORDER BY id DESC", (server_id,)).fetchall()
        return [{**dict(row), "active": bool(row["active"])} for row in rows]

    @app.post("/api/vps/servers/{server_id}/offsite/targets", status_code=201)
    def create_target(server_id: int, payload: TargetCreate, request: Request) -> dict[str, Any]:
        _admin(request)
        server_lookup(server_id)
        now = _now()
        try:
            with db_factory() as connection:
                cursor = connection.execute(
                    "INSERT INTO offsite_backup_targets(server_id,name,host,port,ssh_user,remote_path,identity_file,retention_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (server_id, payload.name, payload.host, payload.port, payload.ssh_user, payload.remote_path, payload.identity_file, payload.retention_count, now, now),
                )
                target_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="A target with this name already exists on the VPS") from exc
        audit_fn("backup.offsite.target.created", "server", server_id, f"Created off-site target {payload.name} at {payload.ssh_user}@{payload.host}:{payload.remote_path}; key contents not stored")
        return target_or_404(server_id, target_id)

    @app.post("/api/vps/servers/{server_id}/offsite/targets/{target_id}/test")
    def test_target(server_id: int, target_id: int, request: Request) -> dict[str, Any]:
        _admin(request)
        source = dict(server_lookup(server_id))
        target = target_or_404(server_id, target_id)
        try:
            output = check_target(source, target)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("backup.offsite.target.tested", "server", server_id, f"Verified off-site target {target['name']}")
        return {"ok": True, "output": output, "checked_at": _now()}

    @app.delete("/api/vps/servers/{server_id}/offsite/targets/{target_id}")
    def delete_target(server_id: int, target_id: int, payload: ConfirmDelete, request: Request) -> dict[str, Any]:
        _admin(request)
        target = target_or_404(server_id, target_id)
        expected = f"DELETE TARGET {target['name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected}")
        with db_factory() as connection:
            connection.execute("DELETE FROM offsite_backup_targets WHERE id=? AND server_id=?", (target_id, server_id))
        audit_fn("backup.offsite.target.deleted", "server", server_id, f"Removed off-site target registration {target['name']}; remote backup files were not deleted")
        return {"deleted": True, "remote_files_preserved": True}

    @app.get("/api/vps/servers/{server_id}/offsite/transfers")
    def transfers(server_id: int) -> list[dict[str, Any]]:
        server_lookup(server_id)
        init_db()
        with db_factory() as connection:
            rows = connection.execute(
                "SELECT x.*,t.name target_name,p.name profile_name FROM offsite_backup_transfers x JOIN offsite_backup_targets t ON t.id=x.target_id JOIN backup_runs r ON r.id=x.backup_run_id JOIN backup_profiles p ON p.id=r.profile_id WHERE x.server_id=? ORDER BY x.id DESC LIMIT 100",
                (server_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    @app.post("/api/vps/servers/{server_id}/offsite/targets/{target_id}/sync-latest/{profile_id}", status_code=202)
    def sync_latest(server_id: int, target_id: int, profile_id: int, background_tasks: BackgroundTasks, request: Request) -> dict[str, Any]:
        _admin(request)
        source = dict(server_lookup(server_id))
        target = target_or_404(server_id, target_id)
        init_db()
        with db_factory() as connection:
            profile = connection.execute("SELECT * FROM backup_profiles WHERE id=? AND server_id=?", (profile_id, server_id)).fetchone()
            if not profile:
                raise HTTPException(status_code=404, detail="Backup profile not found")
            run = connection.execute("SELECT * FROM backup_runs WHERE profile_id=? AND server_id=? AND status='success' AND remote_path IS NOT NULL ORDER BY id DESC LIMIT 1", (profile_id, server_id)).fetchone()
            if not run:
                raise HTTPException(status_code=409, detail="No successful local backup is available for this profile")
            existing = connection.execute("SELECT * FROM offsite_backup_transfers WHERE target_id=? AND backup_run_id=?", (target_id, run["id"])).fetchone()
            if existing and existing["status"] == "success":
                return {"transfer_id": existing["id"], "status": "success", "message": "Latest backup is already off-site"}
            if existing:
                transfer_id = int(existing["id"])
                connection.execute("UPDATE offsite_backup_transfers SET status='queued',message='Queued for retry',error=NULL,created_at=? WHERE id=?", (_now(), transfer_id))
            else:
                cursor = connection.execute("INSERT INTO offsite_backup_transfers(server_id,target_id,backup_run_id,status,message,created_at) VALUES(?,?,?,'queued','Queued',?)", (server_id,target_id,run["id"],_now()))
                transfer_id = int(cursor.lastrowid)
            run_info = dict(run)
            profile_name = str(profile["name"])

        def update(**fields: Any) -> None:
            allowed = {"status","destination","bytes","message","error","started_at","finished_at"}
            pairs = [(k,v) for k,v in fields.items() if k in allowed]
            with db_factory() as connection:
                connection.execute("UPDATE offsite_backup_transfers SET " + ",".join(f"{k}=?" for k,_ in pairs) + " WHERE id=?", tuple(v for _,v in pairs)+(transfer_id,))

        def task() -> None:
            update(status="running", message="Testing target", started_at=_now())
            try:
                check_target(source, target)
                source_path = posixpath.normpath(str(run_info["remote_path"]))
                run_name = posixpath.basename(source_path)
                safe_server = re.sub(r"[^A-Za-z0-9._-]+", "-", str(source["name"]))[:80]
                safe_profile = re.sub(r"[^A-Za-z0-9._-]+", "-", profile_name)[:80]
                profile_root = posixpath.join(str(target["remote_path"]), safe_server, safe_profile)
                destination = posixpath.join(profile_root, run_name)
                remote_mkdir = source_ssh(target) + " " + shlex.quote(f"mkdir -p {shlex.quote(destination)}")
                code, output = ssh_command(source, remote_mkdir, timeout=30)
                if code != 0:
                    raise RuntimeError(output.strip()[-4000:] or "Unable to create off-site run directory")
                ssh_transport = "ssh -p {port} -i {identity} -o BatchMode=yes -o StrictHostKeyChecking=accept-new".format(port=target["port"], identity=shlex.quote(str(target["identity_file"])))
                target_spec = f"{target['ssh_user']}@{target['host']}:{destination}/"
                rsync = f"rsync -a --numeric-ids --partial -e {shlex.quote(ssh_transport)} {shlex.quote(source_path + '/')} {shlex.quote(target_spec)}"
                code, output = ssh_command(source, rsync, timeout=7200)
                if code != 0:
                    raise RuntimeError(output.strip()[-6000:] or "Off-site rsync failed")
                verify_cmd = source_ssh(target) + " " + shlex.quote(f"du -sb {shlex.quote(destination)} | awk '{{print $1}}'")
                code, verify = ssh_command(source, verify_cmd, timeout=60)
                if code != 0:
                    raise RuntimeError(verify.strip()[-4000:] or "Unable to verify off-site backup")
                try:
                    byte_count = int(verify.strip().splitlines()[-1])
                except Exception:
                    byte_count = None
                retention = int(target["retention_count"])
                cleanup_script = f"set -eu; root={shlex.quote(profile_root)}; test -d \"$root\" || exit 0; find \"$root\" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\\n' | sort -nr | tail -n +{retention + 1} | cut -d' ' -f2- | while IFS= read -r old; do case \"$old\" in \"$root\"/*) rm -rf -- \"$old\" ;; *) exit 70 ;; esac; done"
                cleanup_cmd = source_ssh(target) + " " + shlex.quote(cleanup_script)
                ssh_command(source, cleanup_cmd, timeout=300)
                update(status="success", destination=destination, bytes=byte_count, message="Verified off-site copy", finished_at=_now())
                audit_fn("backup.offsite.synced", "server", server_id, f"Copied backup run {run_info['id']} to target {target['name']} at {destination}")
            except Exception as exc:
                update(status="failed", message="Off-site transfer failed", error=str(exc)[:6000], finished_at=_now())
                audit_fn("backup.offsite.failed", "server", server_id, f"Off-site backup to {target['name']} failed: {str(exc)[:1000]}")

        background_tasks.add_task(task)
        return {"transfer_id": transfer_id, "status": "queued", "backup_run_id": run_info["id"], "target": target["name"]}


def _page(server_id: int, server_name: str) -> str:
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Off-site Backups</title><style>body{{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}}.wrap{{max-width:1240px;margin:auto;padding:28px}}.top,.row{{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:18px}}.panel{{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:18px}}.muted{{color:#93a4bb}}.btn{{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;cursor:pointer;text-decoration:none}}.primary{{background:#2878ff}}input{{background:#08101d;color:#fff;border:1px solid #34465e;border-radius:8px;padding:8px}}.target,.transfer{{border-top:1px solid #26364c;padding:12px 0}}.success{{color:#69dda4}}.failed{{color:#ff707c}}@media(max-width:800px){{.grid{{grid-template-columns:1fr}}}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>RECOVERY / {html.escape(server_name)}</div><h1>Off-site Backup Targets</h1><div class='muted'>Copy completed local backups to a separate SSH/rsync host. Private-key contents are never stored by Custom GitHub.</div></div><div><a class='btn' href='/vps/{server_id}/backups'>Local Backups</a> <a class='btn' href='/vps/{server_id}'>VPS Manager</a></div></div><div class='grid'><div class='panel'><h2>Targets</h2><div class='row' style='justify-content:flex-start'><input id='name' placeholder='Name'><input id='host' placeholder='backup.example.com'><input id='user' placeholder='SSH user'><input id='path' placeholder='/srv/backups/custom-github'><input id='key' placeholder='/home/deploy/.ssh/offsite'><button class='btn primary' onclick='createTarget()'>Add target</button></div><div id='targets'></div></div><div class='panel'><h2>Recent Transfers</h2><div class='muted'>Create a normal local backup first, then sync the latest successful run for a profile.</div><div id='profiles' style='margin:12px 0'></div><div id='transfers'></div></div></div></div><script>const sid={server_id};const $=id=>document.getElementById(id);function esc(s){{return String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}async function api(u,o={{}}){{const r=await fetch(u,{{...o,headers:{{'content-type':'application/json',...(o.headers||{{}})}}}});const x=await r.json().catch(()=>({{}}));if(!r.ok)throw Error(x.detail||r.statusText);return x}}let targets=[],profiles=[];async function load(){{try{{[targets,profiles]=await Promise.all([api(`/api/vps/servers/${{sid}}/offsite/targets`),api(`/api/vps/servers/${{sid}}/backups/profiles`)]);const transfers=await api(`/api/vps/servers/${{sid}}/offsite/transfers`);$('targets').innerHTML=targets.length?targets.map(t=>`<div class='target'><b>${{esc(t.name)}}</b><div class='muted'>${{esc(t.ssh_user)}}@${{esc(t.host)}}:${{esc(t.remote_path)}} · retain ${{t.retention_count}}</div><div class='row' style='justify-content:flex-start;margin-top:7px'><button class='btn' onclick='testTarget(${{t.id}})'>Test</button>${{profiles.map(p=>`<button class='btn' onclick='sync(${{t.id}},${{p.id}})'>Sync latest ${{esc(p.name)}}</button>`).join('')}}</div></div>`).join(''):'<p class="muted">No off-site targets configured.</p>';$('profiles').innerHTML=profiles.length?`Profiles: ${{profiles.map(p=>`<b>${{esc(p.name)}}</b>`).join(' · ')}}`:'No local backup profiles yet.';$('transfers').innerHTML=transfers.length?transfers.map(x=>`<div class='transfer'><b class='${{esc(x.status)}}'>${{esc(x.status.toUpperCase())}}</b> · ${{esc(x.profile_name)}} → ${{esc(x.target_name)}}<div class='muted'>${{esc(x.destination||x.message||'')}} ${{x.bytes?(' · '+(x.bytes/1024/1024).toFixed(1)+' MB'):''}}</div>${{x.error?`<div class='failed'>${{esc(x.error)}}</div>`:''}}</div>`).join(''):'<p class="muted">No transfers yet.</p>'}}catch(e){{alert(e.message)}}}}async function createTarget(){{try{{await api(`/api/vps/servers/${{sid}}/offsite/targets`,{{method:'POST',body:JSON.stringify({{name:$('name').value,host:$('host').value,ssh_user:$('user').value,remote_path:$('path').value,identity_file:$('key').value,port:22,retention_count:14}})}});await load()}}catch(e){{alert(e.message)}}}}async function testTarget(id){{try{{const x=await api(`/api/vps/servers/${{sid}}/offsite/targets/${{id}}/test`,{{method:'POST',body:'{{}}'}});alert('Target ready: '+x.output)}}catch(e){{alert(e.message)}}}}async function sync(t,p){{try{{const x=await api(`/api/vps/servers/${{sid}}/offsite/targets/${{t}}/sync-latest/${{p}}`,{{method:'POST',body:'{{}}'}});alert('Transfer '+x.status);setTimeout(load,1500)}}catch(e){{alert(e.message)}}}}load()</script></body></html>"""
