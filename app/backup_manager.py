from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator

from app.deployment import ssh_command

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
VOLUME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(server: dict[str, Any], command: str, timeout: int = 120) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(output.strip()[-6000:] or f"Remote command failed with exit code {code}")
    return output


def _sudo(command: str) -> str:
    return f"if [ \"$(id -u)\" -eq 0 ]; then {command}; else sudo -n {command}; fi"


def _path(value: str) -> str:
    if not value.startswith("/") or "\x00" in value:
        raise ValueError("Backup paths must be absolute")
    normalized = posixpath.normpath(value)
    if normalized in {"/", "/proc", "/sys", "/dev", "/run"}:
        raise ValueError(f"Refusing unsafe backup path: {normalized}")
    return normalized


def _destination(value: str) -> str:
    value = _path(value)
    if value.startswith("/proc/") or value.startswith("/sys/") or value.startswith("/dev/"):
        raise ValueError("Unsafe backup destination")
    return value


def _artifact_name(kind: str, value: str, suffix: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{kind}-{digest}.{suffix}"


class BackupProfileCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120, pattern=r"^[A-Za-z0-9._-]+$")
    paths: list[str] = Field(default_factory=list, max_length=30)
    volumes: list[str] = Field(default_factory=list, max_length=30)
    database_containers: list[str] = Field(default_factory=list, max_length=20)
    destination: str = Field(default="/var/backups/custom-github", max_length=500)
    retention_count: int = Field(default=7, ge=1, le=90)

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(_path(v.strip()) for v in values if v.strip()))

    @field_validator("volumes")
    @classmethod
    def validate_volumes(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            value = value.strip()
            if value and not VOLUME_RE.fullmatch(value):
                raise ValueError(f"Invalid Docker volume name: {value}")
            if value:
                cleaned.append(value)
        return list(dict.fromkeys(cleaned))

    @field_validator("database_containers")
    @classmethod
    def validate_containers(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            value = value.strip()
            if value and not CONTAINER_RE.fullmatch(value):
                raise ValueError(f"Invalid database container name: {value}")
            if value:
                cleaned.append(value)
        return list(dict.fromkeys(cleaned))

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: str) -> str:
        return _destination(value)


class RestoreRequest(BaseModel):
    component_type: str = Field(pattern=r"^(path|volume|database)$")
    component_name: str = Field(min_length=1, max_length=500)
    confirm: str = Field(min_length=8, max_length=260)


class DeleteRunRequest(BaseModel):
    confirm: str = Field(min_length=8, max_length=260)


def _init_db(db_factory: Callable[[], sqlite3.Connection]) -> None:
    with db_factory() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS backup_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                paths_json TEXT NOT NULL,
                volumes_json TEXT NOT NULL,
                databases_json TEXT NOT NULL,
                destination TEXT NOT NULL,
                retention_count INTEGER NOT NULL DEFAULT 7,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(server_id, name),
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );
            CREATE TABLE IF NOT EXISTS backup_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                server_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                remote_path TEXT,
                bytes INTEGER,
                manifest_json TEXT,
                message TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                FOREIGN KEY(profile_id) REFERENCES backup_profiles(id),
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );
            CREATE INDEX IF NOT EXISTS idx_backup_profiles_server ON backup_profiles(server_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_backup_runs_profile ON backup_runs(profile_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_backup_runs_server ON backup_runs(server_id, id DESC);
            """
        )


def _profile(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["paths"] = json.loads(item.pop("paths_json"))
    item["volumes"] = json.loads(item.pop("volumes_json"))
    item["database_containers"] = json.loads(item.pop("databases_json"))
    item["active"] = bool(item["active"])
    return item


def _emit_event(db_factory: Callable[[], sqlite3.Connection], server_id: int, severity: str, title: str, message: str, data: dict[str, Any] | None = None) -> None:
    try:
        with db_factory() as connection:
            connection.execute(
                "INSERT INTO server_events(server_id, category, severity, title, message, data_json, created_at) VALUES (?, 'backup', ?, ?, ?, ?, ?)",
                (server_id, severity, title[:240], message[:4000], json.dumps(data) if data else None, _utc_now()),
            )
    except sqlite3.OperationalError:
        pass


def install_backup_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    _init_db(db_factory)

    def get_profile(profile_id: int, server_id: int | None = None) -> dict[str, Any]:
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM backup_profiles WHERE id = ?", (profile_id,)).fetchone()
        if not row or (server_id is not None and int(row["server_id"]) != server_id):
            raise HTTPException(status_code=404, detail="Backup profile not found")
        return _profile(row)

    @app.get("/vps/{server_id}/backups", response_class=HTMLResponse, include_in_schema=False)
    def backup_page(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        return BACKUP_HTML.replace("__SERVER_ID__", str(server_id)).replace("__SERVER_NAME__", str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/backups/sources")
    def discover_sources(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        with db_factory() as connection:
            targets = connection.execute("SELECT p.name, d.compose_dir FROM deployment_targets d JOIN projects p ON p.id=d.project_id WHERE d.server_id=?", (server_id,)).fetchall()
        volumes: list[str] = []
        databases: list[dict[str, str]] = []
        try:
            volumes = [line.strip() for line in _run(server, "docker volume ls --format '{{.Name}}'", 30).splitlines() if line.strip()]
        except RuntimeError:
            pass
        try:
            raw = _run(server, "docker ps --format '{{.Names}}\\t{{.Image}}'", 30)
            for line in raw.splitlines():
                parts = line.split("\t", 1)
                if len(parts) != 2:
                    continue
                name, image = parts
                low = image.lower()
                engine = "postgres" if "postgres" in low or "postgis" in low else "mysql" if "mysql" in low else "mariadb" if "mariadb" in low else ""
                if engine:
                    databases.append({"container": name, "image": image, "engine": engine})
        except RuntimeError:
            pass
        return {
            "project_paths": [{"project": row["name"], "path": row["compose_dir"]} for row in targets],
            "volumes": sorted(volumes),
            "databases": databases,
            "checked_at": _utc_now(),
        }

    @app.get("/api/vps/servers/{server_id}/backups/profiles")
    def profiles(server_id: int) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            rows = connection.execute("SELECT * FROM backup_profiles WHERE server_id = ? ORDER BY id DESC", (server_id,)).fetchall()
        return [_profile(row) for row in rows]

    @app.post("/api/vps/servers/{server_id}/backups/profiles", status_code=201)
    def create_profile(server_id: int, payload: BackupProfileCreate) -> dict[str, Any]:
        server_lookup(server_id)
        if not payload.paths and not payload.volumes and not payload.database_containers:
            raise HTTPException(status_code=400, detail="Select at least one path, volume, or database container")
        now = _utc_now()
        try:
            with db_factory() as connection:
                cursor = connection.execute(
                    "INSERT INTO backup_profiles(server_id, name, paths_json, volumes_json, databases_json, destination, retention_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (server_id, payload.name, json.dumps(payload.paths), json.dumps(payload.volumes), json.dumps(payload.database_containers), payload.destination, payload.retention_count, now, now),
                )
                profile_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="A backup profile with that name already exists on this VPS") from exc
        audit_fn("vps.backup.profile.created", "server", server_id, f"Created backup profile {payload.name}")
        return get_profile(profile_id)

    @app.get("/api/vps/servers/{server_id}/backups/runs")
    def runs(server_id: int, limit: int = Query(default=50, ge=1, le=200)) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            rows = connection.execute(
                "SELECT r.*, p.name profile_name FROM backup_runs r JOIN backup_profiles p ON p.id=r.profile_id WHERE r.server_id=? ORDER BY r.id DESC LIMIT ?",
                (server_id, limit),
            ).fetchall()
        result=[]
        for row in rows:
            item=dict(row)
            item["manifest"] = json.loads(item.pop("manifest_json")) if item.get("manifest_json") else []
            result.append(item)
        return result

    def update_run(run_id: int, **fields: Any) -> None:
        allowed={"status","progress","remote_path","bytes","manifest_json","message","error","started_at","finished_at"}
        pairs=[(k,v) for k,v in fields.items() if k in allowed]
        if not pairs:
            return
        with db_factory() as connection:
            connection.execute("UPDATE backup_runs SET " + ", ".join(f"{k}=?" for k,_ in pairs) + " WHERE id=?", tuple(v for _,v in pairs)+(run_id,))

    @app.post("/api/vps/servers/{server_id}/backups/profiles/{profile_id}/run", status_code=202)
    def run_backup(server_id: int, profile_id: int, background_tasks: BackgroundTasks) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        profile = get_profile(profile_id, server_id)
        with db_factory() as connection:
            cursor = connection.execute(
                "INSERT INTO backup_runs(profile_id, server_id, status, progress, message, created_at) VALUES (?, ?, 'queued', 0, 'Queued', ?)",
                (profile_id, server_id, _utc_now()),
            )
            run_id = int(cursor.lastrowid)
        _emit_event(db_factory, server_id, "info", "Backup queued", profile["name"], {"run_id": run_id})

        def task() -> None:
            update_run(run_id, status="running", progress=5, message="Preparing backup", started_at=_utc_now())
            _emit_event(db_factory, server_id, "info", "Backup started", profile["name"], {"run_id": run_id})
            manifest: list[dict[str, str]] = []
            try:
                dest = profile["destination"]
                profile_root = f"{dest}/profile-{profile_id}"
                setup = f"mkdir -p {shlex.quote(profile_root)}; stamp=$(date -u +%Y%m%dT%H%M%SZ); run={shlex.quote(profile_root)}/$stamp; mkdir -p \"$run/paths\" \"$run/volumes\" \"$run/databases\"; printf '%s' \"$run\""
                remote_path = _run(server, _sudo(f"sh -c {shlex.quote(setup)}"), 45).strip().splitlines()[-1]
                update_run(run_id, progress=12, remote_path=remote_path, message="Backing up paths")

                for index, path in enumerate(profile["paths"]):
                    archive = _artifact_name("path", path, "tar.gz")
                    relative = path.lstrip("/")
                    command = f"tar -C / -czf {shlex.quote(remote_path + '/paths/' + archive)} --one-file-system -- {shlex.quote(relative)}"
                    _run(server, _sudo(command), 1800)
                    manifest.append({"type":"path","name":path,"file":f"paths/{archive}"})
                    update_run(run_id, progress=min(42, 12 + int(30*(index+1)/max(len(profile["paths"]),1))), message=f"Backed up {path}")

                update_run(run_id, progress=45, message="Backing up Docker volumes")
                for index, volume in enumerate(profile["volumes"]):
                    archive = _artifact_name("volume", volume, "tar.gz")
                    script = f"mp=$(docker volume inspect -f '{{{{.Mountpoint}}}}' {shlex.quote(volume)}) || exit 44; tar -C \"$mp\" -czf {shlex.quote(remote_path + '/volumes/' + archive)} ."
                    _run(server, _sudo(f"sh -c {shlex.quote(script)}"), 1800)
                    manifest.append({"type":"volume","name":volume,"file":f"volumes/{archive}"})
                    update_run(run_id, progress=min(68,45+int(23*(index+1)/max(len(profile["volumes"]),1))), message=f"Backed up volume {volume}")

                update_run(run_id, progress=70, message="Backing up databases")
                for index, container in enumerate(profile["database_containers"]):
                    image = _run(server, f"docker inspect -f '{{{{.Config.Image}}}}' {shlex.quote(container)}", 30).strip().lower()
                    archive = _artifact_name("database", container, "sql.gz")
                    target = shlex.quote(remote_path + "/databases/" + archive)
                    if "postgres" in image or "postgis" in image:
                        command = f"docker exec {shlex.quote(container)} sh -lc 'pg_dumpall -U \"${{POSTGRES_USER:-postgres}}\"' | gzip -c > {target}"
                        engine = "postgres"
                    elif "mysql" in image or "mariadb" in image:
                        inner = "if [ -n \"${MYSQL_ROOT_PASSWORD:-}\" ]; then mysqldump -uroot -p\"$MYSQL_ROOT_PASSWORD\" --all-databases --single-transaction; elif [ -n \"${MYSQL_PASSWORD:-}\" ] && [ -n \"${MYSQL_USER:-}\" ]; then mysqldump -u\"$MYSQL_USER\" -p\"$MYSQL_PASSWORD\" --all-databases --single-transaction; else mysqldump -uroot --all-databases --single-transaction; fi"
                        command = f"docker exec {shlex.quote(container)} sh -lc {shlex.quote(inner)} | gzip -c > {target}"
                        engine = "mariadb" if "mariadb" in image else "mysql"
                    else:
                        raise RuntimeError(f"Unsupported database image for {container}: {image}")
                    _run(server, _sudo(f"sh -c {shlex.quote(command)}"), 1800)
                    manifest.append({"type":"database","name":container,"engine":engine,"file":f"databases/{archive}"})
                    update_run(run_id, progress=min(88,70+int(18*(index+1)/max(len(profile["database_containers"]),1))), message=f"Backed up database {container}")

                manifest_text="".join(f"{m['type']}\t{m['name']}\t{m['file']}\t{m.get('engine','')}\n" for m in manifest)
                encoded=shlex.quote(__import__('base64').b64encode(manifest_text.encode()).decode())
                finalize=f"printf '%s' {encoded} | base64 -d > {shlex.quote(remote_path + '/manifest.tsv')}; du -sb {shlex.quote(remote_path)} | awk '{{print $1}}'"
                size=int(_run(server, _sudo(f"sh -c {shlex.quote(finalize)}"), 60).strip().splitlines()[-1])
                retention=int(profile["retention_count"])
                prune=f"cd {shlex.quote(profile_root)} && ls -1dt -- */ 2>/dev/null | tail -n +{retention+1} | xargs -r rm -rf --"
                _run(server, _sudo(f"sh -c {shlex.quote(prune)}"), 120)
                update_run(run_id,status="success",progress=100,bytes=size,manifest_json=json.dumps(manifest),message="Backup completed",finished_at=_utc_now())
                audit_fn("vps.backup.completed","server",server_id,f"Backup {profile['name']} completed: {remote_path}")
                _emit_event(db_factory,server_id,"success","Backup completed",f"{profile['name']} · {size} bytes",{"run_id":run_id,"remote_path":remote_path})
            except Exception as exc:
                update_run(run_id,status="failed",progress=100,message="Backup failed",error=str(exc)[:6000],finished_at=_utc_now())
                audit_fn("vps.backup.failed","server",server_id,f"Backup {profile['name']} failed: {str(exc)[:1000]}")
                _emit_event(db_factory,server_id,"error","Backup failed",str(exc),{"run_id":run_id})

        background_tasks.add_task(task)
        return {"run_id":run_id,"status":"queued","profile":profile["name"]}

    @app.post("/api/vps/servers/{server_id}/backups/runs/{run_id}/restore", status_code=202)
    def restore_component(server_id: int, run_id: int, payload: RestoreRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        server=dict(server_lookup(server_id))
        with db_factory() as connection:
            row=connection.execute("SELECT r.*,p.name profile_name FROM backup_runs r JOIN backup_profiles p ON p.id=r.profile_id WHERE r.id=? AND r.server_id=?",(run_id,server_id)).fetchone()
        if not row or row["status"]!="success" or not row["remote_path"]:
            raise HTTPException(status_code=404,detail="Successful backup run not found")
        expected=f"RESTORE {row['profile_name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400,detail=f"Confirmation must be exactly: {expected}")
        manifest=json.loads(row["manifest_json"] or "[]")
        item=next((m for m in manifest if m.get("type")==payload.component_type and m.get("name")==payload.component_name),None)
        if not item:
            raise HTTPException(status_code=404,detail="Backup component not found in manifest")
        archive=posixpath.join(row["remote_path"],item["file"])

        def task() -> None:
            try:
                if payload.component_type=="path":
                    _run(server,_sudo(f"tar -xzf {shlex.quote(archive)} -C /"),1800)
                elif payload.component_type=="volume":
                    volume=payload.component_name
                    if not VOLUME_RE.fullmatch(volume): raise RuntimeError("Invalid volume name")
                    script=f"mp=$(docker volume inspect -f '{{{{.Mountpoint}}}}' {shlex.quote(volume)}) || exit 44; find \"$mp\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +; tar -xzf {shlex.quote(archive)} -C \"$mp\""
                    _run(server,_sudo(f"sh -c {shlex.quote(script)}"),1800)
                else:
                    container=payload.component_name
                    if not CONTAINER_RE.fullmatch(container): raise RuntimeError("Invalid container name")
                    engine=item.get("engine")
                    if engine=="postgres":
                        command=f"gzip -dc {shlex.quote(archive)} | docker exec -i {shlex.quote(container)} sh -lc 'psql -v ON_ERROR_STOP=1 -U \"${{POSTGRES_USER:-postgres}}\" postgres'"
                    else:
                        inner="if [ -n \"${MYSQL_ROOT_PASSWORD:-}\" ]; then mysql -uroot -p\"$MYSQL_ROOT_PASSWORD\"; elif [ -n \"${MYSQL_PASSWORD:-}\" ] && [ -n \"${MYSQL_USER:-}\" ]; then mysql -u\"$MYSQL_USER\" -p\"$MYSQL_PASSWORD\"; else mysql -uroot; fi"
                        command=f"gzip -dc {shlex.quote(archive)} | docker exec -i {shlex.quote(container)} sh -lc {shlex.quote(inner)}"
                    _run(server,_sudo(f"sh -c {shlex.quote(command)}"),1800)
                audit_fn("vps.backup.restored","server",server_id,f"Restored {payload.component_type} {payload.component_name} from backup run {run_id}")
                _emit_event(db_factory,server_id,"success","Restore completed",f"{payload.component_type}: {payload.component_name}",{"run_id":run_id})
            except Exception as exc:
                audit_fn("vps.backup.restore.failed","server",server_id,f"Restore failed for {payload.component_name}: {str(exc)[:1000]}")
                _emit_event(db_factory,server_id,"error","Restore failed",str(exc),{"run_id":run_id})
        background_tasks.add_task(task)
        _emit_event(db_factory,server_id,"warning","Restore queued",f"{payload.component_type}: {payload.component_name}",{"run_id":run_id})
        return {"status":"queued","run_id":run_id,"component_type":payload.component_type,"component_name":payload.component_name}

    @app.delete("/api/vps/servers/{server_id}/backups/runs/{run_id}")
    def delete_backup(server_id: int, run_id: int, payload: DeleteRunRequest) -> dict[str, Any]:
        server=dict(server_lookup(server_id))
        with db_factory() as connection:
            row=connection.execute("SELECT r.*,p.name profile_name FROM backup_runs r JOIN backup_profiles p ON p.id=r.profile_id WHERE r.id=? AND r.server_id=?",(run_id,server_id)).fetchone()
        if not row or not row["remote_path"]:
            raise HTTPException(status_code=404,detail="Backup run not found")
        expected=f"DELETE BACKUP {run_id}"
        if payload.confirm!=expected:
            raise HTTPException(status_code=400,detail=f"Confirmation must be exactly: {expected}")
        remote=row["remote_path"]
        profile_root=posixpath.dirname(remote)
        if not remote.startswith(row["remote_path"].split(f"/profile-{row['profile_id']}/")[0] + f"/profile-{row['profile_id']}/"):
            raise HTTPException(status_code=409,detail="Backup path failed safety validation")
        try:
            _run(server,_sudo(f"rm -rf -- {shlex.quote(remote)}"),120)
        except RuntimeError as exc:
            raise HTTPException(status_code=502,detail=str(exc)) from exc
        with db_factory() as connection:
            connection.execute("UPDATE backup_runs SET remote_path=NULL,message='Remote backup deleted' WHERE id=?",(run_id,))
        audit_fn("vps.backup.deleted","server",server_id,f"Deleted backup run {run_id} from {profile_root}")
        return {"deleted":True,"run_id":run_id}


BACKUP_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Backup & Restore</title><style>
:root{font-family:Inter,system-ui;color:#17231f;background:#f6f8f7}body{margin:0}.top{height:64px;background:#173c38;color:white;display:flex;align-items:center;justify-content:space-between;padding:0 24px}.top a{color:white}.stage{max-width:1400px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:white;border:1px solid #dfe7e2;border-radius:16px;overflow:hidden;grid-column:span 6}.wide{grid-column:span 12}.head{padding:15px 17px;border-bottom:1px solid #e8eeea;display:flex;justify-content:space-between}.pad{padding:17px}.sub{font-size:11px;color:#718078}.row{display:flex;gap:8px;flex-wrap:wrap;margin:9px 0}input,textarea{border:1px solid #dfe7e2;border-radius:9px;padding:9px 10px;font:inherit}input{height:38px}textarea{min-height:70px;min-width:280px}button{border:1px solid #dfe7e2;background:white;border-radius:9px;padding:9px 11px;font-weight:750;cursor:pointer}.primary{background:#183f3b;color:white}.danger{color:#b42335}.item{padding:12px 0;border-bottom:1px solid #edf1ef}.tag{display:inline-block;padding:4px 8px;border-radius:99px;background:#eef4f1;font-size:10px;margin-right:5px}.success{color:#167347}.failed{color:#b42335}.running{color:#9a5c0e}code{font-size:11px}.manifest{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}@media(max-width:850px){.card{grid-column:span 12}}</style></head><body><div class="top"><b>Custom GitHub · Backup & Restore · __SERVER_NAME__</b><a href="/vps/__SERVER_ID__">Back to VPS</a></div><div class="stage"><h1>Backup & Restore Center</h1><p class="sub">Back up project directories, Docker volumes and database containers. Restores are component-specific and require explicit confirmation.</p><div class="row"><button class="primary" onclick="loadAll()">↻ Refresh</button><span id="status" class="tag">Loading</span></div><div class="grid"><div class="card"><div class="head"><b>Discovered sources</b></div><div id="sources" class="pad">Loading…</div></div><div class="card"><div class="head"><b>Create backup profile</b></div><div class="pad"><div class="row"><input id="name" placeholder="profile name" value="production"><input id="dest" value="/var/backups/custom-github"></div><textarea id="paths" placeholder="Paths, one per line"></textarea><textarea id="volumes" placeholder="Docker volumes, one per line"></textarea><textarea id="dbs" placeholder="Database containers, one per line"></textarea><div class="row"><input id="retention" type="number" min="1" max="90" value="7"><button class="primary" onclick="createProfile()">Create profile</button></div></div></div><div class="card wide"><div class="head"><b>Profiles</b></div><div id="profiles" class="pad"></div></div><div class="card wide"><div class="head"><b>Backup history</b><span class="sub">Restore overwrites the selected component only.</span></div><div id="runs" class="pad"></div></div></div></div><script>
const sid=__SERVER_ID__;async function api(p,o={}){status.textContent='Working…';const r=await fetch(p,{headers:{'Content-Type':'application/json'},...o});const t=await r.text();let d={};try{d=t?JSON.parse(t):{}}catch{d={detail:t}}status.textContent=r.ok?'Ready':'Error';if(!r.ok)throw new Error(d.detail||t);return d}const lines=id=>document.getElementById(id).value.split(/\n|,/).map(x=>x.trim()).filter(Boolean);function fmt(n){n=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(n<1024)return `${n.toFixed(n>=10?0:1)} ${u}`;n/=1024}return `${n.toFixed(1)} PB`}async function loadAll(){try{const [s,p,r]=await Promise.all([api(`/api/vps/servers/${sid}/backups/sources`),api(`/api/vps/servers/${sid}/backups/profiles`),api(`/api/vps/servers/${sid}/backups/runs`)]);sources.innerHTML=`<b>Project paths</b><p>${s.project_paths.map(x=>`${x.project}: <code>${x.path}</code>`).join('<br>')||'None'}</p><b>Volumes</b><p>${s.volumes.join(', ')||'None'}</p><b>Databases</b><p>${s.databases.map(x=>`${x.container} (${x.engine})`).join(', ')||'None'}</p>`;profiles.innerHTML=p.length?p.map(x=>`<div class=item><b>${x.name}</b> <span class=tag>${x.retention_count} retained</span><div class=sub>${x.paths.length} paths · ${x.volumes.length} volumes · ${x.database_containers.length} databases · ${x.destination}</div><div class=row><button class=primary onclick="runBackup(${x.id})">Back up now</button></div></div>`).join(''):'<div class=sub>No profiles yet.</div>';runs.innerHTML=r.length?r.map(x=>`<div class=item><b>#${x.id} · ${x.profile_name}</b> <span class="tag ${x.status}">${x.status.toUpperCase()}</span><div class=sub>${new Date(x.created_at).toLocaleString()} · ${x.bytes?fmt(x.bytes):''} · ${x.remote_path||x.message||''}</div><div class=manifest>${(x.manifest||[]).map(m=>`<button onclick='restore(${x.id},${JSON.stringify(m.type)},${JSON.stringify(m.name)},${JSON.stringify(x.profile_name)})'>Restore ${m.type}: ${m.name}</button>`).join('')}${x.remote_path?`<button class=danger onclick="delRun(${x.id})">Delete backup</button>`:''}</div>${x.error?`<div class=failed>${x.error}</div>`:''}</div>`).join(''):'<div class=sub>No backup runs yet.</div>';}catch(e){alert(e.message)}}async function createProfile(){try{await api(`/api/vps/servers/${sid}/backups/profiles`,{method:'POST',body:JSON.stringify({name:name.value,paths:lines('paths'),volumes:lines('volumes'),database_containers:lines('dbs'),destination:dest.value,retention_count:Number(retention.value||7)})});loadAll()}catch(e){alert(e.message)}}async function runBackup(id){try{const d=await api(`/api/vps/servers/${sid}/backups/profiles/${id}/run`,{method:'POST'});alert(`Backup queued as run #${d.run_id}`);setTimeout(loadAll,1000)}catch(e){alert(e.message)}}async function restore(id,type,n,p){const phrase=`RESTORE ${p}`;if(prompt(`This overwrites ${type} ${n}.\nType exactly:\n${phrase}`)!==phrase)return;try{await api(`/api/vps/servers/${sid}/backups/runs/${id}/restore`,{method:'POST',body:JSON.stringify({component_type:type,component_name:n,confirm:phrase})});alert('Restore queued. Watch Activity & Events.')}catch(e){alert(e.message)}}async function delRun(id){const phrase=`DELETE BACKUP ${id}`;if(prompt(`Type exactly: ${phrase}`)!==phrase)return;try{await api(`/api/vps/servers/${sid}/backups/runs/${id}`,{method:'DELETE',body:JSON.stringify({confirm:phrase})});loadAll()}catch(e){alert(e.message)}}loadAll();setInterval(loadAll,15000);</script></body></html>"""


__all__ = ["install_backup_routes", "BackupProfileCreate", "_path"]
