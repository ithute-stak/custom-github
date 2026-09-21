from __future__ import annotations

import json
import os
import shlex
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ACTIVE_DEPLOYMENT_STATES, ssh_command
from app.security import ROLE_LEVEL


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _role(request: Request, minimum: str) -> None:
    user = getattr(request.state, "security_user", None)
    if user and ROLE_LEVEL.get(str(user.get("role", "")), 0) < ROLE_LEVEL[minimum]:
        raise HTTPException(status_code=403, detail=f"{minimum.title()} role required")


def _ssh_argv(server: dict[str, Any], remote_command: str) -> list[str]:
    argv = [
        "ssh", "-p", str(server["port"]), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new",
    ]
    identity = str(server.get("identity_file") or "").strip()
    if identity:
        expanded = str(Path(os.path.expanduser(identity)).resolve())
        argv += ["-i", expanded]
    argv += [f"{server['ssh_user']}@{server['host']}", remote_command]
    return argv


class RollbackRequest(BaseModel):
    confirm: str = Field(min_length=8, max_length=180)


class BaselineRequest(BaseModel):
    confirm: str = Field(min_length=8, max_length=180)


class DrillRequest(BaseModel):
    backup_run_id: int = Field(gt=0)
    target_server_id: int = Field(gt=0)
    confirm: str = Field(min_length=8, max_length=180)


def install_reliability_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    project_lookup: Callable[[int], sqlite3.Row],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
    deployment_runner: Callable[[int], None],
) -> None:
    def init_db() -> None:
        with db_factory() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS drift_baselines (
                    project_id INTEGER PRIMARY KEY,
                    compose_sha256 TEXT,
                    env_sha256 TEXT,
                    captured_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                );
                CREATE TABLE IF NOT EXISTS dr_rehearsals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    source_server_id INTEGER NOT NULL,
                    target_server_id INTEGER NOT NULL,
                    backup_run_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT,
                    details_json TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    FOREIGN KEY(project_id) REFERENCES projects(id),
                    FOREIGN KEY(source_server_id) REFERENCES servers(id),
                    FOREIGN KEY(target_server_id) REFERENCES servers(id)
                );
                CREATE INDEX IF NOT EXISTS idx_dr_project ON dr_rehearsals(project_id,id DESC);
                """
            )

    @app.on_event("startup")
    def startup() -> None:
        init_db()

    def project_target(project_id: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        project = dict(project_lookup(project_id))
        with db_factory() as connection:
            target = connection.execute("SELECT * FROM deployment_targets WHERE project_id=?", (project_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=409, detail="Project has no deployment target")
        server = dict(server_lookup(int(target["server_id"])))
        return project, dict(target), server

    def current_expected_image(project_id: int) -> tuple[str | None, dict[str, Any] | None]:
        with db_factory() as connection:
            row = connection.execute(
                "SELECT * FROM deployments WHERE project_id=? AND status IN ('success','rolled-back') ORDER BY id DESC LIMIT 1",
                (project_id,),
            ).fetchone()
        if not row:
            return None, None
        data = dict(row)
        image = data["previous_image"] if data["status"] == "rolled-back" and data.get("previous_image") else data["image_tag"]
        return str(image) if image else None, data

    def inspect_drift(project_id: int) -> dict[str, Any]:
        project, target, server = project_target(project_id)
        expected, deployment = current_expected_image(project_id)
        compose_dir = shlex.quote(str(target["compose_dir"]))
        compose_file = shlex.quote(str(target["compose_file"]))
        service = shlex.quote(str(target["service_name"]))
        script = (
            "set +e; "
            f"cd {compose_dir} 2>/dev/null || exit 42; "
            f"cid=$(docker compose -f {compose_file} -f .custom-github.override.yaml ps -q {service} 2>/dev/null | head -n1); "
            "image=''; [ -n \"$cid\" ] && image=$(docker inspect -f '{{.Config.Image}}' \"$cid\" 2>/dev/null); "
            "release=$(cat .custom-github.release 2>/dev/null || true); "
            f"compose_hash=$(sha256sum {compose_file} 2>/dev/null | awk '{{print $1}}'); "
            "env_hash=$(sha256sum .env 2>/dev/null | awk '{print $1}'); "
            "override_hash=$(sha256sum .custom-github.override.yaml 2>/dev/null | awk '{print $1}'); "
            "printf 'image=%s\\nrelease=%s\\ncompose_hash=%s\\nenv_hash=%s\\noverride_hash=%s\\n' \"$image\" \"$release\" \"$compose_hash\" \"$env_hash\" \"$override_hash\""
        )
        code, raw = ssh_command(server, script, timeout=45)
        if code != 0:
            raise HTTPException(status_code=502, detail=raw.strip()[-4000:] or "Unable to inspect deployment drift")
        values: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                values[k] = v
        init_db()
        with db_factory() as connection:
            baseline = connection.execute("SELECT * FROM drift_baselines WHERE project_id=?", (project_id,)).fetchone()
        base = dict(baseline) if baseline else None
        findings: list[dict[str, str]] = []
        if expected and values.get("image") != expected:
            findings.append({"kind": "image", "severity": "critical", "message": f"Running image {values.get('image') or 'missing'} differs from expected {expected}"})
        if expected and values.get("release") != expected:
            findings.append({"kind": "release-file", "severity": "warning", "message": f"Release marker differs from expected image {expected}"})
        if base and base.get("compose_sha256") and values.get("compose_hash") != base.get("compose_sha256"):
            findings.append({"kind": "compose", "severity": "warning", "message": "Compose file changed since the captured baseline"})
        if base and base.get("env_sha256") and values.get("env_hash") != base.get("env_sha256"):
            findings.append({"kind": "environment", "severity": "warning", "message": ".env changed since the captured baseline"})
        return {
            "project": project["name"], "project_id": project_id, "server": server["name"], "expected_image": expected,
            "running_image": values.get("image"), "release_marker": values.get("release"), "compose_sha256": values.get("compose_hash"),
            "env_sha256": values.get("env_hash"), "override_sha256": values.get("override_hash"), "baseline": base,
            "drift": bool(findings), "findings": findings, "deployment": deployment, "checked_at": _now(),
        }

    @app.get("/projects/{project_id}/reliability", response_class=HTMLResponse, include_in_schema=False)
    def page(project_id: int) -> str:
        project = dict(project_lookup(project_id))
        return _page(project_id, str(project["name"]))

    @app.get("/api/projects/{project_id}/releases")
    def releases(project_id: int) -> dict[str, Any]:
        project = dict(project_lookup(project_id))
        with db_factory() as connection:
            runs = [dict(r) for r in connection.execute(
                "SELECT id,commit_sha,status,image_tag,started_at,finished_at FROM pipeline_runs WHERE project_id=? AND image_tag IS NOT NULL ORDER BY id DESC LIMIT 50",
                (project_id,),
            ).fetchall()]
            deployments = [dict(r) for r in connection.execute(
                "SELECT id,commit_sha,image_tag,previous_image,status,status_message,created_at,finished_at FROM deployments WHERE project_id=? ORDER BY id DESC LIMIT 50",
                (project_id,),
            ).fetchall()]
        expected, current = current_expected_image(project_id)
        return {"project": project["name"], "releases": runs, "deployments": deployments, "current_image": expected, "current_deployment": current}

    @app.post("/api/projects/{project_id}/releases/{pipeline_id}/rollback", status_code=202)
    def rollback(project_id: int, pipeline_id: int, payload: RollbackRequest, background: BackgroundTasks, request: Request) -> dict[str, Any]:
        _role(request, "operator")
        project, target, _server = project_target(project_id)
        with db_factory() as connection:
            release = connection.execute("SELECT * FROM pipeline_runs WHERE id=? AND project_id=?", (pipeline_id, project_id)).fetchone()
        if not release or release["status"] != "success" or not release["image_tag"]:
            raise HTTPException(status_code=409, detail="Selected pipeline is not a deployable successful release")
        expected_confirm = f"ROLLBACK {project['name']} TO {str(release['commit_sha'])[:12]}"
        if payload.confirm != expected_confirm:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected_confirm}")
        probe = subprocess.run(["docker", "image", "inspect", str(release["image_tag"])], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if probe.returncode != 0:
            raise HTTPException(status_code=409, detail="Release image is no longer present on the control-plane Docker host")
        with db_factory() as connection:
            active = connection.execute(
                "SELECT id FROM deployments WHERE server_id=? AND status IN (%s) LIMIT 1" % ",".join("?" for _ in ACTIVE_DEPLOYMENT_STATES),
                (target["server_id"], *sorted(ACTIVE_DEPLOYMENT_STATES)),
            ).fetchone()
            if active:
                raise HTTPException(status_code=409, detail="Another deployment is already active on this VPS")
            cursor = connection.execute(
                "INSERT INTO deployments(project_id,server_id,commit_sha,image_tag,status,status_message,logs,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (project_id, target["server_id"], release["commit_sha"], release["image_tag"], "queued", "Manual rollback queued", "", _now()),
            )
            deployment_id = int(cursor.lastrowid)
        audit_fn("release.rollback.queued", "deployment", deployment_id, f"Rollback {project['name']} to {release['commit_sha'][:12]}")
        background.add_task(deployment_runner, deployment_id)
        return {"deployment_id": deployment_id, "status": "queued", "image_tag": release["image_tag"], "commit_sha": release["commit_sha"]}

    @app.get("/api/projects/{project_id}/drift")
    def drift(project_id: int) -> dict[str, Any]:
        return inspect_drift(project_id)

    @app.post("/api/projects/{project_id}/drift/baseline")
    def baseline(project_id: int, payload: BaselineRequest, request: Request) -> dict[str, Any]:
        _role(request, "admin")
        project = dict(project_lookup(project_id))
        expected = f"BASELINE {project['name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected}")
        snapshot = inspect_drift(project_id)
        init_db()
        with db_factory() as connection:
            connection.execute(
                "INSERT INTO drift_baselines(project_id,compose_sha256,env_sha256,captured_at) VALUES(?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET compose_sha256=excluded.compose_sha256,env_sha256=excluded.env_sha256,captured_at=excluded.captured_at",
                (project_id, snapshot.get("compose_sha256"), snapshot.get("env_sha256"), _now()),
            )
        audit_fn("drift.baseline", "project", project_id, f"Captured config baseline for {project['name']}")
        return inspect_drift(project_id)

    @app.get("/api/projects/{project_id}/dr-rehearsals")
    def drills(project_id: int) -> dict[str, Any]:
        project, target, _server = project_target(project_id)
        init_db()
        with db_factory() as connection:
            backups = [dict(r) for r in connection.execute(
                "SELECT r.id,r.profile_id,r.status,r.remote_path,r.bytes,r.finished_at,p.name profile_name FROM backup_runs r JOIN backup_profiles p ON p.id=r.profile_id WHERE r.server_id=? AND r.status='success' AND r.remote_path IS NOT NULL ORDER BY r.id DESC LIMIT 20",
                (target["server_id"],),
            ).fetchall()]
            history = [dict(r) for r in connection.execute("SELECT * FROM dr_rehearsals WHERE project_id=? ORDER BY id DESC LIMIT 30", (project_id,)).fetchall()]
            spare = [dict(r) for r in connection.execute(
                "SELECT s.* FROM servers s WHERE s.id<>? AND NOT EXISTS(SELECT 1 FROM deployment_targets dt WHERE dt.server_id=s.id) ORDER BY s.name",
                (target["server_id"],),
            ).fetchall()]
        return {"project": project["name"], "source_server_id": target["server_id"], "backups": backups, "spare_servers": spare, "history": history}

    @app.post("/api/projects/{project_id}/dr-rehearsals", status_code=202)
    def start_drill(project_id: int, payload: DrillRequest, background: BackgroundTasks, request: Request) -> dict[str, Any]:
        _role(request, "admin")
        project, target, source = project_target(project_id)
        expected = f"DRILL {project['name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected}")
        if payload.target_server_id == int(target["server_id"]):
            raise HTTPException(status_code=409, detail="Disaster-recovery rehearsal must use a separate registered VPS")
        target_server = dict(server_lookup(payload.target_server_id))
        init_db()
        with db_factory() as connection:
            used = connection.execute("SELECT 1 FROM deployment_targets WHERE server_id=? LIMIT 1", (payload.target_server_id,)).fetchone()
            if used:
                raise HTTPException(status_code=409, detail="Target VPS has production deployment targets; choose an unused rehearsal VPS")
            backup = connection.execute("SELECT * FROM backup_runs WHERE id=? AND server_id=? AND status='success'", (payload.backup_run_id, target["server_id"])).fetchone()
            if not backup or not backup["remote_path"]:
                raise HTTPException(status_code=404, detail="Successful source backup not found")
            cursor = connection.execute(
                "INSERT INTO dr_rehearsals(project_id,source_server_id,target_server_id,backup_run_id,status,message,created_at) VALUES(?,?,?,?,?,?,?)",
                (project_id, target["server_id"], payload.target_server_id, payload.backup_run_id, "queued", "Queued", _now()),
            )
            drill_id = int(cursor.lastrowid)
            backup_data = dict(backup)

        def update(status: str, message: str, details: dict[str, Any] | None = None, *, start: bool = False, finish: bool = False) -> None:
            fields = ["status=?", "message=?", "details_json=?"]
            values: list[Any] = [status, message[:4000], json.dumps(details or {})]
            if start:
                fields.append("started_at=?"); values.append(_now())
            if finish:
                fields.append("finished_at=?"); values.append(_now())
            values.append(drill_id)
            with db_factory() as connection:
                connection.execute("UPDATE dr_rehearsals SET " + ",".join(fields) + " WHERE id=?", tuple(values))

        def task() -> None:
            sandbox = f"/var/tmp/custom-github-drill-{drill_id}"
            remote_path = str(backup_data["remote_path"])
            parent = str(Path(remote_path).parent)
            name = Path(remote_path).name
            update("running", "Streaming backup into isolated rehearsal sandbox", {"sandbox": sandbox}, start=True)
            try:
                source_cmd = f"test -d {shlex.quote(remote_path)} && tar -C {shlex.quote(parent)} -czf - {shlex.quote(name)}"
                target_cmd = f"set -eu; rm -rf -- {shlex.quote(sandbox)}; mkdir -p {shlex.quote(sandbox)}; tar -xzf - -C {shlex.quote(sandbox)}"
                src = subprocess.Popen(_ssh_argv(source, source_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                assert src.stdout is not None
                dst = subprocess.Popen(_ssh_argv(target_server, target_cmd), stdin=src.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                src.stdout.close()
                dst_out, _ = dst.communicate(timeout=1800)
                src_err = src.stderr.read() if src.stderr else b""
                src_code = src.wait(timeout=60)
                if src_code != 0 or dst.returncode != 0:
                    raise RuntimeError((src_err + (dst_out or b"")).decode(errors="replace")[-6000:])
                verify = (
                    f"set -eu; root={shlex.quote(sandbox + '/' + name)}; test -d \"$root\"; "
                    "count=$(find \"$root\" -type f | wc -l); bytes=$(du -sb \"$root\" | awk '{print $1}'); "
                    "bad=0; while IFS= read -r f; do case \"$f\" in *.tar.gz|*.tgz) tar -tzf \"$f\" >/dev/null || bad=$((bad+1));; *.gz) gzip -t \"$f\" || bad=$((bad+1));; esac; done < <(find \"$root\" -type f); "
                    "printf 'files=%s\\nbytes=%s\\nbad=%s\\n' \"$count\" \"$bytes\" \"$bad\""
                )
                # bash is used only on the spare rehearsal host and only against the sandbox path.
                code, out = ssh_command(target_server, "bash -lc " + shlex.quote(verify), timeout=900)
                if code != 0:
                    raise RuntimeError(out[-6000:])
                metrics = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
                if int(metrics.get("bad", "1")) != 0:
                    raise RuntimeError(f"Rehearsal restored with {metrics.get('bad')} corrupt artifact(s)")
                cleanup_code, cleanup_out = ssh_command(target_server, f"rm -rf -- {shlex.quote(sandbox)}", timeout=120)
                if cleanup_code != 0:
                    metrics["cleanup_warning"] = cleanup_out[-2000:]
                update("success", "Backup restored and verified on spare VPS", metrics, finish=True)
                audit_fn("dr.rehearsal.success", "project", project_id, f"DR rehearsal #{drill_id} passed on {target_server['name']}")
            except Exception as exc:
                update("failed", str(exc), {"sandbox": sandbox}, finish=True)
                audit_fn("dr.rehearsal.failed", "project", project_id, f"DR rehearsal #{drill_id} failed: {exc}")

        background.add_task(task)
        return {"id": drill_id, "status": "queued", "target_server": target_server["name"], "backup_run_id": payload.backup_run_id}


def _page(project_id: int, project_name: str) -> str:
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{project_name} Reliability</title><style>body{{margin:0;background:#f5f8f6;color:#17231f;font:14px system-ui}}.top{{background:#173c38;color:#fff;padding:18px 24px;display:flex;justify-content:space-between}}.top a{{color:#fff}}.wrap{{max-width:1300px;margin:auto;padding:24px}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}.card{{background:#fff;border:1px solid #dfe7e2;border-radius:14px;padding:17px;margin-bottom:14px}}button{{border:1px solid #ccd8d2;background:#fff;border-radius:8px;padding:8px 10px;cursor:pointer}}.danger{{color:#b42335}}.muted{{color:#718078;font-size:12px}}pre{{white-space:pre-wrap;background:#101815;color:#d9e7e0;border-radius:9px;padding:12px;max-height:420px;overflow:auto}}table{{width:100%;border-collapse:collapse}}td,th{{padding:8px;border-top:1px solid #edf1ef;text-align:left}}@media(max-width:850px){{.grid{{grid-template-columns:1fr}}}}</style></head><body><div class='top'><b>Custom GitHub · Reliability · {project_name}</b><a href='/deployments'>Projects & Deployments</a></div><div class='wrap'><div class='grid'><div class='card'><h2>Release Center</h2><p class='muted'>Immutable successful pipeline images and deployment history.</p><div id='releases'>Loading…</div></div><div class='card'><h2>Drift Detection</h2><p class='muted'>Compares the running image/release marker and captured Compose/.env hashes.</p><button onclick='loadDrift()'>Check live drift</button><button onclick='baseline()'>Capture baseline</button><pre id='drift'>Loading…</pre></div></div><div class='card'><h2>Disaster-Recovery Rehearsal</h2><p class='muted'>Streams a real successful backup into an unused registered VPS, verifies every compressed artifact, then removes the rehearsal sandbox. Production is not touched.</p><div id='drill'>Loading…</div></div></div><script>const pid={project_id},pname={json.dumps(project_name)};async function api(p,o={{}}){{const r=await fetch(p,{{headers:{{'Content-Type':'application/json'}},...o}});const t=await r.text();let d={{}};try{{d=t?JSON.parse(t):{{}}}}catch{{d={{detail:t}}}}if(!r.ok)throw new Error(d.detail||t);return d}}async function loadReleases(){{try{{const d=await api(`/api/projects/${{pid}}/releases`);releases.innerHTML=`<p><b>Current:</b> ${{d.current_image||'none'}}</p><table><tr><th>SHA</th><th>Image</th><th>Action</th></tr>${{d.releases.map(r=>`<tr><td>${{r.commit_sha.slice(0,12)}}</td><td>${{r.image_tag}}</td><td><button class='danger' onclick='rollback(${{r.id}},"${{r.commit_sha.slice(0,12)}}")'>Rollback</button></td></tr>`).join('')}}</table>`}}catch(e){{releases.textContent=e.message}}}}async function rollback(id,sha){{const c=`ROLLBACK ${{pname}} TO ${{sha}}`;if(prompt(`Type exactly:\n${{c}}`)!==c)return;try{{alert(JSON.stringify(await api(`/api/projects/${{pid}}/releases/${{id}}/rollback`,{{method:'POST',body:JSON.stringify({{confirm:c}})}})))}}catch(e){{alert(e.message)}}}}async function loadDrift(){{try{{drift.textContent=JSON.stringify(await api(`/api/projects/${{pid}}/drift`),null,2)}}catch(e){{drift.textContent=e.message}}}}async function baseline(){{const c=`BASELINE ${{pname}}`;if(prompt(`Type exactly:\n${{c}}`)!==c)return;try{{drift.textContent=JSON.stringify(await api(`/api/projects/${{pid}}/drift/baseline`,{{method:'POST',body:JSON.stringify({{confirm:c}})}}),null,2)}}catch(e){{alert(e.message)}}}}async function loadDrills(){{try{{const d=await api(`/api/projects/${{pid}}/dr-rehearsals`);drill.innerHTML=`<p>Backups: ${{d.backups.length}} · Spare VPSs: ${{d.spare_servers.length}}</p><div><select id='bsel'>${{d.backups.map(x=>`<option value='${{x.id}}'>#${{x.id}} ${{x.profile_name}} · ${{x.finished_at||''}}</option>`).join('')}}</select> <select id='ssel'>${{d.spare_servers.map(x=>`<option value='${{x.id}}'>${{x.name}}</option>`).join('')}}</select> <button onclick='startDrill()'>Run rehearsal</button></div><pre>${{JSON.stringify(d.history.slice(0,10),null,2)}}</pre>`}}catch(e){{drill.textContent=e.message}}}}async function startDrill(){{const c=`DRILL ${{pname}}`;if(prompt(`Type exactly:\n${{c}}`)!==c)return;try{{await api(`/api/projects/${{pid}}/dr-rehearsals`,{{method:'POST',body:JSON.stringify({{backup_run_id:+bsel.value,target_server_id:+ssel.value,confirm:c}})}});loadDrills()}}catch(e){{alert(e.message)}}}}loadReleases();loadDrift();loadDrills();</script></body></html>"""
