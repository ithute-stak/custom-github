from __future__ import annotations

import html
import json
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ssh_command
from app.production_contract import APPROVED_RUNNING, APPROVED_TRANSIENT, image_matches

APP_NAMES = {"loanhub": "LoanHub", "ithute": "Ithute"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expected(app_key: str) -> dict[str, tuple[str, ...]]:
    return {service: images for (project, service), images in APPROVED_RUNNING.items() if project == app_key}


def _transient(app_key: str) -> dict[str, tuple[str, ...]]:
    return {service: images for (project, service), images in APPROVED_TRANSIENT.items() if project == app_key}


def _docker_inventory(server: dict[str, Any], app_key: str) -> list[dict[str, Any]]:
    fmt = '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.State}}\t{{.Status}}\t{{.Ports}}'
    code, output = ssh_command(server, f"docker ps -a --no-trunc --format {shlex.quote(fmt)}", timeout=45)
    if code != 0:
        raise HTTPException(status_code=502, detail=output.strip()[-4000:] or "Unable to inspect Docker applications")
    expected = _expected(app_key)
    transient = _transient(app_key)
    rows: list[dict[str, Any]] = []
    for raw in output.splitlines():
        parts = raw.split("\t")
        if len(parts) < 8:
            continue
        cid, name, image, project, service, state, status, ports = parts[:8]
        if project != app_key:
            continue
        allowed = expected.get(service) or transient.get(service) or ()
        kind = "steady" if service in expected else "transient" if service in transient else "unapproved"
        rows.append({
            "id": cid,
            "name": name,
            "image": image,
            "project": project,
            "service": service,
            "state": state,
            "status": status,
            "ports": ports,
            "contract_kind": kind,
            "image_approved": bool(allowed and image_matches(image, allowed)),
            "allowed_images": list(allowed),
        })
    return rows


def _stats(server: dict[str, Any], container_ids: list[str]) -> dict[str, dict[str, str]]:
    if not container_ids:
        return {}
    names = " ".join(shlex.quote(cid) for cid in container_ids)
    fmt = '{{.ID}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}'
    code, output = ssh_command(server, f"docker stats --no-stream --format {shlex.quote(fmt)} {names}", timeout=45)
    if code != 0:
        return {}
    result: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 7:
            result[parts[0]] = {"cpu": parts[1], "memory": parts[2], "memory_percent": parts[3], "network": parts[4], "block_io": parts[5], "pids": parts[6]}
    return result


def _project_record(connection: sqlite3.Connection, app_key: str) -> dict[str, Any] | None:
    rows = connection.execute("SELECT * FROM projects ORDER BY id").fetchall()
    chosen = None
    for row in rows:
        name = str(row["name"]).lower()
        url = str(row["github_url"]).lower()
        if app_key in name or f"/{app_key}" in url or (app_key == "loanhub" and "/loanhub" in url):
            chosen = row
            break
    if not chosen:
        return None
    project = dict(chosen)
    target = connection.execute("SELECT * FROM deployment_targets WHERE project_id=?", (project["id"],)).fetchone()
    deployment = connection.execute("SELECT * FROM deployments WHERE project_id=? ORDER BY id DESC LIMIT 1", (project["id"],)).fetchone()
    project["target"] = dict(target) if target else None
    project["last_deployment"] = dict(deployment) if deployment else None
    return project


class AppAction(BaseModel):
    confirm: str = Field(min_length=1, max_length=80)


def install_application_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    def summary(server_id: int, app_key: str) -> dict[str, Any]:
        if app_key not in APP_NAMES:
            raise HTTPException(status_code=404, detail="Application not found")
        server = dict(server_lookup(server_id))
        containers = _docker_inventory(server, app_key)
        running_ids = [row["id"] for row in containers if row["state"] == "running"]
        stats = _stats(server, running_ids)
        for row in containers:
            row["resources"] = stats.get(row["id"], {})
        expected = _expected(app_key)
        by_service = {row["service"]: row for row in containers if row["contract_kind"] == "steady"}
        missing = [service for service in expected if service not in by_service]
        stopped = [service for service, row in by_service.items() if row["state"] != "running"]
        wrong_image = [service for service, row in by_service.items() if not row["image_approved"]]
        extra = [row for row in containers if row["contract_kind"] == "unapproved"]
        if not containers:
            state = "offline"
        elif missing or stopped or wrong_image or extra:
            state = "degraded"
        else:
            state = "healthy"
        with db_factory() as connection:
            project = _project_record(connection, app_key)
            backup_profiles = []
            try:
                backup_profiles = [dict(row) for row in connection.execute("SELECT id,name,retention_count,updated_at FROM backup_profiles WHERE server_id=? ORDER BY name", (server_id,)).fetchall()]
            except sqlite3.OperationalError:
                pass
        return {
            "key": app_key,
            "name": APP_NAMES[app_key],
            "state": state,
            "server_id": server_id,
            "expected_services": len(expected),
            "running_expected": sum(1 for service, row in by_service.items() if row["state"] == "running" and row["image_approved"]),
            "missing": missing,
            "stopped": stopped,
            "wrong_image": wrong_image,
            "extra": extra,
            "containers": containers,
            "project": project,
            "backup_profiles": backup_profiles,
            "checked_at": _now(),
            "sources": ["live docker ps", "live docker stats", "production contract", "control-plane deployment database"],
        }

    @app.get("/vps/{server_id}/applications", response_class=HTMLResponse, include_in_schema=False)
    def applications_page(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        return _applications_html(server_id, str(server["name"]))

    @app.get("/vps/{server_id}/applications/{app_key}", response_class=HTMLResponse, include_in_schema=False)
    def application_page(server_id: int, app_key: str) -> str:
        server = dict(server_lookup(server_id))
        if app_key not in APP_NAMES:
            raise HTTPException(status_code=404, detail="Application not found")
        return _application_html(server_id, app_key, str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/applications")
    def applications_api(server_id: int) -> list[dict[str, Any]]:
        return [summary(server_id, key) for key in APP_NAMES]

    @app.get("/api/vps/servers/{server_id}/applications/{app_key}")
    def application_api(server_id: int, app_key: str) -> dict[str, Any]:
        return summary(server_id, app_key)

    @app.post("/api/vps/servers/{server_id}/applications/{app_key}/restart")
    def restart_application(server_id: int, app_key: str, payload: AppAction, request: Request) -> dict[str, Any]:
        if app_key not in APP_NAMES:
            raise HTTPException(status_code=404, detail="Application not found")
        user = getattr(request.state, "security_user", None)
        if user and str(user["role"]) not in {"owner", "admin", "developer", "operator"}:
            raise HTTPException(status_code=403, detail="Operator role required")
        expected_confirm = f"RESTART {APP_NAMES[app_key]}"
        if payload.confirm != expected_confirm:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected_confirm}")
        server = dict(server_lookup(server_id))
        current = _docker_inventory(server, app_key)
        ids = [row["id"] for row in current if row["contract_kind"] == "steady"]
        if not ids:
            raise HTTPException(status_code=409, detail="No approved application containers found")
        code, output = ssh_command(server, "docker restart " + " ".join(shlex.quote(cid) for cid in ids), timeout=180)
        if code != 0:
            raise HTTPException(status_code=502, detail=output.strip()[-4000:] or "Application restart failed")
        audit_fn("application.restart", "server", server_id, f"Restarted {APP_NAMES[app_key]} approved steady-state containers ({len(ids)})")
        return {"restarted": len(ids), "application": app_key, "output": output.strip()}


def _applications_html(server_id: int, server_name: str) -> str:
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Applications</title><style>body{{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}}.wrap{{max-width:1200px;margin:auto;padding:28px}}.top,.row{{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap}}.grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-top:20px}}.card{{background:#111c2b;border:1px solid #26364c;border-radius:16px;padding:20px}}.big{{font-size:30px;font-weight:800}}.muted{{color:#93a4bb}}.btn{{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;text-decoration:none}}.healthy{{color:#69dda4}}.degraded{{color:#ffd76e}}.offline{{color:#ff707c}}@media(max-width:760px){{.grid{{grid-template-columns:1fr}}}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>VPS APPLICATIONS / {html.escape(server_name)}</div><h1>Application Control Center</h1><div class='muted'>Live application state grouped from the production Docker contract.</div></div><a class='btn' href='/vps/{server_id}'>VPS Manager</a></div><div id='grid' class='grid'><div class='card'>Loading live Docker state…</div></div></div><script>const sid={server_id};function esc(s){{return String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}async function load(){{const r=await fetch(`/api/vps/servers/${{sid}}/applications`);const x=await r.json();document.getElementById('grid').innerHTML=x.map(a=>`<div class='card'><div class='muted'>${{esc(a.key.toUpperCase())}}</div><div class='row'><h2>${{esc(a.name)}}</h2><b class='${{esc(a.state)}}'>${{esc(a.state.toUpperCase())}}</b></div><div class='big'>${{a.running_expected}} / ${{a.expected_services}}</div><div class='muted'>approved expected services running</div><p>Missing: ${{a.missing.length}} · Stopped: ${{a.stopped.length}} · Wrong image: ${{a.wrong_image.length}} · Extra: ${{a.extra.length}}</p><div class='muted'>Checked ${{new Date(a.checked_at).toLocaleString()}}</div><p><a class='btn' href='/vps/${{sid}}/applications/${{a.key}}'>Open application →</a></p></div>`).join('')}}load()</script></body></html>"""


def _application_html(server_id: int, app_key: str, server_name: str) -> str:
    app_name = APP_NAMES[app_key]
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(app_name)}</title><style>body{{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}}.wrap{{max-width:1320px;margin:auto;padding:28px}}.top,.row{{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}}.card,.panel{{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:17px}}.big{{font-size:27px;font-weight:800}}.muted{{color:#93a4bb}}.btn{{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;text-decoration:none;cursor:pointer}}.danger{{background:#8c2633}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-top:1px solid #26364c;text-align:left}}.healthy,.running{{color:#69dda4}}.degraded{{color:#ffd76e}}.offline,.exited{{color:#ff707c}}code{{color:#9cc4ff}}@media(max-width:800px){{.cards{{grid-template-columns:1fr 1fr}}}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>APPLICATION / {html.escape(server_name)}</div><h1>{html.escape(app_name)}</h1><div class='muted'>One application view across containers, resources, deployments and recovery.</div></div><div class='row'><a class='btn' href='/vps/{server_id}/applications'>All Applications</a><a class='btn' href='/vps/{server_id}/databases'>Databases</a><a class='btn' href='/vps/{server_id}/backups'>Backups</a><a class='btn' href='/vps/{server_id}/domains'>Domains</a></div></div><div class='cards'><div class='card'><div class='muted'>STATE</div><div id='state' class='big'>Loading…</div></div><div class='card'><div class='muted'>EXPECTED RUNNING</div><div id='services' class='big'>—</div></div><div class='card'><div class='muted'>LAST RELEASE</div><div id='release' class='big' style='font-size:15px'>—</div></div><div class='card'><div class='muted'>LIVE SOURCE</div><div class='big' style='font-size:15px'>Docker + Control DB</div></div></div><div class='panel'><div class='top'><h2>Services</h2><button class='btn' onclick='load()'>Refresh live state</button></div><div style='overflow:auto'><table><thead><tr><th>Service</th><th>State</th><th>Image</th><th>CPU</th><th>Memory</th><th>Ports</th><th>Contract</th></tr></thead><tbody id='rows'></tbody></table></div></div><div class='panel' style='margin-top:16px'><div class='top'><div><h2>Deployment & Recovery</h2><div id='deployment' class='muted'></div></div><button class='btn danger' onclick='restartApp()'>Restart {html.escape(app_name)}</button></div><div id='issues'></div></div></div><script>const sid={server_id},app={json.dumps(app_key)},appName={json.dumps(app_name)};const $=id=>document.getElementById(id);function esc(s){{return String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}async function api(u,o={{}}){{const r=await fetch(u,{{...o,headers:{{'content-type':'application/json',...(o.headers||{{}})}}}});const x=await r.json().catch(()=>({{}}));if(!r.ok)throw Error(x.detail||r.statusText);return x}}async function load(){{try{{const x=await api(`/api/vps/servers/${{sid}}/applications/${{app}}`);$('state').textContent=x.state.toUpperCase();$('state').className='big '+x.state;$('services').textContent=`${{x.running_expected}} / ${{x.expected_services}}`;$('release').textContent=x.project?.last_deployment?.image_tag||x.project?.latest_sha?.slice(0,12)||'No deployment record';$('rows').innerHTML=x.containers.map(c=>`<tr><td><b>${{esc(c.service)}}</b><div class='muted'>${{esc(c.name)}}</div></td><td class='${{esc(c.state)}}'>${{esc(c.state)}}</td><td><code>${{esc(c.image)}}</code></td><td>${{esc(c.resources?.cpu||'—')}}</td><td>${{esc(c.resources?.memory||'—')}}</td><td>${{esc(c.ports||'—')}}</td><td>${{c.image_approved?'✓ approved':esc(c.contract_kind)}}</td></tr>`).join('');const issue=[];if(x.missing.length)issue.push(`<p><b>Missing:</b> ${{esc(x.missing.join(', '))}}</p>`);if(x.stopped.length)issue.push(`<p><b>Stopped:</b> ${{esc(x.stopped.join(', '))}}</p>`);if(x.wrong_image.length)issue.push(`<p><b>Wrong image:</b> ${{esc(x.wrong_image.join(', '))}}</p>`);if(x.extra.length)issue.push(`<p><b>Extra/unapproved:</b> ${{esc(x.extra.map(e=>e.service||e.name).join(', '))}}</p>`);$('issues').innerHTML=issue.join('')||'<p class="healthy">Production contract matches live Docker state.</p>';$('deployment').textContent=x.project?.last_deployment?`Last deployment: ${{x.project.last_deployment.status}} · ${{x.project.last_deployment.created_at}}`:'No deployment record matched to this application.'}}catch(e){{$('issues').innerHTML=`<p class='offline'>${{esc(e.message)}}</p>`}}}}async function restartApp(){{const confirm=prompt(`Type: RESTART ${{appName}}`);if(!confirm)return;try{{await api(`/api/vps/servers/${{sid}}/applications/${{app}}/restart`,{{method:'POST',body:JSON.stringify({{confirm}})}});await load()}}catch(e){{alert(e.message)}}}}load()</script></body></html>"""
