from __future__ import annotations

import json
import os
from typing import Any, Callable, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.github_operations import GitHubAPIError, parse_github_repository


class GitHubActionsAPI:
    def __init__(self, token: str | None = None, timeout: int = 30):
        self.token = token or os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip() or None
        self.timeout = timeout
        self.rate: dict[str, str | None] = {"limit": None, "remaining": None, "reset": None, "resource": None}

    def _headers(self, *, accept: str = "application/vnd.github+json") -> dict[str, str]:
        return {
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "custom-github-control-plane",
            **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
        }

    def _capture_rate(self, headers: Any) -> None:
        if not headers:
            return
        self.rate = {
            "limit": headers.get("X-RateLimit-Limit"),
            "remaining": headers.get("X-RateLimit-Remaining"),
            "reset": headers.get("X-RateLimit-Reset"),
            "resource": headers.get("X-RateLimit-Resource"),
        }

    def request(self, path: str, *, method: str = "GET", payload: Any | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            "https://api.github.com" + path,
            method=method,
            data=data,
            headers={**self._headers(), **({"Content-Type": "application/json"} if data is not None else {})},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                self._capture_rate(response.headers)
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except HTTPError as exc:
            self._capture_rate(exc.headers)
            try:
                body = json.loads(exc.read().decode("utf-8"))
                message = str(body.get("message") or exc.reason)
            except Exception:
                message = str(exc.reason)
            raise GitHubAPIError(exc.code, message, rate_remaining=self.rate.get("remaining")) from exc
        except URLError as exc:
            raise GitHubAPIError(503, f"GitHub API unavailable: {exc.reason}") from exc
        except TimeoutError as exc:
            raise GitHubAPIError(504, "GitHub API request timed out") from exc

    def get(self, path: str) -> Any:
        return self.request(path)

    def post(self, path: str, payload: Any | None = None) -> Any:
        return self.request(path, method="POST", payload=payload)

    def read_text(self, path: str, *, max_bytes: int = 2_000_000) -> str:
        request = Request("https://api.github.com" + path, method="GET", headers=self._headers(accept="application/vnd.github+json"))
        try:
            with urlopen(request, timeout=self.timeout) as response:
                self._capture_rate(response.headers)
                raw = response.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                raw = raw[:max_bytes]
                text = raw.decode("utf-8", errors="replace")
                return text + ("\n\n[Custom GitHub truncated this log after 2 MB.]" if truncated else "")
        except HTTPError as exc:
            raise GitHubAPIError(exc.code, str(exc.reason)) from exc
        except URLError as exc:
            raise GitHubAPIError(503, f"GitHub API unavailable: {exc.reason}") from exc

    def stream(self, path: str) -> Iterator[bytes]:
        request = Request("https://api.github.com" + path, method="GET", headers=self._headers(accept="application/vnd.github+json"))
        try:
            with urlopen(request, timeout=max(self.timeout, 60)) as response:
                self._capture_rate(response.headers)
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    yield chunk
        except HTTPError as exc:
            raise GitHubAPIError(exc.code, str(exc.reason)) from exc
        except URLError as exc:
            raise GitHubAPIError(503, f"GitHub API unavailable: {exc.reason}") from exc


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _actions_write_enabled() -> bool:
    return bool(os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip()) and _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_ACTIONS_WRITE"))


def _repo(project: Any) -> tuple[str, str]:
    try:
        return parse_github_repository(str(project["github_url"]))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _api_error(exc: GitHubAPIError) -> HTTPException:
    status = 502 if exc.status >= 500 else exc.status
    return HTTPException(status_code=status, detail=f"GitHub API: {exc}")


def _client(api_factory: Callable[[], GitHubActionsAPI] | None) -> GitHubActionsAPI:
    return api_factory() if api_factory else GitHubActionsAPI()


def _require_write(client: GitHubActionsAPI) -> None:
    if not client.token:
        raise HTTPException(status_code=409, detail="Authenticated GitHub access is required for Actions write operations")
    if not _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_ACTIONS_WRITE")):
        raise HTTPException(
            status_code=409,
            detail="GitHub Actions write operations are disabled. Set CUSTOM_GITHUB_GITHUB_ACTIONS_WRITE=1 after configuring a least-privilege token or GitHub App.",
        )


def _workflow(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "path": item.get("path"),
        "state": item.get("state"),
        "html_url": item.get("html_url"),
        "badge_url": item.get("badge_url"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
    }


def _run(item: dict[str, Any]) -> dict[str, Any]:
    actor = item.get("actor") or {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "display_title": item.get("display_title"),
        "workflow_id": item.get("workflow_id"),
        "run_number": item.get("run_number"),
        "run_attempt": item.get("run_attempt"),
        "event": item.get("event"),
        "status": item.get("status"),
        "conclusion": item.get("conclusion"),
        "branch": item.get("head_branch"),
        "sha": item.get("head_sha"),
        "actor": actor.get("login"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "run_started_at": item.get("run_started_at"),
        "html_url": item.get("html_url"),
        "jobs_url": item.get("jobs_url"),
        "logs_url": item.get("logs_url"),
        "artifacts_url": item.get("artifacts_url"),
    }


def _job(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "run_id": item.get("run_id"),
        "name": item.get("name"),
        "status": item.get("status"),
        "conclusion": item.get("conclusion"),
        "started_at": item.get("started_at"),
        "completed_at": item.get("completed_at"),
        "runner_name": item.get("runner_name"),
        "runner_group_name": item.get("runner_group_name"),
        "html_url": item.get("html_url"),
        "steps": [
            {
                "number": step.get("number"),
                "name": step.get("name"),
                "status": step.get("status"),
                "conclusion": step.get("conclusion"),
                "started_at": step.get("started_at"),
                "completed_at": step.get("completed_at"),
            }
            for step in (item.get("steps") or [])
        ],
    }


class DispatchRequest(BaseModel):
    ref: str = Field(min_length=1, max_length=255)
    inputs: dict[str, str] = Field(default_factory=dict)


class ConfirmationRequest(BaseModel):
    confirmation: str = Field(default="", max_length=120)


def install_github_actions_routes(
    app: FastAPI,
    *,
    project_lookup: Callable[[int], Any],
    audit_fn: Callable[[str, str, int | None, str], None],
    api_factory: Callable[[], GitHubActionsAPI] | None = None,
) -> None:
    def context(project_id: int) -> tuple[Any, str, str]:
        project = project_lookup(project_id)
        owner, repo = _repo(project)
        return project, owner, repo

    @app.get("/github/actions", response_class=HTMLResponse, include_in_schema=False)
    def github_actions_index() -> str:
        return GITHUB_ACTIONS_INDEX_HTML

    @app.get("/projects/{project_id}/github/actions", response_class=HTMLResponse, include_in_schema=False)
    def github_actions_page(project_id: int) -> str:
        project = project_lookup(project_id)
        return GITHUB_ACTIONS_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"]))

    @app.get("/api/projects/{project_id}/github/actions/capabilities")
    def actions_capabilities(project_id: int) -> dict[str, Any]:
        project, owner, repo = context(project_id)
        token = os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip()
        return {
            "project_id": project_id,
            "project_name": project["name"],
            "repository_full_name": f"{owner}/{repo}",
            "authenticated": bool(token),
            "write_enabled": _actions_write_enabled(),
            "poll_interval_active_seconds": 4,
            "poll_interval_idle_seconds": 15,
        }

    @app.get("/api/projects/{project_id}/github/actions/workflows")
    def actions_workflows(project_id: int) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        try:
            payload = client.get(f"/repos/{owner}/{repo}/actions/workflows?per_page=100") or {}
            return {
                "total_count": payload.get("total_count", 0),
                "workflows": [_workflow(item) for item in (payload.get("workflows") or [])],
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/actions/runs")
    def actions_runs(
        project_id: int,
        workflow_id: int | None = Query(default=None, gt=0),
        branch: str | None = Query(default=None, max_length=255),
        status: str | None = Query(default=None, max_length=40),
        event: str | None = Query(default=None, max_length=80),
        page: int = Query(default=1, ge=1, le=1000),
        per_page: int = Query(default=30, ge=1, le=100),
    ) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if branch:
            params["branch"] = branch
        if status:
            params["status"] = status
        if event:
            params["event"] = event
        path = f"/repos/{owner}/{repo}/actions"
        path += f"/workflows/{workflow_id}/runs" if workflow_id else "/runs"
        client = _client(api_factory)
        try:
            payload = client.get(path + "?" + urlencode(params)) or {}
            return {
                "total_count": payload.get("total_count", 0),
                "workflow_runs": [_run(item) for item in (payload.get("workflow_runs") or [])],
                "page": page,
                "per_page": per_page,
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/actions/runs/{run_id}")
    def actions_run(project_id: int, run_id: int) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        try:
            return {"run": _run(client.get(f"/repos/{owner}/{repo}/actions/runs/{run_id}") or {}), "rate_limit": client.rate}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/actions/runs/{run_id}/jobs")
    def actions_jobs(project_id: int, run_id: int) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        try:
            payload = client.get(f"/repos/{owner}/{repo}/actions/runs/{run_id}/jobs?per_page=100") or {}
            return {
                "total_count": payload.get("total_count", 0),
                "jobs": [_job(item) for item in (payload.get("jobs") or [])],
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/actions/jobs/{job_id}/logs", response_class=PlainTextResponse)
    def actions_job_logs(project_id: int, job_id: int) -> str:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        try:
            return client.read_text(f"/repos/{owner}/{repo}/actions/jobs/{job_id}/logs")
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/actions/runs/{run_id}/artifacts")
    def actions_artifacts(project_id: int, run_id: int) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        try:
            payload = client.get(f"/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts?per_page=100") or {}
            return {
                "total_count": payload.get("total_count", 0),
                "artifacts": [
                    {
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "size_in_bytes": item.get("size_in_bytes"),
                        "expired": item.get("expired"),
                        "created_at": item.get("created_at"),
                        "expires_at": item.get("expires_at"),
                        "updated_at": item.get("updated_at"),
                        "download_url": f"/api/projects/{project_id}/github/actions/artifacts/{item.get('id')}/download",
                    }
                    for item in (payload.get("artifacts") or [])
                ],
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/actions/artifacts/{artifact_id}/download")
    def download_artifact(project_id: int, artifact_id: int) -> StreamingResponse:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        if not client.token:
            raise HTTPException(status_code=409, detail="Authenticated GitHub access is required to download workflow artifacts")
        return StreamingResponse(
            client.stream(f"/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip"),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="github-artifact-{artifact_id}.zip"'},
        )

    @app.post("/api/projects/{project_id}/github/actions/runs/{run_id}/rerun")
    def rerun_actions_run(project_id: int, run_id: int) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        _require_write(client)
        try:
            client.post(f"/repos/{owner}/{repo}/actions/runs/{run_id}/rerun")
            audit_fn("github.actions.rerun", "project", project_id, f"Requested rerun for GitHub Actions run {run_id} in {owner}/{repo}")
            return {"ok": True, "run_id": run_id, "action": "rerun"}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/actions/runs/{run_id}/rerun-failed")
    def rerun_failed_actions_jobs(project_id: int, run_id: int) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        _require_write(client)
        try:
            client.post(f"/repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs")
            audit_fn("github.actions.rerun_failed", "project", project_id, f"Requested failed-job rerun for GitHub Actions run {run_id} in {owner}/{repo}")
            return {"ok": True, "run_id": run_id, "action": "rerun-failed"}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/actions/jobs/{job_id}/rerun")
    def rerun_actions_job(project_id: int, job_id: int) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        _require_write(client)
        try:
            client.post(f"/repos/{owner}/{repo}/actions/jobs/{job_id}/rerun")
            audit_fn("github.actions.job_rerun", "project", project_id, f"Requested rerun for GitHub Actions job {job_id} in {owner}/{repo}")
            return {"ok": True, "job_id": job_id, "action": "rerun-job"}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/actions/runs/{run_id}/cancel")
    def cancel_actions_run(project_id: int, run_id: int, body: ConfirmationRequest) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        if body.confirmation != "CANCEL":
            raise HTTPException(status_code=400, detail="Type CANCEL exactly to cancel this GitHub Actions run")
        client = _client(api_factory)
        _require_write(client)
        try:
            client.post(f"/repos/{owner}/{repo}/actions/runs/{run_id}/cancel")
            audit_fn("github.actions.cancel", "project", project_id, f"Cancelled GitHub Actions run {run_id} in {owner}/{repo}")
            return {"ok": True, "run_id": run_id, "action": "cancel"}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/actions/workflows/{workflow_id}/dispatch")
    def dispatch_actions_workflow(project_id: int, workflow_id: int, body: DispatchRequest) -> dict[str, Any]:
        _, owner, repo = context(project_id)
        client = _client(api_factory)
        _require_write(client)
        try:
            client.post(
                f"/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
                {"ref": body.ref, "inputs": body.inputs},
            )
            audit_fn("github.actions.dispatch", "project", project_id, f"Dispatched GitHub workflow {workflow_id} on ref {body.ref} in {owner}/{repo}")
            return {"ok": True, "workflow_id": workflow_id, "ref": body.ref, "action": "dispatch"}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc


GITHUB_ACTIONS_INDEX_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub Actions</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1200px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:12px 0}.btn{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 12px;text-decoration:none}.muted{color:#8b949e}.repo{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 0;border-top:1px solid #30363d}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB</div><h1>Actions</h1><div class=muted>Live GitHub Actions runs, jobs, steps, logs and artifacts.</div></div><div><a class=btn href='/github'>Repositories</a> <a class=btn href='/'>Infrastructure</a></div></div><div class=card><h2>Repositories</h2><div id=repos>Loading…</div></div></div><script>const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/api/github/projects').then(r=>r.json()).then(xs=>{document.getElementById('repos').innerHTML=xs.filter(x=>x.supported).map(x=>`<div class=repo><div><b>${e(x.name)}</b><div class=muted>${e(x.repository_full_name)} · ${e(x.branch)}</div></div><a class=btn href='/projects/${x.id}/github/actions'>Open Actions</a></div>`).join('')||'<span class=muted>No supported GitHub repositories.</span>'}).catch(e=>document.getElementById('repos').textContent=e.message)</script></body></html>"""


GITHUB_ACTIONS_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Actions · __PROJECT_NAME__</title><style>:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1480px;margin:auto;padding:22px}.top,.row{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}.layout{display:grid;grid-template-columns:260px 1fr;gap:16px}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:12px}.btn,input,select,textarea{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 10px}.btn{text-decoration:none;cursor:pointer}.btn.green{background:#238636;border-color:#2ea043}.btn.red{background:#da3633;border-color:#f85149}.muted{color:#8b949e}.good{color:#3fb950}.bad{color:#f85149}.warn{color:#d29922}.running{color:#58a6ff}.workflow{display:block;width:100%;text-align:left;background:transparent;border:0;border-radius:6px;color:#e6edf3;padding:9px;cursor:pointer}.workflow:hover,.workflow.active{background:#21262d}.run{border-top:1px solid #30363d;padding:12px 0;cursor:pointer}.run:hover{background:#0d111744}.run-title{font-weight:650}.meta{font-size:12px;color:#8b949e;margin-top:4px}.status{font-weight:700}.filters{display:flex;gap:8px;flex-wrap:wrap}.job{border:1px solid #30363d;border-radius:8px;margin:10px 0;overflow:hidden}.jobhead{padding:12px;background:#0d1117;cursor:pointer}.steps{padding:4px 14px 12px}.step{display:grid;grid-template-columns:28px 1fr 120px;gap:8px;padding:6px 0;border-top:1px solid #21262d}.logs{background:#010409;border:1px solid #30363d;border-radius:8px;padding:12px;white-space:pre-wrap;max-height:520px;overflow:auto;font:12px ui-monospace,monospace}.pill{border:1px solid #30363d;border-radius:999px;padding:4px 8px;font-size:12px}.artifact{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:9px 0;border-top:1px solid #30363d}@media(max-width:900px){.layout{grid-template-columns:1fr}.sidebar{order:0}.step{grid-template-columns:26px 1fr}}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB / __PROJECT_NAME__</div><h1>Actions</h1><div id=repo class=muted>Connecting to GitHub…</div></div><div><a class=btn href='/projects/__PROJECT_ID__/github'>Repository</a> <button class=btn id=liveBtn onclick='toggleLive()'>● Live</button> <button class=btn onclick='loadRuns(true)'>↻ Refresh</button></div></div><div class=layout><aside class=sidebar><div class=card><b>Workflows</b><div id=workflows style='margin-top:10px'>Loading…</div></div><div class=card><b>Actions access</b><div id=caps class=meta>Loading…</div></div></aside><main><div class=card><div class=row><div class=filters><select id=status onchange='loadRuns(true)'><option value=''>All statuses</option><option>queued</option><option>in_progress</option><option>completed</option><option>failure</option><option>success</option><option>cancelled</option></select><input id=branch placeholder='Branch' onkeydown="if(event.key==='Enter')loadRuns(true)"><input id=event placeholder='Event (push, pull_request)' onkeydown="if(event.key==='Enter')loadRuns(true)"></div><div id=liveState class='pill running'>LIVE</div></div><div id=runs style='margin-top:8px'>Loading runs…</div></div><div id=detail></div></main></div></div><script>const ID=__PROJECT_ID__;let workflowId=null,live=true,timer=null,selectedRun=null;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const cls=(s,c)=>s==='in_progress'||s==='queued'?'running':c==='success'?'good':c?'bad':'warn';const icon=(s,c)=>s==='in_progress'?'◉':s==='queued'?'◌':c==='success'?'✓':c==='cancelled'?'⊘':c?'×':'•';const req=async(url,opt)=>{const r=await fetch(url,opt);let x;try{x=await r.json()}catch{x={detail:await r.text()}}if(!r.ok)throw new Error(x.detail||'Request failed');return x};async function init(){const c=await req(`/api/projects/${ID}/github/actions/capabilities`);document.getElementById('repo').textContent=c.repository_full_name;document.getElementById('caps').innerHTML=`${c.authenticated?'<span class=good>Authenticated</span>':'<span class=warn>Anonymous reads</span>'}<br>${c.write_enabled?'<span class=good>Rerun / cancel / dispatch enabled</span>':'<span class=muted>Write controls disabled</span>'}`;const w=await req(`/api/projects/${ID}/github/actions/workflows`);document.getElementById('workflows').innerHTML=`<button class='workflow active' data-id='' onclick='chooseWorkflow(null,this)'>All workflows</button>`+(w.workflows||[]).map(x=>`<button class=workflow data-id='${x.id}' onclick='chooseWorkflow(${x.id},this)'>${e(x.name)}<div class=meta>${e(x.state)}</div></button>`).join('');await loadRuns(true)}function chooseWorkflow(id,el){workflowId=id;document.querySelectorAll('.workflow').forEach(x=>x.classList.remove('active'));el.classList.add('active');loadRuns(true)}function schedule(active){clearTimeout(timer);if(!live)return;timer=setTimeout(()=>loadRuns(false),active?4000:15000)}async function loadRuns(show=true){if(show)document.getElementById('runs').innerHTML='<span class=muted>Loading…</span>';const q=new URLSearchParams({per_page:'50'});if(workflowId)q.set('workflow_id',workflowId);const st=document.getElementById('status').value,br=document.getElementById('branch').value.trim(),ev=document.getElementById('event').value.trim();if(st)q.set('status',st);if(br)q.set('branch',br);if(ev)q.set('event',ev);try{const x=await req(`/api/projects/${ID}/github/actions/runs?${q}`);const runs=x.workflow_runs||[];document.getElementById('runs').innerHTML=runs.length?runs.map(r=>`<div class=run onclick='openRun(${r.id})'><div class=row><div><span class='status ${cls(r.status,r.conclusion)}'>${icon(r.status,r.conclusion)} ${e(r.display_title||r.name)}</span><div class=meta>${e(r.name)} · ${e(r.event)} · ${e(r.branch||'—')} · ${e((r.sha||'').slice(0,7))} · ${e(r.actor||'')}</div></div><div class=meta>#${e(r.run_number)} · ${e(r.status)}${r.conclusion?' / '+e(r.conclusion):''}</div></div></div>`).join(''):'<span class=muted>No workflow runs match these filters.</span>';const active=runs.some(r=>r.status!=='completed');document.getElementById('liveState').className='pill '+(live?(active?'running':'good'):'muted');document.getElementById('liveState').textContent=live?(active?'LIVE · ACTIVE':'LIVE · IDLE'):'PAUSED';if(selectedRun)openRun(selectedRun,false);schedule(active)}catch(err){document.getElementById('runs').innerHTML=`<span class=bad>${e(err.message)}</span>`;schedule(false)}}function toggleLive(){live=!live;document.getElementById('liveBtn').textContent=live?'● Live':'○ Paused';if(live)loadRuns(false);else{clearTimeout(timer);document.getElementById('liveState').textContent='PAUSED'}}async function openRun(id,scroll=true){selectedRun=id;const d=document.getElementById('detail');if(scroll)d.innerHTML='<div class=card>Loading run…</div>';try{const [rr,jj,aa]=await Promise.all([req(`/api/projects/${ID}/github/actions/runs/${id}`),req(`/api/projects/${ID}/github/actions/runs/${id}/jobs`),req(`/api/projects/${ID}/github/actions/runs/${id}/artifacts`)]);const r=rr.run,jobs=jj.jobs||[],arts=aa.artifacts||[];d.innerHTML=`<div class=card><div class=row><div><h2 style='margin:0'>${e(r.display_title||r.name)}</h2><div class=meta>${e(r.name)} · run #${e(r.run_number)} attempt ${e(r.run_attempt||1)} · ${e(r.branch||'—')} · ${e((r.sha||'').slice(0,12))}</div></div><div><span class='status ${cls(r.status,r.conclusion)}'>${icon(r.status,r.conclusion)} ${e(r.status)}${r.conclusion?' / '+e(r.conclusion):''}</span></div></div><div class=row style='margin-top:12px'><div><button class=btn onclick='rerun(${r.id})'>Rerun all</button> <button class=btn onclick='rerunFailed(${r.id})'>Rerun failed</button> ${r.status!=='completed'?`<button class='btn red' onclick='cancelRun(${r.id})'>Cancel</button>`:''}</div><a class=btn href='${e(r.html_url)}' target=_blank>Open on GitHub ↗</a></div></div><div class=card><h3>Jobs & steps</h3>${jobs.length?jobs.map(j=>jobHtml(j)).join(''):'<span class=muted>No jobs available yet.</span>'}</div><div class=card><h3>Artifacts</h3>${arts.length?arts.map(a=>`<div class=artifact><div><b>${e(a.name)}</b><div class=meta>${Math.round((a.size_in_bytes||0)/1024)} KB · expires ${e(a.expires_at||'—')}${a.expired?' · EXPIRED':''}</div></div>${a.expired?'':'<a class=btn href='+e(a.download_url)+'>Download ZIP</a>'}</div>`).join(''):'<span class=muted>No artifacts for this run.</span>'}</div>`;if(scroll)d.scrollIntoView({behavior:'smooth',block:'start'})}catch(err){d.innerHTML=`<div class=card><span class=bad>${e(err.message)}</span></div>`}}function jobHtml(j){return `<div class=job><div class='jobhead row' onclick='toggleJob(${j.id})'><div><b class='${cls(j.status,j.conclusion)}'>${icon(j.status,j.conclusion)} ${e(j.name)}</b><div class=meta>${e(j.runner_name||'runner pending')} · ${e(j.status)}${j.conclusion?' / '+e(j.conclusion):''}</div></div><div><button class=btn onclick='event.stopPropagation();showLogs(${j.id})'>Logs</button> <button class=btn onclick='event.stopPropagation();rerunJob(${j.id})'>Rerun</button></div></div><div class=steps id='job-${j.id}'>${(j.steps||[]).map(s=>`<div class=step><span class='${cls(s.status,s.conclusion)}'>${icon(s.status,s.conclusion)}</span><span>${e(s.name)}</span><span class=meta>${e(s.status)}${s.conclusion?' / '+e(s.conclusion):''}</span></div>`).join('')}</div><div id='log-${j.id}'></div></div>`}function toggleJob(id){const x=document.getElementById('job-'+id);x.style.display=x.style.display==='none'?'block':'none'}async function showLogs(id){const el=document.getElementById('log-'+id);el.innerHTML='<div class=logs>Loading logs…</div>';try{const r=await fetch(`/api/projects/${ID}/github/actions/jobs/${id}/logs`);const t=await r.text();if(!r.ok)throw new Error(t);el.innerHTML=`<pre class=logs>${e(t)}</pre>`}catch(err){el.innerHTML=`<div class='logs bad'>${e(err.message)}</div>`}}async function mutate(url,body){try{await req(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});await loadRuns(false)}catch(err){alert(err.message)}}function rerun(id){mutate(`/api/projects/${ID}/github/actions/runs/${id}/rerun`)}function rerunFailed(id){mutate(`/api/projects/${ID}/github/actions/runs/${id}/rerun-failed`)}function rerunJob(id){mutate(`/api/projects/${ID}/github/actions/jobs/${id}/rerun`)}function cancelRun(id){const c=prompt('Type CANCEL to stop this workflow run');if(c==='CANCEL')mutate(`/api/projects/${ID}/github/actions/runs/${id}/cancel`,{confirmation:c})}init().catch(err=>document.getElementById('runs').innerHTML=`<span class=bad>${e(err.message)}</span>`)</script></body></html>"""
