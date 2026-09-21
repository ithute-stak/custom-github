from __future__ import annotations

import json
import os
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Request as FastAPIRequest
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.github_app_webhooks import github_auth_mode, github_integration_status, resolve_github_token
from app.github_operations import GitHubAPIError, parse_github_repository
from app.security import ROLE_LEVEL


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _api_error(exc: GitHubAPIError) -> HTTPException:
    return HTTPException(status_code=502 if exc.status >= 500 else exc.status, detail=f"GitHub API: {exc}")


class GitHubAdminAPI:
    def __init__(self, owner: str, repo: str, token: str | None = None, timeout: int = 30):
        self.owner = owner
        self.repo = repo
        self.token = token or resolve_github_token(owner, repo)
        self.timeout = timeout
        self.rate: dict[str, str | None] = {"limit": None, "remaining": None, "reset": None, "resource": None}

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
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

    def patch(self, path: str, payload: Any) -> Any:
        return self.request(path, method="PATCH", payload=payload)

    def put(self, path: str, payload: Any | None = None) -> Any:
        return self.request(path, method="PUT", payload=payload)

    def delete(self, path: str) -> Any:
        return self.request(path, method="DELETE")


def _repo(project: Any) -> tuple[str, str]:
    try:
        return parse_github_repository(str(project["github_url"]))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _require_admin(request: FastAPIRequest) -> None:
    user = getattr(request.state, "security_user", None)
    if user and ROLE_LEVEL.get(str(user.get("role") or ""), 0) < ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required for GitHub administration mutations")


def _require_admin_write(client: GitHubAdminAPI, request: FastAPIRequest) -> None:
    _require_admin(request)
    if not client.token:
        raise HTTPException(status_code=409, detail="Authenticated GitHub access is required for administration mutations")
    if not _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_ADMIN_WRITE")):
        raise HTTPException(status_code=409, detail="GitHub administration mutations are disabled. Set CUSTOM_GITHUB_GITHUB_ADMIN_WRITE=1 after granting least-privilege GitHub App permissions.")


def _require_cache_write(client: GitHubAdminAPI, request: FastAPIRequest) -> None:
    _require_admin(request)
    if not client.token:
        raise HTTPException(status_code=409, detail="Authenticated GitHub access is required for cache deletion")
    if not _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_CACHE_WRITE")):
        raise HTTPException(status_code=409, detail="GitHub Actions cache deletion is disabled. Set CUSTOM_GITHUB_GITHUB_CACHE_WRITE=1 to enable it.")


def _safe(client: GitHubAdminAPI, path: str) -> dict[str, Any]:
    try:
        return {"available": True, "data": client.get(path), "error": None, "status": 200}
    except GitHubAPIError as exc:
        return {"available": False, "data": None, "error": str(exc), "status": exc.status}


def _variables(payload: Any) -> list[dict[str, Any]]:
    return [
        {"name": item.get("name"), "value": item.get("value"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at")}
        for item in ((payload or {}).get("variables") or [])
    ]


def _secret_metadata(payload: Any) -> list[dict[str, Any]]:
    return [
        {"name": item.get("name"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at")}
        for item in ((payload or {}).get("secrets") or [])
    ]


def _caches(payload: Any) -> list[dict[str, Any]]:
    return [
        {
            "id": item.get("id"), "ref": item.get("ref"), "key": item.get("key"), "version": item.get("version"),
            "size_in_bytes": item.get("size_in_bytes"), "created_at": item.get("created_at"), "last_accessed_at": item.get("last_accessed_at"),
        }
        for item in ((payload or {}).get("actions_caches") or [])
    ]


def _runners(payload: Any) -> list[dict[str, Any]]:
    return [
        {
            "id": item.get("id"), "name": item.get("name"), "os": item.get("os"), "status": item.get("status"), "busy": bool(item.get("busy")),
            "labels": [label.get("name") for label in (item.get("labels") or [])],
        }
        for item in ((payload or {}).get("runners") or [])
    ]


def _dependabot_alerts(payload: Any) -> list[dict[str, Any]]:
    rows = payload if isinstance(payload, list) else []
    return [
        {
            "number": item.get("number"), "state": item.get("state"), "dependency": ((item.get("dependency") or {}).get("package") or {}).get("name"),
            "manifest_path": (item.get("dependency") or {}).get("manifest_path"), "scope": (item.get("dependency") or {}).get("scope"),
            "severity": (item.get("security_advisory") or {}).get("severity"), "summary": (item.get("security_advisory") or {}).get("summary"),
            "dismissed_reason": item.get("dismissed_reason"), "fixed_at": item.get("fixed_at"), "html_url": item.get("html_url"),
        }
        for item in rows
    ]


def _code_alerts(payload: Any) -> list[dict[str, Any]]:
    rows = payload if isinstance(payload, list) else []
    return [
        {
            "number": item.get("number"), "state": item.get("state"), "rule": (item.get("rule") or {}).get("id"),
            "description": (item.get("rule") or {}).get("description"), "severity": (item.get("rule") or {}).get("security_severity_level") or (item.get("rule") or {}).get("severity"),
            "tool": ((item.get("tool") or {}).get("name")), "created_at": item.get("created_at"), "dismissed_reason": item.get("dismissed_reason"), "html_url": item.get("html_url"),
        }
        for item in rows
    ]


def _secret_alerts(payload: Any) -> list[dict[str, Any]]:
    # Deliberately exclude any raw secret/token value that GitHub might include.
    rows = payload if isinstance(payload, list) else []
    return [
        {
            "number": item.get("number"), "state": item.get("state"), "secret_type": item.get("secret_type"),
            "secret_type_display_name": item.get("secret_type_display_name"), "resolution": item.get("resolution"),
            "created_at": item.get("created_at"), "resolved_at": item.get("resolved_at"), "html_url": item.get("html_url"),
            "push_protection_bypassed": bool(item.get("push_protection_bypassed")),
        }
        for item in rows
    ]


class VariableUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    value: str = Field(max_length=48000)


class DeleteConfirmation(BaseModel):
    confirmation: str = Field(min_length=1, max_length=180)


def install_github_admin_routes(
    app: FastAPI,
    *,
    project_lookup: Callable[[int], Any],
    audit_fn: Callable[[str, str, int | None, str], None],
    api_factory: Callable[[str, str], GitHubAdminAPI] | None = None,
) -> None:
    def context(project_id: int) -> tuple[Any, str, str, GitHubAdminAPI]:
        project = project_lookup(project_id)
        owner, repo = _repo(project)
        client = api_factory(owner, repo) if api_factory else GitHubAdminAPI(owner, repo)
        return project, owner, repo, client

    @app.get("/github/admin", response_class=HTMLResponse, include_in_schema=False)
    def admin_index() -> str:
        return ADMIN_INDEX_HTML

    @app.get("/projects/{project_id}/github/admin", response_class=HTMLResponse, include_in_schema=False)
    def admin_project(project_id: int) -> str:
        project = project_lookup(project_id)
        return ADMIN_PROJECT_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"]))

    @app.get("/api/projects/{project_id}/github/admin/capabilities")
    def capabilities(project_id: int) -> dict[str, Any]:
        project, owner, repo, client = context(project_id)
        integration = github_integration_status()
        return {
            "project_id": project_id,
            "project_name": project["name"],
            "repository_full_name": f"{owner}/{repo}",
            "authenticated": bool(client.token),
            "auth_mode": github_auth_mode(),
            "admin_write_enabled": bool(client.token) and _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_ADMIN_WRITE")),
            "cache_write_enabled": bool(client.token) and _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_CACHE_WRITE")),
            "github_app_configured": integration.get("github_app_configured"),
        }

    @app.get("/api/projects/{project_id}/github/admin/overview")
    def overview(project_id: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        base = f"/repos/{owner}/{repo}"
        raw = {
            "variables": _safe(client, base + "/actions/variables?per_page=100"),
            "secrets": _safe(client, base + "/actions/secrets?per_page=100"),
            "environments": _safe(client, base + "/environments?per_page=100"),
            "caches": _safe(client, base + "/actions/caches?per_page=100"),
            "runners": _safe(client, base + "/actions/runners?per_page=100"),
            "deployments": _safe(client, base + "/deployments?per_page=50"),
            "dependabot": _safe(client, base + "/dependabot/alerts?state=open&per_page=100"),
            "code_scanning": _safe(client, base + "/code-scanning/alerts?state=open&per_page=100"),
            "secret_scanning": _safe(client, base + "/secret-scanning/alerts?state=open&per_page=100"),
        }
        return {
            "repository_full_name": f"{owner}/{repo}",
            "variables": {**raw["variables"], "data": _variables(raw["variables"]["data"]) if raw["variables"]["available"] else []},
            "secrets": {**raw["secrets"], "data": _secret_metadata(raw["secrets"]["data"]) if raw["secrets"]["available"] else []},
            "environments": {**raw["environments"], "data": [
                {"id": item.get("id"), "name": item.get("name"), "url": item.get("url"), "html_url": item.get("html_url"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "protection_rules": item.get("protection_rules") or [], "deployment_branch_policy": item.get("deployment_branch_policy")}
                for item in (((raw["environments"]["data"] or {}).get("environments") or []) if raw["environments"]["available"] else [])
            ]},
            "caches": {**raw["caches"], "data": _caches(raw["caches"]["data"]) if raw["caches"]["available"] else []},
            "runners": {**raw["runners"], "data": _runners(raw["runners"]["data"]) if raw["runners"]["available"] else []},
            "deployments": {**raw["deployments"], "data": [
                {"id": item.get("id"), "environment": item.get("environment"), "ref": item.get("ref"), "sha": item.get("sha"), "task": item.get("task"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "creator": ((item.get("creator") or {}).get("login"))}
                for item in ((raw["deployments"]["data"] or []) if raw["deployments"]["available"] else [])
            ]},
            "security": {
                "dependabot": {**raw["dependabot"], "data": _dependabot_alerts(raw["dependabot"]["data"]) if raw["dependabot"]["available"] else []},
                "code_scanning": {**raw["code_scanning"], "data": _code_alerts(raw["code_scanning"]["data"]) if raw["code_scanning"]["available"] else []},
                "secret_scanning": {**raw["secret_scanning"], "data": _secret_alerts(raw["secret_scanning"]["data"]) if raw["secret_scanning"]["available"] else []},
            },
            "rate_limit": client.rate,
        }

    @app.get("/api/projects/{project_id}/github/admin/environments/{environment_name}")
    def environment_detail(project_id: int, environment_name: str) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        encoded = quote(environment_name, safe="")
        base = f"/repos/{owner}/{repo}/environments/{encoded}"
        env = _safe(client, base)
        variables = _safe(client, base + "/variables?per_page=100")
        secrets = _safe(client, base + "/secrets?per_page=100")
        return {
            "environment": env,
            "variables": {**variables, "data": _variables(variables["data"]) if variables["available"] else []},
            "secrets": {**secrets, "data": _secret_metadata(secrets["data"]) if secrets["available"] else []},
        }

    @app.put("/api/projects/{project_id}/github/admin/variables/{name}")
    def upsert_repo_variable(project_id: int, name: str, body: VariableUpsert, request: FastAPIRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_admin_write(client, request)
        if body.name != name:
            raise HTTPException(status_code=400, detail="Variable path/name mismatch")
        base = f"/repos/{owner}/{repo}/actions/variables"
        try:
            existing = client.get(base + f"/{quote(name, safe='')}")
            if existing:
                client.patch(base + f"/{quote(name, safe='')}", {"name": name, "value": body.value})
                action = "updated"
            else:
                client.post(base, {"name": name, "value": body.value})
                action = "created"
        except GitHubAPIError as exc:
            if exc.status == 404:
                try:
                    client.post(base, {"name": name, "value": body.value})
                    action = "created"
                except GitHubAPIError as inner:
                    raise _api_error(inner) from inner
            else:
                raise _api_error(exc) from exc
        audit_fn(f"github.admin.variable.{action}", "project", project_id, f"{action.title()} GitHub Actions variable {name} in {owner}/{repo}")
        return {"ok": True, "name": name, "action": action}

    @app.delete("/api/projects/{project_id}/github/admin/variables/{name}")
    def delete_repo_variable(project_id: int, name: str, body: DeleteConfirmation, request: FastAPIRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_admin_write(client, request)
        expected = f"DELETE VARIABLE {name}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        try:
            client.delete(f"/repos/{owner}/{repo}/actions/variables/{quote(name, safe='')}")
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc
        audit_fn("github.admin.variable.deleted", "project", project_id, f"Deleted GitHub Actions variable {name} in {owner}/{repo}")
        return {"ok": True, "name": name}

    @app.put("/api/projects/{project_id}/github/admin/environments/{environment_name}/variables/{name}")
    def upsert_environment_variable(project_id: int, environment_name: str, name: str, body: VariableUpsert, request: FastAPIRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_admin_write(client, request)
        if body.name != name:
            raise HTTPException(status_code=400, detail="Variable path/name mismatch")
        encoded_env, encoded_name = quote(environment_name, safe=""), quote(name, safe="")
        base = f"/repos/{owner}/{repo}/environments/{encoded_env}/variables"
        try:
            existing = client.get(base + f"/{encoded_name}")
            if existing:
                client.patch(base + f"/{encoded_name}", {"name": name, "value": body.value})
                action = "updated"
            else:
                client.post(base, {"name": name, "value": body.value})
                action = "created"
        except GitHubAPIError as exc:
            if exc.status == 404:
                try:
                    client.post(base, {"name": name, "value": body.value})
                    action = "created"
                except GitHubAPIError as inner:
                    raise _api_error(inner) from inner
            else:
                raise _api_error(exc) from exc
        audit_fn(f"github.admin.environment_variable.{action}", "project", project_id, f"{action.title()} variable {name} in GitHub environment {environment_name} for {owner}/{repo}")
        return {"ok": True, "environment": environment_name, "name": name, "action": action}

    @app.delete("/api/projects/{project_id}/github/admin/caches/{cache_id}")
    def delete_cache(project_id: int, cache_id: int, body: DeleteConfirmation, request: FastAPIRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_cache_write(client, request)
        expected = f"DELETE CACHE {cache_id}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        try:
            client.delete(f"/repos/{owner}/{repo}/actions/caches/{cache_id}")
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc
        audit_fn("github.admin.cache.deleted", "project", project_id, f"Deleted GitHub Actions cache {cache_id} in {owner}/{repo}")
        return {"ok": True, "cache_id": cache_id}


ADMIN_INDEX_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub Administration</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1200px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:12px 0}.btn{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 12px;text-decoration:none}.muted{color:#8b949e}.repo{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-top:1px solid #30363d}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB</div><h1>Administration & Security</h1><div class=muted>Environments, variables, secret metadata, caches, runners, deployments and security alerts.</div></div><a class=btn href='/github'>GitHub Operations</a></div><div class=card><h2>Repositories</h2><div id=repos>Loading…</div></div></div><script>const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/api/github/projects').then(r=>r.json()).then(xs=>repos.innerHTML=xs.filter(x=>x.supported).map(x=>`<div class=repo><div><b>${e(x.name)}</b><div class=muted>${e(x.repository_full_name)}</div></div><a class=btn href='/projects/${x.id}/github/admin'>Open admin</a></div>`).join('')||'<span class=muted>No supported repositories.</span>')</script></body></html>"""


ADMIN_PROJECT_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub Admin · __PROJECT_NAME__</title><style>:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1450px;margin:auto;padding:22px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:12px}.btn,input,select{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 10px}.btn{text-decoration:none;cursor:pointer}.green{background:#238636;border-color:#2ea043}.red{background:#da3633;border-color:#f85149}.muted{color:#8b949e}.good{color:#3fb950}.bad{color:#f85149}.warn{color:#d29922}.item{border-top:1px solid #30363d;padding:9px 0}.metric{font-size:26px;font-weight:800}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.hidden{display:none}@media(max-width:900px){.grid{grid-template-columns:1fr}}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB / __PROJECT_NAME__</div><h1>Administration & Security</h1><div id=repo class=muted>Loading…</div></div><div><a class=btn href='/projects/__PROJECT_ID__/github'>Repository</a> <a class=btn href='/projects/__PROJECT_ID__/github/actions'>Actions</a> <a class=btn href='/projects/__PROJECT_ID__/github/pulls'>PRs</a> <button class=btn onclick='load()'>↻ Refresh</button></div></div><div class=grid id=metrics></div><div class=card><div class=tabs><button class=btn onclick="show('vars')">Variables & secrets</button><button class=btn onclick="show('envs')">Environments</button><button class=btn onclick="show('runtime')">Caches & runners</button><button class=btn onclick="show('security')">Security alerts</button><button class=btn onclick="show('deployments')">Deployments</button></div><div id=vars></div><div id=envs class=hidden></div><div id=runtime class=hidden></div><div id=security class=hidden></div><div id=deployments class=hidden></div></div></div><script>const ID=__PROJECT_ID__;let DATA=null,CAPS=null;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const api=async(u,o)=>{const r=await fetch(u,o);const t=await r.text();let x;try{x=t?JSON.parse(t):{}}catch{x={detail:t}}if(!r.ok)throw new Error(x.detail||`HTTP ${r.status}`);return x};function show(id){['vars','envs','runtime','security','deployments'].forEach(x=>document.getElementById(x).classList.toggle('hidden',x!==id))}function unavailable(x){return !x.available?`<div class='bad'>Unavailable (${e(x.status)}): ${e(x.error)}</div>`:''}async function load(){[CAPS,DATA]=await Promise.all([api(`/api/projects/${ID}/github/admin/capabilities`),api(`/api/projects/${ID}/github/admin/overview`)]);repo.textContent=`${CAPS.repository_full_name} · ${CAPS.auth_mode||'anonymous'}${CAPS.admin_write_enabled?' · admin writes enabled':''}`;const sec=DATA.security||{};metrics.innerHTML=[[DATA.variables.data.length,'Variables'],[DATA.secrets.data.length,'Secret names'],[DATA.environments.data.length,'Environments'],[DATA.caches.data.length,'Caches'],[DATA.runners.data.length,'Runners'],[(sec.dependabot?.data?.length||0)+(sec.code_scanning?.data?.length||0)+(sec.secret_scanning?.data?.length||0),'Open security alerts']].map(m=>`<div class=card><div class=metric>${e(m[0])}</div><div class=muted>${e(m[1])}</div></div>`).join('');vars.innerHTML=`<h3>Repository variables</h3>${unavailable(DATA.variables)}${DATA.variables.data.map(v=>`<div class=item><b>${e(v.name)}</b><div class=muted>${e(v.value)} · updated ${e(v.updated_at||'')}</div></div>`).join('')||'<span class=muted>No variables.</span>'}<h3>Actions secret metadata</h3>${unavailable(DATA.secrets)}${DATA.secrets.data.map(s=>`<div class=item><b>${e(s.name)}</b><div class=muted>Value is never returned · updated ${e(s.updated_at||'')}</div></div>`).join('')||'<span class=muted>No secret metadata available.</span>'}${CAPS.admin_write_enabled?`<h3>Create/update variable</h3><input id=vn placeholder=NAME><input id=vv placeholder=Value><button class='btn green' onclick='saveVar()'>Save variable</button>`:''}`;envs.innerHTML=`<h3>Environments</h3>${unavailable(DATA.environments)}${DATA.environments.data.map(x=>`<div class=item><b>${e(x.name)}</b><div class=muted>${(x.protection_rules||[]).length} protection rule(s) · updated ${e(x.updated_at||'')}</div><button class=btn onclick="envDetail('${e(x.name)}')">Inspect</button><div id='env-${e(x.id)}'></div></div>`).join('')||'<span class=muted>No environments.</span>'}`;runtime.innerHTML=`<h3>Actions caches</h3>${unavailable(DATA.caches)}${DATA.caches.data.map(c=>`<div class=item><div class=row><div><b>${e(c.key)}</b><div class=muted>${Math.round((c.size_in_bytes||0)/1024/1024)} MB · ${e(c.ref)} · last used ${e(c.last_accessed_at||'')}</div></div>${CAPS.cache_write_enabled?`<button class='btn red' onclick='deleteCache(${c.id})'>Delete</button>`:''}</div></div>`).join('')||'<span class=muted>No caches.</span>'}<h3>Self-hosted runners</h3>${unavailable(DATA.runners)}${DATA.runners.data.map(r=>`<div class=item><b>${e(r.name)}</b> <span class='${r.status==='online'?'good':'warn'}'>${e(r.status)}</span>${r.busy?' · BUSY':''}<div class=muted>${e(r.os)} · ${(r.labels||[]).map(e).join(', ')}</div></div>`).join('')||'<span class=muted>No runner data.</span>'}`;const row=(name,x)=>`<h3>${name}</h3>${unavailable(x)}${(x.data||[]).map(a=>`<div class=item><b>${e(a.severity||a.secret_type_display_name||a.secret_type||a.rule||'Alert')}</b> <span class=bad>${e(a.state)}</span><div>${e(a.summary||a.description||a.dependency||'')}</div><div class=muted>${e(a.manifest_path||a.tool||a.resolution||'')}</div></div>`).join('')||'<span class=muted>No open alerts.</span>'}`;security.innerHTML=row('Dependabot',sec.dependabot)+row('Code scanning',sec.code_scanning)+row('Secret scanning',sec.secret_scanning);deployments.innerHTML=`<h3>Recent GitHub deployments</h3>${unavailable(DATA.deployments)}${DATA.deployments.data.map(d=>`<div class=item><b>${e(d.environment||'default')}</b><div class=muted>${e(d.ref)} · ${e((d.sha||'').slice(0,12))} · ${e(d.creator||'')} · ${e(d.created_at||'')}</div></div>`).join('')||'<span class=muted>No deployments.</span>'}`}async function envDetail(name){try{const x=await api(`/api/projects/${ID}/github/admin/environments/${encodeURIComponent(name)}`);alert(`${name}\nVariables: ${(x.variables.data||[]).map(v=>v.name+'='+v.value).join(', ')||'none'}\nSecrets: ${(x.secrets.data||[]).map(s=>s.name).join(', ')||'none'}`)}catch(x){alert(x.message)}}async function saveVar(){try{await api(`/api/projects/${ID}/github/admin/variables/${encodeURIComponent(vn.value)}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:vn.value,value:vv.value})});await load()}catch(x){alert(x.message)}}async function deleteCache(id){const confirmation=prompt(`Type DELETE CACHE ${id} exactly`);if(!confirmation)return;try{await api(`/api/projects/${ID}/github/admin/caches/${id}`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})});await load()}catch(x){alert(x.message)}}load().catch(x=>repo.innerHTML=`<span class=bad>${e(x.message)}</span>`)</script></body></html>"""


__all__ = ["GitHubAdminAPI", "install_github_admin_routes"]
