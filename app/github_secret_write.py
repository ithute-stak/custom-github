from __future__ import annotations

import base64
import os
import re
from typing import Any, Callable
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from nacl.public import PublicKey, SealedBox
from pydantic import BaseModel, Field

from app.github_admin_center import GitHubAdminAPI
from app.github_operations import GitHubAPIError, parse_github_repository
from app.security import ROLE_LEVEL


SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def normalize_secret_name(value: str) -> str:
    name = value.strip()
    if not SECRET_NAME_RE.fullmatch(name):
        raise ValueError("Secret names must begin with a letter or underscore and contain only letters, digits, and underscores")
    name = name.upper()
    if name.startswith("GITHUB_"):
        raise ValueError("Secret names cannot start with GITHUB_")
    return name


def encrypt_github_secret(public_key_b64: str, plaintext: str) -> str:
    try:
        raw_key = base64.b64decode(public_key_b64, validate=True)
    except Exception as exc:
        raise ValueError("GitHub returned an invalid public key") from exc
    if len(raw_key) != 32:
        raise ValueError("GitHub secret public key must be 32 bytes")
    encrypted = SealedBox(PublicKey(raw_key)).encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def _require_admin(request: Request) -> None:
    user = getattr(request.state, "security_user", None)
    if user and ROLE_LEVEL.get(str(user.get("role") or ""), 0) < ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required for GitHub secret mutations")


def _require_secret_write(client: GitHubAdminAPI, request: Request) -> None:
    _require_admin(request)
    if not client.token:
        raise HTTPException(status_code=409, detail="Authenticated GitHub access is required for secret mutations")
    if not _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_SECRET_WRITE")):
        raise HTTPException(
            status_code=409,
            detail="GitHub secret mutations are disabled. Set CUSTOM_GITHUB_GITHUB_SECRET_WRITE=1 only after granting least-privilege GitHub App secrets permission.",
        )


def _repo(project: Any) -> tuple[str, str]:
    try:
        return parse_github_repository(str(project["github_url"]))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _api_error(exc: GitHubAPIError) -> HTTPException:
    return HTTPException(status_code=502 if exc.status >= 500 else exc.status, detail=f"GitHub API: {exc}")


class SecretWrite(BaseModel):
    value: str = Field(min_length=1, max_length=65536)


class SecretDelete(BaseModel):
    confirmation: str = Field(min_length=1, max_length=180)


def install_github_secret_routes(
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

    @app.get("/github/secrets", response_class=HTMLResponse, include_in_schema=False)
    def secret_index() -> str:
        return SECRET_INDEX_HTML

    @app.get("/projects/{project_id}/github/secrets", response_class=HTMLResponse, include_in_schema=False)
    def secret_project(project_id: int) -> str:
        project = project_lookup(project_id)
        return SECRET_PROJECT_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"]))

    @app.get("/api/projects/{project_id}/github/secrets/capabilities")
    def secret_capabilities(project_id: int) -> dict[str, Any]:
        project, owner, repo, client = context(project_id)
        return {
            "project_id": project_id,
            "project_name": project["name"],
            "repository_full_name": f"{owner}/{repo}",
            "authenticated": bool(client.token),
            "write_enabled": bool(client.token) and _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_SECRET_WRITE")),
            "plaintext_storage": False,
            "encryption": "libsodium-sealed-box",
        }

    def encrypted_payload(client: GitHubAdminAPI, public_key_path: str, value: str) -> dict[str, str]:
        try:
            key = client.get(public_key_path) or {}
            key_id = str(key.get("key_id") or "")
            public_key = str(key.get("key") or "")
            if not key_id or not public_key:
                raise HTTPException(status_code=409, detail="GitHub did not return a usable Actions secrets public key")
            return {"encrypted_value": encrypt_github_secret(public_key, value), "key_id": key_id}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.put("/api/projects/{project_id}/github/secrets/repository/{name}")
    def put_repository_secret(project_id: int, name: str, body: SecretWrite, request: Request) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_secret_write(client, request)
        try:
            secret_name = normalize_secret_name(name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        base = f"/repos/{owner}/{repo}/actions/secrets"
        payload = encrypted_payload(client, base + "/public-key", body.value)
        try:
            client.put(base + f"/{quote(secret_name, safe='')}", payload)
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc
        audit_fn("github.secret.repository.upserted", "project", project_id, f"Created or updated GitHub repository secret {secret_name} in {owner}/{repo}")
        return {"ok": True, "scope": "repository", "name": secret_name}

    @app.delete("/api/projects/{project_id}/github/secrets/repository/{name}")
    def delete_repository_secret(project_id: int, name: str, body: SecretDelete, request: Request) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_secret_write(client, request)
        try:
            secret_name = normalize_secret_name(name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        expected = f"DELETE SECRET {secret_name}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        try:
            client.delete(f"/repos/{owner}/{repo}/actions/secrets/{quote(secret_name, safe='')}")
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc
        audit_fn("github.secret.repository.deleted", "project", project_id, f"Deleted GitHub repository secret {secret_name} in {owner}/{repo}")
        return {"ok": True, "scope": "repository", "name": secret_name}

    @app.put("/api/projects/{project_id}/github/secrets/environments/{environment_name}/{name}")
    def put_environment_secret(project_id: int, environment_name: str, name: str, body: SecretWrite, request: Request) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_secret_write(client, request)
        try:
            secret_name = normalize_secret_name(name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        env = quote(environment_name.strip(), safe="")
        if not environment_name.strip():
            raise HTTPException(status_code=400, detail="Environment name is required")
        base = f"/repos/{owner}/{repo}/environments/{env}/secrets"
        payload = encrypted_payload(client, base + "/public-key", body.value)
        try:
            client.put(base + f"/{quote(secret_name, safe='')}", payload)
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc
        audit_fn("github.secret.environment.upserted", "project", project_id, f"Created or updated GitHub environment secret {secret_name} in {environment_name} for {owner}/{repo}")
        return {"ok": True, "scope": "environment", "environment": environment_name, "name": secret_name}

    @app.delete("/api/projects/{project_id}/github/secrets/environments/{environment_name}/{name}")
    def delete_environment_secret(project_id: int, environment_name: str, name: str, body: SecretDelete, request: Request) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_secret_write(client, request)
        try:
            secret_name = normalize_secret_name(name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        expected = f"DELETE SECRET {secret_name}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        env = quote(environment_name.strip(), safe="")
        try:
            client.delete(f"/repos/{owner}/{repo}/environments/{env}/secrets/{quote(secret_name, safe='')}")
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc
        audit_fn("github.secret.environment.deleted", "project", project_id, f"Deleted GitHub environment secret {secret_name} in {environment_name} for {owner}/{repo}")
        return {"ok": True, "scope": "environment", "environment": environment_name, "name": secret_name}


SECRET_INDEX_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub Secrets</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1100px;margin:auto;padding:28px}.top,.repo{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:12px 0}.btn{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 12px;text-decoration:none}.muted{color:#8b949e}.repo{padding:12px 0;border-top:1px solid #30363d}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB</div><h1>Secrets</h1><div class=muted>Write-only repository and environment Actions secrets using GitHub public-key encryption.</div></div><a class=btn href='/github/admin'>Administration</a></div><div class=card><div id=repos>Loading…</div></div></div><script>const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/api/github/projects').then(r=>r.json()).then(xs=>repos.innerHTML=xs.filter(x=>x.supported).map(x=>`<div class=repo><div><b>${e(x.name)}</b><div class=muted>${e(x.repository_full_name)}</div></div><a class=btn href='/projects/${x.id}/github/secrets'>Manage secrets</a></div>`).join('')||'<span class=muted>No supported repositories.</span>')</script></body></html>"""


SECRET_PROJECT_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub Secrets · __PROJECT_NAME__</title><style>:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1150px;margin:auto;padding:24px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:12px 0}.btn,input,select{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:9px 11px}.btn{cursor:pointer;text-decoration:none}.green{background:#238636;border-color:#2ea043}.red{background:#da3633;border-color:#f85149}.muted{color:#8b949e}.good{color:#3fb950}.warn{color:#d29922}.secret{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:10px 0}@media(max-width:700px){.secret{grid-template-columns:1fr}}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB / __PROJECT_NAME__</div><h1>Write-only Secrets</h1><div id=status class=muted>Loading…</div></div><div><a class=btn href='/projects/__PROJECT_ID__/github/admin'>Admin</a> <a class=btn href='/projects/__PROJECT_ID__/github'>Repository</a></div></div><div class=card><h2>Repository secret</h2><p class=muted>The plaintext is encrypted in memory with GitHub's current public key and is never stored by Custom GitHub.</p><div class=secret><input id=repoName placeholder='SECRET_NAME'><input id=repoValue type=password autocomplete=off placeholder='Secret value'></div><button class='btn green' onclick='saveRepo()'>Create / update</button> <button class='btn red' onclick='deleteRepo()'>Delete</button></div><div class=card><h2>Environment secret</h2><div class=secret><input id=envName placeholder='Environment, e.g. production'><input id=envSecretName placeholder='SECRET_NAME'><input id=envValue type=password autocomplete=off placeholder='Secret value'></div><button class='btn green' onclick='saveEnv()'>Create / update</button> <button class='btn red' onclick='deleteEnv()'>Delete</button></div><div class=card><h2>Existing secret metadata</h2><div id=metadata>Loading from GitHub Administration…</div></div></div><script>const ID=__PROJECT_ID__;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const api=async(u,o)=>{const r=await fetch(u,o);const t=await r.text();let x;try{x=t?JSON.parse(t):{}}catch{x={detail:t}}if(!r.ok)throw new Error(x.detail||`HTTP ${r.status}`);return x};async function load(){const [c,a]=await Promise.all([api(`/api/projects/${ID}/github/secrets/capabilities`),api(`/api/projects/${ID}/github/admin/overview`)]);status.innerHTML=`${e(c.repository_full_name)} · ${c.write_enabled?'<span class=good>SECRET WRITES ENABLED</span>':'<span class=warn>WRITE DISABLED</span>'} · ${e(c.encryption)}`;metadata.innerHTML=`<h3>Repository</h3>${(a.secrets.data||[]).map(s=>`<div><b>${e(s.name)}</b> <span class=muted>updated ${e(s.updated_at||'')}</span></div>`).join('')||'<span class=muted>No metadata available.</span>'}<h3>Environments</h3>${(a.environments.data||[]).map(x=>`<div><b>${e(x.name)}</b> <button class=btn onclick="inspectEnv('${e(x.name)}')">Show secret names</button></div>`).join('')||'<span class=muted>No environments.</span>'}`}async function put(url,value){try{await api(url,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({value})});alert('Secret sent to GitHub. Custom GitHub did not store the plaintext.');repoValue.value='';envValue.value='';await load()}catch(x){alert(x.message)}}function saveRepo(){if(!repoName.value||!repoValue.value)return alert('Secret name and value are required');put(`/api/projects/${ID}/github/secrets/repository/${encodeURIComponent(repoName.value)}`,repoValue.value)}function saveEnv(){if(!envName.value||!envSecretName.value||!envValue.value)return alert('Environment, secret name and value are required');put(`/api/projects/${ID}/github/secrets/environments/${encodeURIComponent(envName.value)}/${encodeURIComponent(envSecretName.value)}`,envValue.value)}async function del(url,name){const normalized=name.trim().toUpperCase(),confirmation=prompt(`Type DELETE SECRET ${normalized} exactly`);if(!confirmation)return;try{await api(url,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})});alert('Secret deleted from GitHub.');await load()}catch(x){alert(x.message)}}function deleteRepo(){if(!repoName.value)return alert('Secret name required');del(`/api/projects/${ID}/github/secrets/repository/${encodeURIComponent(repoName.value)}`,repoName.value)}function deleteEnv(){if(!envName.value||!envSecretName.value)return alert('Environment and secret name required');del(`/api/projects/${ID}/github/secrets/environments/${encodeURIComponent(envName.value)}/${encodeURIComponent(envSecretName.value)}`,envSecretName.value)}async function inspectEnv(name){try{const x=await api(`/api/projects/${ID}/github/admin/environments/${encodeURIComponent(name)}`);alert(`${name}: ${(x.secrets.data||[]).map(s=>s.name).join(', ')||'no secret metadata'}`)}catch(x){alert(x.message)}}load().catch(x=>status.textContent=x.message)</script></body></html>"""


__all__ = ["encrypt_github_secret", "normalize_secret_name", "install_github_secret_routes"]
