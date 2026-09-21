from __future__ import annotations

import base64
import json
import os
import re
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.github_app_webhooks import github_auth_mode, resolve_github_token
from app.github_operations import GitHubAPIError, parse_github_repository
from app.github_pull_requests import GitHubPullAPI


_BRANCH_RE = re.compile(r"^(?![./])(?!.*(?:\.\.|//|@\{|\\))[A-Za-z0-9._/-]{1,240}(?<![./])$")
_PATH_RE = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._@+~ /-]{1,800}$")


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _safe_branch(value: str) -> str:
    value = value.strip()
    if not _BRANCH_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid Git branch name")
    return value


def _safe_path(value: str, *, allow_root: bool = True) -> str:
    value = value.strip().strip("/")
    if not value and allow_root:
        return ""
    if not value or not _PATH_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid repository path")
    return value


class GitHubRepoAPI(GitHubPullAPI):
    def delete(self, path: str, payload: Any | None = None) -> Any:
        return self.request_json(path, method="DELETE", payload=payload)


def _repo(project: Any) -> tuple[str, str]:
    try:
        return parse_github_repository(str(project["github_url"]))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _api_error(exc: GitHubAPIError) -> HTTPException:
    return HTTPException(status_code=502 if exc.status >= 500 else exc.status, detail=f"GitHub API: {exc}")


def _require_repo_write(client: GitHubRepoAPI) -> None:
    if not client.token:
        raise HTTPException(status_code=409, detail="Authenticated GitHub access is required for repository mutations")
    if not _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE")):
        raise HTTPException(
            status_code=409,
            detail="GitHub repository mutations are disabled. Set CUSTOM_GITHUB_GITHUB_REPO_WRITE=1 after configuring least-privilege GitHub App permissions.",
        )


def _repository(client: GitHubRepoAPI, owner: str, repo: str) -> dict[str, Any]:
    return client.get(f"/repos/{owner}/{repo}") or {}


def _branch(client: GitHubRepoAPI, owner: str, repo: str, branch: str) -> dict[str, Any]:
    return client.get(f"/repos/{owner}/{repo}/branches/{quote(branch, safe='')}") or {}


def _assert_editable_branch(client: GitHubRepoAPI, owner: str, repo: str, branch: str) -> dict[str, Any]:
    repository = _repository(client, owner, repo)
    default_branch = str(repository.get("default_branch") or "")
    if branch == default_branch:
        raise HTTPException(
            status_code=409,
            detail=f"Direct edits to the default branch '{default_branch}' are blocked. Create a working branch and open a pull request.",
        )
    branch_info = _branch(client, owner, repo, branch)
    if bool(branch_info.get("protected")):
        raise HTTPException(status_code=409, detail=f"Direct edits to protected branch '{branch}' are blocked")
    return branch_info


def _decode_file(item: dict[str, Any], *, max_bytes: int = 1_500_000) -> dict[str, Any]:
    result = {
        "name": item.get("name"),
        "path": item.get("path"),
        "sha": item.get("sha"),
        "size": item.get("size"),
        "type": item.get("type"),
        "html_url": item.get("html_url"),
        "download_url": item.get("download_url"),
        "encoding": item.get("encoding"),
        "content": None,
        "binary": None,
        "truncated": False,
    }
    if item.get("type") != "file":
        return result
    encoded = str(item.get("content") or "").replace("\n", "")
    if not encoded:
        return result
    try:
        raw = base64.b64decode(encoded, validate=False)
    except Exception:
        result["binary"] = True
        return result
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
        result["truncated"] = True
    if b"\x00" in raw:
        result["binary"] = True
        return result
    try:
        result["content"] = raw.decode("utf-8")
        result["binary"] = False
    except UnicodeDecodeError:
        result["binary"] = True
    return result


def _contents_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "path": item.get("path"),
        "sha": item.get("sha"),
        "size": item.get("size"),
        "type": item.get("type"),
        "html_url": item.get("html_url"),
        "download_url": item.get("download_url"),
    }


def _protection_summary(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not payload:
        return {"available": False}
    reviews = payload.get("required_pull_request_reviews") or {}
    checks = payload.get("required_status_checks") or {}
    restrictions = payload.get("restrictions") or {}
    return {
        "available": True,
        "required_approving_review_count": reviews.get("required_approving_review_count"),
        "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews"),
        "require_code_owner_reviews": reviews.get("require_code_owner_reviews"),
        "required_status_checks": checks.get("contexts") or [],
        "strict_status_checks": checks.get("strict"),
        "enforce_admins": bool((payload.get("enforce_admins") or {}).get("enabled")),
        "allow_force_pushes": bool((payload.get("allow_force_pushes") or {}).get("enabled")),
        "allow_deletions": bool((payload.get("allow_deletions") or {}).get("enabled")),
        "restricted_users": [x.get("login") for x in (restrictions.get("users") or [])],
        "restricted_teams": [x.get("slug") for x in (restrictions.get("teams") or [])],
    }


class BranchCreate(BaseModel):
    name: str = Field(min_length=1, max_length=240)
    from_ref: str = Field(default="main", min_length=1, max_length=240)


class BranchDelete(BaseModel):
    confirmation: str = Field(min_length=1, max_length=300)


class FileWrite(BaseModel):
    path: str = Field(min_length=1, max_length=800)
    branch: str = Field(min_length=1, max_length=240)
    message: str = Field(min_length=1, max_length=300)
    content: str = Field(default="", max_length=2_000_000)
    expected_sha: str | None = Field(default=None, min_length=40, max_length=64)


class FileDelete(BaseModel):
    path: str = Field(min_length=1, max_length=800)
    branch: str = Field(min_length=1, max_length=240)
    message: str = Field(min_length=1, max_length=300)
    expected_sha: str = Field(min_length=40, max_length=64)
    confirmation: str = Field(min_length=1, max_length=900)


def install_github_code_governance_routes(
    app: FastAPI,
    *,
    project_lookup: Callable[[int], Any],
    audit_fn: Callable[[str, str, int | None, str], None],
    api_factory: Callable[[], GitHubRepoAPI] | None = None,
) -> None:
    def context(project_id: int) -> tuple[Any, str, str, GitHubRepoAPI]:
        project = project_lookup(project_id)
        owner, repo = _repo(project)
        client = api_factory() if api_factory else GitHubRepoAPI()
        return project, owner, repo, client

    @app.get("/github/code", response_class=HTMLResponse, include_in_schema=False)
    def code_index() -> str:
        return CODE_INDEX_HTML

    @app.get("/projects/{project_id}/github/code", response_class=HTMLResponse, include_in_schema=False)
    def code_project(project_id: int) -> str:
        project = project_lookup(project_id)
        return CODE_PROJECT_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"]))

    @app.get("/api/projects/{project_id}/github/code/capabilities")
    def code_capabilities(project_id: int) -> dict[str, Any]:
        project, owner, repo, client = context(project_id)
        try:
            repository = _repository(client, owner, repo)
            return {
                "project_id": project_id,
                "project_name": project["name"],
                "repository_full_name": f"{owner}/{repo}",
                "default_branch": repository.get("default_branch"),
                "authenticated": bool(client.token),
                "auth_mode": github_auth_mode(),
                "write_enabled": bool(client.token and _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE"))),
                "default_branch_direct_edits": False,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/code/contents")
    def code_contents(project_id: int, path: str = "", ref: str | None = None) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        path = _safe_path(path)
        try:
            repository = _repository(client, owner, repo)
            selected_ref = _safe_branch(ref or str(repository.get("default_branch") or "main"))
            encoded_path = quote(path, safe="/")
            suffix = f"/{encoded_path}" if encoded_path else ""
            payload = client.get(f"/repos/{owner}/{repo}/contents{suffix}?{urlencode({'ref': selected_ref})}")
            if isinstance(payload, list):
                items = [_contents_item(item) for item in payload]
                items.sort(key=lambda x: (0 if x["type"] == "dir" else 1, str(x["name"]).lower()))
                return {"kind": "directory", "path": path, "ref": selected_ref, "items": items, "rate_limit": client.rate}
            if isinstance(payload, dict):
                return {"kind": "file", "path": path, "ref": selected_ref, "file": _decode_file(payload), "rate_limit": client.rate}
            raise HTTPException(status_code=502, detail="Unexpected GitHub contents response")
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/code/history")
    def file_history(project_id: int, path: str, ref: str | None = None, per_page: int = Query(default=30, ge=1, le=100)) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        path = _safe_path(path, allow_root=False)
        try:
            repository = _repository(client, owner, repo)
            selected_ref = _safe_branch(ref or str(repository.get("default_branch") or "main"))
            params = urlencode({"path": path, "sha": selected_ref, "per_page": per_page})
            rows = client.get(f"/repos/{owner}/{repo}/commits?{params}") or []
            return {
                "commits": [
                    {
                        "sha": row.get("sha"),
                        "message": (((row.get("commit") or {}).get("message") or "").splitlines() or [""])[0],
                        "author": ((row.get("author") or {}).get("login") or (((row.get("commit") or {}).get("author") or {}).get("name"))),
                        "date": (((row.get("commit") or {}).get("author") or {}).get("date")),
                        "html_url": row.get("html_url"),
                    }
                    for row in rows
                ],
                "ref": selected_ref,
                "path": path,
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/branches")
    def branches(project_id: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        try:
            repository = _repository(client, owner, repo)
            rows = client.paginate(f"/repos/{owner}/{repo}/branches")
            return {
                "default_branch": repository.get("default_branch"),
                "branches": [
                    {"name": row.get("name"), "sha": ((row.get("commit") or {}).get("sha")), "protected": bool(row.get("protected"))}
                    for row in rows
                ],
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/branches/{branch:path}/governance")
    def branch_governance(project_id: int, branch: str) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        branch = _safe_branch(branch)
        try:
            repository = _repository(client, owner, repo)
            info = _branch(client, owner, repo, branch)
            protection = None
            protection_error = None
            if info.get("protected"):
                try:
                    protection = client.get(f"/repos/{owner}/{repo}/branches/{quote(branch, safe='')}/protection") or {}
                except GitHubAPIError as exc:
                    if exc.status not in {403, 404}:
                        raise
                    protection_error = str(exc)
            rulesets = None
            rulesets_error = None
            try:
                rulesets = client.get(f"/repos/{owner}/{repo}/rulesets?includes_parents=true") or []
            except GitHubAPIError as exc:
                if exc.status not in {403, 404}:
                    raise
                rulesets_error = str(exc)
            return {
                "branch": {"name": branch, "sha": ((info.get("commit") or {}).get("sha")), "protected": bool(info.get("protected"))},
                "default_branch": repository.get("default_branch"),
                "is_default": branch == repository.get("default_branch"),
                "direct_edit_allowed": bool(branch != repository.get("default_branch") and not info.get("protected")),
                "protection": _protection_summary(protection),
                "protection_error": protection_error,
                "rulesets": [
                    {"id": x.get("id"), "name": x.get("name"), "target": x.get("target"), "enforcement": x.get("enforcement"), "source_type": x.get("source_type")}
                    for x in (rulesets or [])
                ] if rulesets is not None else None,
                "rulesets_error": rulesets_error,
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/compare")
    def compare_refs(project_id: int, base: str, head: str) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        base = _safe_branch(base)
        head = _safe_branch(head)
        try:
            result = client.get(f"/repos/{owner}/{repo}/compare/{quote(base, safe='')}...{quote(head, safe='')}") or {}
            return {
                "status": result.get("status"),
                "ahead_by": result.get("ahead_by"),
                "behind_by": result.get("behind_by"),
                "total_commits": result.get("total_commits"),
                "merge_base_sha": ((result.get("merge_base_commit") or {}).get("sha")),
                "commits": [
                    {"sha": row.get("sha"), "message": (((row.get("commit") or {}).get("message") or "").splitlines() or [""])[0], "html_url": row.get("html_url")}
                    for row in (result.get("commits") or [])[:100]
                ],
                "files": [
                    {"filename": row.get("filename"), "status": row.get("status"), "additions": row.get("additions"), "deletions": row.get("deletions"), "changes": row.get("changes")}
                    for row in (result.get("files") or [])[:300]
                ],
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/branches", status_code=201)
    def create_branch(project_id: int, body: BranchCreate) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_repo_write(client)
        name = _safe_branch(body.name)
        source = _safe_branch(body.from_ref)
        try:
            repository = _repository(client, owner, repo)
            if name == repository.get("default_branch"):
                raise HTTPException(status_code=409, detail="Cannot recreate or overwrite the default branch")
            source_branch = _branch(client, owner, repo, source)
            sha = str((source_branch.get("commit") or {}).get("sha") or "")
            if not sha:
                raise HTTPException(status_code=409, detail="Source branch SHA is unavailable")
            result = client.post(f"/repos/{owner}/{repo}/git/refs", {"ref": f"refs/heads/{name}", "sha": sha}) or {}
            audit_fn("github.branch.created", "project", project_id, f"Created GitHub branch {name} from {source}@{sha[:12]} in {owner}/{repo}")
            return {"branch": name, "sha": ((result.get("object") or {}).get("sha") or sha), "from_ref": source}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.delete("/api/projects/{project_id}/github/branches/{branch:path}")
    def delete_branch(project_id: int, branch: str, body: BranchDelete) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_repo_write(client)
        branch = _safe_branch(branch)
        expected = f"DELETE BRANCH {branch}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        try:
            repository = _repository(client, owner, repo)
            if branch == repository.get("default_branch"):
                raise HTTPException(status_code=409, detail="The default branch cannot be deleted")
            info = _branch(client, owner, repo, branch)
            if info.get("protected"):
                raise HTTPException(status_code=409, detail="Protected branches cannot be deleted through Custom GitHub")
            client.delete(f"/repos/{owner}/{repo}/git/refs/heads/{quote(branch, safe='')}")
            audit_fn("github.branch.deleted", "project", project_id, f"Deleted GitHub branch {branch} in {owner}/{repo}")
            return {"ok": True, "branch": branch}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.put("/api/projects/{project_id}/github/code/file")
    def write_file(project_id: int, body: FileWrite) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_repo_write(client)
        path = _safe_path(body.path, allow_root=False)
        branch = _safe_branch(body.branch)
        try:
            _assert_editable_branch(client, owner, repo, branch)
            payload: dict[str, Any] = {
                "message": body.message,
                "content": base64.b64encode(body.content.encode("utf-8")).decode("ascii"),
                "branch": branch,
            }
            if body.expected_sha:
                payload["sha"] = body.expected_sha
            result = client.put(f"/repos/{owner}/{repo}/contents/{quote(path, safe='/')}", payload) or {}
            commit_sha = ((result.get("commit") or {}).get("sha"))
            audit_fn("github.file.written", "project", project_id, f"Wrote {path} on {branch} at {str(commit_sha or '')[:12]} in {owner}/{repo}")
            return {"ok": True, "path": path, "branch": branch, "commit_sha": commit_sha, "content_sha": ((result.get("content") or {}).get("sha"))}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.delete("/api/projects/{project_id}/github/code/file")
    def delete_file(project_id: int, body: FileDelete) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_repo_write(client)
        path = _safe_path(body.path, allow_root=False)
        branch = _safe_branch(body.branch)
        expected = f"DELETE FILE {path} FROM {branch}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        try:
            _assert_editable_branch(client, owner, repo, branch)
            result = client.delete(
                f"/repos/{owner}/{repo}/contents/{quote(path, safe='/')}",
                {"message": body.message, "sha": body.expected_sha, "branch": branch},
            ) or {}
            commit_sha = ((result.get("commit") or {}).get("sha"))
            audit_fn("github.file.deleted", "project", project_id, f"Deleted {path} from {branch} at {str(commit_sha or '')[:12]} in {owner}/{repo}")
            return {"ok": True, "path": path, "branch": branch, "commit_sha": commit_sha}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc


CODE_INDEX_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>GitHub Code</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1200px;margin:auto;padding:28px}.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:12px 0}.repo{padding:12px 0;border-top:1px solid #30363d}.btn{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 12px;text-decoration:none}.muted{color:#8b949e}</style></head><body><div class=wrap><div class=row><div><div class=muted>GITHUB</div><h1>Code & Branch Governance</h1></div><div><a class=btn href='/github'>Repositories</a> <a class=btn href='/github/pulls'>Pull Requests</a></div></div><div class=card><h2>Repositories</h2><div id=repos>Loading…</div></div></div><script>const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/api/github/projects').then(r=>r.json()).then(xs=>repos.innerHTML=xs.filter(x=>x.supported).map(x=>`<div class='repo row'><div><b>${e(x.name)}</b><div class=muted>${e(x.repository_full_name)}</div></div><a class=btn href='/projects/${x.id}/github/code'>Browse code</a></div>`).join('')||'<span class=muted>No repositories.</span>')</script></body></html>"""


CODE_PROJECT_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Code · __PROJECT_NAME__</title><style>:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1450px;margin:auto;padding:22px}.row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.layout{display:grid;grid-template-columns:320px 1fr;gap:16px}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:12px}.btn,input,select,textarea{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 10px}.btn{cursor:pointer;text-decoration:none}.muted{color:#8b949e}.green{color:#3fb950}.warn{color:#d29922}.red{color:#f85149}.entry{display:grid;grid-template-columns:26px 1fr 100px;gap:8px;padding:9px 4px;border-top:1px solid #30363d;cursor:pointer}.entry:hover{background:#21262d}.code{white-space:pre;overflow:auto;background:#010409;padding:14px;border-radius:8px;font:12px ui-monospace,monospace;max-height:70vh}.branch{padding:9px 0;border-top:1px solid #30363d}.pill{border:1px solid #30363d;border-radius:999px;padding:3px 8px}.history{padding:9px 0;border-top:1px solid #30363d}@media(max-width:900px){.layout{grid-template-columns:1fr}}</style></head><body><div class=wrap><div class=row><div><div class=muted>GITHUB / __PROJECT_NAME__</div><h1>Code</h1><div id=repo class=muted>Loading…</div></div><div><a class=btn href='/projects/__PROJECT_ID__/github/pulls'>Pull Requests</a> <a class=btn href='/projects/__PROJECT_ID__/github/actions'>Actions</a></div></div><div class=layout><aside><div class=card><div class=row><b>Branches</b><button class=btn onclick='newBranch()'>+</button></div><div id=branches>Loading…</div></div><div class=card><b>Governance</b><div id=gov class=muted>Select a branch.</div></div></aside><main><div class=card><div class=row><div><b id=breadcrumb>/</b><div id=refLabel class=muted></div></div><div><button class=btn onclick='up()'>↑ Up</button> <button class=btn onclick='refresh()'>↻</button></div></div><div id=browser>Loading…</div></div><div class=card id=fileCard style='display:none'><div class=row><h3 id=fileName></h3><div><button class=btn onclick='editCurrent()'>Edit</button></div></div><pre id=fileContent class=code></pre><h4>History</h4><div id=history></div></div></main></div></div><script>const ID=__PROJECT_ID__;let ref='',path='',file=null,caps=null;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const req=async(u,o)=>{const r=await fetch(u,o);const t=await r.text();let x;try{x=t?JSON.parse(t):{}}catch{x={detail:t}}if(!r.ok)throw new Error(typeof x.detail==='string'?x.detail:JSON.stringify(x.detail));return x};async function init(){caps=await req(`/api/projects/${ID}/github/code/capabilities`);repo.textContent=`${caps.repository_full_name} · ${caps.auth_mode}${caps.write_enabled?' · writes enabled':''}`;ref=caps.default_branch;await loadBranches();await refresh()}async function loadBranches(){const x=await req(`/api/projects/${ID}/github/branches`);branches.innerHTML=(x.branches||[]).map(b=>`<div class=branch><div class=row><span onclick='selectBranch(${JSON.stringify(b.name)})' style='cursor:pointer'><b>${e(b.name)}</b>${b.name===x.default_branch?' <span class=pill>default</span>':''}${b.protected?' <span class=green>protected</span>':''}</span><button class=btn onclick='govern(${JSON.stringify(b.name)})'>Policy</button></div></div>`).join('');}async function selectBranch(b){ref=b;path='';file=null;fileCard.style.display='none';await govern(b);await refresh()}async function govern(b){const x=await req(`/api/projects/${ID}/github/branches/${encodeURIComponent(b)}/governance`);gov.innerHTML=`<p><b>${e(b)}</b></p><p>${x.is_default?'Default branch<br>':''}${x.branch.protected?'<span class=green>Protected</span>':'<span class=warn>Unprotected</span>'}</p><p>Direct editor: ${x.direct_edit_allowed?'<span class=green>allowed on this working branch</span>':'<span class=warn>blocked</span>'}</p>${x.protection.available?`<p>Approvals: ${e(x.protection.required_approving_review_count??'—')}<br>Code owners: ${e(x.protection.require_code_owner_reviews??'—')}<br>Required checks: ${(x.protection.required_status_checks||[]).map(e).join(', ')||'—'}<br>Force pushes: ${e(x.protection.allow_force_pushes)}</p>`:''}<p>Rulesets: ${(x.rulesets||[]).map(r=>e(r.name)+' ('+e(r.enforcement)+')').join('<br>')||'—'}</p>`;}async function refresh(){const x=await req(`/api/projects/${ID}/github/code/contents?path=${encodeURIComponent(path)}&ref=${encodeURIComponent(ref)}`);breadcrumb.textContent='/'+path;refLabel.textContent=ref;if(x.kind==='directory'){file=null;fileCard.style.display='none';browser.innerHTML=(x.items||[]).map(i=>`<div class=entry onclick='openItem(${JSON.stringify(i.path)},${JSON.stringify(i.type)})'><span>${i.type==='dir'?'📁':'📄'}</span><span>${e(i.name)}</span><span class=muted>${i.type==='dir'?'':fmt(i.size)}</span></div>`).join('')||'<span class=muted>Empty directory.</span>'}else{showFile(x.file)}}async function openItem(p,t){path=p;if(t==='dir')await refresh();else{const x=await req(`/api/projects/${ID}/github/code/contents?path=${encodeURIComponent(p)}&ref=${encodeURIComponent(ref)}`);showFile(x.file);await loadHistory(p)}}function showFile(f){file=f;fileCard.style.display='block';fileName.textContent=f.path;fileContent.textContent=f.binary?'[Binary file — content preview disabled]':(f.content??'[Content unavailable]')+(f.truncated?'\n\n[Preview truncated]':'');}async function loadHistory(p){const x=await req(`/api/projects/${ID}/github/code/history?path=${encodeURIComponent(p)}&ref=${encodeURIComponent(ref)}`);history.innerHTML=(x.commits||[]).map(c=>`<div class=history><b>${e((c.sha||'').slice(0,10))}</b> ${e(c.message)}<div class=muted>${e(c.author)} · ${e(c.date)}</div></div>`).join('')||'<span class=muted>No history.</span>'}function up(){if(!path)return;const parts=path.split('/');if(file||!path.endsWith('/'))parts.pop();else parts.pop();path=parts.join('/');file=null;refresh()}function fmt(n){if(n==null)return'';return n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':(n/1048576).toFixed(1)+' MB'}async function newBranch(){if(!caps.write_enabled)return alert('Repository writes are disabled.');const name=prompt('New branch name');if(!name)return;const from_ref=prompt('Create from',ref||caps.default_branch)||caps.default_branch;try{await req(`/api/projects/${ID}/github/branches`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,from_ref})});await loadBranches();await selectBranch(name)}catch(err){alert(err.message)}}async function editCurrent(){if(!file||file.binary)return alert('Select a text file.');if(!caps.write_enabled)return alert('Repository writes are disabled.');if(ref===caps.default_branch)return alert('Direct default-branch edits are blocked. Create a working branch first.');const content=prompt('Replace file content',file.content??'');if(content===null)return;const message=prompt('Commit message',`Update ${file.path}`);if(!message)return;try{await req(`/api/projects/${ID}/github/code/file`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:file.path,branch:ref,message,content,expected_sha:file.sha})});await refresh();await loadHistory(file.path)}catch(err){alert(err.message)}}init().catch(err=>browser.innerHTML=`<span class=red>${e(err.message)}</span>`)</script></body></html>"""


__all__ = ["GitHubRepoAPI", "install_github_code_governance_routes"]
