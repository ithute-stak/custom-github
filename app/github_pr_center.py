from __future__ import annotations

import json
import os
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from app.github_app_webhooks import github_integration_status, resolve_github_token
from app.github_operations import GitHubAPIError, parse_github_repository


class GitHubPRAPI:
    def __init__(self, owner: str, repo: str, timeout: int = 30):
        self.owner = owner
        self.repo = repo
        self.timeout = timeout
        self.token = resolve_github_token(owner, repo)
        self.rate: dict[str, str | None] = {"limit": None, "remaining": None, "reset": None, "resource": None}

    def _headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
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

    def request(self, path: str, *, method: str = "GET", payload: Any | None = None, accept: str = "application/vnd.github+json") -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            "https://api.github.com" + path,
            method=method,
            data=data,
            headers={**self._headers(accept), **({"Content-Type": "application/json"} if data is not None else {})},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                self._capture_rate(response.headers)
                raw = response.read()
                if not raw:
                    return None
                if "json" not in str(response.headers.get("Content-Type", "")).lower() and accept != "application/vnd.github+json":
                    return raw.decode("utf-8", errors="replace")
                return json.loads(raw.decode("utf-8"))
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

    def diff(self, number: int) -> str:
        value = self.request(f"/repos/{self.owner}/{self.repo}/pulls/{number}", accept="application/vnd.github.v3.diff")
        return value if isinstance(value, str) else ""

    def graphql(self, query: str, variables: dict[str, Any]) -> Any:
        if not self.token:
            raise GitHubAPIError(401, "Authenticated GitHub access is required")
        data = json.dumps({"query": query, "variables": variables}).encode("utf-8")
        request = Request(
            "https://api.github.com/graphql",
            method="POST",
            data=data,
            headers={**self._headers(), "Content-Type": "application/json"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise GitHubAPIError(exc.code, str(exc.reason)) from exc
        except URLError as exc:
            raise GitHubAPIError(503, f"GitHub API unavailable: {exc.reason}") from exc
        errors = payload.get("errors") or []
        if errors:
            raise GitHubAPIError(422, str(errors[0].get("message") or "GitHub GraphQL request failed"))
        return payload.get("data")


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _api_error(exc: GitHubAPIError) -> HTTPException:
    return HTTPException(status_code=502 if exc.status >= 500 else exc.status, detail=f"GitHub API: {exc}")


def _pr_write_enabled() -> bool:
    return _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_PR_WRITE"))


def _require_write(client: GitHubPRAPI) -> None:
    if not client.token:
        raise HTTPException(status_code=409, detail="Authenticated GitHub access is required for pull-request write operations")
    if not _pr_write_enabled():
        raise HTTPException(status_code=409, detail="Pull-request write operations are disabled. Set CUSTOM_GITHUB_GITHUB_PR_WRITE=1 after configuring least-privilege GitHub App permissions.")


def _repo(project: Any) -> tuple[str, str]:
    try:
        return parse_github_repository(str(project["github_url"]))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _normalize_pr(item: dict[str, Any]) -> dict[str, Any]:
    head = item.get("head") or {}
    base = item.get("base") or {}
    user = item.get("user") or {}
    return {
        "number": item.get("number"),
        "id": item.get("id"),
        "node_id": item.get("node_id"),
        "title": item.get("title"),
        "body": item.get("body"),
        "state": item.get("state"),
        "draft": bool(item.get("draft")),
        "author": user.get("login"),
        "head_ref": head.get("ref"),
        "head_sha": head.get("sha"),
        "base_ref": base.get("ref"),
        "base_sha": base.get("sha"),
        "mergeable": item.get("mergeable"),
        "mergeable_state": item.get("mergeable_state"),
        "merged": bool(item.get("merged")),
        "merged_at": item.get("merged_at"),
        "merge_commit_sha": item.get("merge_commit_sha"),
        "commits": item.get("commits"),
        "additions": item.get("additions"),
        "deletions": item.get("deletions"),
        "changed_files": item.get("changed_files"),
        "comments": item.get("comments"),
        "review_comments": item.get("review_comments"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "closed_at": item.get("closed_at"),
        "html_url": item.get("html_url"),
        "labels": [label.get("name") for label in (item.get("labels") or [])],
        "requested_reviewers": [(u or {}).get("login") for u in (item.get("requested_reviewers") or [])],
        "requested_teams": [(t or {}).get("slug") for t in (item.get("requested_teams") or [])],
    }


def _check_run(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "status": item.get("status"),
        "conclusion": item.get("conclusion"),
        "started_at": item.get("started_at"),
        "completed_at": item.get("completed_at"),
        "html_url": item.get("html_url"),
        "app": ((item.get("app") or {}).get("name")),
    }


def _review(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "node_id": item.get("node_id"),
        "user": ((item.get("user") or {}).get("login")),
        "state": item.get("state"),
        "body": item.get("body"),
        "submitted_at": item.get("submitted_at"),
        "commit_id": item.get("commit_id"),
        "html_url": item.get("html_url"),
    }


class ReviewRequest(BaseModel):
    event: str = Field(pattern=r"^(APPROVE|REQUEST_CHANGES|COMMENT)$")
    body: str = Field(default="", max_length=65536)


class CommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=65536)


class ReviewerRequest(BaseModel):
    reviewers: list[str] = Field(default_factory=list, max_length=20)
    team_reviewers: list[str] = Field(default_factory=list, max_length=20)


class MergeRequest(BaseModel):
    confirmation: str = Field(max_length=80)
    expected_head_sha: str = Field(min_length=40, max_length=40, pattern=r"^[0-9a-fA-F]{40}$")
    merge_method: str = Field(default="merge", pattern=r"^(merge|squash|rebase)$")
    commit_title: str | None = Field(default=None, max_length=256)
    commit_message: str | None = Field(default=None, max_length=4096)


class StateRequest(BaseModel):
    state: str = Field(pattern=r"^(open|closed)$")


def install_github_pr_routes(
    app: FastAPI,
    *,
    project_lookup: Callable[[int], Any],
    audit_fn: Callable[[str, str, int | None, str], None],
    api_factory: Callable[[str, str], GitHubPRAPI] | None = None,
) -> None:
    def context(project_id: int) -> tuple[Any, str, str, GitHubPRAPI]:
        project = project_lookup(project_id)
        owner, repo = _repo(project)
        client = api_factory(owner, repo) if api_factory else GitHubPRAPI(owner, repo)
        return project, owner, repo, client

    @app.get("/github/pulls", response_class=HTMLResponse, include_in_schema=False)
    def pr_index() -> str:
        return PR_INDEX_HTML

    @app.get("/projects/{project_id}/github/pulls", response_class=HTMLResponse, include_in_schema=False)
    def pr_project(project_id: int) -> str:
        project = project_lookup(project_id)
        return PR_PROJECT_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"]))

    @app.get("/projects/{project_id}/github/pulls/{number}", response_class=HTMLResponse, include_in_schema=False)
    def pr_detail_page(project_id: int, number: int) -> str:
        project = project_lookup(project_id)
        return PR_DETAIL_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"])).replace("__PR_NUMBER__", str(number))

    @app.get("/api/projects/{project_id}/github/pulls/capabilities")
    def pr_capabilities(project_id: int) -> dict[str, Any]:
        project, owner, repo, client = context(project_id)
        integration = github_integration_status()
        return {
            "project_id": project_id,
            "project_name": project["name"],
            "repository_full_name": f"{owner}/{repo}",
            "authenticated": bool(client.token),
            "auth_mode": integration.get("auth_mode"),
            "write_enabled": bool(client.token) and _pr_write_enabled(),
        }

    @app.get("/api/projects/{project_id}/github/pulls")
    def pr_list(
        project_id: int,
        state: str = Query(default="open", pattern=r"^(open|closed|all)$"),
        page: int = Query(default=1, ge=1, le=1000),
        per_page: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        try:
            params = urlencode({"state": state, "sort": "updated", "direction": "desc", "page": page, "per_page": per_page})
            rows = client.get(f"/repos/{owner}/{repo}/pulls?{params}") or []
            return {"pull_requests": [_normalize_pr(item) for item in rows], "page": page, "per_page": per_page, "rate_limit": client.rate}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/pulls/{number}")
    def pr_detail(project_id: int, number: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        try:
            pr = client.get(f"/repos/{owner}/{repo}/pulls/{number}") or {}
            head_sha = str(((pr.get("head") or {}).get("sha")) or "")
            commits = client.get(f"/repos/{owner}/{repo}/pulls/{number}/commits?per_page=100") or []
            files = client.get(f"/repos/{owner}/{repo}/pulls/{number}/files?per_page=100") or []
            reviews = client.get(f"/repos/{owner}/{repo}/pulls/{number}/reviews?per_page=100") or []
            comments = client.get(f"/repos/{owner}/{repo}/issues/{number}/comments?per_page=100") or []
            review_comments = client.get(f"/repos/{owner}/{repo}/pulls/{number}/comments?per_page=100") or []
            requested = client.get(f"/repos/{owner}/{repo}/pulls/{number}/requested_reviewers") or {}
            status = client.get(f"/repos/{owner}/{repo}/commits/{head_sha}/status") if head_sha else {}
            checks = client.get(f"/repos/{owner}/{repo}/commits/{head_sha}/check-runs?per_page=100") if head_sha else {}
            return {
                "pull_request": _normalize_pr(pr),
                "commits": [
                    {
                        "sha": item.get("sha"),
                        "message": (((item.get("commit") or {}).get("message") or "").splitlines() or [""])[0],
                        "author": ((item.get("author") or {}).get("login") or ((item.get("commit") or {}).get("author") or {}).get("name")),
                        "date": (((item.get("commit") or {}).get("author") or {}).get("date")),
                        "html_url": item.get("html_url"),
                    }
                    for item in commits
                ],
                "files": [
                    {
                        "filename": item.get("filename"),
                        "status": item.get("status"),
                        "additions": item.get("additions"),
                        "deletions": item.get("deletions"),
                        "changes": item.get("changes"),
                        "patch": item.get("patch"),
                        "blob_url": item.get("blob_url"),
                        "raw_url": item.get("raw_url"),
                    }
                    for item in files
                ],
                "reviews": [_review(item) for item in reviews],
                "comments": [
                    {"id": item.get("id"), "user": ((item.get("user") or {}).get("login")), "body": item.get("body"), "created_at": item.get("created_at"), "updated_at": item.get("updated_at"), "html_url": item.get("html_url")}
                    for item in comments
                ],
                "review_comments": [
                    {"id": item.get("id"), "user": ((item.get("user") or {}).get("login")), "body": item.get("body"), "path": item.get("path"), "line": item.get("line"), "side": item.get("side"), "in_reply_to_id": item.get("in_reply_to_id"), "created_at": item.get("created_at"), "html_url": item.get("html_url")}
                    for item in review_comments
                ],
                "requested_reviewers": [(u or {}).get("login") for u in (requested.get("users") or [])],
                "requested_teams": [(t or {}).get("slug") for t in (requested.get("teams") or [])],
                "combined_status": {
                    "state": (status or {}).get("state"),
                    "total_count": (status or {}).get("total_count"),
                    "statuses": [
                        {"context": s.get("context"), "state": s.get("state"), "description": s.get("description"), "target_url": s.get("target_url"), "updated_at": s.get("updated_at")}
                        for s in ((status or {}).get("statuses") or [])
                    ],
                },
                "check_runs": [_check_run(item) for item in ((checks or {}).get("check_runs") or [])],
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/pulls/{number}/diff", response_class=PlainTextResponse)
    def pr_diff(project_id: int, number: int) -> str:
        _, _, _, client = context(project_id)
        try:
            text = client.diff(number)
            if len(text.encode("utf-8")) > 4_000_000:
                return text[:4_000_000] + "\n\n[Custom GitHub truncated this diff after approximately 4 MB.]"
            return text
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/comments")
    def add_comment(project_id: int, number: int, body: CommentRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        try:
            result = client.post(f"/repos/{owner}/{repo}/issues/{number}/comments", {"body": body.body}) or {}
            audit_fn("github.pr.comment", "project", project_id, f"Commented on GitHub PR #{number} in {owner}/{repo}")
            return {"ok": True, "id": result.get("id"), "html_url": result.get("html_url")}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/reviews")
    def add_review(project_id: int, number: int, body: ReviewRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        if body.event in {"COMMENT", "REQUEST_CHANGES"} and not body.body.strip():
            raise HTTPException(status_code=400, detail=f"{body.event} requires review text")
        try:
            result = client.post(f"/repos/{owner}/{repo}/pulls/{number}/reviews", {"event": body.event, "body": body.body}) or {}
            audit_fn("github.pr.review", "project", project_id, f"Submitted {body.event} review on GitHub PR #{number} in {owner}/{repo}")
            return {"ok": True, "id": result.get("id"), "state": result.get("state")}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/reviewers")
    def request_reviewers(project_id: int, number: int, body: ReviewerRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        reviewers = [x.strip() for x in body.reviewers if x.strip()]
        teams = [x.strip() for x in body.team_reviewers if x.strip()]
        if not reviewers and not teams:
            raise HTTPException(status_code=400, detail="At least one reviewer or team is required")
        try:
            client.post(f"/repos/{owner}/{repo}/pulls/{number}/requested_reviewers", {"reviewers": reviewers, "team_reviewers": teams})
            audit_fn("github.pr.reviewers", "project", project_id, f"Requested reviewers for GitHub PR #{number} in {owner}/{repo}")
            return {"ok": True, "reviewers": reviewers, "team_reviewers": teams}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/ready")
    def mark_ready(project_id: int, number: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        try:
            pr = client.get(f"/repos/{owner}/{repo}/pulls/{number}") or {}
            node_id = pr.get("node_id")
            if not node_id:
                raise HTTPException(status_code=409, detail="GitHub PR node ID is unavailable")
            query = "mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{number isDraft}}}"
            data = client.graphql(query, {"id": node_id}) or {}
            audit_fn("github.pr.ready", "project", project_id, f"Marked GitHub PR #{number} ready for review in {owner}/{repo}")
            return {"ok": True, "pull_request": ((data.get("markPullRequestReadyForReview") or {}).get("pullRequest"))}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/draft")
    def convert_draft(project_id: int, number: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        try:
            pr = client.get(f"/repos/{owner}/{repo}/pulls/{number}") or {}
            node_id = pr.get("node_id")
            if not node_id:
                raise HTTPException(status_code=409, detail="GitHub PR node ID is unavailable")
            query = "mutation($id:ID!){convertPullRequestToDraft(input:{pullRequestId:$id}){pullRequest{number isDraft}}}"
            data = client.graphql(query, {"id": node_id}) or {}
            audit_fn("github.pr.draft", "project", project_id, f"Converted GitHub PR #{number} to draft in {owner}/{repo}")
            return {"ok": True, "pull_request": ((data.get("convertPullRequestToDraft") or {}).get("pullRequest"))}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.patch("/api/projects/{project_id}/github/pulls/{number}/state")
    def update_state(project_id: int, number: int, body: StateRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        try:
            result = client.patch(f"/repos/{owner}/{repo}/pulls/{number}", {"state": body.state}) or {}
            audit_fn("github.pr.state", "project", project_id, f"Set GitHub PR #{number} state to {body.state} in {owner}/{repo}")
            return {"ok": True, "pull_request": _normalize_pr(result)}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/merge")
    def merge_pr(project_id: int, number: int, body: MergeRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        if body.confirmation != f"MERGE #{number}":
            raise HTTPException(status_code=400, detail=f"Type MERGE #{number} exactly to merge this pull request")
        try:
            fresh = client.get(f"/repos/{owner}/{repo}/pulls/{number}") or {}
            current_sha = str(((fresh.get("head") or {}).get("sha")) or "")
            if current_sha.lower() != body.expected_head_sha.lower():
                raise HTTPException(status_code=409, detail="Pull-request head changed after this page was loaded. Refresh before merging.")
            if fresh.get("draft"):
                raise HTTPException(status_code=409, detail="Draft pull requests cannot be merged")
            if fresh.get("mergeable") is False or fresh.get("mergeable_state") in {"dirty", "blocked"}:
                raise HTTPException(status_code=409, detail=f"GitHub reports this pull request as {fresh.get('mergeable_state') or 'not mergeable'}")
            payload: dict[str, Any] = {"sha": current_sha, "merge_method": body.merge_method}
            if body.commit_title:
                payload["commit_title"] = body.commit_title
            if body.commit_message:
                payload["commit_message"] = body.commit_message
            result = client.put(f"/repos/{owner}/{repo}/pulls/{number}/merge", payload) or {}
            if not result.get("merged"):
                raise HTTPException(status_code=409, detail=str(result.get("message") or "GitHub did not merge this pull request"))
            audit_fn("github.pr.merge", "project", project_id, f"Merged GitHub PR #{number} in {owner}/{repo} using {body.merge_method}")
            return {"ok": True, "merged": True, "sha": result.get("sha"), "message": result.get("message")}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc


PR_INDEX_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Pull Requests</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1200px;margin:auto;padding:28px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:12px 0}.btn{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 12px;text-decoration:none}.muted{color:#8b949e}.repo{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 0;border-top:1px solid #30363d}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB</div><h1>Pull Requests</h1><div class=muted>Review, checks, diffs, discussion and guarded merge operations.</div></div><div><a class=btn href='/github'>Repositories</a> <a class=btn href='/github/actions'>Actions</a></div></div><div class=card><h2>Repositories</h2><div id=repos>Loading…</div></div></div><script>const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/api/github/projects').then(r=>r.json()).then(xs=>repos.innerHTML=xs.filter(x=>x.supported).map(x=>`<div class=repo><div><b>${e(x.name)}</b><div class=muted>${e(x.repository_full_name)}</div></div><a class=btn href='/projects/${x.id}/github/pulls'>Open PRs</a></div>`).join('')||'<span class=muted>No supported repositories.</span>')</script></body></html>"""


PR_PROJECT_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>PRs · __PROJECT_NAME__</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1250px;margin:auto;padding:24px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin:12px 0}.btn,select{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 11px;text-decoration:none}.muted{color:#8b949e}.good{color:#3fb950}.warn{color:#d29922}.pr{display:grid;grid-template-columns:76px 1fr 150px;gap:12px;border-top:1px solid #30363d;padding:13px 0;align-items:center}@media(max-width:700px){.pr{grid-template-columns:1fr}}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB / __PROJECT_NAME__</div><h1>Pull Requests</h1><div id=repo class=muted>Loading…</div></div><div><a class=btn href='/projects/__PROJECT_ID__/github'>Repository</a> <a class=btn href='/projects/__PROJECT_ID__/github/actions'>Actions</a></div></div><div class=card><div class=row><h2>Pull requests</h2><select id=state onchange='load()'><option value=open>Open</option><option value=closed>Closed</option><option value=all>All</option></select></div><div id=list>Loading…</div></div></div><script>const ID=__PROJECT_ID__;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function load(){const [c,r]=await Promise.all([fetch(`/api/projects/${ID}/github/pulls/capabilities`).then(x=>x.json()),fetch(`/api/projects/${ID}/github/pulls?state=${state.value}`).then(x=>x.json())]);repo.textContent=`${c.repository_full_name} · ${c.auth_mode||'anonymous'}${c.write_enabled?' · write enabled':''}`;list.innerHTML=(r.pull_requests||[]).map(p=>`<div class=pr><div><b>#${e(p.number)}</b><div class=muted>${p.draft?'DRAFT':e(p.state)}</div></div><div><a href='/projects/${ID}/github/pulls/${p.number}' style='color:#58a6ff;font-weight:700;text-decoration:none'>${e(p.title)}</a><div class=muted>${e(p.head_ref)} → ${e(p.base_ref)} · ${e(p.author)} · updated ${e(p.updated_at||'')}</div></div><div>${p.labels.map(x=>`<span class=muted>${e(x)}</span>`).join(' ')}</div></div>`).join('')||'<span class=muted>No pull requests.</span>'}load()</script></body></html>"""


PR_DETAIL_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>PR #__PR_NUMBER__ · __PROJECT_NAME__</title><style>:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1460px;margin:auto;padding:22px}.top,.row{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}.grid{display:grid;grid-template-columns:2fr 1fr;gap:14px}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:12px}.btn,input,select,textarea{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 10px}.btn{text-decoration:none;cursor:pointer}.green{background:#238636;border-color:#2ea043}.red{background:#da3633;border-color:#f85149}.muted{color:#8b949e}.good{color:#3fb950}.bad{color:#f85149}.warn{color:#d29922}.pill{border:1px solid #30363d;border-radius:99px;padding:4px 8px;font-size:12px}.file{border-top:1px solid #30363d;padding:12px 0}.patch,.diff{white-space:pre;overflow:auto;background:#010409;border:1px solid #30363d;border-radius:8px;padding:12px;font:12px ui-monospace,monospace;max-height:520px}.comment{border-top:1px solid #30363d;padding:10px 0}.check{display:grid;grid-template-columns:1fr 120px;gap:8px;padding:8px 0;border-top:1px solid #30363d}.tabs{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}.tab{cursor:pointer}.hidden{display:none}textarea{width:100%;min-height:90px;box-sizing:border-box}@media(max-width:900px){.grid{grid-template-columns:1fr}}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB / __PROJECT_NAME__</div><h1 id=title>Pull request #__PR_NUMBER__</h1><div id=meta class=muted>Loading…</div></div><div><a class=btn href='/projects/__PROJECT_ID__/github/pulls'>All PRs</a> <button class=btn onclick='load()'>↻ Refresh</button></div></div><div class=grid><main><div class=card id=summary>Loading…</div><div class=card><div class=tabs><button class='btn tab' onclick="show('files')">Files</button><button class='btn tab' onclick="show('diff')">Full diff</button><button class='btn tab' onclick="show('conversation')">Conversation</button><button class='btn tab' onclick="show('commits')">Commits</button></div><div id=files></div><div id=diff class=hidden></div><div id=conversation class=hidden></div><div id=commits class=hidden></div></div></main><aside><div class=card><h3>Checks</h3><div id=checks>Loading…</div></div><div class=card><h3>Reviews</h3><div id=reviews>Loading…</div></div><div class=card><h3>Reviewers</h3><div id=reviewers>Loading…</div><div id=requestBox style='margin-top:10px'></div></div><div class=card><h3>Actions</h3><div id=actions>Loading…</div></div></aside></div></div><script>const ID=__PROJECT_ID__,N=__PR_NUMBER__;let DATA=null,CAPS=null;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const req=async(u,o)=>{const r=await fetch(u,o);const t=await r.text();let x;try{x=t?JSON.parse(t):{}}catch{x={detail:t}}if(!r.ok)throw new Error(x.detail||`HTTP ${r.status}`);return x};function show(id){['files','diff','conversation','commits'].forEach(x=>document.getElementById(x).classList.toggle('hidden',x!==id));if(id==='diff'&&!diff.dataset.loaded)loadDiff()}function checkClass(s,c){if(s==='completed'&&c==='success')return'good';if(s==='completed'||c==='failure'||c==='cancelled')return'bad';return'warn'}async function load(){try{[CAPS,DATA]=await Promise.all([req(`/api/projects/${ID}/github/pulls/capabilities`),req(`/api/projects/${ID}/github/pulls/${N}`)]);render()}catch(x){summary.innerHTML=`<span class=bad>${e(x.message)}</span>`}}function render(){const p=DATA.pull_request;title.textContent=`#${p.number} ${p.title}`;meta.textContent=`${CAPS.repository_full_name} · ${p.head_ref} → ${p.base_ref} · ${p.author}`;summary.innerHTML=`<div class=row><div><span class='pill ${p.merged?'good':p.state==='open'?'good':'muted'}'>${p.merged?'MERGED':p.draft?'DRAFT':String(p.state).toUpperCase()}</span> <span class='pill'>${e(p.mergeable_state||'unknown')}</span></div><a class=btn href='${e(p.html_url)}' target=_blank>Open on GitHub ↗</a></div><p>${e(p.body||'No description.')}</p><div class=muted>${e(p.commits)} commits · +${e(p.additions)} −${e(p.deletions)} · ${e(p.changed_files)} files</div>`;files.innerHTML=(DATA.files||[]).map(f=>`<div class=file><div class=row><b>${e(f.filename)}</b><span class=muted>${e(f.status)} · +${e(f.additions)} −${e(f.deletions)}</span></div>${f.patch?`<pre class=patch>${e(f.patch)}</pre>`:'<div class=muted>Patch unavailable (binary or too large).</div>'}</div>`).join('');conversation.innerHTML=`<h3>Conversation</h3>${(DATA.comments||[]).map(c=>`<div class=comment><b>${e(c.user)}</b> <span class=muted>${e(c.created_at)}</span><div>${e(c.body||'')}</div></div>`).join('')||'<span class=muted>No comments.</span>'}<h3>Inline review comments</h3>${(DATA.review_comments||[]).map(c=>`<div class=comment><b>${e(c.user)}</b> <span class=muted>${e(c.path)}${c.line?' : '+c.line:''}</span><div>${e(c.body||'')}</div></div>`).join('')||'<span class=muted>No inline comments.</span>'}${CAPS.write_enabled?`<h3>Add comment</h3><textarea id=commentText placeholder='Comment on this pull request'></textarea><button class='btn green' onclick='comment()'>Comment</button>`:''}`;commits.innerHTML=(DATA.commits||[]).map(c=>`<div class=comment><a href='${e(c.html_url)}' target=_blank style='color:#58a6ff'>${e((c.sha||'').slice(0,12))}</a> <b>${e(c.message)}</b><div class=muted>${e(c.author)} · ${e(c.date)}</div></div>`).join('');const cr=DATA.check_runs||[],st=(DATA.combined_status||{}).statuses||[];checks.innerHTML=`<div class='pill ${DATA.combined_status.state==='success'?'good':DATA.combined_status.state==='failure'?'bad':'warn'}'>STATUS ${e(DATA.combined_status.state||'none')}</div>`+cr.map(c=>`<div class=check><div><b>${e(c.name)}</b><div class=muted>${e(c.app||'')}</div></div><div class='${checkClass(c.status,c.conclusion)}'>${e(c.status)}${c.conclusion?' / '+e(c.conclusion):''}</div></div>`).join('')+st.map(s=>`<div class=check><div><b>${e(s.context)}</b><div class=muted>${e(s.description||'')}</div></div><div class='${s.state==='success'?'good':s.state==='failure'||s.state==='error'?'bad':'warn'}'>${e(s.state)}</div></div>`).join('');reviews.innerHTML=(DATA.reviews||[]).map(r=>`<div class=comment><b>${e(r.user)}</b> <span class='pill ${r.state==='APPROVED'?'good':r.state==='CHANGES_REQUESTED'?'bad':'muted'}'>${e(r.state)}</span>${r.body?`<div>${e(r.body)}</div>`:''}</div>`).join('')||'<span class=muted>No reviews.</span>';reviewers.innerHTML=`<div>${(DATA.requested_reviewers||[]).map(x=>`<span class=pill>${e(x)}</span>`).join(' ')||'<span class=muted>No requested users.</span>'}</div><div style='margin-top:6px'>${(DATA.requested_teams||[]).map(x=>`<span class=pill>${e(x)}</span>`).join(' ')}</div>`;requestBox.innerHTML=CAPS.write_enabled?`<input id=reviewerNames placeholder='user1,user2' style='width:100%;box-sizing:border-box'><button class=btn onclick='requestReviewers()' style='margin-top:6px'>Request reviewers</button>`:'';actions.innerHTML=CAPS.write_enabled?actionHtml(p):`<span class=muted>Write controls disabled. Auth: ${e(CAPS.auth_mode||'anonymous')}.</span>`}function actionHtml(p){if(p.merged)return'<span class=good>Merged</span>';let h=`<textarea id=reviewBody placeholder='Review comment'></textarea><div><button class='btn green' onclick="review('APPROVE')">Approve</button> <button class=btn onclick="review('COMMENT')">Comment review</button> <button class='btn red' onclick="review('REQUEST_CHANGES')">Request changes</button></div><hr style='border-color:#30363d'>`;h+=p.draft?`<button class=btn onclick='ready()'>Ready for review</button>`:`<button class=btn onclick='draft()'>Convert to draft</button>`;if(p.state==='open')h+=` <button class=btn onclick="stateChange('closed')">Close</button>`;else h+=` <button class=btn onclick="stateChange('open')">Reopen</button>`;if(p.state==='open'&&!p.draft)h+=`<hr style='border-color:#30363d'><select id=mergeMethod><option value=merge>Merge commit</option><option value=squash>Squash</option><option value=rebase>Rebase</option></select><button class='btn green' onclick='merge()'>Merge pull request</button>`;return h}async function loadDiff(){diff.innerHTML='<span class=muted>Loading diff…</span>';try{const r=await fetch(`/api/projects/${ID}/github/pulls/${N}/diff`);const t=await r.text();if(!r.ok)throw new Error(t);diff.innerHTML=`<pre class=diff>${e(t)}</pre>`;diff.dataset.loaded='1'}catch(x){diff.innerHTML=`<span class=bad>${e(x.message)}</span>`}}async function post(url,body={}){try{await req(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});await load()}catch(x){alert(x.message)}}function comment(){post(`/api/projects/${ID}/github/pulls/${N}/comments`,{body:commentText.value})}function review(event){post(`/api/projects/${ID}/github/pulls/${N}/reviews`,{event,body:reviewBody.value})}function requestReviewers(){post(`/api/projects/${ID}/github/pulls/${N}/reviewers`,{reviewers:reviewerNames.value.split(',').map(x=>x.trim()).filter(Boolean),team_reviewers:[]})}function ready(){post(`/api/projects/${ID}/github/pulls/${N}/ready`)}function draft(){post(`/api/projects/${ID}/github/pulls/${N}/draft`)}async function stateChange(state){try{await req(`/api/projects/${ID}/github/pulls/${N}/state`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({state})});await load()}catch(x){alert(x.message)}}async function merge(){const p=DATA.pull_request,c=prompt(`Type MERGE #${N} exactly`);if(!c)return;await post(`/api/projects/${ID}/github/pulls/${N}/merge`,{confirmation:c,expected_head_sha:p.head_sha,merge_method:mergeMethod.value})}load()</script></body></html>"""


__all__ = ["GitHubPRAPI", "install_github_pr_routes"]
