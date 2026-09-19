from __future__ import annotations

import json
import os
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query, Request as FastAPIRequest
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from app.github_app_webhooks import github_auth_mode, resolve_github_token
from app.github_operations import GitHubAPIError, parse_github_repository
from app.security import ROLE_LEVEL


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


class GitHubPullAPI:
    def __init__(self, token: str | None = None, timeout: int = 30):
        self.token = token or resolve_github_token()
        self.timeout = timeout
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

    def request_json(self, path: str, *, method: str = "GET", payload: Any | None = None) -> Any:
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
        return self.request_json(path)

    def post(self, path: str, payload: Any | None = None) -> Any:
        return self.request_json(path, method="POST", payload=payload)

    def patch(self, path: str, payload: Any) -> Any:
        return self.request_json(path, method="PATCH", payload=payload)

    def put(self, path: str, payload: Any) -> Any:
        return self.request_json(path, method="PUT", payload=payload)

    def paginate(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        joiner = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            batch = self.get(f"{path}{joiner}per_page=100&page={page}") or []
            if not isinstance(batch, list):
                break
            result.extend(batch)
            if len(batch) < 100:
                break
        return result

    def read_text(self, path: str, *, accept: str, max_bytes: int = 4_000_000) -> str:
        request = Request("https://api.github.com" + path, method="GET", headers=self._headers(accept))
        try:
            with urlopen(request, timeout=self.timeout) as response:
                self._capture_rate(response.headers)
                raw = response.read(max_bytes + 1)
                truncated = len(raw) > max_bytes
                text = raw[:max_bytes].decode("utf-8", errors="replace")
                return text + ("\n\n[Custom GitHub truncated this diff after 4 MB.]" if truncated else "")
        except HTTPError as exc:
            raise GitHubAPIError(exc.code, str(exc.reason)) from exc
        except URLError as exc:
            raise GitHubAPIError(503, f"GitHub API unavailable: {exc.reason}") from exc

    def review_threads(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        if not self.token:
            return {"known": False, "unresolved": None, "total": None, "truncated": False}
        query = """
        query($owner:String!,$repo:String!,$number:Int!){
          repository(owner:$owner,name:$repo){
            pullRequest(number:$number){
              reviewThreads(first:100){nodes{isResolved} pageInfo{hasNextPage}}
            }
          }
        }
        """
        try:
            result = self.post("/graphql", {"query": query, "variables": {"owner": owner, "repo": repo, "number": number}}) or {}
            if result.get("errors"):
                return {"known": False, "unresolved": None, "total": None, "truncated": False}
            threads = (((result.get("data") or {}).get("repository") or {}).get("pullRequest") or {}).get("reviewThreads") or {}
            nodes = threads.get("nodes") or []
            return {
                "known": True,
                "unresolved": sum(1 for node in nodes if not bool(node.get("isResolved"))),
                "total": len(nodes),
                "truncated": bool((threads.get("pageInfo") or {}).get("hasNextPage")),
            }
        except GitHubAPIError:
            return {"known": False, "unresolved": None, "total": None, "truncated": False}


def _repo(project: Any) -> tuple[str, str]:
    try:
        return parse_github_repository(str(project["github_url"]))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _api_error(exc: GitHubAPIError) -> HTTPException:
    return HTTPException(status_code=502 if exc.status >= 500 else exc.status, detail=f"GitHub API: {exc}")


def _require_write(client: GitHubPullAPI) -> None:
    if not client.token:
        raise HTTPException(status_code=409, detail="Authenticated GitHub access is required for pull-request mutations")
    if not _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_PR_WRITE")):
        raise HTTPException(
            status_code=409,
            detail="GitHub pull-request mutations are disabled. Set CUSTOM_GITHUB_GITHUB_PR_WRITE=1 after configuring least-privilege GitHub App permissions.",
        )


def _require_admin(request: FastAPIRequest) -> None:
    user = getattr(request.state, "security_user", None)
    if user and ROLE_LEVEL.get(str(user.get("role") or ""), 0) < ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required for GitHub pull-request merge/close operations")


def _pull(item: dict[str, Any]) -> dict[str, Any]:
    head = item.get("head") or {}
    base = item.get("base") or {}
    return {
        "id": item.get("id"),
        "number": item.get("number"),
        "title": item.get("title"),
        "state": item.get("state"),
        "draft": bool(item.get("draft")),
        "locked": bool(item.get("locked")),
        "author": ((item.get("user") or {}).get("login")),
        "body": item.get("body"),
        "head": head.get("ref"),
        "head_sha": head.get("sha"),
        "base": base.get("ref"),
        "mergeable": item.get("mergeable"),
        "mergeable_state": item.get("mergeable_state"),
        "merged": bool(item.get("merged")),
        "merged_at": item.get("merged_at"),
        "comments": item.get("comments"),
        "review_comments": item.get("review_comments"),
        "commits": item.get("commits"),
        "additions": item.get("additions"),
        "deletions": item.get("deletions"),
        "changed_files": item.get("changed_files"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "html_url": item.get("html_url"),
    }


def _file(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": item.get("filename"),
        "status": item.get("status"),
        "additions": item.get("additions"),
        "deletions": item.get("deletions"),
        "changes": item.get("changes"),
        "patch": item.get("patch"),
        "blob_url": item.get("blob_url"),
        "raw_url": item.get("raw_url"),
        "previous_filename": item.get("previous_filename"),
    }


def _review(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "user": ((item.get("user") or {}).get("login")),
        "state": item.get("state"),
        "body": item.get("body"),
        "submitted_at": item.get("submitted_at"),
        "commit_id": item.get("commit_id"),
        "html_url": item.get("html_url"),
    }


def _latest_review_states(reviews: list[dict[str, Any]]) -> dict[str, str]:
    latest: dict[str, str] = {}
    for review in reviews:
        user = ((review.get("user") or {}).get("login"))
        state = str(review.get("state") or "").upper()
        if user and state and state != "COMMENTED":
            latest[user] = state
    return latest


def _merge_gate(client: GitHubPullAPI, owner: str, repo: str, pr: dict[str, Any]) -> dict[str, Any]:
    number = int(pr["number"])
    sha = str((pr.get("head") or {}).get("sha") or "")
    combined = client.get(f"/repos/{owner}/{repo}/commits/{sha}/status") or {} if sha else {}
    checks_payload = client.get(f"/repos/{owner}/{repo}/commits/{sha}/check-runs?per_page=100") or {} if sha else {}
    reviews = client.paginate(f"/repos/{owner}/{repo}/pulls/{number}/reviews")
    review_states = _latest_review_states(reviews)
    threads = client.review_threads(owner, repo, number)

    reasons: list[str] = []
    if pr.get("state") != "open":
        reasons.append("Pull request is not open")
    if bool(pr.get("draft")):
        reasons.append("Pull request is still a draft")
    if pr.get("mergeable") is False or str(pr.get("mergeable_state") or "") == "dirty":
        reasons.append("GitHub reports merge conflicts")
    if pr.get("mergeable") is None:
        reasons.append("GitHub mergeability is still being calculated")

    statuses = combined.get("statuses") or []
    combined_state = str(combined.get("state") or "").lower()
    if statuses and combined_state != "success":
        reasons.append(f"Combined commit status is {combined_state or 'unknown'}")

    checks = checks_payload.get("check_runs") or []
    allowed_check_conclusions = {"success", "neutral", "skipped"}
    incomplete_checks = [c for c in checks if c.get("status") != "completed"]
    failed_checks = [c for c in checks if c.get("status") == "completed" and str(c.get("conclusion") or "") not in allowed_check_conclusions]
    if incomplete_checks:
        reasons.append(f"{len(incomplete_checks)} check run(s) are still in progress")
    if failed_checks:
        reasons.append(f"{len(failed_checks)} check run(s) are not successful")

    requested_changes = [user for user, state in review_states.items() if state == "CHANGES_REQUESTED"]
    approvals = [user for user, state in review_states.items() if state == "APPROVED"]
    if requested_changes:
        reasons.append("Changes are still requested by: " + ", ".join(sorted(requested_changes)))
    if _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_REQUIRE_APPROVAL")) and not approvals:
        reasons.append("At least one approval is required by Custom GitHub policy")

    if threads.get("known"):
        if threads.get("truncated"):
            reasons.append("Review-thread list exceeds 100 threads; resolve/verify on GitHub before merging")
        elif int(threads.get("unresolved") or 0) > 0:
            reasons.append(f"{threads['unresolved']} review thread(s) are unresolved")

    return {
        "ready": not reasons,
        "reasons": reasons,
        "head_sha": sha,
        "combined_status": combined_state or ("none" if not statuses else "unknown"),
        "status_count": len(statuses),
        "check_count": len(checks),
        "checks_in_progress": len(incomplete_checks),
        "checks_failed": len(failed_checks),
        "approvals": approvals,
        "changes_requested_by": requested_changes,
        "review_threads": threads,
        "approval_required_by_custom_policy": _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_REQUIRE_APPROVAL")),
    }


class PullCreate(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    head: str = Field(min_length=1, max_length=255)
    base: str = Field(min_length=1, max_length=255)
    body: str = Field(default="", max_length=100_000)
    draft: bool = False


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=100_000)


class ReviewCreate(BaseModel):
    event: str = Field(pattern=r"^(APPROVE|REQUEST_CHANGES|COMMENT)$")
    body: str = Field(default="", max_length=100_000)


class ReviewerRequest(BaseModel):
    reviewers: list[str] = Field(default_factory=list, max_length=20)
    team_reviewers: list[str] = Field(default_factory=list, max_length=20)


class PullStateUpdate(BaseModel):
    state: str = Field(pattern=r"^(open|closed)$")
    confirmation: str = Field(default="", max_length=120)


class MergeRequest(BaseModel):
    confirmation: str = Field(min_length=1, max_length=120)
    method: str = Field(default="merge", pattern=r"^(merge|squash|rebase)$")
    commit_title: str | None = Field(default=None, max_length=256)
    commit_message: str | None = Field(default=None, max_length=10_000)


def install_github_pull_request_routes(
    app: FastAPI,
    *,
    project_lookup: Callable[[int], Any],
    audit_fn: Callable[[str, str, int | None, str], None],
    api_factory: Callable[[], GitHubPullAPI] | None = None,
) -> None:
    def context(project_id: int) -> tuple[Any, str, str, GitHubPullAPI]:
        project = project_lookup(project_id)
        owner, repo = _repo(project)
        client = api_factory() if api_factory else GitHubPullAPI()
        return project, owner, repo, client

    @app.get("/github/pulls", response_class=HTMLResponse, include_in_schema=False)
    def pull_request_index() -> str:
        return PULL_INDEX_HTML

    @app.get("/projects/{project_id}/github/pulls", response_class=HTMLResponse, include_in_schema=False)
    def pull_request_page(project_id: int) -> str:
        project = project_lookup(project_id)
        return PULL_CENTER_HTML.replace("__PROJECT_ID__", str(project_id)).replace("__PROJECT_NAME__", str(project["name"]))

    @app.get("/api/projects/{project_id}/github/pulls/capabilities")
    def pull_capabilities(project_id: int) -> dict[str, Any]:
        project, owner, repo, client = context(project_id)
        return {
            "project_id": project_id,
            "project_name": project["name"],
            "repository_full_name": f"{owner}/{repo}",
            "authenticated": bool(client.token),
            "auth_mode": github_auth_mode(),
            "write_enabled": bool(client.token and _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_PR_WRITE"))),
            "approval_required": _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_REQUIRE_APPROVAL")),
        }

    @app.get("/api/projects/{project_id}/github/pulls")
    def list_pulls(
        project_id: int,
        state: str = Query(default="open", pattern=r"^(open|closed)$"),
        sort: str = Query(default="updated", pattern=r"^(created|updated|popularity|long-running)$"),
        direction: str = Query(default="desc", pattern=r"^(asc|desc)$"),
        page: int = Query(default=1, ge=1, le=1000),
        per_page: int = Query(default=50, ge=1, le=100),
    ) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        params = urlencode({"state": state, "sort": sort, "direction": direction, "page": page, "per_page": per_page})
        try:
            rows = client.get(f"/repos/{owner}/{repo}/pulls?{params}") or []
            return {"pull_requests": [_pull(row) for row in rows], "page": page, "per_page": per_page, "rate_limit": client.rate}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/pulls/{number}/summary")
    def pull_summary(project_id: int, number: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        try:
            raw = client.get(f"/repos/{owner}/{repo}/pulls/{number}") or {}
            return {"pull_request": _pull(raw), "merge_gate": _merge_gate(client, owner, repo, raw), "rate_limit": client.rate}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/pulls/{number}/files")
    def pull_files(project_id: int, number: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        try:
            rows = client.paginate(f"/repos/{owner}/{repo}/pulls/{number}/files")
            return {"files": [_file(row) for row in rows], "total": len(rows), "rate_limit": client.rate}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/pulls/{number}/conversation")
    def pull_conversation(project_id: int, number: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        try:
            reviews = client.paginate(f"/repos/{owner}/{repo}/pulls/{number}/reviews")
            issue_comments = client.paginate(f"/repos/{owner}/{repo}/issues/{number}/comments")
            review_comments = client.paginate(f"/repos/{owner}/{repo}/pulls/{number}/comments")
            commits = client.paginate(f"/repos/{owner}/{repo}/pulls/{number}/commits")
            return {
                "reviews": [_review(row) for row in reviews],
                "issue_comments": [
                    {"id": row.get("id"), "user": ((row.get("user") or {}).get("login")), "body": row.get("body"), "created_at": row.get("created_at"), "updated_at": row.get("updated_at"), "html_url": row.get("html_url")}
                    for row in issue_comments
                ],
                "review_comments": [
                    {"id": row.get("id"), "user": ((row.get("user") or {}).get("login")), "body": row.get("body"), "path": row.get("path"), "line": row.get("line"), "side": row.get("side"), "created_at": row.get("created_at"), "html_url": row.get("html_url")}
                    for row in review_comments
                ],
                "commits": [
                    {"sha": row.get("sha"), "message": (((row.get("commit") or {}).get("message") or "").splitlines() or [""])[0], "author": ((row.get("author") or {}).get("login") or (((row.get("commit") or {}).get("author") or {}).get("name"))), "date": (((row.get("commit") or {}).get("author") or {}).get("date")), "html_url": row.get("html_url")}
                    for row in commits
                ],
                "review_threads": client.review_threads(owner, repo, number),
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/pulls/{number}/checks")
    def pull_checks(project_id: int, number: int) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        try:
            pr = client.get(f"/repos/{owner}/{repo}/pulls/{number}") or {}
            sha = str((pr.get("head") or {}).get("sha") or "")
            combined = client.get(f"/repos/{owner}/{repo}/commits/{sha}/status") or {}
            checks = client.get(f"/repos/{owner}/{repo}/commits/{sha}/check-runs?per_page=100") or {}
            return {
                "head_sha": sha,
                "combined_state": combined.get("state"),
                "statuses": combined.get("statuses") or [],
                "check_runs": checks.get("check_runs") or [],
                "rate_limit": client.rate,
            }
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.get("/api/projects/{project_id}/github/pulls/{number}/diff", response_class=PlainTextResponse)
    def pull_diff(project_id: int, number: int) -> str:
        _, owner, repo, client = context(project_id)
        try:
            return client.read_text(f"/repos/{owner}/{repo}/pulls/{number}", accept="application/vnd.github.v3.diff")
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls", status_code=201)
    def create_pull(project_id: int, body: PullCreate) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        try:
            result = client.post(f"/repos/{owner}/{repo}/pulls", body.model_dump()) or {}
            audit_fn("github.pull.created", "project", project_id, f"Created GitHub PR #{result.get('number')} {body.head} -> {body.base} in {owner}/{repo}")
            return {"pull_request": _pull(result)}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/comments", status_code=201)
    def add_comment(project_id: int, number: int, body: CommentCreate) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        try:
            result = client.post(f"/repos/{owner}/{repo}/issues/{number}/comments", {"body": body.body}) or {}
            audit_fn("github.pull.comment", "project", project_id, f"Commented on GitHub PR #{number} in {owner}/{repo}")
            return {"id": result.get("id"), "html_url": result.get("html_url")}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/reviews", status_code=201)
    def add_review(project_id: int, number: int, body: ReviewCreate) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        if body.event in {"REQUEST_CHANGES", "COMMENT"} and not body.body.strip():
            raise HTTPException(status_code=400, detail=f"{body.event} requires a review message")
        try:
            result = client.post(f"/repos/{owner}/{repo}/pulls/{number}/reviews", {"event": body.event, "body": body.body}) or {}
            audit_fn("github.pull.review", "project", project_id, f"Submitted {body.event} review on GitHub PR #{number} in {owner}/{repo}")
            return {"review": _review(result)}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/reviewers")
    def request_reviewers(project_id: int, number: int, body: ReviewerRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        if not body.reviewers and not body.team_reviewers:
            raise HTTPException(status_code=400, detail="At least one reviewer or team reviewer is required")
        try:
            client.post(f"/repos/{owner}/{repo}/pulls/{number}/requested_reviewers", {"reviewers": body.reviewers, "team_reviewers": body.team_reviewers})
            audit_fn("github.pull.reviewers", "project", project_id, f"Requested reviewers on GitHub PR #{number} in {owner}/{repo}")
            return {"ok": True, "reviewers": body.reviewers, "team_reviewers": body.team_reviewers}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.patch("/api/projects/{project_id}/github/pulls/{number}/state")
    def update_pull_state(project_id: int, number: int, body: PullStateUpdate, request: FastAPIRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        _require_admin(request)
        expected = f"CLOSE #{number}" if body.state == "closed" else f"REOPEN #{number}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        try:
            result = client.patch(f"/repos/{owner}/{repo}/pulls/{number}", {"state": body.state}) or {}
            audit_fn("github.pull.state", "project", project_id, f"Set GitHub PR #{number} state to {body.state} in {owner}/{repo}")
            return {"pull_request": _pull(result)}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc

    @app.post("/api/projects/{project_id}/github/pulls/{number}/merge")
    def merge_pull(project_id: int, number: int, body: MergeRequest, request: FastAPIRequest) -> dict[str, Any]:
        _, owner, repo, client = context(project_id)
        _require_write(client)
        _require_admin(request)
        expected = f"MERGE #{number}"
        if body.confirmation != expected:
            raise HTTPException(status_code=400, detail=f"Type {expected} exactly")
        try:
            pr = client.get(f"/repos/{owner}/{repo}/pulls/{number}") or {}
            gate = _merge_gate(client, owner, repo, pr)
            if not gate["ready"]:
                raise HTTPException(status_code=409, detail={"message": "Pull request is not ready to merge", "merge_gate": gate})
            payload: dict[str, Any] = {"sha": gate["head_sha"], "merge_method": body.method}
            if body.commit_title:
                payload["commit_title"] = body.commit_title
            if body.commit_message:
                payload["commit_message"] = body.commit_message
            result = client.put(f"/repos/{owner}/{repo}/pulls/{number}/merge", payload) or {}
            if not result.get("merged"):
                raise HTTPException(status_code=409, detail=str(result.get("message") or "GitHub did not merge the pull request"))
            audit_fn("github.pull.merged", "project", project_id, f"Merged GitHub PR #{number} with {body.method} at {gate['head_sha'][:12]} in {owner}/{repo}")
            return {"ok": True, "merged": True, "sha": result.get("sha"), "message": result.get("message"), "merge_gate": gate}
        except GitHubAPIError as exc:
            raise _api_error(exc) from exc


PULL_INDEX_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Pull Requests</title><style>body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1200px;margin:auto;padding:28px}.top,.repo{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin:12px 0}.repo{padding:12px 0;border-top:1px solid #30363d}.btn{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 12px;text-decoration:none}.muted{color:#8b949e}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB</div><h1>Pull Request Center</h1><div class=muted>Reviews, diffs, checks and guarded merges.</div></div><div><a class=btn href='/github'>Repositories</a> <a class=btn href='/github/actions'>Actions</a></div></div><div class=card><h2>Repositories</h2><div id=repos>Loading…</div></div></div><script>const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/api/github/projects').then(r=>r.json()).then(xs=>repos.innerHTML=xs.filter(x=>x.supported).map(x=>`<div class=repo><div><b>${e(x.name)}</b><div class=muted>${e(x.repository_full_name)}</div></div><a class=btn href='/projects/${x.id}/github/pulls'>Open PRs</a></div>`).join('')||'<span class=muted>No supported repositories.</span>').catch(x=>repos.textContent=x.message)</script></body></html>"""


PULL_CENTER_HTML = r"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Pull Requests · __PROJECT_NAME__</title><style>:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:14px system-ui}.wrap{max-width:1500px;margin:auto;padding:22px}.top,.row{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}.layout{display:grid;grid-template-columns:380px 1fr;gap:16px}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:12px}.btn,input,select,textarea{background:#21262d;color:#f0f6fc;border:1px solid #30363d;border-radius:7px;padding:8px 10px}.btn{cursor:pointer;text-decoration:none}.green{color:#3fb950}.red{color:#f85149}.warn{color:#d29922}.muted{color:#8b949e}.pr{border-top:1px solid #30363d;padding:12px 4px;cursor:pointer}.pr:hover{background:#21262d}.pill{border:1px solid #30363d;border-radius:999px;padding:4px 8px;font-size:12px}.file{border:1px solid #30363d;border-radius:8px;margin:10px 0;overflow:hidden}.filehead{padding:10px;background:#0d1117}.patch{white-space:pre-wrap;overflow:auto;background:#010409;padding:12px;font:12px ui-monospace,monospace;max-height:480px}.comment{border-top:1px solid #30363d;padding:12px 0}.checks{display:grid;gap:7px}.check{display:flex;justify-content:space-between;gap:10px;border-top:1px solid #30363d;padding:8px 0}@media(max-width:1000px){.layout{grid-template-columns:1fr}}</style></head><body><div class=wrap><div class=top><div><div class=muted>GITHUB / __PROJECT_NAME__</div><h1>Pull Requests</h1><div id=repo class=muted>Loading…</div></div><div><a class=btn href='/projects/__PROJECT_ID__/github'>Repository</a> <a class=btn href='/projects/__PROJECT_ID__/github/actions'>Actions</a> <button class=btn onclick='loadPulls()'>↻ Refresh</button></div></div><div class=layout><aside><div class=card><div class=row><b>Pull requests</b><select id=state onchange='loadPulls()'><option>open</option><option>closed</option></select></div><div id=pulls>Loading…</div></div><div class=card><b>Access</b><div id=caps class=muted>Loading…</div></div></aside><main id=detail><div class=card>Select a pull request.</div></main></div></div><script>const ID=__PROJECT_ID__;let selected=null,socket=null;const e=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const req=async(u,o)=>{const r=await fetch(u,o);const t=await r.text();let x;try{x=t?JSON.parse(t):{}}catch{x={detail:t}}if(!r.ok)throw new Error(typeof x.detail==='string'?x.detail:JSON.stringify(x.detail));return x};async function init(){const c=await req(`/api/projects/${ID}/github/pulls/capabilities`);repo.textContent=c.repository_full_name;caps.innerHTML=`${c.authenticated?'<span class=green>Authenticated · '+e(c.auth_mode)+'</span>':'<span class=warn>Anonymous reads</span>'}<br>${c.write_enabled?'<span class=green>PR mutations enabled</span>':'Mutations disabled'}${c.approval_required?'<br>Approval policy enabled':''}`;await loadPulls();connect()}async function loadPulls(){const x=await req(`/api/projects/${ID}/github/pulls?state=${state.value}`);pulls.innerHTML=(x.pull_requests||[]).map(p=>`<div class=pr onclick='openPr(${p.number})'><div><b>#${p.number} ${e(p.title)}</b></div><div class=muted>${e(p.head)} → ${e(p.base)} · ${e(p.author)}${p.draft?' · DRAFT':''}</div></div>`).join('')||'<span class=muted>No pull requests.</span>';if(selected)openPr(selected,false)}async function openPr(n,scroll=true){selected=n;detail.innerHTML='<div class=card>Loading PR…</div>';try{const [s,f,c,k]=await Promise.all([req(`/api/projects/${ID}/github/pulls/${n}/summary`),req(`/api/projects/${ID}/github/pulls/${n}/files`),req(`/api/projects/${ID}/github/pulls/${n}/conversation`),req(`/api/projects/${ID}/github/pulls/${n}/checks`)]);const p=s.pull_request,g=s.merge_gate;detail.innerHTML=`<div class=card><div class=row><div><h2 style='margin:0'>#${p.number} ${e(p.title)}</h2><div class=muted>${e(p.head)} → ${e(p.base)} · ${e(p.author)} · ${e(p.state)}${p.draft?' · draft':''}</div></div><a class=btn target=_blank href='${e(p.html_url)}'>GitHub ↗</a></div><p>${e(p.body||'')}</p><div class=row><span class='pill ${g.ready?'green':'warn'}'>${g.ready?'READY TO MERGE':'MERGE BLOCKED'}</span><span class=muted>${p.changed_files||0} files · +${p.additions||0} / -${p.deletions||0}</span></div>${g.reasons.length?`<ul class=warn>${g.reasons.map(x=>`<li>${e(x)}</li>`).join('')}</ul>`:''}<div class=row style='margin-top:12px'><div><button class=btn onclick='comment(${n})'>Comment</button> <button class=btn onclick='review(${n})'>Review</button></div><button class=btn onclick='mergePr(${n})' ${g.ready?'':'disabled'}>Merge…</button></div></div><div class=card><h3>Checks</h3>${checksHtml(k,g)}</div><div class=card><h3>Conversation & reviews</h3>${conversationHtml(c)}</div><div class=card><h3>Files changed (${f.total})</h3>${(f.files||[]).map(fileHtml).join('')||'<span class=muted>No files.</span>'}</div>`;if(scroll)detail.scrollIntoView({behavior:'smooth',block:'start'})}catch(err){detail.innerHTML=`<div class=card><span class=red>${e(err.message)}</span></div>`}}function checksHtml(k,g){const runs=k.check_runs||[],statuses=k.statuses||[];return `<div class=row><span>Combined status: <b>${e(k.combined_state||'none')}</b></span><span>${g.review_threads.known?`${g.review_threads.unresolved||0} unresolved review thread(s)`:'Review-thread state unknown'}</span></div><div class=checks>${runs.map(x=>`<div class=check><span>${e(x.name)}</span><span>${e(x.status)} / ${e(x.conclusion||'—')}</span></div>`).join('')}${statuses.map(x=>`<div class=check><span>${e(x.context)}</span><span>${e(x.state)}</span></div>`).join('')}</div>`}function conversationHtml(c){return `<div><b>Reviews</b>${(c.reviews||[]).map(x=>`<div class=comment><b>${e(x.user)}</b> · ${e(x.state)}<div>${e(x.body||'')}</div></div>`).join('')||'<div class=muted>No reviews.</div>'}</div><div><b>Comments</b>${(c.issue_comments||[]).map(x=>`<div class=comment><b>${e(x.user)}</b><div>${e(x.body||'')}</div></div>`).join('')||'<div class=muted>No comments.</div>'}</div>`}function fileHtml(f){return `<div class=file><div class='filehead row'><b>${e(f.filename)}</b><span class=muted>${e(f.status)} · +${f.additions||0} / -${f.deletions||0}</span></div><pre class=patch>${e(f.patch||'[Patch unavailable for this file]')}</pre></div>`}async function mutate(url,body){try{await req(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});await loadPulls()}catch(err){alert(err.message)}}function comment(n){const body=prompt('Comment');if(body)mutate(`/api/projects/${ID}/github/pulls/${n}/comments`,{body})}function review(n){const event=prompt('Review event: APPROVE, REQUEST_CHANGES, or COMMENT','APPROVE');if(!event)return;const body=event==='APPROVE'?(prompt('Optional review message','')||''):(prompt('Review message')||'');mutate(`/api/projects/${ID}/github/pulls/${n}/reviews`,{event:event.toUpperCase(),body})}async function mergePr(n){const confirmation=prompt(`Type MERGE #${n} exactly`);if(!confirmation)return;const method=prompt('Merge method: merge, squash, or rebase','merge')||'merge';await mutate(`/api/projects/${ID}/github/pulls/${n}/merge`,{confirmation,method})}function connect(){if(!('WebSocket'in window))return;const scheme=location.protocol==='https:'?'wss':'ws';socket=new WebSocket(`${scheme}://${location.host}/ws/github/events`);socket.onmessage=ev=>{let x;try{x=JSON.parse(ev.data)}catch{return}if(x.type!=='github'||Number(x.project_id||0)!==ID)return;if(['pull_request','pull_request_review','pull_request_review_comment','issue_comment','check_run','status','workflow_run'].includes(x.event)){loadPulls()}};socket.onclose=()=>setTimeout(connect,3000)}init().catch(err=>detail.innerHTML=`<div class=card><span class=red>${e(err.message)}</span></div>`)</script></body></html>"""


__all__ = ["GitHubPullAPI", "install_github_pull_request_routes"]
