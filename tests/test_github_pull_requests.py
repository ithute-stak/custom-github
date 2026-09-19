from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.github_pull_requests import install_github_pull_request_routes


class FakePullAPI:
    token = "installation-token"
    mode = "ready"
    calls: list[tuple[str, str, Any]] = []

    def __init__(self):
        self.rate = {"limit": "5000", "remaining": "4990", "reset": "0", "resource": "core"}

    def _pr(self) -> dict[str, Any]:
        mergeable = self.mode != "conflict"
        return {
            "id": 101,
            "number": 7,
            "title": "Improve control plane",
            "state": "open",
            "draft": False,
            "locked": False,
            "user": {"login": "tester"},
            "body": "Body",
            "head": {"ref": "feature/test", "sha": "a" * 40},
            "base": {"ref": "main"},
            "mergeable": mergeable,
            "mergeable_state": "dirty" if self.mode == "conflict" else "clean",
            "merged": False,
            "merged_at": None,
            "comments": 1,
            "review_comments": 0,
            "commits": 2,
            "additions": 10,
            "deletions": 2,
            "changed_files": 1,
            "created_at": "2026-09-19T00:00:00Z",
            "updated_at": "2026-09-19T00:01:00Z",
            "html_url": "https://github.com/o/r/pull/7",
        }

    def get(self, path: str):
        self.calls.append(("GET", path, None))
        if path.startswith("/repos/o/r/pulls?"):
            return [self._pr()]
        if path == "/repos/o/r/pulls/7":
            return self._pr()
        if path == f"/repos/o/r/commits/{'a' * 40}/status":
            if self.mode == "failed-status":
                return {"state": "failure", "statuses": [{"context": "ci", "state": "failure"}]}
            return {"state": "success", "statuses": [{"context": "ci", "state": "success"}]}
        if path == f"/repos/o/r/commits/{'a' * 40}/check-runs?per_page=100":
            if self.mode == "in-progress":
                return {"check_runs": [{"id": 1, "name": "tests", "status": "in_progress", "conclusion": None}]}
            if self.mode == "failed-check":
                return {"check_runs": [{"id": 1, "name": "tests", "status": "completed", "conclusion": "failure"}]}
            return {"check_runs": [{"id": 1, "name": "tests", "status": "completed", "conclusion": "success"}]}
        raise AssertionError(f"Unexpected GET {path}")

    def paginate(self, path: str, *, max_pages: int = 10):
        self.calls.append(("PAGINATE", path, None))
        if path == "/repos/o/r/pulls/7/reviews":
            state = "CHANGES_REQUESTED" if self.mode == "changes-requested" else "APPROVED"
            return [{"id": 12, "user": {"login": "reviewer"}, "state": state, "body": "review", "submitted_at": "2026-09-19T00:00:00Z", "commit_id": "a" * 40, "html_url": "https://github.com/o/r/pull/7#review"}]
        if path == "/repos/o/r/pulls/7/files":
            return [{"filename": "app.py", "status": "modified", "additions": 10, "deletions": 2, "changes": 12, "patch": "@@ -1 +1 @@", "blob_url": "x", "raw_url": "y"}]
        if path == "/repos/o/r/issues/7/comments":
            return [{"id": 20, "user": {"login": "tester"}, "body": "hello", "created_at": "2026-09-19T00:00:00Z", "updated_at": "2026-09-19T00:00:00Z", "html_url": "x"}]
        if path == "/repos/o/r/pulls/7/comments":
            return []
        if path == "/repos/o/r/pulls/7/commits":
            return [{"sha": "a" * 40, "html_url": "x", "author": {"login": "tester"}, "commit": {"message": "change", "author": {"name": "Tester", "date": "2026-09-19T00:00:00Z"}}}]
        raise AssertionError(f"Unexpected paginate {path}")

    def review_threads(self, owner: str, repo: str, number: int):
        assert (owner, repo, number) == ("o", "r", 7)
        unresolved = 1 if self.mode == "unresolved" else 0
        return {"known": True, "unresolved": unresolved, "total": unresolved, "truncated": False}

    def read_text(self, path: str, *, accept: str, max_bytes: int = 4_000_000):
        assert path == "/repos/o/r/pulls/7"
        assert "diff" in accept
        return "diff --git a/app.py b/app.py\n"

    def post(self, path: str, payload=None):
        self.calls.append(("POST", path, payload))
        if path == "/repos/o/r/pulls":
            result = self._pr()
            result["number"] = 8
            return result
        if path == "/repos/o/r/issues/7/comments":
            return {"id": 30, "html_url": "x"}
        if path == "/repos/o/r/pulls/7/reviews":
            return {"id": 31, "user": {"login": "me"}, "state": payload["event"], "body": payload["body"], "submitted_at": "2026-09-19T00:00:00Z", "commit_id": "a" * 40, "html_url": "x"}
        if path == "/repos/o/r/pulls/7/requested_reviewers":
            return {}
        raise AssertionError(f"Unexpected POST {path}")

    def patch(self, path: str, payload):
        self.calls.append(("PATCH", path, payload))
        assert path == "/repos/o/r/pulls/7"
        result = self._pr()
        result["state"] = payload["state"]
        return result

    def put(self, path: str, payload):
        self.calls.append(("PUT", path, payload))
        assert path == "/repos/o/r/pulls/7/merge"
        return {"sha": "b" * 40, "merged": True, "message": "Pull Request successfully merged"}


def _mini_app():
    def project_lookup(project_id: int):
        if project_id != 1:
            raise HTTPException(status_code=404, detail="Project not found")
        return {"id": 1, "name": "demo", "github_url": "https://github.com/o/r", "branch": "main"}

    audits: list[tuple] = []
    app = FastAPI()
    install_github_pull_request_routes(
        app,
        project_lookup=project_lookup,
        audit_fn=lambda *args: audits.append(args),
        api_factory=FakePullAPI,
    )
    return app, audits


def test_pull_request_reads_cover_files_conversation_checks_and_diff(monkeypatch) -> None:
    FakePullAPI.mode = "ready"
    FakePullAPI.calls = []
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    app, _ = _mini_app()
    client = TestClient(app)

    listing = client.get("/api/projects/1/github/pulls")
    assert listing.status_code == 200
    assert listing.json()["pull_requests"][0]["number"] == 7

    summary = client.get("/api/projects/1/github/pulls/7/summary")
    assert summary.status_code == 200, summary.text
    assert summary.json()["merge_gate"]["ready"] is True
    assert summary.json()["merge_gate"]["approvals"] == ["reviewer"]

    files = client.get("/api/projects/1/github/pulls/7/files").json()
    assert files["total"] == 1
    assert files["files"][0]["filename"] == "app.py"

    conversation = client.get("/api/projects/1/github/pulls/7/conversation").json()
    assert conversation["reviews"][0]["state"] == "APPROVED"
    assert conversation["issue_comments"][0]["body"] == "hello"

    checks = client.get("/api/projects/1/github/pulls/7/checks").json()
    assert checks["combined_state"] == "success"
    assert checks["check_runs"][0]["conclusion"] == "success"

    diff = client.get("/api/projects/1/github/pulls/7/diff")
    assert diff.status_code == 200
    assert "diff --git" in diff.text


def test_ready_pull_request_can_merge_with_exact_confirmation(monkeypatch) -> None:
    FakePullAPI.mode = "ready"
    FakePullAPI.calls = []
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    app, audits = _mini_app()
    response = TestClient(app).post(
        "/api/projects/1/github/pulls/7/merge",
        json={"confirmation": "MERGE #7", "method": "squash"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["merged"] is True
    put_calls = [call for call in FakePullAPI.calls if call[0] == "PUT"]
    assert len(put_calls) == 1
    assert put_calls[0][2]["sha"] == "a" * 40
    assert put_calls[0][2]["merge_method"] == "squash"
    assert any(event[0] == "github.pull.merged" for event in audits)


def test_merge_requires_exact_confirmation(monkeypatch) -> None:
    FakePullAPI.mode = "ready"
    FakePullAPI.calls = []
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    app, _ = _mini_app()
    response = TestClient(app).post(
        "/api/projects/1/github/pulls/7/merge",
        json={"confirmation": "MERGE", "method": "merge"},
    )
    assert response.status_code == 400
    assert not any(call[0] == "PUT" for call in FakePullAPI.calls)


def test_merge_is_blocked_by_conflict_checks_reviews_or_threads(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    for mode, expected in [
        ("conflict", "merge conflicts"),
        ("failed-status", "Combined commit status"),
        ("in-progress", "still in progress"),
        ("failed-check", "not successful"),
        ("changes-requested", "Changes are still requested"),
        ("unresolved", "review thread"),
    ]:
        FakePullAPI.mode = mode
        FakePullAPI.calls = []
        app, _ = _mini_app()
        response = TestClient(app).post(
            "/api/projects/1/github/pulls/7/merge",
            json={"confirmation": "MERGE #7", "method": "merge"},
        )
        assert response.status_code == 409, (mode, response.text)
        assert expected.lower() in response.text.lower(), (mode, response.text)
        assert not any(call[0] == "PUT" for call in FakePullAPI.calls)


def test_custom_approval_policy_blocks_without_approval(monkeypatch) -> None:
    class NoApprovalAPI(FakePullAPI):
        def paginate(self, path: str, *, max_pages: int = 10):
            if path == "/repos/o/r/pulls/7/reviews":
                return []
            return super().paginate(path, max_pages=max_pages)

    def lookup(project_id: int):
        return {"id": 1, "name": "demo", "github_url": "https://github.com/o/r", "branch": "main"}

    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_REQUIRE_APPROVAL", "1")
    app = FastAPI()
    install_github_pull_request_routes(app, project_lookup=lookup, audit_fn=lambda *args: None, api_factory=NoApprovalAPI)
    response = TestClient(app).post(
        "/api/projects/1/github/pulls/7/merge",
        json={"confirmation": "MERGE #7", "method": "merge"},
    )
    assert response.status_code == 409
    assert "approval" in response.text.lower()


def test_write_operations_are_off_by_default(monkeypatch) -> None:
    FakePullAPI.mode = "ready"
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", raising=False)
    app, _ = _mini_app()
    response = TestClient(app).post(
        "/api/projects/1/github/pulls/7/comments",
        json={"body": "hello"},
    )
    assert response.status_code == 409
    assert "disabled" in response.text.lower()


def test_close_requires_typed_confirmation(monkeypatch) -> None:
    FakePullAPI.mode = "ready"
    FakePullAPI.calls = []
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    app, _ = _mini_app()
    bad = TestClient(app).patch(
        "/api/projects/1/github/pulls/7/state",
        json={"state": "closed", "confirmation": "CLOSE"},
    )
    assert bad.status_code == 400
    good = TestClient(app).patch(
        "/api/projects/1/github/pulls/7/state",
        json={"state": "closed", "confirmation": "CLOSE #7"},
    )
    assert good.status_code == 200, good.text
    assert any(call[0] == "PATCH" for call in FakePullAPI.calls)


def test_platform_pull_request_routes_are_unique_by_method_and_path() -> None:
    from app.platform import app

    route_keys: list[tuple[str, str]] = []
    for route in app.router.routes:
        path = getattr(route, "path", "")
        for method in (getattr(route, "methods", None) or set()):
            route_keys.append((path, method))

    expected = {
        ("/github/pulls", "GET"),
        ("/projects/{project_id}/github/pulls", "GET"),
        ("/api/projects/{project_id}/github/pulls/capabilities", "GET"),
        ("/api/projects/{project_id}/github/pulls", "GET"),
        ("/api/projects/{project_id}/github/pulls", "POST"),
        ("/api/projects/{project_id}/github/pulls/{number}/summary", "GET"),
        ("/api/projects/{project_id}/github/pulls/{number}/files", "GET"),
        ("/api/projects/{project_id}/github/pulls/{number}/conversation", "GET"),
        ("/api/projects/{project_id}/github/pulls/{number}/checks", "GET"),
        ("/api/projects/{project_id}/github/pulls/{number}/diff", "GET"),
        ("/api/projects/{project_id}/github/pulls/{number}/merge", "POST"),
    }
    for key in expected:
        assert route_keys.count(key) == 1, (key, route_keys.count(key))
