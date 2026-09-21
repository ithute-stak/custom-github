from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.github_pr_center import GitHubPRAPI, install_github_pr_routes
from app.platform import app as platform_app


PR = {
    "number": 7,
    "id": 700,
    "node_id": "PR_node_7",
    "title": "Improve deployment safety",
    "body": "Safer production rollout.",
    "state": "open",
    "draft": False,
    "user": {"login": "tester"},
    "head": {"ref": "feature/safe", "sha": "a" * 40},
    "base": {"ref": "main", "sha": "b" * 40},
    "mergeable": True,
    "mergeable_state": "clean",
    "merged": False,
    "commits": 2,
    "additions": 12,
    "deletions": 3,
    "changed_files": 1,
    "comments": 1,
    "review_comments": 1,
    "created_at": "2026-09-21T00:00:00Z",
    "updated_at": "2026-09-21T01:00:00Z",
    "html_url": "https://github.com/o/r/pull/7",
    "labels": [{"name": "safe"}],
    "requested_reviewers": [{"login": "reviewer"}],
    "requested_teams": [],
}


class FakePRAPI:
    def __init__(self, owner: str, repo: str):
        self.owner = owner
        self.repo = repo
        self.token = "installation-token"
        self.rate = {"limit": "5000", "remaining": "4990", "reset": "0", "resource": "core"}
        self.last_put: tuple[str, dict[str, Any] | None] | None = None
        self.last_post: tuple[str, dict[str, Any] | None] | None = None
        self.pr = dict(PR)

    def get(self, path: str):
        if "/pulls?" in path:
            return [self.pr]
        if path.endswith("/pulls/7"):
            return self.pr
        if path.endswith("/pulls/7/commits?per_page=100"):
            return [{"sha": "a" * 40, "html_url": "https://github.com/o/r/commit/a", "commit": {"message": "Safe change", "author": {"name": "Tester", "date": "2026-09-21T00:00:00Z"}}, "author": {"login": "tester"}}]
        if path.endswith("/pulls/7/files?per_page=100"):
            return [{"filename": "app/main.py", "status": "modified", "additions": 12, "deletions": 3, "changes": 15, "patch": "@@ -1 +1 @@\n-old\n+new", "blob_url": "b", "raw_url": "r"}]
        if path.endswith("/pulls/7/reviews?per_page=100"):
            return [{"id": 1, "node_id": "R1", "user": {"login": "reviewer"}, "state": "APPROVED", "body": "Good", "submitted_at": "2026-09-21T01:00:00Z", "commit_id": "a" * 40, "html_url": "review"}]
        if path.endswith("/issues/7/comments?per_page=100"):
            return [{"id": 2, "user": {"login": "tester"}, "body": "Comment", "created_at": "2026-09-21T00:20:00Z", "updated_at": "2026-09-21T00:20:00Z", "html_url": "comment"}]
        if path.endswith("/pulls/7/comments?per_page=100"):
            return [{"id": 3, "user": {"login": "reviewer"}, "body": "Inline", "path": "app/main.py", "line": 1, "side": "RIGHT", "created_at": "2026-09-21T00:30:00Z", "html_url": "inline"}]
        if path.endswith("/pulls/7/requested_reviewers"):
            return {"users": [{"login": "reviewer"}], "teams": []}
        if path.endswith("/commits/" + "a" * 40 + "/status"):
            return {"state": "success", "total_count": 1, "statuses": [{"context": "ci/test", "state": "success", "description": "green", "target_url": "status", "updated_at": "2026-09-21T01:00:00Z"}]}
        if path.endswith("/commits/" + "a" * 40 + "/check-runs?per_page=100"):
            return {"check_runs": [{"id": 8, "name": "verify", "status": "completed", "conclusion": "success", "app": {"name": "GitHub Actions"}, "html_url": "check"}]}
        raise AssertionError(f"Unexpected GET {path}")

    def post(self, path: str, payload: Any | None = None):
        self.last_post = (path, payload)
        if path.endswith("/comments"):
            return {"id": 10, "html_url": "comment"}
        if path.endswith("/reviews"):
            return {"id": 11, "state": payload.get("event") if payload else None}
        return {}

    def patch(self, path: str, payload: Any):
        result = dict(self.pr)
        result["state"] = payload["state"]
        return result

    def put(self, path: str, payload: Any | None = None):
        self.last_put = (path, payload)
        return {"merged": True, "sha": "c" * 40, "message": "Pull Request successfully merged"}

    def diff(self, number: int) -> str:
        return "diff --git a/app/main.py b/app/main.py\n-old\n+new\n"

    def graphql(self, query: str, variables: dict[str, Any]):
        if "markPullRequestReadyForReview" in query:
            return {"markPullRequestReadyForReview": {"pullRequest": {"number": 7, "isDraft": False}}}
        return {"convertPullRequestToDraft": {"pullRequest": {"number": 7, "isDraft": True}}}


def _mini_app(monkeypatch):
    project = {"id": 1, "name": "demo", "github_url": "https://github.com/o/r", "branch": "main"}
    fake = FakePRAPI("o", "r")

    def lookup(project_id: int):
        if project_id != 1:
            raise HTTPException(status_code=404, detail="Project not found")
        return project

    app = FastAPI()
    audit: list[tuple] = []
    install_github_pr_routes(app, project_lookup=lookup, audit_fn=lambda *args: audit.append(args), api_factory=lambda owner, repo: fake)
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", raising=False)
    return app, fake, audit


def test_pr_list_detail_and_diff(monkeypatch) -> None:
    app, _, _ = _mini_app(monkeypatch)
    client = TestClient(app)
    listing = client.get("/api/projects/1/github/pulls?state=open")
    assert listing.status_code == 200, listing.text
    assert listing.json()["pull_requests"][0]["number"] == 7

    detail = client.get("/api/projects/1/github/pulls/7")
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert payload["pull_request"]["mergeable_state"] == "clean"
    assert payload["files"][0]["filename"] == "app/main.py"
    assert payload["reviews"][0]["state"] == "APPROVED"
    assert payload["combined_status"]["state"] == "success"
    assert payload["check_runs"][0]["conclusion"] == "success"

    diff = client.get("/api/projects/1/github/pulls/7/diff")
    assert diff.status_code == 200
    assert "diff --git" in diff.text


def test_pr_writes_are_off_by_default(monkeypatch) -> None:
    app, _, _ = _mini_app(monkeypatch)
    client = TestClient(app)
    response = client.post("/api/projects/1/github/pulls/7/comments", json={"body": "hello"})
    assert response.status_code == 409
    assert "disabled" in response.json()["detail"].lower()


def test_review_text_rules_and_audit(monkeypatch) -> None:
    app, fake, audit = _mini_app(monkeypatch)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    client = TestClient(app)
    bad = client.post("/api/projects/1/github/pulls/7/reviews", json={"event": "REQUEST_CHANGES", "body": ""})
    assert bad.status_code == 400
    good = client.post("/api/projects/1/github/pulls/7/reviews", json={"event": "APPROVE", "body": "Looks good"})
    assert good.status_code == 200, good.text
    assert fake.last_post is not None
    assert audit and audit[-1][0] == "github.pr.review"


def test_merge_requires_exact_confirmation_and_current_head(monkeypatch) -> None:
    app, fake, audit = _mini_app(monkeypatch)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    client = TestClient(app)
    wrong_phrase = client.post(
        "/api/projects/1/github/pulls/7/merge",
        json={"confirmation": "MERGE", "expected_head_sha": "a" * 40, "merge_method": "squash"},
    )
    assert wrong_phrase.status_code == 400

    stale = client.post(
        "/api/projects/1/github/pulls/7/merge",
        json={"confirmation": "MERGE #7", "expected_head_sha": "d" * 40, "merge_method": "squash"},
    )
    assert stale.status_code == 409
    assert "head changed" in stale.json()["detail"].lower()

    ok = client.post(
        "/api/projects/1/github/pulls/7/merge",
        json={"confirmation": "MERGE #7", "expected_head_sha": "a" * 40, "merge_method": "squash"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["merged"] is True
    assert fake.last_put is not None
    assert fake.last_put[1]["sha"] == "a" * 40
    assert fake.last_put[1]["merge_method"] == "squash"
    assert audit[-1][0] == "github.pr.merge"


def test_merge_rejects_draft_and_blocked(monkeypatch) -> None:
    app, fake, _ = _mini_app(monkeypatch)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_PR_WRITE", "1")
    client = TestClient(app)
    fake.pr["draft"] = True
    draft = client.post("/api/projects/1/github/pulls/7/merge", json={"confirmation": "MERGE #7", "expected_head_sha": "a" * 40, "merge_method": "merge"})
    assert draft.status_code == 409
    fake.pr["draft"] = False
    fake.pr["mergeable_state"] = "blocked"
    blocked = client.post("/api/projects/1/github/pulls/7/merge", json={"confirmation": "MERGE #7", "expected_head_sha": "a" * 40, "merge_method": "merge"})
    assert blocked.status_code == 409


def test_platform_pr_routes_are_unique() -> None:
    paths = [getattr(route, "path", "") for route in platform_app.router.routes]
    expected = {
        "/github/pulls",
        "/projects/{project_id}/github/pulls",
        "/projects/{project_id}/github/pulls/{number}",
        "/api/projects/{project_id}/github/pulls/capabilities",
        "/api/projects/{project_id}/github/pulls",
        "/api/projects/{project_id}/github/pulls/{number}",
        "/api/projects/{project_id}/github/pulls/{number}/diff",
        "/api/projects/{project_id}/github/pulls/{number}/merge",
    }
    for path in expected:
        assert paths.count(path) == 1, (path, paths.count(path))
