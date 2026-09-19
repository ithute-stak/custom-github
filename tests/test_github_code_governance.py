from __future__ import annotations

import base64
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.github_code_governance import install_github_code_governance_routes


class FakeRepoAPI:
    token = "installation-token"
    calls: list[tuple[str, str, Any]] = []

    def __init__(self):
        self.rate = {"limit": "5000", "remaining": "4980", "reset": "0", "resource": "core"}

    def get(self, path: str):
        self.calls.append(("GET", path, None))
        if path == "/repos/o/r":
            return {"id": 1, "full_name": "o/r", "default_branch": "main", "private": False}
        if path == "/repos/o/r/branches/main":
            return {"name": "main", "protected": True, "commit": {"sha": "a" * 40}}
        if path == "/repos/o/r/branches/feature%2Fwork":
            return {"name": "feature/work", "protected": False, "commit": {"sha": "b" * 40}}
        if path == "/repos/o/r/branches/release":
            return {"name": "release", "protected": True, "commit": {"sha": "c" * 40}}
        if path == "/repos/o/r/branches/main/protection":
            return {
                "required_pull_request_reviews": {"required_approving_review_count": 2, "dismiss_stale_reviews": True, "require_code_owner_reviews": True},
                "required_status_checks": {"strict": True, "contexts": ["ci", "security"]},
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "restrictions": {"users": [], "teams": []},
            }
        if path == "/repos/o/r/rulesets?includes_parents=true":
            return [{"id": 10, "name": "Protect main", "target": "branch", "enforcement": "active", "source_type": "Repository"}]
        if path == "/repos/o/r/contents?ref=main":
            return [
                {"name": "app", "path": "app", "sha": "d" * 40, "size": 0, "type": "dir", "html_url": "x", "download_url": None},
                {"name": "README.md", "path": "README.md", "sha": "e" * 40, "size": 5, "type": "file", "html_url": "x", "download_url": "x"},
            ]
        if path == "/repos/o/r/contents/README.md?ref=main":
            return {"name": "README.md", "path": "README.md", "sha": "e" * 40, "size": 6, "type": "file", "encoding": "base64", "content": base64.b64encode(b"hello\n").decode(), "html_url": "x", "download_url": "x"}
        if path.startswith("/repos/o/r/commits?"):
            return [{"sha": "f" * 40, "html_url": "x", "author": {"login": "tester"}, "commit": {"message": "Update README", "author": {"name": "Tester", "date": "2026-09-19T00:00:00Z"}}}]
        if path == "/repos/o/r/compare/main...feature%2Fwork":
            return {
                "status": "ahead",
                "ahead_by": 2,
                "behind_by": 0,
                "total_commits": 2,
                "merge_base_commit": {"sha": "a" * 40},
                "commits": [{"sha": "b" * 40, "html_url": "x", "commit": {"message": "Work"}}],
                "files": [{"filename": "README.md", "status": "modified", "additions": 2, "deletions": 1, "changes": 3}],
            }
        raise AssertionError(f"Unexpected GET {path}")

    def paginate(self, path: str, *, max_pages: int = 10):
        self.calls.append(("PAGINATE", path, None))
        if path == "/repos/o/r/branches":
            return [
                {"name": "main", "protected": True, "commit": {"sha": "a" * 40}},
                {"name": "feature/work", "protected": False, "commit": {"sha": "b" * 40}},
                {"name": "release", "protected": True, "commit": {"sha": "c" * 40}},
            ]
        raise AssertionError(f"Unexpected paginate {path}")

    def post(self, path: str, payload=None):
        self.calls.append(("POST", path, payload))
        if path == "/repos/o/r/git/refs":
            return {"ref": payload["ref"], "object": {"sha": payload["sha"]}}
        raise AssertionError(f"Unexpected POST {path}")

    def put(self, path: str, payload=None):
        self.calls.append(("PUT", path, payload))
        if path == "/repos/o/r/contents/README.md":
            return {"content": {"sha": "9" * 40}, "commit": {"sha": "8" * 40}}
        raise AssertionError(f"Unexpected PUT {path}")

    def delete(self, path: str, payload=None):
        self.calls.append(("DELETE", path, payload))
        if path == "/repos/o/r/git/refs/heads/feature%2Fwork":
            return None
        if path == "/repos/o/r/contents/README.md":
            return {"commit": {"sha": "7" * 40}}
        raise AssertionError(f"Unexpected DELETE {path}")


def _app():
    def lookup(project_id: int):
        if project_id != 1:
            raise HTTPException(status_code=404, detail="Project not found")
        return {"id": 1, "name": "demo", "github_url": "https://github.com/o/r", "branch": "main"}

    audits: list[tuple] = []
    app = FastAPI()
    install_github_code_governance_routes(app, project_lookup=lookup, audit_fn=lambda *args: audits.append(args), api_factory=FakeRepoAPI)
    return app, audits


def test_code_browser_lists_directories_and_decodes_text_files(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE", "1")
    FakeRepoAPI.calls = []
    app, _ = _app()
    client = TestClient(app)

    root = client.get("/api/projects/1/github/code/contents?ref=main")
    assert root.status_code == 200, root.text
    assert root.json()["kind"] == "directory"
    assert root.json()["items"][0]["type"] == "dir"

    file = client.get("/api/projects/1/github/code/contents?path=README.md&ref=main")
    assert file.status_code == 200, file.text
    payload = file.json()["file"]
    assert payload["binary"] is False
    assert payload["content"] == "hello\n"
    assert payload["sha"] == "e" * 40

    history = client.get("/api/projects/1/github/code/history?path=README.md&ref=main")
    assert history.status_code == 200
    assert history.json()["commits"][0]["message"] == "Update README"


def test_branch_governance_exposes_protection_and_rulesets() -> None:
    FakeRepoAPI.calls = []
    app, _ = _app()
    client = TestClient(app)
    response = client.get("/api/projects/1/github/branches/main/governance")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["is_default"] is True
    assert payload["direct_edit_allowed"] is False
    assert payload["protection"]["required_approving_review_count"] == 2
    assert payload["protection"]["require_code_owner_reviews"] is True
    assert payload["protection"]["required_status_checks"] == ["ci", "security"]
    assert payload["rulesets"][0]["name"] == "Protect main"


def test_compare_refs_reports_ahead_behind_and_files() -> None:
    app, _ = _app()
    response = TestClient(app).get("/api/projects/1/github/compare?base=main&head=feature%2Fwork")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["ahead_by"] == 2
    assert payload["behind_by"] == 0
    assert payload["files"][0]["filename"] == "README.md"


def test_default_and_protected_branch_file_writes_are_blocked(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE", "1")
    for branch, expected in [("main", "default branch"), ("release", "protected branch")]:
        FakeRepoAPI.calls = []
        app, _ = _app()
        response = TestClient(app).put(
            "/api/projects/1/github/code/file",
            json={"path": "README.md", "branch": branch, "message": "Edit", "content": "new", "expected_sha": "e" * 40},
        )
        assert response.status_code == 409, (branch, response.text)
        assert expected in response.text.lower()
        assert not any(call[0] == "PUT" for call in FakeRepoAPI.calls)


def test_working_branch_file_write_uses_expected_sha(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE", "1")
    FakeRepoAPI.calls = []
    app, audits = _app()
    response = TestClient(app).put(
        "/api/projects/1/github/code/file",
        json={"path": "README.md", "branch": "feature/work", "message": "Edit README", "content": "new\n", "expected_sha": "e" * 40},
    )
    assert response.status_code == 200, response.text
    put = [call for call in FakeRepoAPI.calls if call[0] == "PUT"]
    assert len(put) == 1
    assert put[0][2]["branch"] == "feature/work"
    assert put[0][2]["sha"] == "e" * 40
    assert base64.b64decode(put[0][2]["content"]).decode() == "new\n"
    assert any(event[0] == "github.file.written" for event in audits)


def test_create_branch_from_known_ref(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE", "1")
    FakeRepoAPI.calls = []
    app, audits = _app()
    response = TestClient(app).post(
        "/api/projects/1/github/branches",
        json={"name": "feature/new", "from_ref": "main"},
    )
    assert response.status_code == 201, response.text
    post = [call for call in FakeRepoAPI.calls if call[0] == "POST"]
    assert post[0][2] == {"ref": "refs/heads/feature/new", "sha": "a" * 40}
    assert any(event[0] == "github.branch.created" for event in audits)


def test_branch_delete_blocks_default_protected_and_bad_confirmation(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE", "1")
    app, _ = _app()
    client = TestClient(app)

    default = client.request("DELETE", "/api/projects/1/github/branches/main", json={"confirmation": "DELETE BRANCH main"})
    assert default.status_code == 409

    protected = client.request("DELETE", "/api/projects/1/github/branches/release", json={"confirmation": "DELETE BRANCH release"})
    assert protected.status_code == 409

    wrong = client.request("DELETE", "/api/projects/1/github/branches/feature/work", json={"confirmation": "DELETE"})
    assert wrong.status_code == 400

    good = client.request("DELETE", "/api/projects/1/github/branches/feature/work", json={"confirmation": "DELETE BRANCH feature/work"})
    assert good.status_code == 200, good.text


def test_file_delete_requires_exact_confirmation_and_working_branch(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE", "1")
    FakeRepoAPI.calls = []
    app, _ = _app()
    client = TestClient(app)
    payload = {"path": "README.md", "branch": "feature/work", "message": "Delete README", "expected_sha": "e" * 40}

    bad = client.request("DELETE", "/api/projects/1/github/code/file", json={**payload, "confirmation": "DELETE"})
    assert bad.status_code == 400
    good = client.request("DELETE", "/api/projects/1/github/code/file", json={**payload, "confirmation": "DELETE FILE README.md FROM feature/work"})
    assert good.status_code == 200, good.text
    delete = [call for call in FakeRepoAPI.calls if call[0] == "DELETE" and "/contents/" in call[1]]
    assert delete[0][2]["sha"] == "e" * 40


def test_repo_mutations_are_off_by_default(monkeypatch) -> None:
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_REPO_WRITE", raising=False)
    app, _ = _app()
    response = TestClient(app).post("/api/projects/1/github/branches", json={"name": "feature/new", "from_ref": "main"})
    assert response.status_code == 409
    assert "disabled" in response.text.lower()


def test_path_traversal_is_rejected_before_github_call() -> None:
    FakeRepoAPI.calls = []
    app, _ = _app()
    response = TestClient(app).get("/api/projects/1/github/code/contents?path=../secrets&ref=main")
    assert response.status_code == 400
    assert not any("contents" in call[1] for call in FakeRepoAPI.calls)


def test_platform_code_governance_routes_are_unique_by_method_and_path() -> None:
    from app.platform import app

    keys: list[tuple[str, str]] = []
    for route in app.router.routes:
        for method in (getattr(route, "methods", None) or set()):
            keys.append((getattr(route, "path", ""), method))
    expected = {
        ("/github/code", "GET"),
        ("/projects/{project_id}/github/code", "GET"),
        ("/api/projects/{project_id}/github/code/capabilities", "GET"),
        ("/api/projects/{project_id}/github/code/contents", "GET"),
        ("/api/projects/{project_id}/github/code/history", "GET"),
        ("/api/projects/{project_id}/github/branches", "GET"),
        ("/api/projects/{project_id}/github/branches", "POST"),
        ("/api/projects/{project_id}/github/branches/{branch:path}/governance", "GET"),
        ("/api/projects/{project_id}/github/compare", "GET"),
        ("/api/projects/{project_id}/github/code/file", "PUT"),
        ("/api/projects/{project_id}/github/code/file", "DELETE"),
    }
    for key in expected:
        assert keys.count(key) == 1, (key, keys.count(key))
