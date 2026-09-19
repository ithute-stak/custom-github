from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.github_actions_live import install_github_actions_routes
from app.platform import app as platform_app


class FakeActionsAPI:
    def __init__(self):
        self.token = "fake-token"
        self.rate = {"limit": "5000", "remaining": "4999", "reset": "0", "resource": "core"}
        self.posts: list[tuple[str, object]] = []

    def get(self, path: str):
        if "/actions/workflows?" in path:
            return {"total_count": 1, "workflows": [{"id": 5, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active", "html_url": "https://github.com/o/r/actions/workflows/ci.yml"}]}
        if "/actions/runs/9/jobs" in path:
            return {
                "total_count": 1,
                "jobs": [{
                    "id": 17,
                    "run_id": 9,
                    "name": "verify",
                    "status": "completed",
                    "conclusion": "failure",
                    "runner_name": "GitHub Actions 1",
                    "steps": [
                        {"number": 1, "name": "Checkout", "status": "completed", "conclusion": "success"},
                        {"number": 2, "name": "Tests", "status": "completed", "conclusion": "failure"},
                    ],
                }],
            }
        if "/actions/runs/9/artifacts" in path:
            return {"total_count": 1, "artifacts": [{"id": 22, "name": "report", "size_in_bytes": 1024, "expired": False, "expires_at": "2026-09-30T00:00:00Z"}]}
        if path.endswith("/actions/runs/9"):
            return {
                "id": 9,
                "name": "CI",
                "display_title": "Test live actions",
                "workflow_id": 5,
                "run_number": 3,
                "run_attempt": 1,
                "event": "push",
                "status": "completed",
                "conclusion": "failure",
                "head_branch": "main",
                "head_sha": "a" * 40,
                "actor": {"login": "tester"},
                "html_url": "https://github.com/o/r/actions/runs/9",
            }
        if "/actions/runs?" in path or "/workflows/5/runs?" in path:
            return {
                "total_count": 1,
                "workflow_runs": [{
                    "id": 9,
                    "name": "CI",
                    "display_title": "Test live actions",
                    "workflow_id": 5,
                    "run_number": 3,
                    "run_attempt": 1,
                    "event": "push",
                    "status": "in_progress",
                    "conclusion": None,
                    "head_branch": "main",
                    "head_sha": "a" * 40,
                    "actor": {"login": "tester"},
                    "html_url": "https://github.com/o/r/actions/runs/9",
                }],
            }
        raise AssertionError(f"Unexpected GitHub GET: {path}")

    def post(self, path: str, payload=None):
        self.posts.append((path, payload))
        return None

    def read_text(self, path: str, *, max_bytes: int = 2_000_000):
        assert path.endswith("/actions/jobs/17/logs")
        return "checkout ok\ntests failed\n"

    def stream(self, path: str):
        assert path.endswith("/actions/artifacts/22/zip")
        yield b"PK-test"


def _mini_app():
    fake = FakeActionsAPI()
    app = FastAPI()

    def lookup(project_id: int):
        if project_id != 1:
            raise HTTPException(status_code=404, detail="Project not found")
        return {
            "id": 1,
            "name": "demo",
            "github_url": "https://github.com/o/r",
            "branch": "main",
        }

    audits: list[tuple] = []
    install_github_actions_routes(
        app,
        project_lookup=lookup,
        audit_fn=lambda *args: audits.append(args),
        api_factory=lambda: fake,
    )
    return app, fake, audits


def test_live_actions_read_surface(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_TOKEN", "token-not-returned")
    app, _, _ = _mini_app()
    client = TestClient(app)

    page = client.get("/projects/1/github/actions")
    assert page.status_code == 200
    assert "Live" in page.text
    assert "Jobs & steps" in page.text

    capabilities = client.get("/api/projects/1/github/actions/capabilities").json()
    assert capabilities["repository_full_name"] == "o/r"
    assert capabilities["authenticated"] is True
    assert "token-not-returned" not in str(capabilities)

    workflows = client.get("/api/projects/1/github/actions/workflows").json()
    assert workflows["workflows"][0]["name"] == "CI"

    runs = client.get("/api/projects/1/github/actions/runs?workflow_id=5&branch=main&status=in_progress").json()
    assert runs["workflow_runs"][0]["status"] == "in_progress"
    assert runs["workflow_runs"][0]["sha"] == "a" * 40

    run = client.get("/api/projects/1/github/actions/runs/9").json()["run"]
    assert run["conclusion"] == "failure"

    jobs = client.get("/api/projects/1/github/actions/runs/9/jobs").json()["jobs"]
    assert jobs[0]["steps"][1]["conclusion"] == "failure"

    logs = client.get("/api/projects/1/github/actions/jobs/17/logs")
    assert logs.status_code == 200
    assert "tests failed" in logs.text

    artifacts = client.get("/api/projects/1/github/actions/runs/9/artifacts").json()["artifacts"]
    assert artifacts[0]["download_url"].endswith("/22/download")


def test_actions_mutations_are_explicitly_gated(monkeypatch) -> None:
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_TOKEN", "token")
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_ACTIONS_WRITE", raising=False)
    app, fake, audits = _mini_app()
    client = TestClient(app)

    blocked = client.post("/api/projects/1/github/actions/runs/9/rerun", json={})
    assert blocked.status_code == 409
    assert fake.posts == []

    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_ACTIONS_WRITE", "1")
    assert client.post("/api/projects/1/github/actions/runs/9/rerun", json={}).status_code == 200
    assert client.post("/api/projects/1/github/actions/runs/9/rerun-failed", json={}).status_code == 200
    assert client.post("/api/projects/1/github/actions/jobs/17/rerun", json={}).status_code == 200

    bad_cancel = client.post("/api/projects/1/github/actions/runs/9/cancel", json={"confirmation": "yes"})
    assert bad_cancel.status_code == 400
    assert client.post("/api/projects/1/github/actions/runs/9/cancel", json={"confirmation": "CANCEL"}).status_code == 200

    dispatch = client.post(
        "/api/projects/1/github/actions/workflows/5/dispatch",
        json={"ref": "main", "inputs": {"environment": "staging"}},
    )
    assert dispatch.status_code == 200
    assert any(path.endswith("/actions/workflows/5/dispatches") for path, _ in fake.posts)
    assert len(audits) == 5


def test_platform_live_actions_routes_are_unique() -> None:
    paths = [getattr(route, "path", "") for route in platform_app.router.routes]
    expected = {
        "/github/actions",
        "/projects/{project_id}/github/actions",
        "/api/projects/{project_id}/github/actions/capabilities",
        "/api/projects/{project_id}/github/actions/workflows",
        "/api/projects/{project_id}/github/actions/runs",
        "/api/projects/{project_id}/github/actions/runs/{run_id}",
        "/api/projects/{project_id}/github/actions/runs/{run_id}/jobs",
        "/api/projects/{project_id}/github/actions/jobs/{job_id}/logs",
        "/api/projects/{project_id}/github/actions/runs/{run_id}/artifacts",
        "/api/projects/{project_id}/github/actions/runs/{run_id}/rerun",
        "/api/projects/{project_id}/github/actions/runs/{run_id}/rerun-failed",
        "/api/projects/{project_id}/github/actions/jobs/{job_id}/rerun",
        "/api/projects/{project_id}/github/actions/runs/{run_id}/cancel",
        "/api/projects/{project_id}/github/actions/workflows/{workflow_id}/dispatch",
    }
    for path in expected:
        assert paths.count(path) == 1, path
