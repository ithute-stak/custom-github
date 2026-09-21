from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app.github_admin_center import install_github_admin_routes
from app.github_operations import GitHubAPIError
from app.platform import app as platform_app


class FakeAdminAPI:
    def __init__(self, owner: str, repo: str):
        self.owner = owner
        self.repo = repo
        self.token = "installation-token"
        self.rate = {"limit": "5000", "remaining": "4980", "reset": "0", "resource": "core"}
        self.calls: list[tuple[str, str, Any | None]] = []
        self.fail_paths: set[str] = set()

    def get(self, path: str):
        self.calls.append(("GET", path, None))
        if path in self.fail_paths:
            raise GitHubAPIError(403, "Resource not accessible by integration")
        if path.endswith("/actions/variables?per_page=100"):
            return {"variables": [{"name": "DEPLOY_REGION", "value": "ls-maseru", "updated_at": "2026-09-20T00:00:00Z"}]}
        if path.endswith("/actions/secrets?per_page=100"):
            return {"secrets": [{"name": "DEPLOY_TOKEN", "updated_at": "2026-09-20T00:00:00Z", "value": "MUST_NOT_LEAK"}]}
        if path.endswith("/environments?per_page=100"):
            return {"environments": [{"id": 8, "name": "production", "updated_at": "2026-09-20T00:00:00Z", "protection_rules": [{"type": "wait_timer"}], "deployment_branch_policy": {"protected_branches": True}}]}
        if path.endswith("/actions/caches?per_page=100"):
            return {"actions_caches": [{"id": 41, "ref": "refs/heads/main", "key": "pip-linux", "version": "v1", "size_in_bytes": 1048576, "last_accessed_at": "2026-09-21T00:00:00Z"}]}
        if path.endswith("/actions/runners?per_page=100"):
            return {"runners": [{"id": 9, "name": "build-01", "os": "linux", "status": "online", "busy": False, "labels": [{"name": "self-hosted"}]}]}
        if path.endswith("/deployments?per_page=50"):
            return [{"id": 11, "environment": "production", "ref": "main", "sha": "a" * 40, "creator": {"login": "tester"}}]
        if "/dependabot/alerts?" in path:
            return [{"number": 1, "state": "open", "dependency": {"package": {"name": "demo-lib"}, "manifest_path": "requirements.txt"}, "security_advisory": {"severity": "high", "summary": "Upgrade dependency"}}]
        if "/code-scanning/alerts?" in path:
            return [{"number": 2, "state": "open", "rule": {"id": "py/demo", "description": "Unsafe call", "security_severity_level": "high"}, "tool": {"name": "CodeQL"}}]
        if "/secret-scanning/alerts?" in path:
            return [{"number": 3, "state": "open", "secret_type": "github_pat", "secret_type_display_name": "GitHub token", "secret": "ghp_THIS_MUST_NEVER_LEAK"}]
        if "/environments/production/variables?" in path:
            return {"variables": [{"name": "API_URL", "value": "https://api.example.test"}]}
        if "/environments/production/secrets?" in path:
            return {"secrets": [{"name": "PROD_PASSWORD", "secret": "MUST_NOT_LEAK_EITHER"}]}
        if path.endswith("/environments/production"):
            return {"id": 8, "name": "production", "protection_rules": []}
        if "/actions/variables/" in path or "/environments/production/variables/" in path:
            raise GitHubAPIError(404, "Not Found")
        raise AssertionError(f"Unexpected GET {path}")

    def post(self, path: str, payload: Any | None = None):
        self.calls.append(("POST", path, payload))
        return None

    def patch(self, path: str, payload: Any):
        self.calls.append(("PATCH", path, payload))
        return None

    def put(self, path: str, payload: Any | None = None):
        self.calls.append(("PUT", path, payload))
        return None

    def delete(self, path: str):
        self.calls.append(("DELETE", path, None))
        return None


def _mini_app(monkeypatch, *, role: str | None = None):
    project = {"id": 1, "name": "demo", "github_url": "https://github.com/o/r", "branch": "main"}
    fake = FakeAdminAPI("o", "r")
    audit: list[tuple] = []

    def lookup(project_id: int):
        if project_id != 1:
            raise HTTPException(status_code=404, detail="Project not found")
        return project

    app = FastAPI()
    if role:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.security_user = {"role": role, "username": "test-user"}
            return await call_next(request)

    install_github_admin_routes(
        app,
        project_lookup=lookup,
        audit_fn=lambda *args: audit.append(args),
        api_factory=lambda owner, repo: fake,
    )
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_ADMIN_WRITE", raising=False)
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_CACHE_WRITE", raising=False)
    return app, fake, audit


def test_overview_sanitizes_secret_values(monkeypatch) -> None:
    app, _, _ = _mini_app(monkeypatch)
    response = TestClient(app).get("/api/projects/1/github/admin/overview")
    assert response.status_code == 200, response.text
    payload = response.json()
    text = str(payload)
    assert payload["secrets"]["data"][0]["name"] == "DEPLOY_TOKEN"
    assert payload["security"]["secret_scanning"]["data"][0]["secret_type"] == "github_pat"
    assert "MUST_NOT_LEAK" not in text
    assert "ghp_THIS_MUST_NEVER_LEAK" not in text
    assert "secret" not in payload["secrets"]["data"][0]
    assert "secret" not in payload["security"]["secret_scanning"]["data"][0]


def test_overview_degrades_per_permission_surface(monkeypatch) -> None:
    app, fake, _ = _mini_app(monkeypatch)
    fake.fail_paths.add("/repos/o/r/dependabot/alerts?state=open&per_page=100")
    payload = TestClient(app).get("/api/projects/1/github/admin/overview").json()
    assert payload["variables"]["available"] is True
    assert payload["security"]["dependabot"]["available"] is False
    assert payload["security"]["dependabot"]["status"] == 403
    assert payload["runners"]["available"] is True


def test_environment_detail_sanitizes_secret_metadata(monkeypatch) -> None:
    app, _, _ = _mini_app(monkeypatch)
    response = TestClient(app).get("/api/projects/1/github/admin/environments/production")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["variables"]["data"][0]["name"] == "API_URL"
    assert payload["secrets"]["data"][0]["name"] == "PROD_PASSWORD"
    assert "MUST_NOT_LEAK_EITHER" not in str(payload)


def test_admin_writes_are_off_by_default(monkeypatch) -> None:
    app, _, _ = _mini_app(monkeypatch)
    response = TestClient(app).put(
        "/api/projects/1/github/admin/variables/DEPLOY_REGION",
        json={"name": "DEPLOY_REGION", "value": "secretish-value"},
    )
    assert response.status_code == 409
    assert "disabled" in response.json()["detail"].lower()


def test_admin_variable_write_audits_name_not_value(monkeypatch) -> None:
    app, fake, audit = _mini_app(monkeypatch, role="admin")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_ADMIN_WRITE", "1")
    response = TestClient(app).put(
        "/api/projects/1/github/admin/variables/NEW_VALUE",
        json={"name": "NEW_VALUE", "value": "do-not-place-this-in-audit"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["action"] == "created"
    assert any(call[0] == "POST" and call[1].endswith("/actions/variables") for call in fake.calls)
    assert "NEW_VALUE" in audit[-1][3]
    assert "do-not-place-this-in-audit" not in str(audit)


def test_viewer_cannot_mutate_admin_configuration(monkeypatch) -> None:
    app, _, _ = _mini_app(monkeypatch, role="viewer")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_ADMIN_WRITE", "1")
    response = TestClient(app).put(
        "/api/projects/1/github/admin/variables/TEST_VALUE",
        json={"name": "TEST_VALUE", "value": "x"},
    )
    assert response.status_code == 403
    assert "admin role" in response.json()["detail"].lower()


def test_variable_delete_requires_exact_confirmation(monkeypatch) -> None:
    app, fake, _ = _mini_app(monkeypatch, role="admin")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_ADMIN_WRITE", "1")
    client = TestClient(app)
    bad = client.request("DELETE", "/api/projects/1/github/admin/variables/OLD_VALUE", json={"confirmation": "DELETE"})
    assert bad.status_code == 400
    good = client.request("DELETE", "/api/projects/1/github/admin/variables/OLD_VALUE", json={"confirmation": "DELETE VARIABLE OLD_VALUE"})
    assert good.status_code == 200, good.text
    assert ("DELETE", "/repos/o/r/actions/variables/OLD_VALUE", None) in fake.calls


def test_cache_deletion_has_separate_switch_and_confirmation(monkeypatch) -> None:
    app, fake, _ = _mini_app(monkeypatch, role="admin")
    client = TestClient(app)
    off = client.request("DELETE", "/api/projects/1/github/admin/caches/41", json={"confirmation": "DELETE CACHE 41"})
    assert off.status_code == 409
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_CACHE_WRITE", "1")
    bad = client.request("DELETE", "/api/projects/1/github/admin/caches/41", json={"confirmation": "DELETE 41"})
    assert bad.status_code == 400
    good = client.request("DELETE", "/api/projects/1/github/admin/caches/41", json={"confirmation": "DELETE CACHE 41"})
    assert good.status_code == 200, good.text
    assert ("DELETE", "/repos/o/r/actions/caches/41", None) in fake.calls


def test_platform_admin_routes_are_unique_by_method() -> None:
    route_keys: list[tuple[str, str]] = []
    for route in platform_app.router.routes:
        path = getattr(route, "path", "")
        for method in (getattr(route, "methods", None) or set()):
            route_keys.append((method, path))

    expected = {
        ("GET", "/github/admin"),
        ("GET", "/projects/{project_id}/github/admin"),
        ("GET", "/api/projects/{project_id}/github/admin/capabilities"),
        ("GET", "/api/projects/{project_id}/github/admin/overview"),
        ("GET", "/api/projects/{project_id}/github/admin/environments/{environment_name}"),
        ("PUT", "/api/projects/{project_id}/github/admin/variables/{name}"),
        ("DELETE", "/api/projects/{project_id}/github/admin/variables/{name}"),
        ("PUT", "/api/projects/{project_id}/github/admin/environments/{environment_name}/variables/{name}"),
        ("DELETE", "/api/projects/{project_id}/github/admin/caches/{cache_id}"),
    }
    for key in expected:
        assert route_keys.count(key) == 1, (key, route_keys.count(key))
