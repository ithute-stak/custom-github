import os
from pathlib import Path

os.environ.setdefault("CUSTOM_GITHUB_DATA_DIR", "/tmp/custom-github-test-data")
os.environ.setdefault("CUSTOM_GITHUB_WORKSPACE_ROOT", "/tmp/custom-github-test-workspaces")

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health() -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_loads() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Deploy Latest" in response.text


def test_rejects_non_github_repository() -> None:
    response = client.post(
        "/api/projects",
        json={"name": "unsafe", "github_url": "https://example.com/repo.git", "branch": "main"},
    )
    assert response.status_code == 400


def test_data_paths_are_not_repo_root() -> None:
    assert Path(os.environ["CUSTOM_GITHUB_DATA_DIR"]).name == "custom-github-test-data"
