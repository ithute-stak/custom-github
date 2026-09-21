from __future__ import annotations

import base64
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from nacl.public import PrivateKey, SealedBox

from app.github_secret_write import encrypt_github_secret, install_github_secret_routes, normalize_secret_name
from app.platform import app as platform_app


class FakeSecretAPI:
    def __init__(self, owner: str, repo: str, public_key_b64: str):
        self.owner = owner
        self.repo = repo
        self.token = "installation-token"
        self.public_key_b64 = public_key_b64
        self.calls: list[tuple[str, str, Any | None]] = []

    def get(self, path: str):
        self.calls.append(("GET", path, None))
        if path.endswith("/secrets/public-key"):
            return {"key_id": "key-123", "key": self.public_key_b64}
        raise AssertionError(f"Unexpected GET {path}")

    def put(self, path: str, payload: Any | None = None):
        self.calls.append(("PUT", path, payload))
        return None

    def delete(self, path: str):
        self.calls.append(("DELETE", path, None))
        return None


def _mini_app(monkeypatch, *, role: str | None = None):
    private_key = PrivateKey.generate()
    public_key_b64 = base64.b64encode(bytes(private_key.public_key)).decode("ascii")
    fake = FakeSecretAPI("o", "r", public_key_b64)
    project = {"id": 1, "name": "demo", "github_url": "https://github.com/o/r", "branch": "main"}
    audit: list[tuple] = []

    def lookup(project_id: int):
        if project_id != 1:
            raise HTTPException(status_code=404, detail="Project not found")
        return project

    app = FastAPI()
    if role:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.security_user = {"role": role, "username": "operator"}
            return await call_next(request)

    install_github_secret_routes(
        app,
        project_lookup=lookup,
        audit_fn=lambda *args: audit.append(args),
        api_factory=lambda owner, repo: fake,
    )
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_SECRET_WRITE", raising=False)
    return app, fake, audit, private_key


def test_sealed_box_encryption_round_trip() -> None:
    private_key = PrivateKey.generate()
    public_key_b64 = base64.b64encode(bytes(private_key.public_key)).decode("ascii")
    plaintext = "very-sensitive-value"
    encrypted_b64 = encrypt_github_secret(public_key_b64, plaintext)
    assert plaintext not in encrypted_b64
    decrypted = SealedBox(private_key).decrypt(base64.b64decode(encrypted_b64)).decode("utf-8")
    assert decrypted == plaintext


def test_secret_name_validation() -> None:
    assert normalize_secret_name("deploy_token") == "DEPLOY_TOKEN"
    for value in ["1BAD", "bad-name", "GITHUB_TOKEN", "github_custom"]:
        try:
            normalize_secret_name(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected invalid secret name: {value}")


def test_secret_writes_are_disabled_by_default(monkeypatch) -> None:
    app, _, _, _ = _mini_app(monkeypatch, role="admin")
    response = TestClient(app).put(
        "/api/projects/1/github/secrets/repository/DEPLOY_TOKEN",
        json={"value": "plaintext-secret"},
    )
    assert response.status_code == 409
    assert "disabled" in response.json()["detail"].lower()


def test_repository_secret_is_encrypted_and_audit_is_redacted(monkeypatch) -> None:
    app, fake, audit, private_key = _mini_app(monkeypatch, role="admin")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_SECRET_WRITE", "1")
    plaintext = "repo-super-secret-value"
    response = TestClient(app).put(
        "/api/projects/1/github/secrets/repository/deploy_token",
        json={"value": plaintext},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True, "scope": "repository", "name": "DEPLOY_TOKEN"}
    put_calls = [call for call in fake.calls if call[0] == "PUT"]
    assert len(put_calls) == 1
    path, payload = put_calls[0][1], put_calls[0][2]
    assert path.endswith("/actions/secrets/DEPLOY_TOKEN")
    assert payload["key_id"] == "key-123"
    assert plaintext not in str(payload)
    decrypted = SealedBox(private_key).decrypt(base64.b64decode(payload["encrypted_value"])).decode("utf-8")
    assert decrypted == plaintext
    assert plaintext not in response.text
    assert plaintext not in str(audit)
    assert "DEPLOY_TOKEN" in audit[-1][3]


def test_environment_secret_uses_environment_public_key(monkeypatch) -> None:
    app, fake, audit, private_key = _mini_app(monkeypatch, role="owner")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_SECRET_WRITE", "1")
    plaintext = "prod-password-value"
    response = TestClient(app).put(
        "/api/projects/1/github/secrets/environments/production/db_password",
        json={"value": plaintext},
    )
    assert response.status_code == 200, response.text
    get_paths = [call[1] for call in fake.calls if call[0] == "GET"]
    assert "/repos/o/r/environments/production/secrets/public-key" in get_paths
    put_call = [call for call in fake.calls if call[0] == "PUT"][0]
    assert put_call[1].endswith("/environments/production/secrets/DB_PASSWORD")
    decrypted = SealedBox(private_key).decrypt(base64.b64decode(put_call[2]["encrypted_value"])).decode("utf-8")
    assert decrypted == plaintext
    assert plaintext not in str(audit)


def test_secret_delete_requires_exact_confirmation(monkeypatch) -> None:
    app, fake, _, _ = _mini_app(monkeypatch, role="admin")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_SECRET_WRITE", "1")
    client = TestClient(app)
    bad = client.request(
        "DELETE",
        "/api/projects/1/github/secrets/repository/DEPLOY_TOKEN",
        json={"confirmation": "DELETE"},
    )
    assert bad.status_code == 400
    good = client.request(
        "DELETE",
        "/api/projects/1/github/secrets/repository/DEPLOY_TOKEN",
        json={"confirmation": "DELETE SECRET DEPLOY_TOKEN"},
    )
    assert good.status_code == 200, good.text
    assert ("DELETE", "/repos/o/r/actions/secrets/DEPLOY_TOKEN", None) in fake.calls


def test_viewer_cannot_write_secrets(monkeypatch) -> None:
    app, _, _, _ = _mini_app(monkeypatch, role="viewer")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_SECRET_WRITE", "1")
    response = TestClient(app).put(
        "/api/projects/1/github/secrets/repository/DEPLOY_TOKEN",
        json={"value": "nope"},
    )
    assert response.status_code == 403
    assert "admin role" in response.json()["detail"].lower()


def test_platform_secret_routes_are_unique_by_method() -> None:
    route_keys: list[tuple[str, str]] = []
    for route in platform_app.router.routes:
        path = getattr(route, "path", "")
        for method in (getattr(route, "methods", None) or set()):
            route_keys.append((method, path))
    expected = {
        ("GET", "/github/secrets"),
        ("GET", "/projects/{project_id}/github/secrets"),
        ("GET", "/api/projects/{project_id}/github/secrets/capabilities"),
        ("PUT", "/api/projects/{project_id}/github/secrets/repository/{name}"),
        ("DELETE", "/api/projects/{project_id}/github/secrets/repository/{name}"),
        ("PUT", "/api/projects/{project_id}/github/secrets/environments/{environment_name}/{name}"),
        ("DELETE", "/api/projects/{project_id}/github/secrets/environments/{environment_name}/{name}"),
    }
    for key in expected:
        assert route_keys.count(key) == 1, (key, route_keys.count(key))
