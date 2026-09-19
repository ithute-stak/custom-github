from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.github_app_webhooks import (
    GitHubAppAuth,
    github_integration_status,
    install_github_app_webhook_routes,
    verify_webhook_signature,
)
from app.github_event_ui import LIVE_EVENT_SCRIPT


def _decode_segment(value: str) -> dict:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def _rsa_key_file(tmp_path: Path) -> tuple[Path, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "github-app.pem"
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path, key


def test_github_app_jwt_is_rs256_signed_and_short_lived(tmp_path: Path, monkeypatch) -> None:
    key_file, key = _rsa_key_file(tmp_path)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_PRIVATE_KEY_FILE", str(key_file))
    token = GitHubAppAuth().app_jwt(now=1_800_000_000)
    header_b64, payload_b64, signature_b64 = token.split(".")
    assert _decode_segment(header_b64) == {"alg": "RS256", "typ": "JWT"}
    payload = _decode_segment(payload_b64)
    assert payload["iss"] == "12345"
    assert payload["iat"] == 1_799_999_940
    assert payload["exp"] == 1_800_000_540
    padded = signature_b64 + "=" * ((4 - len(signature_b64) % 4) % 4)
    signature = base64.urlsafe_b64decode(padded)
    key.public_key().verify(
        signature,
        f"{header_b64}.{payload_b64}".encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_github_app_rejects_loose_private_key_permissions(tmp_path: Path, monkeypatch) -> None:
    key_file, _ = _rsa_key_file(tmp_path)
    key_file.chmod(0o644)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_PRIVATE_KEY_FILE", str(key_file))
    try:
        GitHubAppAuth().app_jwt(now=1_800_000_000)
    except RuntimeError as exc:
        assert "chmod 600" in str(exc)
    else:
        raise AssertionError("Expected insecure GitHub App key permissions to be rejected")


def test_installation_token_is_cached(tmp_path: Path, monkeypatch) -> None:
    key_file, _ = _rsa_key_file(tmp_path)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_PRIVATE_KEY_FILE", str(key_file))
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_INSTALLATION_ID", "777")

    class FakeAuth(GitHubAppAuth):
        calls = 0

        def _request_json(self, path: str, *, method: str = "GET", bearer: str, payload=None):
            self.calls += 1
            assert path == "/app/installations/777/access_tokens"
            assert method == "POST"
            return {
                "token": "ghs_short_lived",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat(),
            }

    auth = FakeAuth()
    assert auth.installation_token() == "ghs_short_lived"
    assert auth.installation_token() == "ghs_short_lived"
    assert auth.calls == 1


def _mini_app(tmp_path: Path):
    db_path = tmp_path / "webhooks.db"

    def db_factory():
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    with db_factory() as connection:
        connection.executescript(
            """
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                github_url TEXT NOT NULL
            );
            INSERT INTO projects(name,github_url) VALUES('demo','https://github.com/o/r.git');
            """
        )

    events: list[tuple] = []
    app = FastAPI()
    install_github_app_webhook_routes(app, db_factory=db_factory, audit_fn=lambda *args: events.append(args))
    return app, db_factory, events


def _signed_headers(body: bytes, secret: str, delivery: str = "delivery-1", event: str = "workflow_run") -> dict[str, str]:
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "content-type": "application/json",
        "x-hub-signature-256": signature,
        "x-github-delivery": delivery,
        "x-github-event": event,
    }


def test_webhook_signature_helper() -> None:
    body = b'{"ok":true}'
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(body, signature, "secret") is True
    assert verify_webhook_signature(body + b"x", signature, "secret") is False
    assert verify_webhook_signature(body, "sha1=bad", "secret") is False


def test_signed_webhook_is_mapped_stored_and_deduplicated(tmp_path: Path, monkeypatch) -> None:
    secret = "webhook-secret-value"
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_WEBHOOK_SECRET", secret)
    app, db_factory, audit_events = _mini_app(tmp_path)
    client = TestClient(app)
    payload = {
        "action": "completed",
        "repository": {"id": 99, "full_name": "o/r"},
        "installation": {"id": 777},
        "workflow_run": {"id": 1234},
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = _signed_headers(body, secret)

    response = client.post("/auth/github/webhook", content=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["project_id"] == 1
    assert response.json()["duplicate"] is False

    duplicate = client.post("/auth/github/webhook", content=body, headers=headers)
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True

    with db_factory() as connection:
        row = connection.execute("SELECT * FROM github_webhook_deliveries").fetchone()
        assert connection.execute("SELECT COUNT(*) FROM github_webhook_deliveries").fetchone()[0] == 1
    assert row["delivery_id"] == "delivery-1"
    assert row["event_name"] == "workflow_run"
    assert row["repository_full_name"] == "o/r"
    assert row["project_id"] == 1
    assert row["installation_id"] == 777
    assert row["entity_id"] == "1234"
    assert audit_events


def test_webhook_rejects_bad_signature_and_missing_secret(tmp_path: Path, monkeypatch) -> None:
    app, _, _ = _mini_app(tmp_path)
    client = TestClient(app)
    body = b'{"repository":{"full_name":"o/r"}}'
    monkeypatch.delenv("CUSTOM_GITHUB_GITHUB_WEBHOOK_SECRET", raising=False)
    unavailable = client.post("/auth/github/webhook", content=body, headers={"x-github-delivery": "x", "x-github-event": "push"})
    assert unavailable.status_code == 503

    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_WEBHOOK_SECRET", "correct")
    rejected = client.post(
        "/auth/github/webhook",
        content=body,
        headers={"x-github-delivery": "x", "x-github-event": "push", "x-hub-signature-256": "sha256=deadbeef"},
    )
    assert rejected.status_code == 401


def test_integration_status_never_discloses_credentials(tmp_path: Path, monkeypatch) -> None:
    key_file, _ = _rsa_key_file(tmp_path)
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_INSTALLATION_ID", "777")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_APP_PRIVATE_KEY_FILE", str(key_file))
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_TOKEN", "ghp_do_not_disclose")
    monkeypatch.setenv("CUSTOM_GITHUB_GITHUB_WEBHOOK_SECRET", "webhook_do_not_disclose")
    status = github_integration_status()
    rendered = json.dumps(status)
    assert status["auth_mode"] == "github-app"
    assert status["webhook_path"] == "/auth/github/webhook"
    assert "ghp_do_not_disclose" not in rendered
    assert "webhook_do_not_disclose" not in rendered
    assert "12345" not in rendered
    assert "777" not in rendered


def test_actions_live_page_has_websocket_event_refresh() -> None:
    assert "/ws/github/events" in LIVE_EVENT_SCRIPT
    assert "workflow_run" in LIVE_EVENT_SCRIPT
    assert "workflow_job" in LIVE_EVENT_SCRIPT
    assert "loadRuns(false)" in LIVE_EVENT_SCRIPT


def test_platform_github_app_routes_are_unique() -> None:
    from app.platform import app

    paths = [getattr(route, "path", "") for route in app.router.routes]
    expected = {
        "/api/github/integration",
        "/api/github/webhooks/recent",
        "/auth/github/webhook",
        "/webhooks/github",
        "/ws/github/events",
        "/projects/{project_id}/github/actions",
        "/api/projects/{project_id}/github/actions/capabilities",
    }
    for path in expected:
        assert paths.count(path) == 1, (path, paths.count(path))
