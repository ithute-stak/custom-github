from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, HTTPException, Request as FastAPIRequest, WebSocket

from app.security import authorize_websocket


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def github_app_configured() -> bool:
    return bool(
        os.getenv("CUSTOM_GITHUB_GITHUB_APP_ID", "").strip()
        and os.getenv("CUSTOM_GITHUB_GITHUB_APP_PRIVATE_KEY_FILE", "").strip()
    )


def github_pat_configured() -> bool:
    return bool(os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip())


def github_webhook_configured() -> bool:
    return bool(os.getenv("CUSTOM_GITHUB_GITHUB_WEBHOOK_SECRET", "").strip())


class GitHubAppAuth:
    """Mint and cache short-lived GitHub App installation tokens.

    Private-key bytes are read from the configured local file only when signing an App JWT.
    Installation tokens stay in process memory and are refreshed before expiry.
    """

    def __init__(self, *, timeout: int = 20):
        self.timeout = timeout
        self._tokens: dict[int, tuple[str, float]] = {}
        self.last_error: str | None = None

    @property
    def app_id(self) -> str:
        return os.getenv("CUSTOM_GITHUB_GITHUB_APP_ID", "").strip()

    @property
    def key_file(self) -> Path | None:
        raw = os.getenv("CUSTOM_GITHUB_GITHUB_APP_PRIVATE_KEY_FILE", "").strip()
        return Path(raw).expanduser() if raw else None

    @property
    def configured_installation_id(self) -> int | None:
        raw = os.getenv("CUSTOM_GITHUB_GITHUB_APP_INSTALLATION_ID", "").strip()
        try:
            return int(raw) if raw else None
        except ValueError:
            return None

    def app_jwt(self, now: int | None = None) -> str:
        if not self.app_id or not self.key_file:
            raise RuntimeError("GitHub App ID and private-key file are required")
        key_path = self.key_file
        if not key_path.is_file():
            raise RuntimeError("GitHub App private-key file does not exist")
        if key_path.stat().st_mode & 0o077:
            raise RuntimeError("GitHub App private-key file must not be group/world accessible; use chmod 600")
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RuntimeError("GitHub App private key must be RSA")
        timestamp = int(now or time.time())
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
        payload = _b64url(
            json.dumps({"iat": timestamp - 60, "exp": timestamp + 540, "iss": self.app_id}, separators=(",", ":")).encode()
        )
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{_b64url(signature)}"

    def _request_json(self, path: str, *, method: str = "GET", bearer: str, payload: Any | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            "https://api.github.com" + path,
            method=method,
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "custom-github-control-plane",
                "Authorization": f"Bearer {bearer}",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8"))
                message = str(body.get("message") or exc.reason)
            except Exception:
                message = str(exc.reason)
            raise RuntimeError(f"GitHub App API HTTP {exc.code}: {message}") from exc
        except URLError as exc:
            raise RuntimeError(f"GitHub App API unavailable: {exc.reason}") from exc

    def installation_id(self, owner: str | None = None, repo: str | None = None) -> int:
        configured = self.configured_installation_id
        if configured:
            return configured
        if not owner or not repo:
            raise RuntimeError("GitHub App installation ID is required when repository discovery is unavailable")
        result = self._request_json(f"/repos/{owner}/{repo}/installation", bearer=self.app_jwt()) or {}
        value = result.get("id")
        if not value:
            raise RuntimeError(f"GitHub App is not installed for {owner}/{repo}")
        return int(value)

    def installation_token(self, owner: str | None = None, repo: str | None = None) -> str:
        installation_id = self.installation_id(owner, repo)
        cached = self._tokens.get(installation_id)
        if cached and cached[1] - time.time() > 120:
            return cached[0]
        result = self._request_json(
            f"/app/installations/{installation_id}/access_tokens",
            method="POST",
            bearer=self.app_jwt(),
            payload={},
        ) or {}
        token = str(result.get("token") or "")
        if not token:
            raise RuntimeError("GitHub did not return an installation access token")
        expires_at = str(result.get("expires_at") or "")
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
        except Exception:
            expiry = time.time() + 3000
        self._tokens[installation_id] = (token, expiry)
        self.last_error = None
        return token


_APP_AUTH = GitHubAppAuth()


def github_auth_mode() -> str:
    if github_app_configured():
        return "github-app"
    if github_pat_configured():
        return "token"
    return "anonymous"


def resolve_github_token(owner: str | None = None, repo: str | None = None) -> str | None:
    if github_app_configured():
        try:
            return _APP_AUTH.installation_token(owner, repo)
        except Exception as exc:
            _APP_AUTH.last_error = str(exc)[:500]
            fallback = os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip()
            return fallback or None
    return os.getenv("CUSTOM_GITHUB_GITHUB_TOKEN", "").strip() or None


def github_integration_status() -> dict[str, Any]:
    key_file = _APP_AUTH.key_file
    key_secure = None
    if key_file and key_file.exists():
        key_secure = not bool(key_file.stat().st_mode & 0o077)
    return {
        "provider": "github.com",
        "auth_mode": github_auth_mode(),
        "github_app_configured": github_app_configured(),
        "installation_id_configured": _APP_AUTH.configured_installation_id is not None,
        "private_key_file_configured": bool(key_file),
        "private_key_permissions_secure": key_secure,
        "pat_fallback_configured": github_pat_configured(),
        "webhook_configured": github_webhook_configured(),
        "webhook_path": "/auth/github/webhook",
        "actions_write_enabled": _truthy(os.getenv("CUSTOM_GITHUB_GITHUB_ACTIONS_WRITE")),
        "last_app_auth_error": _APP_AUTH.last_error,
    }


class GitHubEventHub:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    async def publish(self, event: dict[str, Any]) -> None:
        for queue in tuple(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass


EVENT_HUB = GitHubEventHub()


def verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    if not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _project_for_repo(db_factory: Callable, full_name: str) -> int | None:
    normalized = full_name.lower()
    with db_factory() as connection:
        rows = connection.execute("SELECT id, github_url FROM projects").fetchall()
    for row in rows:
        url = str(row["github_url"] or "").lower().removesuffix(".git").rstrip("/")
        if url == f"https://github.com/{normalized}":
            return int(row["id"])
    return None


def _event_summary(payload: dict[str, Any], event_name: str, delivery_id: str) -> dict[str, Any]:
    repository = payload.get("repository") or {}
    installation = payload.get("installation") or {}
    action = payload.get("action")
    entity_id = None
    for key in ("workflow_run", "workflow_job", "pull_request", "release", "check_run"):
        item = payload.get(key)
        if isinstance(item, dict) and item.get("id") is not None:
            entity_id = item.get("id")
            break
    return {
        "delivery_id": delivery_id,
        "event": event_name,
        "action": action,
        "repository": repository.get("full_name"),
        "repository_id": repository.get("id"),
        "installation_id": installation.get("id"),
        "entity_id": entity_id,
        "received_at": _now(),
    }


def install_github_app_webhook_routes(
    app: FastAPI,
    *,
    db_factory: Callable,
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    with db_factory() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                event_name TEXT NOT NULL,
                action TEXT,
                repository_full_name TEXT,
                project_id INTEGER,
                installation_id INTEGER,
                entity_id TEXT,
                received_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );
            CREATE INDEX IF NOT EXISTS idx_github_webhook_project ON github_webhook_deliveries(project_id, received_at DESC);
            CREATE INDEX IF NOT EXISTS idx_github_webhook_repo ON github_webhook_deliveries(repository_full_name, received_at DESC);
            """
        )

    @app.get("/api/github/integration")
    def integration_status() -> dict[str, Any]:
        status = github_integration_status()
        with db_factory() as connection:
            status["webhook_deliveries"] = int(connection.execute("SELECT COUNT(*) FROM github_webhook_deliveries").fetchone()[0])
        return status

    @app.get("/api/github/webhooks/recent")
    def recent_webhooks(limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        with db_factory() as connection:
            rows = connection.execute(
                "SELECT delivery_id,event_name,action,repository_full_name,project_id,installation_id,entity_id,received_at FROM github_webhook_deliveries ORDER BY received_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    async def receive_webhook(request: FastAPIRequest) -> dict[str, Any]:
        secret = os.getenv("CUSTOM_GITHUB_GITHUB_WEBHOOK_SECRET", "").strip()
        if not secret:
            raise HTTPException(status_code=503, detail="GitHub webhook secret is not configured")
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > 2_000_000:
            raise HTTPException(status_code=413, detail="GitHub webhook payload is too large")
        body = await request.body()
        if len(body) > 2_000_000:
            raise HTTPException(status_code=413, detail="GitHub webhook payload is too large")
        signature = request.headers.get("x-hub-signature-256", "")
        if not verify_webhook_signature(body, signature, secret):
            raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")
        delivery_id = request.headers.get("x-github-delivery", "").strip()
        event_name = request.headers.get("x-github-event", "").strip()
        if not delivery_id or not event_name:
            raise HTTPException(status_code=400, detail="GitHub delivery and event headers are required")
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid GitHub webhook JSON") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="GitHub webhook payload must be an object")
        summary = _event_summary(payload, event_name, delivery_id)
        full_name = str(summary.get("repository") or "")
        project_id = _project_for_repo(db_factory, full_name) if full_name else None
        summary["project_id"] = project_id
        with db_factory() as connection:
            existing = connection.execute("SELECT 1 FROM github_webhook_deliveries WHERE delivery_id=?", (delivery_id,)).fetchone()
            if existing:
                return {"ok": True, "duplicate": True, "delivery_id": delivery_id}
            connection.execute(
                """
                INSERT INTO github_webhook_deliveries(
                    delivery_id,event_name,action,repository_full_name,project_id,installation_id,entity_id,received_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    delivery_id,
                    event_name,
                    summary.get("action"),
                    full_name or None,
                    project_id,
                    summary.get("installation_id"),
                    str(summary.get("entity_id")) if summary.get("entity_id") is not None else None,
                    summary["received_at"],
                ),
            )
        audit_fn(
            "github.webhook.received",
            "project" if project_id else "github_webhook",
            project_id,
            f"GitHub {event_name}{'/' + str(summary.get('action')) if summary.get('action') else ''} for {full_name or 'unknown repository'} delivery {delivery_id}",
        )
        await EVENT_HUB.publish(summary)
        return {"ok": True, "duplicate": False, "delivery_id": delivery_id, "project_id": project_id}

    @app.post("/auth/github/webhook")
    async def github_webhook_ingress(request: FastAPIRequest) -> dict[str, Any]:
        return await receive_webhook(request)

    @app.post("/webhooks/github")
    async def github_webhook_compat(request: FastAPIRequest) -> dict[str, Any]:
        return await receive_webhook(request)

    @app.websocket("/ws/github/events")
    async def github_events(websocket: WebSocket) -> None:
        allowed, identity = authorize_websocket(websocket, "viewer")
        if not allowed:
            code = 4401 if "Authentication" in identity else 4403
            await websocket.close(code=code, reason=identity[:120])
            return
        await websocket.accept()
        queue = EVENT_HUB.subscribe()
        await websocket.send_json({"type": "connected", "identity": identity, "time": _now()})
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25)
                    await websocket.send_json({"type": "github", **event})
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "ping", "time": _now()})
        except Exception:
            pass
        finally:
            EVENT_HUB.unsubscribe(queue)


__all__ = [
    "EVENT_HUB",
    "GitHubAppAuth",
    "github_app_configured",
    "github_auth_mode",
    "github_integration_status",
    "github_pat_configured",
    "github_webhook_configured",
    "install_github_app_webhook_routes",
    "resolve_github_token",
    "verify_webhook_signature",
]
