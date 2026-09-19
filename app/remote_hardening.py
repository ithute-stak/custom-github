from __future__ import annotations

import os
import sqlite3
from typing import Callable
from urllib.parse import urlparse

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def install_remote_hardening(app: FastAPI, *, db_factory: Callable[[], sqlite3.Connection]) -> None:
    if not _truthy(os.getenv("CUSTOM_GITHUB_REMOTE_MODE")):
        return

    public_url = os.getenv("CUSTOM_GITHUB_PUBLIC_URL", "").strip()
    parsed = urlparse(public_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("CUSTOM_GITHUB_REMOTE_MODE requires an HTTPS CUSTOM_GITHUB_PUBLIC_URL")

    hosts = [item.strip() for item in os.getenv("CUSTOM_GITHUB_TRUSTED_HOSTS", "").split(",") if item.strip()]
    if not hosts:
        hosts = [parsed.hostname]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    @app.on_event("startup")
    def verify_remote_security() -> None:
        with db_factory() as connection:
            settings = connection.execute("SELECT enabled FROM security_settings WHERE id=1").fetchone()
            owners = connection.execute("SELECT COUNT(*) FROM security_users WHERE active=1 AND role='owner'").fetchone()[0]
            privileged_mfa = connection.execute("SELECT COUNT(*) FROM security_users WHERE active=1 AND role IN ('owner','admin') AND mfa_enabled=1").fetchone()[0]
        if not settings or not settings["enabled"]:
            raise RuntimeError("Remote mode refuses to start until authentication is enabled")
        if int(owners) < 1:
            raise RuntimeError("Remote mode requires at least one active Owner")
        if int(privileged_mfa) < 1:
            raise RuntimeError("Remote mode requires MFA on at least one Owner/Admin account")

    @app.middleware("http")
    async def production_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault("Cache-Control", "no-store")
        return response
