from __future__ import annotations

import sqlite3
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class BootstrapSecurityBoundary(BaseHTTPMiddleware):
    """Keep the security API read-only until the localhost Owner bootstrap is complete."""

    def __init__(self, app: Any, db_factory: Callable[[], sqlite3.Connection]):
        super().__init__(app)
        self.db_factory = db_factory

    async def dispatch(self, request: Request, call_next: Callable[..., Any]):
        if request.url.path.startswith("/api/security/") and request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            try:
                with self.db_factory() as connection:
                    count = int(connection.execute("SELECT COUNT(*) FROM security_users").fetchone()[0])
            except sqlite3.OperationalError:
                count = 0
            if count == 0:
                return JSONResponse(
                    {"detail": "Create the first Owner through the localhost bootstrap flow before using security mutation APIs"},
                    status_code=409,
                )
        return await call_next(request)


def install_bootstrap_security_boundary(app: FastAPI, db_factory: Callable[[], sqlite3.Connection]) -> None:
    app.add_middleware(BootstrapSecurityBoundary, db_factory=db_factory)


__all__ = ["install_bootstrap_security_boundary"]
