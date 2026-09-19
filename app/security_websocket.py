from __future__ import annotations

from typing import Any

from fastapi import FastAPI, WebSocket

from app.security import authorize_websocket


def secure_terminal_websocket(app: FastAPI) -> None:
    """Wrap the VPS terminal WebSocket with the same RBAC boundary as the HTTP UI.

    Starlette HTTP middleware does not process WebSocket connections, so the terminal
    route needs an explicit authorization gate. The existing terminal endpoint remains
    responsible for accepting the socket and running the PTY after this check succeeds.
    """

    target_path = "/api/vps/servers/{server_id}/terminal/ws"
    endpoint: Any | None = None
    for route in list(app.router.routes):
        if getattr(route, "path", None) == target_path and hasattr(route, "endpoint"):
            endpoint = route.endpoint
            app.router.routes.remove(route)
            break
    if endpoint is None:
        return

    @app.websocket(target_path)
    async def secured_terminal_socket(websocket: WebSocket, server_id: int) -> None:
        allowed, identity = authorize_websocket(websocket, "developer")
        if not allowed:
            code = 4401 if "Authentication" in identity else 4403
            await websocket.close(code=code, reason=identity[:120])
            return
        await endpoint(websocket, server_id)


__all__ = ["secure_terminal_websocket"]
