from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.github_admin_center import install_github_admin_routes
from app.github_app_webhooks import github_auth_mode, github_integration_status


LIVE_EVENT_SCRIPT = r"""
<script id="github-webhook-live-events">
(() => {
  const projectId = Number(typeof ID !== 'undefined' ? ID : 0);
  if (!projectId || !('WebSocket' in window)) return;
  let socket = null;
  let retry = null;
  const connect = () => {
    clearTimeout(retry);
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${scheme}://${location.host}/ws/github/events`);
    socket.onopen = () => {
      const el = document.getElementById('liveState');
      if (el && typeof live !== 'undefined' && live) el.title = 'Webhook event stream connected';
    };
    socket.onmessage = event => {
      let payload;
      try { payload = JSON.parse(event.data); } catch { return; }
      if (payload.type !== 'github' || Number(payload.project_id || 0) !== projectId) return;
      const interesting = new Set(['workflow_run','workflow_job','check_run','push','pull_request']);
      if (!interesting.has(payload.event)) return;
      const el = document.getElementById('liveState');
      if (el) {
        el.textContent = `LIVE · ${String(payload.event).toUpperCase()}`;
        el.title = `GitHub webhook ${payload.delivery_id || ''}`;
      }
      if (typeof loadRuns === 'function') loadRuns(false);
    };
    socket.onclose = () => { retry = setTimeout(connect, 3000); };
    socket.onerror = () => { try { socket.close(); } catch {} };
  };
  connect();
  window.addEventListener('beforeunload', () => { try { socket?.close(); } catch {} });
})();
</script>
"""


def _replace_get_page(app: FastAPI, path: str, wrapper: Any) -> None:
    endpoint: Any | None = None
    for route in list(app.router.routes):
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == path and "GET" in methods:
            endpoint = route.endpoint
            app.router.routes.remove(route)
            break
    if endpoint is not None:
        wrapper(endpoint)


def install_github_event_ui(app: FastAPI) -> None:
    """Add webhook refresh, App-aware Actions status, and GitHub admin navigation."""
    from app.main import audit, project_or_404

    # Admin/security routes are composed here so platform.py stays focused and all routes are
    # still installed before the global browser security middleware is added.
    install_github_admin_routes(app, project_lookup=project_or_404, audit_fn=audit)

    page_target = "/projects/{project_id}/github/actions"
    page_endpoint: Any | None = None
    for route in list(app.router.routes):
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == page_target and "GET" in methods:
            page_endpoint = route.endpoint
            app.router.routes.remove(route)
            break

    if page_endpoint is not None:
        @app.get(page_target, response_class=HTMLResponse, include_in_schema=False)
        def webhook_live_actions_page(project_id: int) -> str:
            html = page_endpoint(project_id)
            if not isinstance(html, str):
                return html
            return html.replace("</body>", LIVE_EVENT_SCRIPT + "\n</body>")

    capability_target = "/api/projects/{project_id}/github/actions/capabilities"
    capability_endpoint: Any | None = None
    for route in list(app.router.routes):
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == capability_target and "GET" in methods:
            capability_endpoint = route.endpoint
            app.router.routes.remove(route)
            break

    if capability_endpoint is not None:
        @app.get(capability_target)
        def app_aware_actions_capabilities(project_id: int) -> dict[str, Any]:
            payload = dict(capability_endpoint(project_id))
            integration = github_integration_status()
            authenticated = github_auth_mode() != "anonymous"
            payload["authenticated"] = authenticated
            payload["auth_mode"] = integration["auth_mode"]
            payload["write_enabled"] = bool(authenticated and integration["actions_write_enabled"])
            payload["webhook_configured"] = bool(integration["webhook_configured"])
            payload["webhook_live_updates"] = bool(integration["webhook_configured"])
            return payload

    def wrap_github_index(endpoint: Any) -> None:
        @app.get("/github", response_class=HTMLResponse, include_in_schema=False)
        def github_index_with_admin() -> str:
            html = endpoint()
            if not isinstance(html, str):
                return html
            link = "<a class='btn' href='/github/admin'>Administration & Security</a> "
            if "/github/admin" in html:
                return html
            return html.replace("<a class='btn' href='/'>Infrastructure</a>", link + "<a class='btn' href='/'>Infrastructure</a>")

    _replace_get_page(app, "/github", wrap_github_index)

    def wrap_project_page(endpoint: Any) -> None:
        @app.get("/projects/{project_id}/github", response_class=HTMLResponse, include_in_schema=False)
        def github_project_with_admin(project_id: int) -> str:
            html = endpoint(project_id)
            if not isinstance(html, str):
                return html
            link = f"<a class='btn' href='/projects/{project_id}/github/admin'>Admin & Security</a> "
            if "/github/admin" in html:
                return html
            return html.replace("<a class='btn' href='/github'>All repositories</a>", link + "<a class='btn' href='/github'>All repositories</a>")

    _replace_get_page(app, "/projects/{project_id}/github", wrap_project_page)


__all__ = ["LIVE_EVENT_SCRIPT", "install_github_event_ui"]
