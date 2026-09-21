from __future__ import annotations

from typing import Any, Callable

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.github_app_webhooks import github_auth_mode, github_integration_status
from app.github_pr_center import install_github_pr_routes


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
      const interesting = new Set(['workflow_run','workflow_job','check_run','check_suite','push','pull_request']);
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


PR_EVENT_SCRIPT = r"""
<script id="github-pr-live-events">
(() => {
  const projectId = Number(typeof ID !== 'undefined' ? ID : 0);
  if (!projectId || !('WebSocket' in window)) return;
  let retry = null;
  let socket = null;
  const interesting = new Set(['pull_request','pull_request_review','pull_request_review_comment','check_run','check_suite','status','push']);
  const connect = () => {
    clearTimeout(retry);
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${scheme}://${location.host}/ws/github/events`);
    socket.onmessage = event => {
      let payload;
      try { payload = JSON.parse(event.data); } catch { return; }
      if (payload.type !== 'github' || Number(payload.project_id || 0) !== projectId || !interesting.has(payload.event)) return;
      document.title = `● ${document.title.replace(/^● /,'')}`;
      if (typeof load === 'function') load();
    };
    socket.onclose = () => { retry = setTimeout(connect, 3000); };
    socket.onerror = () => { try { socket.close(); } catch {} };
  };
  connect();
  window.addEventListener('beforeunload', () => { try { socket?.close(); } catch {} });
})();
</script>
"""


def _replace_get_route(app: FastAPI, path: str, builder: Callable[[Any], Any]) -> None:
    endpoint: Any | None = None
    for route in list(app.router.routes):
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == path and "GET" in methods:
            endpoint = route.endpoint
            app.router.routes.remove(route)
            break
    if endpoint is None:
        return
    builder(endpoint)


def install_github_event_ui(app: FastAPI) -> None:
    """Compose live Actions, GitHub App status and the Pull Request Center."""
    from app.main import audit, project_or_404

    install_github_pr_routes(app, project_lookup=project_or_404, audit_fn=audit)

    def actions_builder(endpoint: Any) -> None:
        @app.get("/projects/{project_id}/github/actions", response_class=HTMLResponse, include_in_schema=False)
        def webhook_live_actions_page(project_id: int) -> str:
            html = endpoint(project_id)
            if not isinstance(html, str):
                return html
            return html.replace("</body>", LIVE_EVENT_SCRIPT + "\n</body>")

    _replace_get_route(app, "/projects/{project_id}/github/actions", actions_builder)

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

    def pr_detail_builder(endpoint: Any) -> None:
        @app.get("/projects/{project_id}/github/pulls/{number}", response_class=HTMLResponse, include_in_schema=False)
        def live_pr_detail(project_id: int, number: int) -> str:
            html = endpoint(project_id, number)
            if not isinstance(html, str):
                return html
            return html.replace("</body>", PR_EVENT_SCRIPT + "\n</body>")

    _replace_get_route(app, "/projects/{project_id}/github/pulls/{number}", pr_detail_builder)

    def pr_list_builder(endpoint: Any) -> None:
        @app.get("/projects/{project_id}/github/pulls", response_class=HTMLResponse, include_in_schema=False)
        def live_pr_list(project_id: int) -> str:
            html = endpoint(project_id)
            if not isinstance(html, str):
                return html
            return html.replace("</body>", PR_EVENT_SCRIPT + "\n</body>")

    _replace_get_route(app, "/projects/{project_id}/github/pulls", pr_list_builder)

    def github_index_builder(endpoint: Any) -> None:
        @app.get("/github", response_class=HTMLResponse, include_in_schema=False)
        def github_index_with_prs() -> str:
            html = endpoint()
            if not isinstance(html, str):
                return html
            link = "<a class='btn' href='/github/pulls'>Pull Requests</a> <a class='btn' href='/github/actions'>Actions</a> "
            return html.replace("<a class='btn' href='/'>Infrastructure</a>", link + "<a class='btn' href='/'>Infrastructure</a>")

    _replace_get_route(app, "/github", github_index_builder)


__all__ = ["LIVE_EVENT_SCRIPT", "PR_EVENT_SCRIPT", "install_github_event_ui"]
