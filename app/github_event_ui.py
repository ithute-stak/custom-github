from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse


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


def install_github_event_ui(app: FastAPI) -> None:
    """Wrap the existing project Actions page with webhook/WebSocket live refresh."""
    target = "/projects/{project_id}/github/actions"
    endpoint: Any | None = None
    for route in list(app.router.routes):
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == target and "GET" in methods:
            endpoint = route.endpoint
            app.router.routes.remove(route)
            break
    if endpoint is None:
        return

    @app.get(target, response_class=HTMLResponse, include_in_schema=False)
    def webhook_live_actions_page(project_id: int) -> str:
        html = endpoint(project_id)
        if not isinstance(html, str):
            return html
        return html.replace("</body>", LIVE_EVENT_SCRIPT + "\n</body>")


__all__ = ["LIVE_EVENT_SCRIPT", "install_github_event_ui"]
