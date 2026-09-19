"""Custom GitHub application entry point with VPS management enabled.

The repository/deployment dashboard remains available under /deployments, while the root
page is the VPS-first infrastructure control center. This keeps the existing CI/CD flow
intact without hiding the Linux server-management capabilities behind a secondary button.
"""

from fastapi.responses import HTMLResponse

from app.main import APP_ROOT, DASHBOARD_PATH, app, audit, db, server_or_404
from app.vps import install_vps_routes

CONTROL_CENTER_PATH = APP_ROOT / "static" / "control-center.html"
VPS_DASHBOARD_PATH = APP_ROOT / "static" / "vps.html"

install_vps_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)

# The base module originally owns GET /. VPS management also installs GET /vps/{server_id}.
# Replace only those two HTML routes here; API and WebSocket routes remain untouched.
for route in list(app.router.routes):
    methods = getattr(route, "methods", None) or set()
    path = getattr(route, "path", None)
    if path == "/" and "GET" in methods:
        app.router.routes.remove(route)
    elif path == "/vps/{server_id}" and "GET" in methods:
        app.router.routes.remove(route)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def infrastructure_control_center() -> str:
    return CONTROL_CENTER_PATH.read_text(encoding="utf-8")


@app.get("/deployments", response_class=HTMLResponse, include_in_schema=False)
def deployment_control_center() -> str:
    """Preserve the original repository, pipeline and deployment dashboard."""
    return DASHBOARD_PATH.read_text(encoding="utf-8")


@app.get("/vps/{server_id}", response_class=HTMLResponse, include_in_schema=False)
def vps_dashboard(server_id: int) -> str:
    """Serve the full VPS workspace and honor direct module links such as ?section=files."""
    server_or_404(server_id)
    html = VPS_DASHBOARD_PATH.read_text(encoding="utf-8")
    deep_link = r"""
<script id="vps-deep-link">
(() => {
  const requested = new URLSearchParams(window.location.search).get('section');
  const allowed = new Set(['overview','files','docker','services','processes','logs','network','terminal','activity']);
  if (requested && allowed.has(requested) && typeof goSection === 'function') {
    window.setTimeout(() => goSection(requested), 0);
  }
})();
</script>
"""
    return html.replace("</body>", deep_link + "\n</body>")


__all__ = ["app"]
