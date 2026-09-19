"""Custom GitHub application entry point with VPS management enabled.

The repository/deployment dashboard remains available under /deployments, while the root
page is the VPS-first infrastructure control center. This keeps the existing CI/CD flow
intact without hiding the Linux server-management capabilities behind a secondary button.
"""

from fastapi.responses import HTMLResponse

from app.container_inventory import install_container_inventory_routes
from app.container_inventory_ui import CONTAINER_INVENTORY_DASHBOARD
from app.database_manager import install_database_routes
from app.docker_cleanup import install_docker_cleanup_routes
from app.file_manager_enhancements import FILE_MANAGER_ENHANCEMENT, install_file_manager_enhancements_routes
from app.main import APP_ROOT, DASHBOARD_PATH, app, audit, db, server_or_404
from app.maintenance import install_maintenance_routes
from app.production_contract import install_production_contract_routes
from app.server_registry import install_server_registry_routes
from app.vps import install_vps_routes

CONTROL_CENTER_PATH = APP_ROOT / "app" / "static" / "control-center.html"
VPS_DASHBOARD_PATH = APP_ROOT / "app" / "static" / "vps.html"

install_vps_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)
install_file_manager_enhancements_routes(app, server_lookup=server_or_404)
install_container_inventory_routes(app, db_factory=db, server_lookup=server_or_404)
install_docker_cleanup_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)
install_maintenance_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)
install_database_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)
install_server_registry_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)
install_production_contract_routes(
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
    html = CONTROL_CENTER_PATH.read_text(encoding="utf-8")
    old_link = '<a href="#fleet"><span class="ico">▤</span>VPS Servers <span class="navbadge">LIVE</span></a>'
    new_link = '<a href="/server-registry"><span class="ico">▤</span>VPS Servers <span class="navbadge">REGISTRY</span></a>'
    html = html.replace(old_link, new_link)
    return html.replace("</body>", CONTAINER_INVENTORY_DASHBOARD + "\n</body>")


@app.get("/deployments", response_class=HTMLResponse, include_in_schema=False)
def deployment_control_center() -> str:
    """Preserve the original repository, pipeline and deployment dashboard."""
    return DASHBOARD_PATH.read_text(encoding="utf-8")


@app.get("/vps/{server_id}", response_class=HTMLResponse, include_in_schema=False)
def vps_dashboard(server_id: int) -> str:
    """Serve the full VPS workspace and honor direct module links such as ?section=files."""
    server_or_404(server_id)
    html = VPS_DASHBOARD_PATH.read_text(encoding="utf-8")
    docker_toolbar = '<div class="toolbar"><button class="btn primary" onclick="loadDocker()">↻ Refresh Docker</button><button class="btn" onclick="loadDockerStorage()">Storage usage</button></div>'
    enhanced_toolbar = (
        '<div class="toolbar"><button class="btn primary" onclick="loadDocker()">↻ Refresh Docker</button>'
        '<button class="btn" onclick="loadDockerStorage()">Storage usage</button>'
        f'<a class="btn" href="/vps/{server_id}/production-contract">Production Contract</a>'
        f'<a class="btn" href="/vps/{server_id}/databases">Database Manager</a>'
        f'<a class="btn" href="/vps/{server_id}/maintenance">Maintenance Center</a>'
        f'<a class="btn danger" href="/vps/{server_id}/docker-cleanup">Cleanup unused images</a></div>'
    )
    html = html.replace(docker_toolbar, enhanced_toolbar)
    maintenance_nav = (
        '<div class="nav-title">Administration</div>'
        '<nav>'
        f'<a class="navbtn" href="/vps/{server_id}/production-contract"><span><span class="navico">✓</span>Production Contract</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/databases"><span><span class="navico">▦</span>Databases</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/maintenance"><span><span class="navico">◈</span>Maintenance Center</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/docker-cleanup"><span><span class="navico">⌫</span>Docker Cleanup</span></a>'
        '<a class="navbtn" href="/server-registry"><span><span class="navico">▤</span>Server Registry</span></a>'
        '</nav>'
    )
    html = html.replace('<div class="aside-foot">', maintenance_nav + '<div class="aside-foot">', 1)
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
    return html.replace("</body>", FILE_MANAGER_ENHANCEMENT + "\n" + deep_link + "\n</body>")


__all__ = ["app"]
