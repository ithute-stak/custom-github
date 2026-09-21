"""Custom GitHub application entry point with VPS management enabled.

The repository/deployment dashboard remains available under /deployments, while the root
page is the VPS-first infrastructure control center. This module composes the management
surfaces and keeps the individual VPS capabilities in focused modules.
"""

import app.main as main_module
from fastapi.responses import HTMLResponse

from app.agent_control import install_agent_routes
from app.agent_transport import install_agent_transport_routes
from app.applications import install_application_routes
from app.backup_manager import install_backup_routes
from app.container_inventory import install_container_inventory_routes
from app.container_inventory_ui import CONTAINER_INVENTORY_DASHBOARD
from app.control_db import make_db_factory
from app.database_manager import install_database_routes
from app.docker_cleanup import install_docker_cleanup_routes
from app.domain_manager import install_domain_routes
from app.file_manager_enhancements import FILE_MANAGER_ENHANCEMENT, install_file_manager_enhancements_routes
from app.fleet import install_fleet_routes
from app.github_actions_live import GitHubActionsAPI, install_github_actions_routes
from app.github_app_webhooks import install_github_app_webhook_routes, resolve_github_token
from app.github_code_governance import GitHubRepoAPI, install_github_code_governance_routes
from app.github_event_ui import install_github_event_ui
from app.github_operations import GitHubAPI, install_github_operations_routes
from app.github_pull_requests import GitHubPullAPI, install_github_pull_request_routes
from app.main import (
    APP_ROOT,
    DASHBOARD_PATH,
    DATA_DIR,
    DB_PATH,
    app,
    audit,
    detect_pipeline,
    git_sha,
    project_or_404,
    run_deployment_task,
    server_or_404,
    sync_project,
    utc_now,
)
from app.maintenance import install_maintenance_routes
from app.observability import install_observability_routes
from app.offsite_backups import install_offsite_backup_routes
from app.pipeline_isolation import install_isolated_pipeline_route
from app.privilege_bridge import install_privilege_bridge
from app.production_contract import install_production_contract_routes
from app.production_readiness import install_readiness_routes
from app.reliability_center import install_reliability_routes
from app.reliability_index import install_reliability_index
from app.remote_hardening import install_remote_hardening
from app.security import install_security_routes
from app.security_bootstrap_guard import install_bootstrap_security_boundary
from app.security_scanner import install_security_scanner_routes
from app.security_websocket import secure_terminal_websocket
from app.server_registry import install_server_registry_routes
from app.system_admin import install_system_admin_routes
from app.vault import install_vault_routes
from app.vps import install_vps_routes

CONTROL_CENTER_PATH = APP_ROOT / "app" / "static" / "control-center.html"
VPS_DASHBOARD_PATH = APP_ROOT / "app" / "static" / "vps.html"

# The default remains SQLite. PostgreSQL is selected only through environment configuration
# and only after the verified migration/empty-schema gate in make_db_factory() succeeds.
db = make_db_factory(DB_PATH)
# app.main's helper functions resolve their module-level db global at call time. Replacing it
# here moves core repository/deployment routes and every composed module onto the same backend.
main_module.db = db
# Feature modules create tables with foreign keys to core projects/servers. Initialize the core
# schema immediately after selecting the backend so a brand-new PostgreSQL schema is composable.
main_module.init_db()

install_github_app_webhook_routes(app, db_factory=db, audit_fn=audit)
install_github_operations_routes(
    app,
    db_factory=db,
    project_lookup=project_or_404,
    audit_fn=audit,
    api_factory=lambda: GitHubAPI(token=resolve_github_token()),
)
install_github_actions_routes(
    app,
    project_lookup=project_or_404,
    audit_fn=audit,
    api_factory=lambda: GitHubActionsAPI(token=resolve_github_token()),
)
install_github_pull_request_routes(
    app,
    project_lookup=project_or_404,
    audit_fn=audit,
    api_factory=lambda: GitHubPullAPI(token=resolve_github_token()),
)
install_github_code_governance_routes(
    app,
    project_lookup=project_or_404,
    audit_fn=audit,
    api_factory=lambda: GitHubRepoAPI(token=resolve_github_token()),
)
install_github_event_ui(app)
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
install_domain_routes(app, server_lookup=server_or_404, audit_fn=audit)
install_backup_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_offsite_backup_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_system_admin_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_privilege_bridge(app, server_lookup=server_or_404)
install_observability_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_security_scanner_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_application_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_fleet_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_vault_routes(app, db_factory=db, audit_fn=audit, data_dir=DATA_DIR)
install_agent_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_agent_transport_routes(app, db_factory=db, audit_fn=audit)
install_readiness_routes(app, db_factory=db, server_lookup=server_or_404, audit_fn=audit)
install_isolated_pipeline_route(
    app,
    db_factory=db,
    project_lookup=project_or_404,
    sync_fn=sync_project,
    git_sha_fn=git_sha,
    detect_pipeline_fn=detect_pipeline,
    audit_fn=audit,
    runs_root=DATA_DIR / "runner-workspaces",
    utc_now_fn=utc_now,
)
install_reliability_routes(
    app,
    db_factory=db,
    project_lookup=project_or_404,
    server_lookup=server_or_404,
    audit_fn=audit,
    deployment_runner=run_deployment_task,
)
install_reliability_index(app, db_factory=db)
# Install browser security after all management routes so one RBAC policy protects the full UI/API.
# Dedicated /auth/agent/v1 transport and /auth/github/webhook perform their own authentication.
install_security_routes(app, db_factory=db, audit_fn=audit)
install_remote_hardening(app, db_factory=db)
install_bootstrap_security_boundary(app, db)
secure_terminal_websocket(app)

# The base module originally owns GET /. VPS management also installs GET /vps/{server_id}.
# Replace only those two HTML routes here; API and WebSocket routes remain untouched.
for route in list(app.router.routes):
    methods = getattr(route, "methods", None) or set()
    path = getattr(route, "path", None)
    if path == "/" and "GET" in methods:
        app.router.routes.remove(route)
    elif path == "/vps/{server_id}" and "GET" in methods:
        app.router.routes.remove(route)


@app.get("/api/control-plane/database")
def control_database_status() -> dict[str, str]:
    """Expose backend identity without exposing database credentials."""
    return {
        "backend": str(getattr(db, "backend", "sqlite")),
        "location": str(getattr(db, "location", DB_PATH)),
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def infrastructure_control_center() -> str:
    html = CONTROL_CENTER_PATH.read_text(encoding="utf-8")
    old_link = '<a href="#fleet"><span class="ico">▤</span>VPS Servers <span class="navbadge">LIVE</span></a>'
    new_link = (
        '<a href="/server-registry"><span class="ico">▤</span>VPS Servers <span class="navbadge">REGISTRY</span></a>'
        '<a href="/fleet"><span class="ico">⌘</span>Multi-VPS Fleet <span class="navbadge">GROUPS</span></a>'
        '<a href="/agents"><span class="ico">◉</span>VPS Agents <span class="navbadge">LIVE</span></a>'
        '<a href="/github"><span class="ico">⌘</span>GitHub Operations <span class="navbadge">SOURCE</span></a>'
        '<a href="/github/code"><span class="ico">&lt;/&gt;</span>GitHub Code <span class="navbadge">BROWSE</span></a>'
        '<a href="/github/pulls"><span class="ico">⎇</span>Pull Request Center <span class="navbadge">REVIEW</span></a>'
        '<a href="/github/actions"><span class="ico">▶</span>GitHub Actions <span class="navbadge">LIVE</span></a>'
        '<a href="/reliability"><span class="ico">↺</span>Reliability Center <span class="navbadge">RELEASES</span></a>'
    )
    html = html.replace(old_link, new_link)
    if "/security" not in html:
        marker = new_link
        security_link = (
            marker
            + '<a href="/security"><span class="ico">◈</span>Security Center <span class="navbadge">RBAC</span></a>'
            + '<a href="/vault"><span class="ico">◆</span>Secrets Vault <span class="navbadge">ENCRYPTED</span></a>'
        )
        html = html.replace(marker, security_link, 1)
    backend_badge = (
        "<div style='position:fixed;right:18px;bottom:18px;z-index:50;background:#173c38;color:white;"
        "padding:8px 12px;border-radius:999px;font:700 11px system-ui'>CONTROL DB · "
        + str(getattr(db, "backend", "sqlite")).upper()
        + "</div>"
    )
    return html.replace("</body>", CONTAINER_INVENTORY_DASHBOARD + backend_badge + "\n</body>")


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
        f'<a class="btn" href="/vps/{server_id}/applications">Applications</a>'
        f'<a class="btn" href="/vps/{server_id}/readiness">Production Readiness</a>'
        '<a class="btn" href="/reliability">Release & DR</a>'
        f'<a class="btn" href="/vps/{server_id}/production-contract">Production Contract</a>'
        f'<a class="btn" href="/vps/{server_id}/databases">Database Manager</a>'
        f'<a class="btn" href="/vps/{server_id}/observability">Monitoring</a>'
        f'<a class="btn" href="/vps/{server_id}/security-scan">Security Scan</a>'
        f'<a class="btn" href="/vps/{server_id}/domains">Domains & SSL</a>'
        f'<a class="btn" href="/vps/{server_id}/backups">Backups</a>'
        f'<a class="btn" href="/vps/{server_id}/offsite-backups">Off-site</a>'
        f'<a class="btn" href="/vps/{server_id}/system-admin">System Admin</a>'
        f'<a class="btn" href="/vps/{server_id}/maintenance">Maintenance Center</a>'
        f'<a class="btn danger" href="/vps/{server_id}/docker-cleanup">Cleanup unused images</a></div>'
    )
    html = html.replace(docker_toolbar, enhanced_toolbar)
    administration_nav = (
        '<div class="nav-title">Applications & Administration</div>'
        '<nav>'
        f'<a class="navbtn" href="/vps/{server_id}/applications"><span><span class="navico">▣</span>Applications</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/readiness"><span><span class="navico">✓</span>Production Readiness</span></a>'
        '<a class="navbtn" href="/reliability"><span><span class="navico">↺</span>Release / Drift / DR</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/production-contract"><span><span class="navico">✓</span>Production Contract</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/databases"><span><span class="navico">▦</span>Databases</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/observability"><span><span class="navico">⌁</span>Monitoring & Incidents</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/security-scan"><span><span class="navico">盾</span>Security Scanner</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/domains"><span><span class="navico">◎</span>Domains & SSL</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/backups"><span><span class="navico">↺</span>Backup & Restore</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/offsite-backups"><span><span class="navico">⇱</span>Off-site Recovery</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/system-admin"><span><span class="navico">⚙</span>System Admin</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/maintenance"><span><span class="navico">◈</span>Maintenance Center</span></a>'
        f'<a class="navbtn" href="/vps/{server_id}/docker-cleanup"><span><span class="navico">⌫</span>Docker Cleanup</span></a>'
        '<a class="navbtn" href="/fleet"><span><span class="navico">⌘</span>Multi-VPS Fleet</span></a>'
        '<a class="navbtn" href="/agents"><span><span class="navico">◉</span>VPS Agents</span></a>'
        '<a class="navbtn" href="/github"><span><span class="navico">⌘</span>GitHub Operations</span></a>'
        '<a class="navbtn" href="/github/code"><span><span class="navico">&lt;/&gt;</span>GitHub Code</span></a>'
        '<a class="navbtn" href="/github/pulls"><span><span class="navico">⎇</span>Pull Request Center</span></a>'
        '<a class="navbtn" href="/github/actions"><span><span class="navico">▶</span>GitHub Actions</span></a>'
        '<a class="navbtn" href="/server-registry"><span><span class="navico">▤</span>Server Registry</span></a>'
        '<a class="navbtn" href="/security"><span><span class="navico">◆</span>Security Center</span></a>'
        '<a class="navbtn" href="/vault"><span><span class="navico">◇</span>Secrets Vault</span></a>'
        '</nav>'
    )
    html = html.replace('<div class="aside-foot">', administration_nav + '<div class="aside-foot">', 1)
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
