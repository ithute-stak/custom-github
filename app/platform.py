"""Custom GitHub application entry point with VPS management enabled.

The repository/deployment dashboard remains available under /deployments, while the root
page is the VPS-first infrastructure control center. This keeps the existing CI/CD flow
intact without hiding the Linux server-management capabilities behind a secondary button.
"""

from fastapi.responses import HTMLResponse

from app.container_inventory import install_container_inventory_routes
from app.database_manager import install_database_routes
from app.docker_cleanup import install_docker_cleanup_routes
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


_CONTAINER_INVENTORY_DASHBOARD = r"""
<script id="container-inventory-dashboard">
(() => {
  const inventories = new Map();

  function ensureSection() {
    if (document.getElementById('containerInventorySection')) return;
    const manage = document.getElementById('manage');
    if (!manage) return;
    manage.insertAdjacentHTML('afterend', `
      <section class="section" id="containerInventorySection">
        <div class="section-title"><div><h2>Docker workload inventory</h2><div class="sub">Explains every running container by Compose stack and registered Custom GitHub project. “Review required” does not mean safe to delete.</div></div><div style="display:flex;gap:8px"><a class="btn" id="productionContractLink" href="#">Production Contract</a><button class="btn" id="inventoryRefreshBtn">↻ Analyze containers</button></div></div>
        <div class="grid">
          <div class="card c3 metric"><div class="label">Running on selected VPS</div><div class="value" id="invTotal">—</div><div class="caption">All running containers</div></div>
          <div class="card c3 metric"><div class="label">Registered projects</div><div class="value" id="invRegistered">—</div><div class="caption">Mapped to registered project stacks</div></div>
          <div class="card c3 metric"><div class="label">Compose stacks</div><div class="value" id="invStacks">—</div><div class="caption">Distinct running Compose projects</div></div>
          <div class="card c3 metric"><div class="label">Review required</div><div class="value" id="invReview">—</div><div class="caption">Unregistered stack or no Compose label</div></div>
        </div>
        <div class="grid" style="margin-top:14px">
          <article class="card c6"><div class="head"><div><h2>Running stacks</h2><div class="sub">A project can legitimately run several containers: app/API, database, cache, proxy and workers.</div></div></div><div class="pad"><div id="invStackRows" class="repo-list"><div class="empty">Analyzing Docker stacks…</div></div></div></article>
          <article class="card c6"><div class="head"><div><h2>Containers needing review</h2><div class="sub">Running containers that do not map to a registered Custom GitHub project.</div></div><a class="btn" id="invDockerLink" href="#">Open Docker</a></div><div class="pad"><div id="invReviewRows" class="repo-list"><div class="empty">Analyzing container ownership…</div></div></div></article>
        </div>
        <details class="card" style="margin-top:14px"><summary style="padding:15px 17px;cursor:pointer;font-size:12px;font-weight:800">Show every running container</summary><div class="pad"><div id="invContainerRows" class="repo-list"></div></div></details>
      </section>`);
    document.getElementById('inventoryRefreshBtn')?.addEventListener('click', loadInventories);
  }

  function roleText(roles) {
    const entries = Object.entries(roles || {});
    return entries.length ? entries.map(([k,v]) => `${k}: ${v}`).join(' · ') : 'No role classification';
  }

  function renderSelectedInventory() {
    ensureSection();
    const id = selectedId();
    const inv = inventories.get(Number(id));
    const contractLink=document.getElementById('productionContractLink'); if(contractLink && id) contractLink.href=`/vps/${id}/production-contract`;
    const set = (name, value) => { const el=document.getElementById(name); if(el) el.textContent=value; };
    if (!inv) {
      ['invTotal','invRegistered','invStacks','invReview'].forEach(x=>set(x,'—'));
      if (document.getElementById('invStackRows')) document.getElementById('invStackRows').innerHTML='<div class="empty">Container inventory unavailable for this VPS.</div>';
      return;
    }
    set('invTotal', inv.total_running);
    set('invRegistered', inv.registered_project_running);
    set('invStacks', inv.compose_stack_count);
    set('invReview', inv.review_required_running);
    const dockerLink=document.getElementById('invDockerLink'); if(dockerLink) dockerLink.href=`/vps/${id}?section=docker`;

    const stackRows=document.getElementById('invStackRows');
    stackRows.innerHTML=inv.stacks.length ? inv.stacks.map(s=>`<div class="repo"><div><b>${esc(s.name)}</b><small>${esc(s.registered_project ? `Registered project: ${s.registered_project}` : 'Not mapped to a registered project')} · ${esc(roleText(s.roles))}</small></div><span class="tag ${s.review_required?'red':'green'}">${s.container_count} container${s.container_count===1?'':'s'}</span></div>`).join('') : '<div class="empty">No running containers.</div>';

    const review=inv.containers.filter(c=>c.relation!=='registered-project');
    const reviewRows=document.getElementById('invReviewRows');
    reviewRows.innerHTML=review.length ? review.map(c=>`<div class="repo"><div><b>${esc(c.name)}</b><small>${esc(c.compose_project || 'No Compose project')} · ${esc(c.role)} · ${esc(c.image)}</small></div><span class="tag red">${esc(c.relation==='unmanaged'?'UNMANAGED':'UNREGISTERED STACK')}</span></div>`).join('') : '<div class="empty">Every running container maps to a registered project stack.</div>';

    const allRows=document.getElementById('invContainerRows');
    allRows.innerHTML=inv.containers.length ? inv.containers.map(c=>`<div class="repo"><div><b>${esc(c.name)}</b><small>${esc(c.compose_project || 'No Compose project')} / ${esc(c.compose_service || 'no service label')} · ${esc(c.role)} · ${esc(c.image)}</small></div><span class="tag ${c.relation==='registered-project'?'green':c.relation==='unmanaged'?'red':''}">${esc(c.registered_project || c.relation)}</span></div>`).join('') : '<div class="empty">No running containers.</div>';
  }

  function updateTopMetric() {
    const values=[...inventories.values()];
    if (!values.length) return;
    const total=values.reduce((n,x)=>n+Number(x.total_running||0),0);
    const registered=values.reduce((n,x)=>n+Number(x.registered_project_running||0),0);
    const review=values.reduce((n,x)=>n+Number(x.review_required_running||0),0);
    const count=document.getElementById('containerCount');
    if (count) {
      count.textContent=total;
      const card=count.closest('.metric');
      const label=card?.querySelector('.label'); const caption=card?.querySelector('.caption');
      if(label) label.textContent='All running containers';
      if(caption) caption.textContent=`${registered} mapped to registered projects · ${review} need review`;
    }
  }

  async function loadInventories() {
    ensureSection();
    const button=document.getElementById('inventoryRefreshBtn');
    if(button){button.disabled=true;button.textContent='Analyzing…';}
    try {
      const servers=(typeof S!=='undefined' && S.servers)||[];
      await Promise.all(servers.map(async s=>{
        try { inventories.set(Number(s.id), await api(`/api/vps/servers/${s.id}/docker/inventory`)); }
        catch (_) { inventories.delete(Number(s.id)); }
      }));
      updateTopMetric(); renderSelectedInventory();
    } finally {
      if(button){button.disabled=false;button.textContent='↻ Analyze containers';}
    }
  }

  ensureSection();
  document.getElementById('serverSelect')?.addEventListener('change',()=>setTimeout(renderSelectedInventory,0));
  window.setTimeout(loadInventories, 500);
  window.setInterval(loadInventories, 30000);
})();
</script>
"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def infrastructure_control_center() -> str:
    html = CONTROL_CENTER_PATH.read_text(encoding="utf-8")
    old_link = '<a href="#fleet"><span class="ico">▤</span>VPS Servers <span class="navbadge">LIVE</span></a>'
    new_link = '<a href="/server-registry"><span class="ico">▤</span>VPS Servers <span class="navbadge">REGISTRY</span></a>'
    html = html.replace(old_link, new_link)
    return html.replace("</body>", _CONTAINER_INVENTORY_DASHBOARD + "\n</body>")


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
    return html.replace("</body>", deep_link + "\n</body>")


__all__ = ["app"]
