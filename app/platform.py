"""Custom GitHub application entry point with VPS management enabled.

The original control-plane module remains focused on repository, pipeline and deployment
behavior. This module composes that existing app with the VPS management surface so the
new functionality can evolve without turning app/main.py into a monolith.
"""

from fastapi.responses import HTMLResponse

from app.main import APP_ROOT, DASHBOARD_PATH, app, audit, db, server_or_404
from app.vps import install_vps_routes

install_vps_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)

# Replace only the original GET / dashboard route with an enhanced version. The base
# dashboard markup stays untouched; a tiny client-side enhancement adds an explicit
# VPS Manager link to every rendered server card.
for route in list(app.router.routes):
    methods = getattr(route, "methods", None) or set()
    if getattr(route, "path", None) == "/" and "GET" in methods:
        app.router.routes.remove(route)
        break


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def platform_dashboard() -> str:
    html = DASHBOARD_PATH.read_text(encoding="utf-8")
    enhancement = r"""
<script id="vps-manager-dashboard-enhancement">
(() => {
  function attachVpsManagerButtons() {
    document.querySelectorAll('#servers .server').forEach(card => {
      if (card.querySelector('.vps-manager-link')) return;
      const checkButton = card.querySelector('button[onclick^="checkServer("]');
      if (!checkButton) return;
      const match = (checkButton.getAttribute('onclick') || '').match(/checkServer\((\d+)/);
      if (!match) return;
      const link = document.createElement('a');
      link.href = `/vps/${match[1]}`;
      link.className = 'button primary vps-manager-link';
      link.style.marginLeft = '8px';
      link.textContent = 'Open VPS Manager';
      checkButton.insertAdjacentElement('afterend', link);
    });
  }

  const target = document.getElementById('servers');
  if (target) {
    new MutationObserver(attachVpsManagerButtons).observe(target, {childList: true, subtree: true});
    attachVpsManagerButtons();
  }
})();
</script>
"""
    return html.replace("</body>", enhancement + "\n</body>")


__all__ = ["app"]
