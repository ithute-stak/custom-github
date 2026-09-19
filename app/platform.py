"""Custom GitHub application entry point with VPS management enabled.

The original control-plane module remains focused on repository, pipeline and deployment
behavior. This module composes that existing app with the VPS management surface so the
new functionality can evolve without turning app/main.py into a monolith.
"""

from app.main import APP_ROOT, app, audit, db, server_or_404
from app.vps import install_vps_routes

install_vps_routes(
    app,
    db_factory=db,
    server_lookup=server_or_404,
    audit_fn=audit,
    app_root=APP_ROOT,
)

__all__ = ["app"]
