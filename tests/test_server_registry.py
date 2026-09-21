import os
import sqlite3
import tempfile

from app.platform import app
from app.server_registry import _identity_state, _table_exists


def test_identity_state_flags_missing_and_existing_keys() -> None:
    missing = _identity_state("~/.ssh/definitely-not-a-real-custom-github-key")
    assert missing["configured"] is True
    assert missing["exists"] is False
    assert missing["state"] == "missing"

    with tempfile.NamedTemporaryFile() as handle:
        ready = _identity_state(handle.name)
        assert ready["configured"] is True
        assert ready["exists"] is True
        assert ready["state"] == "ready"

    default = _identity_state(None)
    assert default == {"configured": False, "exists": False, "path": None, "state": "not-configured"}


def test_table_exists_is_safe_for_optional_management_tables() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE server_events(id INTEGER PRIMARY KEY, server_id INTEGER)")
    assert _table_exists(connection, "server_events") is True
    assert _table_exists(connection, "server_metric_samples") is False


def test_server_registry_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/server-registry" in paths
    assert "/api/server-registry" in paths
    assert "/api/server-registry/{server_id}" in paths


def test_inventory_route_remains_registered_with_registry() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/api/vps/servers/{server_id}/docker/inventory" in paths
