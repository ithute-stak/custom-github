from app.file_manager_enhancements import FILE_MANAGER_ENHANCEMENT
from app.platform import app


def test_file_manager_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/api/vps/servers/{server_id}/files/browse" in paths
    assert "/api/vps/servers/{server_id}/files/usage" in paths


def test_file_manager_supports_list_and_tile_views() -> None:
    assert 'id="fileListViewBtn"' in FILE_MANAGER_ENHANCEMENT
    assert 'id="fileTileViewBtn"' in FILE_MANAGER_ENHANCEMENT
    assert 'id="fileTilePane"' in FILE_MANAGER_ENHANCEMENT
    assert "custom-github.file-view" in FILE_MANAGER_ENHANCEMENT


def test_file_manager_exposes_folder_disk_usage_states() -> None:
    assert "Calculating folder sizes" in FILE_MANAGER_ENHANCEMENT
    assert "/files/usage?path=" in FILE_MANAGER_ENHANCEMENT
    assert "allocated disk usage" in FILE_MANAGER_ENHANCEMENT
    assert "Folder sizes unavailable" in FILE_MANAGER_ENHANCEMENT


def test_file_manager_keeps_sort_and_view_preferences() -> None:
    assert "custom-github.file-sort" in FILE_MANAGER_ENHANCEMENT
    assert "Sort: Name" in FILE_MANAGER_ENHANCEMENT
    assert "Sort: Size" in FILE_MANAGER_ENHANCEMENT
    assert "Sort: Modified" in FILE_MANAGER_ENHANCEMENT


def test_file_manager_uses_authoritative_browse_route() -> None:
    assert "/files/browse?path=" in FILE_MANAGER_ENHANCEMENT
    assert "Filesystem verified" in FILE_MANAGER_ENHANCEMENT
    assert "resolved_path" in FILE_MANAGER_ENHANCEMENT
    assert "mount_point" in FILE_MANAGER_ENHANCEMENT


def test_browse_and_usage_requests_have_independent_state() -> None:
    assert "browseToken" in FILE_MANAGER_ENHANCEMENT
    assert "usageToken" in FILE_MANAGER_ENHANCEMENT
    assert "requestToken" not in FILE_MANAGER_ENHANCEMENT


def test_usage_failure_does_not_replace_directory_listing() -> None:
    assert "Folder size scan failed" in FILE_MANAGER_ENHANCEMENT
    assert "usageBadge.textContent='Folder sizes unavailable'" in FILE_MANAGER_ENHANCEMENT
