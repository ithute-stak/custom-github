from app.file_manager_enhancements import FILE_MANAGER_ENHANCEMENT
from app.platform import app


def test_folder_usage_route_is_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
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
