from app.docker_cleanup import DockerCleanupRequest, _parse_snapshot
from app.platform import app


def test_cleanup_preview_excludes_container_and_rollback_images() -> None:
    snapshot = """
__IMAGES__
sha256:aaa\tcustom-github/loanhub\tcurrent\t2026-09-19 06:00:00 +0000 UTC
sha256:bbb\tcustom-github/loanhub\trollback\t2026-09-18 06:00:00 +0000 UTC
sha256:ccc\tcustom-github/loanhub\told\t2026-09-10 06:00:00 +0000 UTC
sha256:ddd\t<none>\t<none>\t2026-09-01 06:00:00 +0000 UTC
__SIZES__
sha256:aaa\t100
sha256:bbb\t200
sha256:ccc\t300
sha256:ddd\t400
__CONTAINER_IMAGES__
sha256:aaa
__SYSTEM_DF__
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          4         1         1000B     700B
""".strip()

    result = _parse_snapshot(snapshot, {"custom-github/loanhub:rollback"})

    assert result["total_images"] == 4
    assert result["protected_images"] == 2
    assert result["candidate_images"] == 2
    assert result["estimated_reclaimable_bytes"] == 700
    candidate_ids = {item["id"] for item in result["candidates"]}
    assert candidate_ids == {"sha256:ccc", "sha256:ddd"}

    protected = {item["id"]: item["protection_reasons"] for item in result["protected"]}
    assert "referenced by a container" in protected["sha256:aaa"]
    assert "kept for deployment/rollback" in protected["sha256:bbb"]


def test_cleanup_request_defaults_to_images_only() -> None:
    request = DockerCleanupRequest(confirm=True)
    assert request.confirm is True
    assert request.clean_build_cache is False
    assert request.build_cache_older_than_hours == 168


def test_docker_cleanup_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/vps/{server_id}/docker-cleanup" in paths
    assert "/api/vps/servers/{server_id}/docker/cleanup/preview" in paths
    assert "/api/vps/servers/{server_id}/docker/cleanup" in paths
