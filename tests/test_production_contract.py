from app.platform import app
from app.production_contract import (
    APPROVED_RUNNING,
    APPROVED_TRANSIENT,
    EXPECTED_RUNNING_COUNT,
    classify_container,
    image_matches,
    parse_inventory,
    summarize,
)


def row(project: str, service: str, image: str, state: str = "running") -> dict[str, str]:
    return {
        "id": f"{project}-{service}",
        "name": f"{project}-{service}-1",
        "image": image,
        "compose_project": project,
        "compose_service": service,
        "status": "Up 1 hour" if state == "running" else "Exited (0) 1 hour ago",
        "state": state,
        "created": "2026-09-19 00:00:00 +0000 UTC",
    }


def expected_image(patterns: tuple[str, ...]) -> str:
    pattern = patterns[0]
    return pattern + "a" * 40 if pattern.endswith(":") else pattern


def test_contract_has_exact_27_steady_state_services() -> None:
    assert EXPECTED_RUNNING_COUNT == 27
    assert len(APPROVED_RUNNING) == 27
    assert len([key for key in APPROVED_RUNNING if key[0] == "loanhub"]) == 5
    assert len([key for key in APPROVED_RUNNING if key[0] == "ithute"]) == 22
    assert ("loanhub", "migrate") in APPROVED_TRANSIENT


def test_image_matching_supports_release_tags_but_not_wrong_repo() -> None:
    assert image_matches("loanhub-backend:abc123", ("loanhub-backend:",))
    assert image_matches("ithute-web:" + "a" * 40, ("ithute-web:",))
    assert image_matches("postgres:16-alpine", ("postgres:16-alpine",))
    assert not image_matches("postgres:17-alpine", ("postgres:16-alpine",))
    assert not image_matches("wrong:abc123", ("loanhub-backend:",))


def test_unknown_container_and_wrong_image_are_non_approved() -> None:
    unknown = classify_container(row("old-stack", "api", "old-app:latest"))
    assert unknown["classification"] == "non-approved"
    assert unknown["approved"] is False

    wrong = classify_container(row("loanhub", "backend", "some-other-backend:latest"))
    assert wrong["classification"] == "image-mismatch"
    assert wrong["approved"] is False


def test_migrate_is_approved_transient_not_steady_state() -> None:
    migrate = classify_container(row("loanhub", "migrate", "loanhub-backend:abc123"))
    assert migrate["classification"] == "approved-transient"
    assert migrate["approved"] is True
    assert migrate["expected_running"] is False


def test_summary_recognizes_clean_27_plus_transient() -> None:
    rows = [
        classify_container(row(project, service, expected_image(images)))
        for (project, service), images in APPROVED_RUNNING.items()
    ]
    rows.append(classify_container(row("loanhub", "migrate", "loanhub-backend:abc123")))
    summary = summarize(rows)
    assert summary["expected_running"] == 27
    assert summary["actual_running"] == 28
    assert summary["approved_running"] == 27
    assert summary["transient_running"] == 1
    assert summary["non_approved_running"] == 0
    assert summary["missing_expected"] == 0


def test_summary_surfaces_two_extra_running_containers() -> None:
    rows = [
        classify_container(row(project, service, expected_image(images)))
        for (project, service), images in APPROVED_RUNNING.items()
    ]
    rows.extend(
        [
            classify_container(row("old-loanhub", "api", "old-loanhub:1")),
            classify_container(row("", "", "legacy-worker:latest")),
        ]
    )
    summary = summarize(rows)
    assert summary["actual_running"] == 29
    assert summary["approved_running"] == 27
    assert summary["non_approved_running"] == 2
    assert summary["missing_expected"] == 0


def test_parser_understands_compose_labels() -> None:
    output = "\n".join(
        [
            "a\tloanhub-backend-1\tloanhub-backend:abc\tloanhub\tbackend\tUp 1 hour\trunning\t2026-09-19",
            "b\trogue\trogue:latest\told\tweb\tUp 1 hour\trunning\t2026-09-19",
        ]
    )
    parsed = parse_inventory(output)
    assert parsed[0]["approved"] is True
    assert parsed[1]["approved"] is False


def test_production_contract_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/vps/{server_id}/production-contract" in paths
    assert "/api/vps/servers/{server_id}/production-contract" in paths
    assert "/api/vps/servers/{server_id}/production-contract/cleanup" in paths
