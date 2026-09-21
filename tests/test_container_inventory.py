from app.container_inventory import _container_role, _parse_inventory
from app.platform import app


def test_inventory_groups_registered_and_unregistered_stacks() -> None:
    context = {
        "aliases": {
            "loanhub": {"project_id": 1, "project_name": "loanhub", "targeted": True},
            "ithute": {"project_id": 2, "project_name": "ithute", "targeted": False},
        },
        "by_dir": {
            "/opt/loanhub": {
                "project_id": 1,
                "project_name": "loanhub",
                "targeted": True,
                "compose_dir": "/opt/loanhub",
                "service_name": "api",
            }
        },
    }
    output = "\n".join(
        [
            "a\tloanhub-api\tcustom/loanhub:abc\tloanhub\tapi\t/opt/loanhub\tUp 1 hour\t0.0.0.0:8000->8000/tcp",
            "b\tloanhub-db\tpostgres:17\tloanhub\tdb\t/opt/loanhub\tUp 1 hour\t5432/tcp",
            "c\tithute-web\tcustom/ithute:def\tithute\tweb\t/opt/ithute\tUp 1 hour\t443/tcp",
            "d\told-worker\tcustom/old:1\told-stack\tworker\t/opt/old\tUp 2 days\t",
            "e\tmanual-redis\tredis:7\t\t\t\tUp 2 days\t6379/tcp",
        ]
    )

    result = _parse_inventory(output, context)

    assert result["total_running"] == 5
    assert result["registered_project_running"] == 3
    assert result["unregistered_stack_running"] == 1
    assert result["unmanaged_running"] == 1
    assert result["review_required_running"] == 2
    assert result["compose_stack_count"] == 3
    assert result["registered_stack_count"] == 2

    stacks = {row["name"]: row for row in result["stacks"]}
    assert stacks["loanhub"]["container_count"] == 2
    assert stacks["loanhub"]["registered_project"] == "loanhub"
    assert stacks["loanhub"]["roles"]["database"] == 1
    assert stacks["old-stack"]["review_required"] is True
    assert stacks["Unmanaged / no Compose project"]["review_required"] is True


def test_container_roles_are_descriptive_not_delete_signals() -> None:
    assert _container_role("postgres:17", "db", "loanhub-db") == "database"
    assert _container_role("redis:7", "cache", "cache") == "cache-queue"
    assert _container_role("nginx:alpine", "proxy", "web-proxy") == "proxy"
    assert _container_role("custom/app:latest", "api", "loanhub-api") == "application"


def test_container_inventory_route_is_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/api/vps/servers/{server_id}/docker/inventory" in paths
