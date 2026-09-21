from app.observability import AlertPolicyUpdate, _conditions, _parse_sample
from app.platform import app


def test_parse_live_metric_sample() -> None:
    raw = """
cpu_percent=37.5
memory_percent=61.2
disk_percent=72
load_1=2.50
cpu_count=4
network_rx_bytes=1000
network_tx_bytes=2000
containers_running=27
containers_total=29
max_container_restarts=2
failed_services=0
reboot_required=1
""".strip()
    result = _parse_sample(raw)
    assert result["cpu_percent"] == 37.5
    assert result["containers_running"] == 27
    assert result["reboot_required"] is True


def test_alert_conditions_distinguish_warning_and_critical() -> None:
    policy = AlertPolicyUpdate().model_dump()
    sample = {
        "cpu_percent": 96.0,
        "memory_percent": 81.0,
        "disk_percent": 91.0,
        "load_1": 2.0,
        "cpu_count": 4,
        "network_rx_bytes": 0,
        "network_tx_bytes": 0,
        "containers_running": 27,
        "containers_total": 27,
        "max_container_restarts": 4,
        "failed_services": 1,
        "reboot_required": True,
    }
    conditions = _conditions(sample, policy)
    assert conditions["cpu"]["severity"] == "critical"
    assert conditions["memory"]["severity"] == "warning"
    assert conditions["disk"]["severity"] == "critical"
    assert conditions["failed-services"]["severity"] == "critical"
    assert "container-restarts" in conditions
    assert "reboot-required" in conditions


def test_healthy_sample_produces_no_resource_incident() -> None:
    policy = AlertPolicyUpdate().model_dump()
    sample = {
        "cpu_percent": 20.0,
        "memory_percent": 40.0,
        "disk_percent": 35.0,
        "load_1": 0.5,
        "cpu_count": 4,
        "network_rx_bytes": 0,
        "network_tx_bytes": 0,
        "containers_running": 27,
        "containers_total": 27,
        "max_container_restarts": 0,
        "failed_services": 0,
        "reboot_required": False,
    }
    assert _conditions(sample, policy) == {}


def test_observability_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    assert "/vps/{server_id}/observability" in paths
    assert "/api/vps/servers/{server_id}/observability/sample" in paths
    assert "/api/vps/servers/{server_id}/observability/history" in paths
    assert "/api/vps/servers/{server_id}/observability/incidents" in paths
    assert "/api/vps/servers/{server_id}/observability/incidents/{incident_id}" in paths
    assert "/api/vps/servers/{server_id}/observability/policy" in paths
