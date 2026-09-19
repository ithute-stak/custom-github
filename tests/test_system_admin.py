import pytest
from pydantic import ValidationError

from app.platform import app
from app.system_admin import CronCreate, FirewallRule, LinuxUserCreate, PackageAction


def test_system_admin_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    expected = {
        "/vps/{server_id}/system-admin",
        "/api/vps/servers/{server_id}/system-admin/users",
        "/api/vps/servers/{server_id}/system-admin/users/{username}/keys",
        "/api/vps/servers/{server_id}/system-admin/firewall",
        "/api/vps/servers/{server_id}/system-admin/firewall/rules",
        "/api/vps/servers/{server_id}/system-admin/packages",
        "/api/vps/servers/{server_id}/system-admin/packages/action",
        "/api/vps/servers/{server_id}/system-admin/reboot",
        "/api/vps/servers/{server_id}/system-admin/cron",
    }
    assert expected.issubset(paths)


def test_linux_user_payload_validates_groups_and_shell() -> None:
    payload = LinuxUserCreate(
        username="deploy2",
        display_name="Deployment Operator",
        groups=["docker", "www-data"],
        sudo=True,
        public_key=None,
    )
    assert payload.groups == ["docker", "www-data"]
    with pytest.raises(ValidationError):
        LinuxUserCreate(username="bad", groups=["not a group"])


def test_firewall_rule_validates_cidr_and_port() -> None:
    rule = FirewallRule(action="allow", port=443, protocol="tcp", source="10.0.0.7/24")
    assert rule.source == "10.0.0.0/24"
    with pytest.raises(ValidationError):
        FirewallRule(action="allow", port=70000, protocol="tcp")
    with pytest.raises(ValidationError):
        FirewallRule(action="deny", port=22, protocol="icmp")


def test_package_names_reject_shell_syntax() -> None:
    good = PackageAction(action="install", packages=["fail2ban", "nginx-core"])
    assert good.packages == ["fail2ban", "nginx-core"]
    with pytest.raises(ValidationError):
        PackageAction(action="install", packages=["nginx;rm -rf /"])


def test_managed_cron_requires_five_numeric_fields_and_single_line_command() -> None:
    job = CronCreate(name="backup-nightly", schedule="0 2 * * *", run_as="root", command="/usr/local/bin/backup --quiet")
    assert job.schedule == "0 2 * * *"
    with pytest.raises(ValidationError):
        CronCreate(name="bad", schedule="@reboot", run_as="root", command="echo hi")
    with pytest.raises(ValidationError):
        CronCreate(name="bad", schedule="0 2 * * *", run_as="root", command="echo ok\nrm -rf /tmp/x")
