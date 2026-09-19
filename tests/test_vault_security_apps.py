import os

from app.applications import _expected
from app.platform import app
from app.security_scanner import _evaluate
from app.vault import _load_fernet, _master_key_path


def test_vault_generates_separate_key_and_encrypts_round_trip(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("CUSTOM_GITHUB_VAULT_KEY", raising=False)
    monkeypatch.delenv("CUSTOM_GITHUB_VAULT_KEY_FILE", raising=False)
    fernet = _load_fernet(tmp_path, create=True)
    key_path = _master_key_path(tmp_path)
    assert key_path.exists()
    assert key_path != tmp_path / "custom-github.db"
    assert os.stat(key_path).st_mode & 0o777 == 0o600
    token = fernet.encrypt(b"super-secret-value")
    assert b"super-secret-value" not in token
    assert _load_fernet(tmp_path).decrypt(token) == b"super-secret-value"


def test_application_contract_counts_are_exact() -> None:
    assert len(_expected("loanhub")) == 5
    assert len(_expected("ithute")) == 22
    assert set(_expected("loanhub")) == {"db", "redis", "backend", "maintenance", "frontend"}


def test_security_scanner_detects_public_database_and_docker_risk() -> None:
    findings = _evaluate(
        {
            "sshd": ["permitrootlogin yes", "passwordauthentication yes", "permitemptypasswords no"],
            "ufw": ["Status: inactive"],
            "fail2ban": ["not-installed-or-failed"],
            "unattended": ["missing"],
            "listen": ["tcp LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:*"],
            "docker": ["/bad\t\ttrue\thost\t/var/run/docker.sock=>/var/run/docker.sock;"],
            "world_writable_etc": ["/etc/example.conf"],
            "docker_socket": ["666 root:docker /var/run/docker.sock"],
        }
    )
    keys = {item["key"] for item in findings}
    assert "ssh-root-login" in keys
    assert "public-data-port" in keys
    assert "docker-privileged" in keys
    assert "docker-socket" in keys
    assert "firewall-inactive" in keys
    assert "fail2ban" in keys


def test_security_scanner_clean_baseline_returns_info() -> None:
    findings = _evaluate(
        {
            "sshd": ["permitrootlogin no", "passwordauthentication no", "permitemptypasswords no"],
            "ufw": ["Status: active"],
            "fail2ban": ["Status", "Jail list: sshd"],
            "unattended": ["installed"],
            "listen": ["tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:*"],
            "docker": [],
            "world_writable_etc": [],
            "docker_socket": ["660 root:docker /var/run/docker.sock"],
        }
    )
    assert findings == [
        {
            "key": "baseline-clean",
            "severity": "info",
            "title": "No baseline security findings detected",
            "evidence": "Live checks completed",
            "recommendation": "Continue patching, monitoring and reviewing application-specific exposure.",
        }
    ]


def test_vault_scanner_and_application_routes_registered_once() -> None:
    paths = [getattr(route, "path", "") for route in app.router.routes]
    expected = {
        "/vault",
        "/api/vault/status",
        "/api/vault/items",
        "/vps/{server_id}/security-scan",
        "/api/vps/servers/{server_id}/security/scan",
        "/api/vps/servers/{server_id}/security/fail2ban",
        "/vps/{server_id}/applications",
        "/vps/{server_id}/applications/{app_key}",
        "/api/vps/servers/{server_id}/applications/{app_key}",
    }
    assert expected.issubset(set(paths))
    for path in expected:
        assert paths.count(path) >= 1
