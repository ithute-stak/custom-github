import pytest
from fastapi import HTTPException

from app.fleet import _normalize_unit
from app.offsite_backups import TargetCreate, _safe_identity, _safe_remote_path
from app.platform import app


def test_offsite_paths_require_dedicated_absolute_locations() -> None:
    assert _safe_remote_path('/srv/backups/custom-github') == '/srv/backups/custom-github'
    assert _safe_identity('/home/deploy/.ssh/offsite') == '/home/deploy/.ssh/offsite'
    for value in ['/', '/etc', '/usr', '/var', '/home', '/root', 'relative/path']:
        with pytest.raises(ValueError):
            _safe_remote_path(value)
    with pytest.raises(ValueError):
        _safe_identity('id_ed25519')


def test_offsite_target_validation() -> None:
    target = TargetCreate(
        name='recovery-1',
        host='backup.example.com',
        ssh_user='backup',
        remote_path='/srv/backups/custom-github',
        identity_file='/home/deploy/.ssh/offsite',
    )
    assert target.port == 22
    assert target.retention_count == 14
    with pytest.raises(Exception):
        TargetCreate(
            name='bad',
            host='user@host;rm',
            ssh_user='backup',
            remote_path='/srv/backups/custom-github',
            identity_file='/home/deploy/.ssh/offsite',
        )


def test_fleet_bulk_restart_blocks_connectivity_services() -> None:
    assert _normalize_unit('nginx') == 'nginx.service'
    assert _normalize_unit('fail2ban.service') == 'fail2ban.service'
    for service in ['ssh', 'sshd.service', 'ufw', 'firewalld', 'systemd-networkd']:
        with pytest.raises(HTTPException):
            _normalize_unit(service)


def test_offsite_and_fleet_routes_are_registered() -> None:
    paths = {getattr(route, 'path', '') for route in app.router.routes}
    expected = {
        '/fleet',
        '/api/fleet/groups',
        '/api/fleet/groups/{group_id}/state',
        '/api/fleet/groups/{group_id}/restart-service',
        '/vps/{server_id}/offsite-backups',
        '/api/vps/servers/{server_id}/offsite/targets',
        '/api/vps/servers/{server_id}/offsite/targets/{target_id}/test',
        '/api/vps/servers/{server_id}/offsite/targets/{target_id}/sync-latest/{profile_id}',
    }
    assert expected.issubset(paths)
