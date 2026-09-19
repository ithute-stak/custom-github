from __future__ import annotations

import base64
import html
import shlex
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app import system_admin as system_admin_module
from app.deployment import ssh_command

HELPER_PATH = "/usr/local/sbin/custom-github-privileged"
SUDOERS_PATH = "/etc/sudoers.d/custom-github-control-plane"


def privileged_command(command: str) -> str:
    """Run a System Admin command as root via the policy-enforcing VPS helper.

    Root SSH sessions execute the existing command directly. Non-root sessions may elevate
    only through the root-owned helper installed by scripts/bootstrap-vps-privileges.sh.
    The helper validates the decoded operation before invoking a root shell.
    """
    encoded = base64.b64encode(command.encode("utf-8")).decode("ascii")
    return (
        'if [ "$(id -u)" -eq 0 ]; then '
        + command
        + f"; else sudo -n {HELPER_PATH} run {shlex.quote(encoded)}; fi"
    )


def _bootstrap_command(server: dict[str, Any]) -> str:
    parts = [
        "bash",
        "scripts/bootstrap-vps-privileges.sh",
        "--host",
        str(server["host"]),
        "--user",
        str(server["ssh_user"]),
        "--port",
        str(server["port"]),
    ]
    identity = str(server.get("identity_file") or "").strip()
    if identity:
        parts.extend(["--identity", identity])
    return " ".join(shlex.quote(part) for part in parts)


def _probe(server: dict[str, Any]) -> dict[str, Any]:
    script = f'''set +e
uid=$(id -u)
printf 'uid=%s\\n' "$uid"
if [ "$uid" -eq 0 ]; then
  printf 'helper_installed=%s\\n' "$([ -x {shlex.quote(HELPER_PATH)} ] && echo yes || echo no)"
  printf 'ready=yes\\n'
  printf 'mode=root\\n'
  exit 0
fi
if [ -x {shlex.quote(HELPER_PATH)} ]; then
  printf 'helper_installed=yes\\n'
else
  printf 'helper_installed=no\\n'
fi
out=$(sudo -n {shlex.quote(HELPER_PATH)} probe 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'CUSTOM_GITHUB_PRIVILEGE_READY=1'; then
  printf 'ready=yes\\n'
  printf 'mode=bridge\\n'
else
  printf 'ready=no\\n'
  printf 'mode=unconfigured\\n'
  printf 'error_b64=%s\\n' "$(printf '%s' "$out" | base64 -w0)"
fi
'''.strip()
    code, output = ssh_command(server, script, timeout=20)
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    error = ""
    if values.get("error_b64"):
        try:
            error = base64.b64decode(values["error_b64"]).decode("utf-8", errors="replace")
        except Exception:
            error = "Unable to decode privilege diagnostic"
    ready = code == 0 and values.get("ready") == "yes"
    return {
        "ready": ready,
        "mode": values.get("mode", "unknown"),
        "remote_uid": int(values["uid"]) if values.get("uid", "").isdigit() else None,
        "helper_installed": values.get("helper_installed") == "yes",
        "helper_path": HELPER_PATH,
        "sudoers_path": SUDOERS_PATH,
        "error": error.strip()[-3000:],
        "raw_probe_exit": code,
    }


def _remove_route(app: FastAPI, path: str, method: str) -> None:
    method = method.upper()
    for route in list(app.router.routes):
        methods = getattr(route, "methods", None) or set()
        if getattr(route, "path", None) == path and method in methods:
            app.router.routes.remove(route)


def install_privilege_bridge(
    app: FastAPI,
    *,
    server_lookup: Callable[[int], Any],
) -> None:
    # Routes registered in app.system_admin resolve this module global at request time, so
    # swapping the elevation wrapper upgrades all existing privileged operations without
    # duplicating their validation/business logic.
    system_admin_module._sudo = privileged_command

    @app.get("/api/vps/servers/{server_id}/system-admin/privilege")
    def privilege_status(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        state = _probe(server)
        state.update(
            {
                "ssh_user": server["ssh_user"],
                "host": server["host"],
                "port": server["port"],
                "bootstrap_command": _bootstrap_command(server),
                "note": "One-time interactive setup. Custom GitHub does not store the sudo password and does not configure NOPASSWD: ALL.",
            }
        )
        return state

    # Replace the page only to add a clear privilege-state banner. All original tabs/actions
    # remain sourced from System Admin's canonical HTML.
    _remove_route(app, "/vps/{server_id}/system-admin", "GET")

    @app.get("/vps/{server_id}/system-admin", response_class=HTMLResponse, include_in_schema=False)
    def system_admin_page_with_privilege_state(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        page = system_admin_module.ADMIN_HTML.replace("__SERVER_ID__", str(server_id)).replace(
            "__SERVER_NAME__", str(server["name"])
        )
        banner = r'''
<div id="privilegeState" style="border:1px solid #dfe7e2;background:#fff;border-radius:14px;padding:14px 16px;margin:14px 0">
  <b>Privileged access</b>
  <div id="privilegeMessage" class="sub" style="margin-top:5px">Checking the VPS privilege bridge…</div>
  <div id="privilegeSetup" style="display:none;margin-top:10px">
    <div class="sub">Run this once from the Custom GitHub repository on your PC. SSH may ask for your VPS sudo password during setup; the password is never stored by Custom GitHub.</div>
    <div class="row"><input id="privilegeCommand" readonly style="min-width:min(850px,90vw);font-family:monospace"><button onclick="copyPrivilegeCommand()">Copy setup command</button><button onclick="loadPrivilegeState()">Recheck privileged access</button></div>
  </div>
</div>
'''
        page = page.replace('<div class="tabs">', banner + '<div class="tabs">', 1)
        script = f'''
<script id="privilege-bridge-ui">
async function loadPrivilegeState(){{
  const msg=document.getElementById('privilegeMessage');
  const setup=document.getElementById('privilegeSetup');
  try{{
    const r=await fetch('/api/vps/servers/{server_id}/system-admin/privilege');
    const d=await r.json();
    if(!r.ok) throw new Error(d.detail||`HTTP ${{r.status}}`);
    if(d.ready){{
      msg.innerHTML=`<span style="color:#167347;font-weight:800">READY</span> · ${{d.mode==='root'?'SSH session is root':'restricted privilege bridge active'}}`;
      setup.style.display='none';
    }}else{{
      msg.innerHTML=`<span style="color:#b42335;font-weight:800">SETUP REQUIRED</span> · The SSH account <b>${{d.ssh_user}}</b> cannot run System Administration commands non-interactively.${{d.error?' · '+d.error:''}}`;
      document.getElementById('privilegeCommand').value=d.bootstrap_command||'';
      setup.style.display='block';
    }}
  }}catch(e){{msg.textContent='Unable to check privileged access: '+e.message;setup.style.display='none'}}
}}
async function copyPrivilegeCommand(){{
  const el=document.getElementById('privilegeCommand');
  try{{await navigator.clipboard.writeText(el.value)}}catch{{el.select();document.execCommand('copy')}}
}}
loadPrivilegeState();
</script>
'''
        return page.replace("</body>", script + "\n</body>")

    # Replace only the read-only firewall endpoint so lack of sudo does not hide useful live
    # listening-port data. Mutating firewall routes remain the canonical System Admin routes and
    # automatically use privileged_command through the patched _sudo global above.
    _remove_route(app, "/api/vps/servers/{server_id}/system-admin/firewall", "GET")

    @app.get("/api/vps/servers/{server_id}/system-admin/firewall")
    def firewall_with_partial_truth(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        code, installed_out = ssh_command(
            server,
            "command -v ufw >/dev/null 2>&1 && echo yes || echo no",
            timeout=15,
        )
        installed = code == 0 and installed_out.strip() == "yes"
        _, listening = ssh_command(server, "ss -lntupH 2>/dev/null || true", timeout=30)
        privilege = _probe(server)
        if not installed:
            return {
                "installed": False,
                "active": False,
                "rules": "UFW is not installed on this VPS.",
                "verbose": "",
                "listening": listening,
                "ssh_port": server["port"],
                "privilege_ready": privilege["ready"],
                "checked_at": system_admin_module._utc_now(),
            }
        if not privilege["ready"]:
            message = (
                "Privileged access is not configured yet. UFW status needs root access. "
                "Listening ports below are still live data from the VPS."
            )
            return {
                "installed": True,
                "active": None,
                "rules": message,
                "verbose": privilege.get("error") or "",
                "listening": listening,
                "ssh_port": server["port"],
                "privilege_ready": False,
                "checked_at": system_admin_module._utc_now(),
            }
        numbered_code, rules = ssh_command(server, privileged_command("ufw status numbered"), timeout=30)
        verbose_code, verbose = ssh_command(server, privileged_command("ufw status verbose"), timeout=30)
        if numbered_code != 0 or verbose_code != 0:
            detail = (rules if numbered_code != 0 else verbose).strip()[-4000:]
            return {
                "installed": True,
                "active": None,
                "rules": "UFW could not be read through the configured privilege bridge.",
                "verbose": detail,
                "listening": listening,
                "ssh_port": server["port"],
                "privilege_ready": False,
                "checked_at": system_admin_module._utc_now(),
            }
        return {
            "installed": True,
            "active": "Status: active" in verbose,
            "rules": rules,
            "verbose": verbose,
            "listening": listening,
            "ssh_port": server["port"],
            "privilege_ready": True,
            "checked_at": system_admin_module._utc_now(),
        }


__all__ = ["HELPER_PATH", "install_privilege_bridge", "privileged_command"]
