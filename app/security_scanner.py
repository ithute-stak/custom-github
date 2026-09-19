from __future__ import annotations

import base64
import html
import ipaddress
import json
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ssh_command


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _remote(server: dict[str, Any], command: str, timeout: int = 60, *, allow_failure: bool = False) -> tuple[int, str]:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0 and not allow_failure:
        raise HTTPException(status_code=502, detail=output.strip()[-4000:] or f"Remote command failed ({code})")
    return code, output


def _admin(request: Request) -> None:
    user = getattr(request.state, "security_user", None)
    if user and str(user["role"]) not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Admin role required")


def _parse_sections(output: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = ""
    for raw in output.splitlines():
        if raw.startswith("__") and raw.endswith("__"):
            current = raw.strip("_").lower()
            sections.setdefault(current, [])
        elif current:
            sections[current].append(raw)
    return sections


def _finding(key: str, severity: str, title: str, evidence: str, recommendation: str) -> dict[str, str]:
    return {"key": key, "severity": severity, "title": title, "evidence": evidence, "recommendation": recommendation}


def _evaluate(sections: dict[str, list[str]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    ssh = {}
    for line in sections.get("sshd", []):
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            ssh[parts[0].lower()] = parts[1].strip().lower()
    permit_root = ssh.get("permitrootlogin", "unknown")
    if permit_root == "yes":
        findings.append(_finding("ssh-root-login", "critical", "Direct SSH root login is allowed", "PermitRootLogin yes", "Set PermitRootLogin to prohibit-password or no after confirming an administrative sudo account works."))
    elif permit_root not in {"no", "prohibit-password", "without-password", "forced-commands-only"}:
        findings.append(_finding("ssh-root-policy", "warning", "SSH root-login policy could not be confirmed as hardened", f"PermitRootLogin {permit_root}", "Review the effective sshd configuration."))
    if ssh.get("passwordauthentication") == "yes":
        findings.append(_finding("ssh-password-auth", "warning", "SSH password authentication is enabled", "PasswordAuthentication yes", "Prefer public-key authentication and disable password login after confirming key access."))
    if ssh.get("permitemptypasswords") == "yes":
        findings.append(_finding("ssh-empty-password", "critical", "SSH permits empty passwords", "PermitEmptyPasswords yes", "Disable empty-password authentication immediately."))

    firewall_text = "\n".join(sections.get("ufw", [])).lower()
    if "status: active" not in firewall_text:
        findings.append(_finding("firewall-inactive", "high", "Host firewall is not active", ("\n".join(sections.get("ufw", [])) or "UFW unavailable")[:500], "Enable UFW only after confirming the SSH allow rule is present."))

    fail2ban_text = "\n".join(sections.get("fail2ban", []))
    if not fail2ban_text.strip() or "not-installed" in fail2ban_text or "failed" in fail2ban_text.lower():
        findings.append(_finding("fail2ban", "warning", "Fail2ban is not actively protecting SSH", fail2ban_text.strip() or "No status returned", "Install/enable Fail2ban and configure the sshd jail."))

    unattended = "\n".join(sections.get("unattended", [])).strip()
    if unattended != "installed":
        findings.append(_finding("unattended-upgrades", "warning", "Automatic security updates are not confirmed", unattended or "unattended-upgrades not installed", "Install and configure unattended-upgrades or maintain a strict manual patch schedule."))

    public_sensitive: list[str] = []
    for line in sections.get("listen", []):
        low = line.lower()
        if re.search(r"(?:0\.0\.0\.0|\[::\]|\*):(?:3306|5432|6379)(?:\s|$)", low):
            public_sensitive.append(line)
    if public_sensitive:
        findings.append(_finding("public-data-port", "critical", "Database/cache port is listening publicly", "\n".join(public_sensitive[:10]), "Bind PostgreSQL/MySQL/Redis to private interfaces or localhost and restrict access with the firewall."))

    privileged: list[str] = []
    socket_mounts: list[str] = []
    host_network: list[str] = []
    for line in sections.get("docker", []):
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        name, user, is_privileged, network, mounts = parts[:5]
        if is_privileged.lower() == "true":
            privileged.append(name)
        if "/var/run/docker.sock" in mounts:
            socket_mounts.append(name)
        if network == "host":
            host_network.append(name)
    if privileged:
        findings.append(_finding("docker-privileged", "high", "Privileged Docker containers are running", ", ".join(privileged), "Remove privileged mode unless the workload has a documented requirement."))
    if socket_mounts:
        findings.append(_finding("docker-socket", "high", "Containers can access the Docker daemon socket", ", ".join(socket_mounts), "Avoid mounting docker.sock into application containers; it effectively grants host-level control."))
    if host_network:
        findings.append(_finding("docker-host-network", "warning", "Containers use host networking", ", ".join(host_network), "Confirm host networking is required and firewall rules cover exposed services."))

    writable = [line for line in sections.get("world_writable_etc", []) if line.strip()]
    if writable:
        findings.append(_finding("world-writable-etc", "high", "World-writable files exist under /etc", "\n".join(writable[:20]), "Remove world-write permission and verify ownership of these configuration files."))

    docker_sock = "\n".join(sections.get("docker_socket", [])).strip()
    if docker_sock:
        parts = docker_sock.split()
        if parts and parts[0].endswith("6"):
            findings.append(_finding("docker-socket-permissions", "high", "Docker socket may be writable by users outside the intended group", docker_sock, "Restrict Docker socket permissions and review docker-group membership."))

    if not findings:
        findings.append(_finding("baseline-clean", "info", "No baseline security findings detected", "Live checks completed", "Continue patching, monitoring and reviewing application-specific exposure."))
    order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    return sorted(findings, key=lambda x: (order.get(x["severity"], 9), x["title"]))


class Fail2banConfig(BaseModel):
    enabled: bool = True
    maxretry: int = Field(default=5, ge=2, le=20)
    findtime_seconds: int = Field(default=600, ge=60, le=86400)
    bantime_seconds: int = Field(default=3600, ge=60, le=604800)


class IPAction(BaseModel):
    ip: str = Field(min_length=3, max_length=64)


def install_security_scanner_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    def init_db() -> None:
        with db_factory() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    findings_json TEXT NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    checked_at TEXT NOT NULL,
                    FOREIGN KEY(server_id) REFERENCES servers(id)
                );
                CREATE INDEX IF NOT EXISTS idx_security_scans_server ON security_scans(server_id,id DESC);
                """
            )

    @app.on_event("startup")
    def startup_security_scanner() -> None:
        init_db()

    @app.get("/vps/{server_id}/security-scan", response_class=HTMLResponse, include_in_schema=False)
    def security_page(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        return _page(server_id, str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/security/scan")
    def scan(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        command = r"""
set +e
printf '%s\n' __SSHD__
(sshd -T 2>/dev/null || sudo -n sshd -T 2>/dev/null) | grep -E '^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|x11forwarding|allowtcpforwarding) ' || true
printf '%s\n' __UFW__
(sudo -n ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null || echo unavailable)
printf '%s\n' __FAIL2BAN__
(command -v fail2ban-client >/dev/null && sudo -n fail2ban-client status 2>&1) || echo not-installed-or-failed
printf '%s\n' __UNATTENDED__
dpkg-query -W -f='installed' unattended-upgrades 2>/dev/null || echo missing
printf '%s\n' __LISTEN__
ss -lntupH 2>/dev/null || true
printf '%s\n' __DOCKER__
for cid in $(docker ps -q 2>/dev/null); do docker inspect --format '{{.Name}}\t{{.Config.User}}\t{{.HostConfig.Privileged}}\t{{.HostConfig.NetworkMode}}\t{{range .Mounts}}{{.Source}}=>{{.Destination}};{{end}}' "$cid" 2>/dev/null; done
printf '%s\n' __WORLD_WRITABLE_ETC__
(sudo -n find /etc -xdev -type f -perm -0002 -print 2>/dev/null || find /etc -xdev -type f -perm -0002 -print 2>/dev/null) | head -n 20
printf '%s\n' __DOCKER_SOCKET__
stat -c '%a %U:%G %n' /var/run/docker.sock 2>/dev/null || true
""".strip()
        _, output = _remote(server, command, timeout=90)
        sections = _parse_sections(output)
        findings = _evaluate(sections)
        counts = {level: sum(1 for f in findings if f["severity"] == level) for level in ("critical", "high", "warning", "info")}
        checked_at = _now()
        init_db()
        with db_factory() as connection:
            cursor = connection.execute(
                "INSERT INTO security_scans(server_id,findings_json,critical_count,high_count,warning_count,checked_at) VALUES(?,?,?,?,?,?)",
                (server_id, json.dumps(findings), counts["critical"], counts["high"], counts["warning"], checked_at),
            )
            scan_id = int(cursor.lastrowid)
        audit_fn("security.scan", "server", server_id, f"Security scan {scan_id}: critical={counts['critical']} high={counts['high']} warning={counts['warning']}")
        return {"scan_id": scan_id, "checked_at": checked_at, "counts": counts, "findings": findings, "sources": ["sshd -T", "ufw", "fail2ban", "ss", "docker inspect", "find /etc", "dpkg-query"]}

    @app.get("/api/vps/servers/{server_id}/security/scans")
    def scan_history(server_id: int) -> list[dict[str, Any]]:
        server_lookup(server_id)
        init_db()
        with db_factory() as connection:
            rows = connection.execute("SELECT id,critical_count,high_count,warning_count,checked_at FROM security_scans WHERE server_id=? ORDER BY id DESC LIMIT 50", (server_id,)).fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/vps/servers/{server_id}/security/fail2ban")
    def fail2ban_status(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        command = "command -v fail2ban-client >/dev/null || { echo '__NOT_INSTALLED__'; exit 0; }; sudo -n fail2ban-client status 2>&1; echo '__SSHD__'; sudo -n fail2ban-client status sshd 2>&1 || true; echo '__CONFIG__'; sudo -n cat /etc/fail2ban/jail.d/custom-github-sshd.local 2>/dev/null || true"
        _, output = _remote(server, command, timeout=30)
        installed = "__NOT_INSTALLED__" not in output
        return {"installed": installed, "output": output}

    @app.put("/api/vps/servers/{server_id}/security/fail2ban")
    def configure_fail2ban(server_id: int, payload: Fail2banConfig, request: Request) -> dict[str, Any]:
        _admin(request)
        server = dict(server_lookup(server_id))
        content = f"""[sshd]\nenabled = {'true' if payload.enabled else 'false'}\nmaxretry = {payload.maxretry}\nfindtime = {payload.findtime_seconds}\nbantime = {payload.bantime_seconds}\nbackend = systemd\n"""
        encoded = base64.b64encode(content.encode()).decode()
        script = f"""
set -eu
command -v fail2ban-client >/dev/null || {{ echo 'Fail2ban is not installed'; exit 20; }}
tmp=$(mktemp)
printf %s {shlex.quote(encoded)} | base64 -d > "$tmp"
sudo -n install -d -m 755 /etc/fail2ban/jail.d
backup=''
if sudo -n test -f /etc/fail2ban/jail.d/custom-github-sshd.local; then backup=$(mktemp); sudo -n cp /etc/fail2ban/jail.d/custom-github-sshd.local "$backup"; fi
sudo -n install -m 644 "$tmp" /etc/fail2ban/jail.d/custom-github-sshd.local
rm -f "$tmp"
if ! sudo -n fail2ban-client -t >/tmp/custom-github-f2b-test.log 2>&1; then
  if [ -n "$backup" ]; then sudo -n cp "$backup" /etc/fail2ban/jail.d/custom-github-sshd.local; else sudo -n rm -f /etc/fail2ban/jail.d/custom-github-sshd.local; fi
  cat /tmp/custom-github-f2b-test.log
  exit 21
fi
sudo -n systemctl enable --now fail2ban
sudo -n systemctl restart fail2ban
sudo -n fail2ban-client status sshd
""".strip()
        _, output = _remote(server, script, timeout=90)
        audit_fn("security.fail2ban.configured", "server", server_id, f"Configured sshd Fail2ban jail maxretry={payload.maxretry} findtime={payload.findtime_seconds} bantime={payload.bantime_seconds} enabled={payload.enabled}")
        return {"configured": True, "output": output, "managed_file": "/etc/fail2ban/jail.d/custom-github-sshd.local"}

    @app.post("/api/vps/servers/{server_id}/security/fail2ban/unban")
    def unban_ip(server_id: int, payload: IPAction, request: Request) -> dict[str, Any]:
        _admin(request)
        try:
            address = str(ipaddress.ip_address(payload.ip))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid IP address") from exc
        server = dict(server_lookup(server_id))
        _, output = _remote(server, f"sudo -n fail2ban-client set sshd unbanip {shlex.quote(address)}", timeout=30)
        audit_fn("security.fail2ban.unban", "server", server_id, f"Unbanned {address} from sshd jail")
        return {"unbanned": address, "output": output.strip()}


def _page(server_id: int, name: str) -> str:
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Security Scanner</title><style>body{{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}}.wrap{{max-width:1240px;margin:auto;padding:28px}}.top,.row{{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}}.card,.panel{{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:17px}}.big{{font-size:28px;font-weight:800}}.muted{{color:#93a4bb}}.btn{{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;cursor:pointer;text-decoration:none}}.primary{{background:#2878ff}}.finding{{border-top:1px solid #26364c;padding:14px 0}}.critical{{color:#ff707c}}.high{{color:#ffad66}}.warning{{color:#ffd76e}}.info{{color:#7eb9ff}}input{{background:#08101d;color:#fff;border:1px solid #34465e;border-radius:8px;padding:8px}}code,pre{{white-space:pre-wrap;color:#a9c8ef}}@media(max-width:800px){{.cards{{grid-template-columns:1fr 1fr}}}}</style></head><body><div class='wrap'><div class='top'><div><div class='muted'>VPS SECURITY / {html.escape(name)}</div><h1>Security Scanner & Fail2ban</h1><div class='muted'>Live Linux security checks with evidence and guarded remediation controls.</div></div><div><a class='btn' href='/vps/{server_id}'>VPS Manager</a> <button class='btn primary' onclick='scan()'>Run live scan</button></div></div><div class='cards'><div class='card'><div class='muted'>CRITICAL</div><div id='critical' class='big critical'>—</div></div><div class='card'><div class='muted'>HIGH</div><div id='high' class='big high'>—</div></div><div class='card'><div class='muted'>WARNING</div><div id='warning' class='big warning'>—</div></div><div class='card'><div class='muted'>LAST CHECK</div><div id='when' class='big' style='font-size:16px'>—</div></div></div><div class='panel'><div class='top'><div><h2>Findings</h2><div class='muted'>Every finding comes from live server commands.</div></div></div><div id='findings' class='muted'>Run a scan to inspect this VPS.</div></div><div class='panel' style='margin-top:16px'><div class='top'><div><h2>Fail2ban SSH Protection</h2><div class='muted'>Custom GitHub owns only /etc/fail2ban/jail.d/custom-github-sshd.local</div></div><button class='btn' onclick='f2b()'>Refresh</button></div><pre id='f2bout'>Loading…</pre><div class='row' style='justify-content:flex-start'><input id='retry' type='number' value='5' min='2' max='20' title='maxretry'><input id='findtime' type='number' value='600' title='findtime seconds'><input id='bantime' type='number' value='3600' title='bantime seconds'><button class='btn primary' onclick='saveF2b()'>Apply SSH jail</button><input id='unban' placeholder='IP to unban'><button class='btn' onclick='unbanIp()'>Unban</button></div></div></div><script>const sid={server_id};const $=id=>document.getElementById(id);function esc(s){{return String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]))}}async function api(u,o={{}}){{const r=await fetch(u,{{...o,headers:{{'content-type':'application/json',...(o.headers||{{}})}}}});const x=await r.json().catch(()=>({{}}));if(!r.ok)throw Error(x.detail||r.statusText);return x}}async function scan(){{$('findings').innerHTML='Scanning live VPS…';try{{const x=await api(`/api/vps/servers/${{sid}}/security/scan`);$('critical').textContent=x.counts.critical;$('high').textContent=x.counts.high;$('warning').textContent=x.counts.warning;$('when').textContent=new Date(x.checked_at).toLocaleString();$('findings').innerHTML=x.findings.map(f=>`<div class='finding'><b class='${{esc(f.severity)}}'>${{esc(f.severity.toUpperCase())}} — ${{esc(f.title)}}</b><div class='muted' style='margin-top:7px'>Evidence</div><pre>${{esc(f.evidence)}}</pre><div><b>Recommended:</b> ${{esc(f.recommendation)}}</div></div>`).join('')}}catch(e){{$('findings').innerHTML=`<span class='critical'>${{esc(e.message)}}</span>`}}}}async function f2b(){{try{{const x=await api(`/api/vps/servers/${{sid}}/security/fail2ban`);$('f2bout').textContent=x.output||'No output'}}catch(e){{$('f2bout').textContent=e.message}}}}async function saveF2b(){{try{{const x=await api(`/api/vps/servers/${{sid}}/security/fail2ban`,{{method:'PUT',body:JSON.stringify({{enabled:true,maxretry:Number($('retry').value),findtime_seconds:Number($('findtime').value),bantime_seconds:Number($('bantime').value)}})}});alert('Fail2ban configuration applied');$('f2bout').textContent=x.output}}catch(e){{alert(e.message)}}}}async function unbanIp(){{try{{await api(`/api/vps/servers/${{sid}}/security/fail2ban/unban`,{{method:'POST',body:JSON.stringify({{ip:$('unban').value}})}});await f2b()}}catch(e){{alert(e.message)}}}}f2b()</script></body></html>"""
