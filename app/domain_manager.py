from __future__ import annotations

import base64
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ssh_command

DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
UPSTREAM_RE = re.compile(r"^https?://(?:127\.0\.0\.1|localhost|[A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9A-Fa-f:]+\])(?::[1-9][0-9]{0,4})?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(server: dict[str, Any], command: str, timeout: int = 60) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(output.strip()[-5000:] or f"Remote command failed with exit code {code}")
    return output


def _sudo_shell(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return (
        f"payload={shlex.quote(encoded)}; "
        "if [ \"$(id -u)\" -eq 0 ]; then printf '%s' \"$payload\" | base64 -d | bash; "
        "else printf '%s' \"$payload\" | base64 -d | sudo -n bash; fi"
    )


def _domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid domain name")
    return value


def _upstream(value: str) -> str:
    value = value.strip()
    if not UPSTREAM_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Upstream must be an http(s) URL to a host/container and optional port")
    match = re.search(r":(\d{1,5})(?:/|$)", value)
    if match and int(match.group(1)) > 65535:
        raise HTTPException(status_code=400, detail="Upstream port is invalid")
    return value


class ProxyCreate(BaseModel):
    domain: str = Field(min_length=4, max_length=253)
    upstream: str = Field(min_length=8, max_length=500)
    websocket: bool = True
    max_body_mb: int = Field(default=50, ge=1, le=4096)


class DomainConfirm(BaseModel):
    confirm_domain: str = Field(min_length=4, max_length=253)


class CertificateIssue(BaseModel):
    domain: str = Field(min_length=4, max_length=253)
    email: str = Field(min_length=5, max_length=254)
    redirect_https: bool = True


def _parse_nginx_configs(raw: str) -> list[dict[str, Any]]:
    sites: list[dict[str, Any]] = []
    for line in raw.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        try:
            path = base64.b64decode(parts[0]).decode("utf-8", errors="replace")
            content = base64.b64decode(parts[1]).decode("utf-8", errors="replace")
        except Exception:
            continue
        domains: list[str] = []
        for match in re.findall(r"(?m)^\s*server_name\s+([^;]+);", content):
            domains.extend(x for x in match.split() if x and x != "_")
        upstreams = re.findall(r"(?m)^\s*proxy_pass\s+([^;]+);", content)
        listens = re.findall(r"(?m)^\s*listen\s+([^;]+);", content)
        sites.append(
            {
                "path": path,
                "name": path.rsplit("/", 1)[-1],
                "managed": path.rsplit("/", 1)[-1].startswith("custom-github-"),
                "domains": sorted(set(domains)),
                "upstreams": sorted(set(upstreams)),
                "listens": sorted(set(listens)),
            }
        )
    return sites


def _parse_certificates(raw: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        result.append({"domain": parts[0], "expires": parts[1], "issuer": parts[2], "path": parts[3] if len(parts) > 3 else ""})
    return result


def install_domain_routes(
    app: FastAPI,
    *,
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    @app.get("/vps/{server_id}/domains", response_class=HTMLResponse, include_in_schema=False)
    def domain_page(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        return DOMAIN_HTML.replace("__SERVER_ID__", str(server_id)).replace("__SERVER_NAME__", str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/domains")
    def inspect_domains(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        detect = _run(
            server,
            "printf 'nginx=%s\\n' \"$(command -v nginx >/dev/null 2>&1 && echo yes || echo no)\"; "
            "printf 'caddy=%s\\n' \"$(command -v caddy >/dev/null 2>&1 && echo yes || echo no)\"; "
            "printf 'certbot=%s\\n' \"$(command -v certbot >/dev/null 2>&1 && echo yes || echo no)\"; "
            "printf 'caddy_containers=%s\\n' \"$(docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null | grep -Ei '(^|[|/_-])caddy([|:_-]|$)' | paste -sd, - || true)\"",
            timeout=30,
        )
        capabilities = {}
        for line in detect.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                capabilities[key] = value

        nginx_sites: list[dict[str, Any]] = []
        if capabilities.get("nginx") == "yes":
            script = r'''
set +e
for f in /etc/nginx/sites-enabled/*; do
  [ -f "$f" ] || continue
  p=$(printf '%s' "$f" | base64 -w0)
  c=$(cat -- "$f" 2>/dev/null | base64 -w0)
  printf '%s\t%s\n' "$p" "$c"
done
'''.strip()
            try:
                nginx_sites = _parse_nginx_configs(_run(server, _sudo_shell(script), timeout=45))
            except RuntimeError:
                nginx_sites = []

        caddy = {"system_config": None, "containers": capabilities.get("caddy_containers", "")}
        try:
            caddy_raw = _run(
                server,
                "if [ -r /etc/caddy/Caddyfile ]; then base64 -w0 /etc/caddy/Caddyfile; "
                "elif sudo -n test -r /etc/caddy/Caddyfile 2>/dev/null; then sudo -n base64 -w0 /etc/caddy/Caddyfile; fi",
                timeout=20,
            ).strip()
            if caddy_raw:
                caddy["system_config"] = base64.b64decode(caddy_raw).decode("utf-8", errors="replace")
        except Exception:
            pass

        certificates: list[dict[str, Any]] = []
        cert_script = r'''
set +e
for d in /etc/letsencrypt/live/*; do
  [ -d "$d" ] || continue
  cert="$d/fullchain.pem"
  [ -f "$cert" ] || continue
  domain=$(basename "$d")
  end=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
  printf '%s\t%s\t%s\t%s\n' "$domain" "$end" "$issuer" "$cert"
done
'''.strip()
        try:
            certificates = _parse_certificates(_run(server, _sudo_shell(cert_script), timeout=30))
        except RuntimeError:
            certificates = []

        return {
            "server_id": server_id,
            "server_name": server["name"],
            "checked_at": _utc_now(),
            "capabilities": {
                "nginx": capabilities.get("nginx") == "yes",
                "caddy": capabilities.get("caddy") == "yes" or bool(capabilities.get("caddy_containers")),
                "certbot": capabilities.get("certbot") == "yes",
            },
            "nginx_sites": nginx_sites,
            "caddy": caddy,
            "certificates": certificates,
        }

    @app.post("/api/vps/servers/{server_id}/domains/nginx", status_code=201)
    def create_nginx_proxy(server_id: int, payload: ProxyCreate) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        domain = _domain(payload.domain)
        upstream = _upstream(payload.upstream)
        filename = f"custom-github-{domain}.conf"
        websocket_block = """
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection \"upgrade\";""" if payload.websocket else ""
        config = f"""server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    client_max_body_size {payload.max_body_mb}m;

    location / {{
        proxy_pass {upstream};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;{websocket_block}
    }}
}}
"""
        encoded = base64.b64encode(config.encode("utf-8")).decode("ascii")
        script = f'''
set -eu
command -v nginx >/dev/null 2>&1 || {{ echo "nginx is not installed" >&2; exit 40; }}
avail=/etc/nginx/sites-available/{shlex.quote(filename)}
enabled=/etc/nginx/sites-enabled/{shlex.quote(filename)}
[ ! -e "$avail" ] || {{ echo "Custom GitHub proxy already exists for {domain}" >&2; exit 41; }}
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s' {shlex.quote(encoded)} | base64 -d > "$tmp"
install -m 0644 "$tmp" "$avail"
ln -s "$avail" "$enabled"
if ! nginx -t; then
  rm -f "$enabled" "$avail"
  echo "nginx configuration test failed; changes rolled back" >&2
  exit 42
fi
systemctl reload nginx
'''.strip()
        try:
            output = _run(server, _sudo_shell(script), timeout=90)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.domain.created", "server", server_id, f"Created nginx proxy {domain} -> {upstream}")
        return {"domain": domain, "upstream": upstream, "config": f"/etc/nginx/sites-available/{filename}", "validated": True, "output": output[-3000:]}

    @app.delete("/api/vps/servers/{server_id}/domains/nginx/{domain}")
    def delete_nginx_proxy(server_id: int, domain: str, payload: DomainConfirm) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        domain = _domain(domain)
        if _domain(payload.confirm_domain) != domain:
            raise HTTPException(status_code=400, detail="Confirmation domain does not match")
        filename = f"custom-github-{domain}.conf"
        script = f'''
set -eu
avail=/etc/nginx/sites-available/{shlex.quote(filename)}
enabled=/etc/nginx/sites-enabled/{shlex.quote(filename)}
[ -e "$avail" ] || {{ echo "Managed proxy does not exist" >&2; exit 44; }}
backup=$(mktemp)
cp "$avail" "$backup"
rm -f "$enabled" "$avail"
if ! nginx -t; then
  cp "$backup" "$avail"
  ln -s "$avail" "$enabled"
  rm -f "$backup"
  echo "nginx test failed after removal; proxy restored" >&2
  exit 45
fi
rm -f "$backup"
systemctl reload nginx
'''.strip()
        try:
            _run(server, _sudo_shell(script), timeout=90)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.domain.deleted", "server", server_id, f"Removed Custom GitHub nginx proxy {domain}")
        return {"domain": domain, "removed": True, "nginx_validated": True}

    @app.post("/api/vps/servers/{server_id}/ssl/issue")
    def issue_certificate(server_id: int, payload: CertificateIssue) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        domain = _domain(payload.domain)
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", payload.email.strip()):
            raise HTTPException(status_code=400, detail="Valid email address required for ACME")
        redirect = "--redirect" if payload.redirect_https else "--no-redirect"
        command = (
            f"certbot --nginx -d {shlex.quote(domain)} --non-interactive --agree-tos "
            f"--email {shlex.quote(payload.email.strip())} {redirect}"
        )
        try:
            output = _run(server, _sudo_shell(f"set -eu\ncommand -v certbot >/dev/null || {{ echo 'certbot is not installed' >&2; exit 40; }}\n{command}\nnginx -t\nsystemctl reload nginx"), timeout=300)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.ssl.issued", "server", server_id, f"Issued/updated certificate for {domain}")
        return {"domain": domain, "success": True, "output": output[-5000:]}

    @app.post("/api/vps/servers/{server_id}/ssl/renew")
    def renew_certificates(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        try:
            output = _run(server, _sudo_shell("set -eu\ncertbot renew --non-interactive\nif command -v nginx >/dev/null; then nginx -t && systemctl reload nginx; fi"), timeout=600)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.ssl.renew", "server", server_id, "Renewed eligible ACME certificates")
        return {"success": True, "output": output[-8000:]}


DOMAIN_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Domains & SSL</title><style>
:root{font-family:Inter,system-ui;color:#17231f;background:#f6f8f7}body{margin:0}.top{height:64px;background:#173c38;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 24px}.top a{color:#fff}.stage{max-width:1350px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:white;border:1px solid #dfe7e2;border-radius:16px;overflow:hidden;grid-column:span 6}.wide{grid-column:span 12}.head{padding:15px 17px;border-bottom:1px solid #e8eeea;display:flex;justify-content:space-between}.pad{padding:17px}.sub{color:#718078;font-size:11px}.row{display:flex;gap:8px;flex-wrap:wrap;margin:9px 0}input{height:38px;border:1px solid #dfe7e2;border-radius:9px;padding:0 10px;min-width:180px}button,.btn{border:1px solid #dfe7e2;background:white;border-radius:9px;padding:9px 11px;font-weight:750;cursor:pointer}.primary{background:#183f3b;color:white}.danger{color:#b42335}.site{padding:11px 0;border-bottom:1px solid #edf1ef}.tag{display:inline-block;padding:4px 8px;border-radius:99px;background:#eef4f1;font-size:10px;margin-right:5px}.good{color:#167347}.warn{color:#9a5c0e}.log{background:#101815;color:#d9e7e0;padding:12px;border-radius:10px;white-space:pre-wrap;font-size:11px;max-height:260px;overflow:auto}@media(max-width:850px){.card{grid-column:span 12}}</style></head><body><div class="top"><b>Custom GitHub · Domains & SSL · __SERVER_NAME__</b><a href="/vps/__SERVER_ID__">Back to VPS</a></div><div class="stage"><h1>Domains, reverse proxy & SSL</h1><p class="sub">Read the live proxy state, create guarded Nginx routes, and manage Let's Encrypt certificates. Existing non-Custom-GitHub configs remain read-only.</p><div class="row"><button class="primary" onclick="load()">↻ Refresh live state</button><button onclick="renew()">Renew eligible certificates</button><span id="status" class="tag">Loading</span></div><div class="grid"><div class="card"><div class="head"><b>Proxy capabilities</b></div><div id="caps" class="pad">Loading…</div></div><div class="card"><div class="head"><b>Create Nginx proxy</b></div><div class="pad"><div class="row"><input id="domain" placeholder="app.example.com"><input id="upstream" placeholder="http://127.0.0.1:3000"></div><div class="row"><input id="body" value="50" type="number" min="1" max="4096"><label><input id="ws" type="checkbox" checked style="min-width:auto;height:auto"> WebSocket headers</label><button class="primary" onclick="createProxy()">Create + validate + reload</button></div></div></div><div class="card wide"><div class="head"><b>Nginx sites</b><span class="sub">Only CUSTOM GITHUB sites can be removed here.</span></div><div id="sites" class="pad"></div></div><div class="card"><div class="head"><b>Certificates</b></div><div id="certs" class="pad"></div><div class="pad"><div class="row"><input id="certDomain" placeholder="app.example.com"><input id="email" placeholder="acme@example.com"><button class="primary" onclick="issue()">Issue with Certbot</button></div></div></div><div class="card"><div class="head"><b>Caddy</b></div><div id="caddy" class="pad"></div></div><div class="card wide"><div class="head"><b>Operation output</b></div><div class="pad"><pre id="out" class="log">No operation yet.</pre></div></div></div></div><script>
const sid=__SERVER_ID__;async function api(p,o={}){status.textContent='Working…';const r=await fetch(p,{headers:{'Content-Type':'application/json'},...o});const t=await r.text();let d={};try{d=t?JSON.parse(t):{}}catch{d={detail:t}}status.textContent=r.ok?'Ready':'Error';if(!r.ok)throw new Error(d.detail||t);return d}async function load(){try{const d=await api(`/api/vps/servers/${sid}/domains`);caps.innerHTML=`<span class='tag ${d.capabilities.nginx?'good':'warn'}'>Nginx ${d.capabilities.nginx?'available':'not found'}</span><span class='tag ${d.capabilities.caddy?'good':'warn'}'>Caddy ${d.capabilities.caddy?'detected':'not found'}</span><span class='tag ${d.capabilities.certbot?'good':'warn'}'>Certbot ${d.capabilities.certbot?'available':'not found'}</span><p class='sub'>Checked ${new Date(d.checked_at).toLocaleString()}</p>`;sites.innerHTML=d.nginx_sites.length?d.nginx_sites.map(s=>`<div class='site'><b>${s.domains.join(', ')||s.name}</b><div class='sub'>${s.upstreams.join(', ')||'No proxy_pass'} · ${s.path}</div><div class='row'><span class='tag ${s.managed?'good':''}'>${s.managed?'CUSTOM GITHUB':'READ ONLY'}</span>${s.managed&&s.domains[0]?`<button class='danger' onclick="removeProxy('${s.domains[0]}')">Remove</button>`:''}</div></div>`).join(''):'<div class=sub>No Nginx sites discovered.</div>';certs.innerHTML=d.certificates.length?d.certificates.map(c=>`<div class='site'><b>${c.domain}</b><div class='sub'>Expires ${c.expires}<br>${c.issuer}</div></div>`).join(''):'<div class=sub>No Let's Encrypt certificate files discovered.</div>';caddy.innerHTML=`<p>${d.caddy.containers?`Containers: ${d.caddy.containers}`:'No Caddy container detected.'}</p>${d.caddy.system_config?`<pre class=log>${esc(d.caddy.system_config)}</pre>`:'<p class=sub>No readable /etc/caddy/Caddyfile.</p>'}`;}catch(e){out.textContent=e.message}}function esc(s){return String(s).replace(/[&<>]/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[x]))}async function createProxy(){try{const d=await api(`/api/vps/servers/${sid}/domains/nginx`,{method:'POST',body:JSON.stringify({domain:domain.value,upstream:upstream.value,websocket:ws.checked,max_body_mb:Number(body.value||50)})});out.textContent=d.output||'Proxy created and nginx validated.';load()}catch(e){out.textContent=e.message}}async function removeProxy(d){if(!confirm(`Remove Custom GitHub proxy for ${d}?`))return;try{const x=await api(`/api/vps/servers/${sid}/domains/nginx/${encodeURIComponent(d)}`,{method:'DELETE',body:JSON.stringify({confirm_domain:d})});out.textContent=JSON.stringify(x,null,2);load()}catch(e){out.textContent=e.message}}async function issue(){try{const d=await api(`/api/vps/servers/${sid}/ssl/issue`,{method:'POST',body:JSON.stringify({domain:certDomain.value,email:email.value,redirect_https:true})});out.textContent=d.output;load()}catch(e){out.textContent=e.message}}async function renew(){try{const d=await api(`/api/vps/servers/${sid}/ssl/renew`,{method:'POST'});out.textContent=d.output;load()}catch(e){out.textContent=e.message}}load();</script></body></html>"""


__all__ = ["install_domain_routes", "_domain", "_upstream"]
