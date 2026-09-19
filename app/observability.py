from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ssh_command


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(server: dict[str, Any], command: str, timeout: int = 45) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(output.strip()[-5000:] or f"Remote command failed with exit code {code}")
    return output


class AlertPolicyUpdate(BaseModel):
    cpu_warning: float = Field(default=80, ge=10, le=100)
    cpu_critical: float = Field(default=95, ge=20, le=100)
    memory_warning: float = Field(default=80, ge=10, le=100)
    memory_critical: float = Field(default=92, ge=20, le=100)
    disk_warning: float = Field(default=80, ge=10, le=100)
    disk_critical: float = Field(default=90, ge=20, le=100)
    load_warning_per_cpu: float = Field(default=1.25, ge=0.25, le=10)
    restart_warning: int = Field(default=3, ge=1, le=1000)
    backup_stale_hours: int = Field(default=48, ge=1, le=720)


class IncidentStateUpdate(BaseModel):
    status: str = Field(pattern=r"^(acknowledged|resolved|new)$")


def _init_db(db_factory: Callable[[], sqlite3.Connection]) -> None:
    with db_factory() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS alert_policies (
                server_id INTEGER PRIMARY KEY,
                cpu_warning REAL NOT NULL DEFAULT 80,
                cpu_critical REAL NOT NULL DEFAULT 95,
                memory_warning REAL NOT NULL DEFAULT 80,
                memory_critical REAL NOT NULL DEFAULT 92,
                disk_warning REAL NOT NULL DEFAULT 80,
                disk_critical REAL NOT NULL DEFAULT 90,
                load_warning_per_cpu REAL NOT NULL DEFAULT 1.25,
                restart_warning INTEGER NOT NULL DEFAULT 3,
                backup_stale_hours INTEGER NOT NULL DEFAULT 48,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );
            CREATE TABLE IF NOT EXISTS server_metric_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                cpu_percent REAL NOT NULL,
                memory_percent REAL NOT NULL,
                disk_percent REAL NOT NULL,
                load_1 REAL NOT NULL,
                cpu_count INTEGER NOT NULL,
                network_rx_bytes INTEGER NOT NULL,
                network_tx_bytes INTEGER NOT NULL,
                containers_running INTEGER NOT NULL,
                containers_total INTEGER NOT NULL,
                max_container_restarts INTEGER NOT NULL,
                failed_services INTEGER NOT NULL,
                reboot_required INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );
            CREATE INDEX IF NOT EXISTS idx_metric_samples_server ON server_metric_samples(server_id, id DESC);
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                acknowledged_at TEXT,
                resolved_at TEXT,
                UNIQUE(server_id, fingerprint),
                FOREIGN KEY(server_id) REFERENCES servers(id)
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_server ON incidents(server_id, status, id DESC);
            """
        )


def _ensure_policy(db_factory: Callable[[], sqlite3.Connection], server_id: int) -> dict[str, Any]:
    now = _utc_now()
    with db_factory() as connection:
        connection.execute("INSERT OR IGNORE INTO alert_policies(server_id, updated_at) VALUES (?, ?)", (server_id, now))
        row = connection.execute("SELECT * FROM alert_policies WHERE server_id = ?", (server_id,)).fetchone()
    assert row is not None
    return dict(row)


def _parse_sample(raw: str) -> dict[str, Any]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    required = {"cpu_percent", "memory_percent", "disk_percent", "load_1", "cpu_count", "network_rx_bytes", "network_tx_bytes", "containers_running", "containers_total", "max_container_restarts", "failed_services", "reboot_required"}
    missing = sorted(required - values.keys())
    if missing:
        raise RuntimeError(f"VPS metric sample missing: {', '.join(missing)}")
    return {
        "cpu_percent": max(0.0, min(100.0, float(values["cpu_percent"]))),
        "memory_percent": max(0.0, min(100.0, float(values["memory_percent"]))),
        "disk_percent": max(0.0, min(100.0, float(values["disk_percent"]))),
        "load_1": float(values["load_1"]),
        "cpu_count": max(1, int(values["cpu_count"])),
        "network_rx_bytes": max(0, int(values["network_rx_bytes"])),
        "network_tx_bytes": max(0, int(values["network_tx_bytes"])),
        "containers_running": max(0, int(values["containers_running"])),
        "containers_total": max(0, int(values["containers_total"])),
        "max_container_restarts": max(0, int(values["max_container_restarts"])),
        "failed_services": max(0, int(values["failed_services"])),
        "reboot_required": values["reboot_required"] == "1",
    }


def _collect(server: dict[str, Any]) -> dict[str, Any]:
    script = r'''
set -u
read_cpu() {
  read -r cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat
  idle_all=$((idle+iowait)); non_idle=$((user+nice+system+irq+softirq+steal)); total=$((idle_all+non_idle))
  printf '%s %s\n' "$total" "$idle_all"
}
set -- $(read_cpu); total1=$1; idle1=$2
sleep 0.25
set -- $(read_cpu); total2=$1; idle2=$2
delta_total=$((total2-total1)); delta_idle=$((idle2-idle1))
if [ "$delta_total" -gt 0 ]; then cpu=$(awk -v t="$delta_total" -v i="$delta_idle" 'BEGIN {printf "%.1f", 100*(t-i)/t}'); else cpu=0; fi
mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
mem_avail=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
mem=$(awk -v t="$mem_total" -v a="$mem_avail" 'BEGIN {if(t>0) printf "%.1f",100*(t-a)/t; else print "0"}')
disk=$(df -Pk / | awk 'NR==2 {gsub(/%/,"",$5);print $5}')
load=$(awk '{print $1}' /proc/loadavg)
cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)
net=$(awk -F'[: ]+' 'NR>2 && $1!="lo" {rx+=$3;tx+=$11} END{printf "%d %d",rx,tx}' /proc/net/dev)
set -- $net; rx=${1:-0}; tx=${2:-0}
running=$(docker ps -q 2>/dev/null | wc -l)
total=$(docker ps -aq 2>/dev/null | wc -l)
max_restart=0
for c in $(docker ps -aq 2>/dev/null); do
  r=$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null || echo 0)
  case "$r" in ''|*[!0-9]*) r=0;; esac
  [ "$r" -gt "$max_restart" ] && max_restart=$r
done
failed=$(systemctl --failed --type=service --no-legend 2>/dev/null | wc -l)
reboot=0; [ -f /var/run/reboot-required ] && reboot=1
printf 'cpu_percent=%s\n' "$cpu"
printf 'memory_percent=%s\n' "$mem"
printf 'disk_percent=%s\n' "$disk"
printf 'load_1=%s\n' "$load"
printf 'cpu_count=%s\n' "$cpus"
printf 'network_rx_bytes=%s\n' "$rx"
printf 'network_tx_bytes=%s\n' "$tx"
printf 'containers_running=%s\n' "$running"
printf 'containers_total=%s\n' "$total"
printf 'max_container_restarts=%s\n' "$max_restart"
printf 'failed_services=%s\n' "$failed"
printf 'reboot_required=%s\n' "$reboot"
'''.strip()
    return _parse_sample(_run(server, script, timeout=45))


def _conditions(sample: dict[str, Any], policy: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    def threshold(metric: str, value: float, warning: float, critical: float, label: str) -> None:
        if value >= critical:
            result[metric] = {"category": "resource", "severity": "critical", "title": f"{label} critical", "message": f"{label} is {value:.1f}% (critical threshold {critical:.1f}%)."}
        elif value >= warning:
            result[metric] = {"category": "resource", "severity": "warning", "title": f"{label} high", "message": f"{label} is {value:.1f}% (warning threshold {warning:.1f}%)."}
    threshold("cpu", sample["cpu_percent"], float(policy["cpu_warning"]), float(policy["cpu_critical"]), "CPU usage")
    threshold("memory", sample["memory_percent"], float(policy["memory_warning"]), float(policy["memory_critical"]), "Memory usage")
    threshold("disk", sample["disk_percent"], float(policy["disk_warning"]), float(policy["disk_critical"]), "Disk usage")
    load_ratio = sample["load_1"] / max(sample["cpu_count"], 1)
    if load_ratio >= float(policy["load_warning_per_cpu"]):
        result["load"] = {"category": "resource", "severity": "warning", "title": "System load high", "message": f"1-minute load is {sample['load_1']:.2f} across {sample['cpu_count']} CPU(s) ({load_ratio:.2f} per CPU)."}
    if sample["failed_services"] > 0:
        result["failed-services"] = {"category": "service", "severity": "critical", "title": "Failed system services", "message": f"systemd reports {sample['failed_services']} failed service(s)."}
    if sample["max_container_restarts"] >= int(policy["restart_warning"]):
        result["container-restarts"] = {"category": "docker", "severity": "warning", "title": "Container restart activity", "message": f"At least one container has restarted {sample['max_container_restarts']} time(s)."}
    if sample["reboot_required"]:
        result["reboot-required"] = {"category": "os", "severity": "warning", "title": "Server reboot required", "message": "Ubuntu reports that a reboot is required to complete installed updates."}
    return result


def _sync_incidents(db_factory: Callable[[], sqlite3.Connection], server_id: int, active: dict[str, dict[str, str]]) -> None:
    now = _utc_now()
    with db_factory() as connection:
        existing = {row["fingerprint"]: dict(row) for row in connection.execute("SELECT * FROM incidents WHERE server_id=?", (server_id,)).fetchall()}
        for fingerprint, condition in active.items():
            row = existing.get(fingerprint)
            if row:
                status = row["status"] if row["status"] in {"new", "acknowledged"} else "new"
                connection.execute(
                    "UPDATE incidents SET category=?,severity=?,status=?,title=?,message=?,last_seen_at=?,resolved_at=NULL WHERE id=?",
                    (condition["category"], condition["severity"], status, condition["title"], condition["message"], now, row["id"]),
                )
            else:
                connection.execute(
                    "INSERT INTO incidents(server_id,fingerprint,category,severity,status,title,message,first_seen_at,last_seen_at) VALUES (?,?,?,?, 'new',?,?,?,?)",
                    (server_id, fingerprint, condition["category"], condition["severity"], condition["title"], condition["message"], now, now),
                )
        for fingerprint, row in existing.items():
            if fingerprint not in active and row["status"] != "resolved":
                connection.execute("UPDATE incidents SET status='resolved',resolved_at=?,last_seen_at=? WHERE id=?", (now, now, row["id"]))


def install_observability_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    _init_db(db_factory)

    @app.get("/vps/{server_id}/observability", response_class=HTMLResponse, include_in_schema=False)
    def observability_page(server_id: int) -> str:
        server = dict(server_lookup(server_id))
        return OBS_HTML.replace("__SERVER_ID__", str(server_id)).replace("__SERVER_NAME__", str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/observability/policy")
    def policy(server_id: int) -> dict[str, Any]:
        server_lookup(server_id)
        return _ensure_policy(db_factory, server_id)

    @app.put("/api/vps/servers/{server_id}/observability/policy")
    def update_policy(server_id: int, payload: AlertPolicyUpdate) -> dict[str, Any]:
        server_lookup(server_id)
        if payload.cpu_critical <= payload.cpu_warning or payload.memory_critical <= payload.memory_warning or payload.disk_critical <= payload.disk_warning:
            raise HTTPException(status_code=400, detail="Critical thresholds must be greater than warning thresholds")
        now = _utc_now()
        with db_factory() as connection:
            connection.execute(
                """INSERT INTO alert_policies(server_id,cpu_warning,cpu_critical,memory_warning,memory_critical,disk_warning,disk_critical,load_warning_per_cpu,restart_warning,backup_stale_hours,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(server_id) DO UPDATE SET cpu_warning=excluded.cpu_warning,cpu_critical=excluded.cpu_critical,memory_warning=excluded.memory_warning,memory_critical=excluded.memory_critical,disk_warning=excluded.disk_warning,disk_critical=excluded.disk_critical,load_warning_per_cpu=excluded.load_warning_per_cpu,restart_warning=excluded.restart_warning,backup_stale_hours=excluded.backup_stale_hours,updated_at=excluded.updated_at""",
                (server_id,payload.cpu_warning,payload.cpu_critical,payload.memory_warning,payload.memory_critical,payload.disk_warning,payload.disk_critical,payload.load_warning_per_cpu,payload.restart_warning,payload.backup_stale_hours,now),
            )
        audit_fn("vps.alert.policy", "server", server_id, "Updated observability alert thresholds")
        return _ensure_policy(db_factory, server_id)

    @app.post("/api/vps/servers/{server_id}/observability/sample", status_code=201)
    def sample(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        policy_row = _ensure_policy(db_factory, server_id)
        try:
            metrics = _collect(server)
        except Exception as exc:
            now = _utc_now()
            active = {"unreachable": {"category": "connectivity", "severity": "critical", "title": "VPS unreachable", "message": str(exc)[:1000]}}
            _sync_incidents(db_factory, server_id, active)
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        now = _utc_now()
        with db_factory() as connection:
            cursor = connection.execute(
                """INSERT INTO server_metric_samples(server_id,cpu_percent,memory_percent,disk_percent,load_1,cpu_count,network_rx_bytes,network_tx_bytes,containers_running,containers_total,max_container_restarts,failed_services,reboot_required,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (server_id,metrics["cpu_percent"],metrics["memory_percent"],metrics["disk_percent"],metrics["load_1"],metrics["cpu_count"],metrics["network_rx_bytes"],metrics["network_tx_bytes"],metrics["containers_running"],metrics["containers_total"],metrics["max_container_restarts"],metrics["failed_services"],1 if metrics["reboot_required"] else 0,now),
            )
            sample_id = int(cursor.lastrowid)
        conditions = _conditions(metrics, policy_row)
        _sync_incidents(db_factory, server_id, conditions)
        return {"id": sample_id, "created_at": now, **metrics, "active_conditions": conditions}

    @app.get("/api/vps/servers/{server_id}/observability/history")
    def history(server_id: int, limit: int = Query(default=240, ge=1, le=2000)) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            rows = connection.execute("SELECT * FROM server_metric_samples WHERE server_id=? ORDER BY id DESC LIMIT ?", (server_id, limit)).fetchall()
        return [dict(row) for row in reversed(rows)]

    @app.get("/api/vps/servers/{server_id}/observability/incidents")
    def incidents(server_id: int, include_resolved: bool = False) -> list[dict[str, Any]]:
        server_lookup(server_id)
        with db_factory() as connection:
            if include_resolved:
                rows = connection.execute("SELECT * FROM incidents WHERE server_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, id DESC", (server_id,)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM incidents WHERE server_id=? AND status!='resolved' ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, id DESC", (server_id,)).fetchall()
        return [dict(row) for row in rows]

    @app.patch("/api/vps/servers/{server_id}/observability/incidents/{incident_id}")
    def incident_state(server_id: int, incident_id: int, payload: IncidentStateUpdate) -> dict[str, Any]:
        server_lookup(server_id)
        now = _utc_now()
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM incidents WHERE id=? AND server_id=?", (incident_id, server_id)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Incident not found")
            if payload.status == "acknowledged":
                connection.execute("UPDATE incidents SET status='acknowledged',acknowledged_at=? WHERE id=?", (now, incident_id))
            elif payload.status == "resolved":
                connection.execute("UPDATE incidents SET status='resolved',resolved_at=? WHERE id=?", (now, incident_id))
            else:
                connection.execute("UPDATE incidents SET status='new',acknowledged_at=NULL,resolved_at=NULL WHERE id=?", (incident_id,))
            updated = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        audit_fn("vps.incident.state", "server", server_id, f"Incident {incident_id} -> {payload.status}")
        return dict(updated)


OBS_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Observability & Incidents</title><style>
:root{font-family:Inter,system-ui;color:#17231f;background:#f6f8f7}body{margin:0}.top{height:64px;background:#173c38;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 24px}.top a{color:#fff}.stage{max-width:1450px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:#fff;border:1px solid #dfe7e2;border-radius:16px;overflow:hidden}.c3{grid-column:span 3}.c6{grid-column:span 6}.c12{grid-column:span 12}.pad{padding:17px}.head{padding:15px 17px;border-bottom:1px solid #e8eeea;display:flex;justify-content:space-between;gap:10px}.label{font-size:10px;color:#718078;text-transform:uppercase}.value{font-size:2rem;font-weight:900;margin:5px 0}.sub{font-size:11px;color:#718078}.row{display:flex;gap:8px;flex-wrap:wrap;margin:9px 0}button,input{border:1px solid #dfe7e2;background:#fff;border-radius:9px;padding:9px 11px;font:inherit}button{font-weight:750;cursor:pointer}.primary{background:#183f3b;color:#fff}.incident{padding:12px 0;border-bottom:1px solid #edf1ef}.tag{display:inline-block;padding:4px 8px;border-radius:99px;background:#eef4f1;font-size:10px}.critical{background:#fdecef;color:#a72b39}.warning{background:#fff4dd;color:#9a5c0e}.new{font-weight:800}.chart{width:100%;height:210px;background:#fafcfb;border:1px solid #edf1ef;border-radius:10px}.policy input{width:80px}.bar{height:6px;background:#edf1ef;border-radius:6px;overflow:hidden}.bar i{display:block;height:100%;background:#285b55}@media(max-width:900px){.c3,.c6{grid-column:span 12}}</style></head><body><div class="top"><b>Custom GitHub · Observability · __SERVER_NAME__</b><a href="/vps/__SERVER_ID__">Back to VPS</a></div><div class="stage"><h1>Live Monitoring & Incident Center</h1><p class="sub">Every sample comes from live Linux/Docker sources on the VPS and is timestamped before it becomes history.</p><div class="row"><button class="primary" onclick="collect()">Collect live sample</button><label><input id="auto" type="checkbox" checked style="height:auto"> auto every 30s while open</label><span id="stamp" class="tag">No sample yet</span></div><div class="grid"><div class="card c3 pad"><div class="label">CPU</div><div id="cpu" class="value">—</div><div class="bar"><i id="cpuBar"></i></div></div><div class="card c3 pad"><div class="label">Memory</div><div id="mem" class="value">—</div><div class="bar"><i id="memBar"></i></div></div><div class="card c3 pad"><div class="label">Disk</div><div id="disk" class="value">—</div><div class="bar"><i id="diskBar"></i></div></div><div class="card c3 pad"><div class="label">Containers</div><div id="containers" class="value">—</div><div id="containerSub" class="sub"></div></div><div class="card c6"><div class="head"><b>Resource history</b><span class="sub">CPU / memory / disk %</span></div><div class="pad"><svg id="chart" class="chart" viewBox="0 0 900 210" preserveAspectRatio="none"></svg></div></div><div class="card c6"><div class="head"><b>Active incidents</b><span id="incidentCount" class="tag">0</span></div><div id="incidents" class="pad"></div></div><div class="card c12"><div class="head"><b>Alert policy</b><span class="sub">Critical must be higher than warning.</span></div><div class="pad policy"><div class="row">CPU <input id="cw" type="number"> / <input id="cc" type="number"> Memory <input id="mw" type="number"> / <input id="mc" type="number"> Disk <input id="dw" type="number"> / <input id="dc" type="number"> Load/CPU <input id="lw" type="number" step=".1"> Restart warn <input id="rw" type="number"><button onclick="savePolicy()">Save thresholds</button></div></div></div></div></div><script>
const sid=__SERVER_ID__;async function api(p,o={}){const r=await fetch(p,{headers:{'Content-Type':'application/json'},...o});const t=await r.text();let d={};try{d=t?JSON.parse(t):{}}catch{d={detail:t}}if(!r.ok)throw new Error(d.detail||t);return d}function setMetric(id,v){document.getElementById(id).textContent=`${Number(v).toFixed(1)}%`;const b=document.getElementById(id+'Bar');if(b)b.style.width=`${Math.min(100,Number(v))}%`}function draw(rows){const svg=chart;svg.innerHTML='';if(rows.length<2)return;const keys=[['cpu_percent','#285b55'],['memory_percent','#9a5c0e'],['disk_percent','#a72b39']];for(const [key,color] of keys){const pts=rows.map((r,i)=>`${i/(rows.length-1)*900},${205-Math.min(100,Number(r[key]))*2}`).join(' ');const p=document.createElementNS('http://www.w3.org/2000/svg','polyline');p.setAttribute('points',pts);p.setAttribute('fill','none');p.setAttribute('stroke',color);p.setAttribute('stroke-width','3');svg.appendChild(p)}}async function collect(){try{const d=await api(`/api/vps/servers/${sid}/observability/sample`,{method:'POST'});setMetric('cpu',d.cpu_percent);setMetric('mem',d.memory_percent);setMetric('disk',d.disk_percent);containers.textContent=`${d.containers_running}/${d.containers_total}`;containerSub.textContent=`running/total · max restarts ${d.max_container_restarts}`;stamp.textContent=`Live ${new Date(d.created_at).toLocaleTimeString()}`;await refresh()}catch(e){stamp.textContent=`Sample failed: ${e.message}`;await loadIncidents()}}async function refresh(){const h=await api(`/api/vps/servers/${sid}/observability/history?limit=120`);draw(h);if(h.length){const d=h[h.length-1];setMetric('cpu',d.cpu_percent);setMetric('mem',d.memory_percent);setMetric('disk',d.disk_percent);containers.textContent=`${d.containers_running}/${d.containers_total}`;stamp.textContent=`Sample ${new Date(d.created_at).toLocaleString()}`}await loadIncidents()}async function loadIncidents(){const rows=await api(`/api/vps/servers/${sid}/observability/incidents`);incidentCount.textContent=rows.length;incidents.innerHTML=rows.length?rows.map(x=>`<div class="incident ${x.status}"><div><span class="tag ${x.severity}">${x.severity.toUpperCase()}</span> <span class=tag>${x.status}</span></div><b>${x.title}</b><div class=sub>${x.message}<br>First ${new Date(x.first_seen_at).toLocaleString()} · last ${new Date(x.last_seen_at).toLocaleString()}</div><div class=row>${x.status!=='acknowledged'?`<button onclick="setIncident(${x.id},'acknowledged')">Acknowledge</button>`:''}<button onclick="setIncident(${x.id},'resolved')">Resolve</button></div></div>`).join(''):'<p class=sub>No active incidents.</p>'}async function setIncident(id,s){await api(`/api/vps/servers/${sid}/observability/incidents/${id}`,{method:'PATCH',body:JSON.stringify({status:s})});loadIncidents()}async function loadPolicy(){const p=await api(`/api/vps/servers/${sid}/observability/policy`);cw.value=p.cpu_warning;cc.value=p.cpu_critical;mw.value=p.memory_warning;mc.value=p.memory_critical;dw.value=p.disk_warning;dc.value=p.disk_critical;lw.value=p.load_warning_per_cpu;rw.value=p.restart_warning}async function savePolicy(){try{await api(`/api/vps/servers/${sid}/observability/policy`,{method:'PUT',body:JSON.stringify({cpu_warning:Number(cw.value),cpu_critical:Number(cc.value),memory_warning:Number(mw.value),memory_critical:Number(mc.value),disk_warning:Number(dw.value),disk_critical:Number(dc.value),load_warning_per_cpu:Number(lw.value),restart_warning:Number(rw.value),backup_stale_hours:48})});alert('Alert policy saved.')}catch(e){alert(e.message)}}loadPolicy();refresh();collect();setInterval(()=>{if(auto.checked)collect()},30000);</script></body></html>"""


__all__ = ["install_observability_routes", "AlertPolicyUpdate", "_parse_sample", "_conditions"]
