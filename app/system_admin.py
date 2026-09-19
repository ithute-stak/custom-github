from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator

from app.deployment import ssh_command
from app.security import ROLE_LEVEL

USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
GROUP_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:-]{0,127}$")
CRON_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
SSH_KEY_RE = re.compile(r"^(ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/=]+(?:\s+.*)?$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(server: dict[str, Any], command: str, timeout: int = 90) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(output.strip()[-6000:] or f"Remote command failed with exit code {code}")
    return output


def _sudo(command: str) -> str:
    return f"if [ \"$(id -u)\" -eq 0 ]; then {command}; else sudo -n {command}; fi"


def _require_admin(request: Request) -> None:
    user = getattr(request.state, "security_user", None)
    if user and ROLE_LEVEL.get(user.get("role", ""), 0) < ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")


def _event(db_factory: Callable[[], sqlite3.Connection], server_id: int, severity: str, title: str, message: str) -> None:
    try:
        with db_factory() as connection:
            connection.execute(
                "INSERT INTO server_events(server_id, category, severity, title, message, created_at) VALUES (?, 'system-admin', ?, ?, ?, ?)",
                (server_id, severity, title[:240], message[:4000], _utc_now()),
            )
    except sqlite3.OperationalError:
        pass


def _user(value: str) -> str:
    value = value.strip().lower()
    if not USER_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid Linux username")
    return value


def _public_key(value: str) -> str:
    value = " ".join(value.strip().split())
    if not SSH_KEY_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Only standard OpenSSH public keys are accepted")
    return value


class LinuxUserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    display_name: str = Field(default="", max_length=120)
    shell: str = Field(default="/bin/bash", pattern=r"^/[A-Za-z0-9._/-]+$")
    groups: list[str] = Field(default_factory=list, max_length=20)
    sudo: bool = False
    public_key: str | None = Field(default=None, max_length=8192)

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, values: list[str]) -> list[str]:
        result=[]
        for value in values:
            value=value.strip().lower()
            if not GROUP_RE.fullmatch(value):
                raise ValueError(f"Invalid group: {value}")
            result.append(value)
        return list(dict.fromkeys(result))


class SshKeyAdd(BaseModel):
    public_key: str = Field(min_length=20, max_length=8192)


class UserAction(BaseModel):
    action: str = Field(pattern=r"^(disable|enable)$")


class UserDelete(BaseModel):
    confirm_username: str = Field(min_length=1, max_length=32)
    remove_home: bool = True


class FirewallRule(BaseModel):
    action: str = Field(pattern=r"^(allow|deny)$")
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern=r"^(tcp|udp)$")
    source: str | None = Field(default=None, max_length=64)
    comment: str | None = Field(default=None, max_length=100)

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str | None) -> str | None:
        if value is None or not value.strip() or value.strip().lower() in {"any", "anywhere"}:
            return None
        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise ValueError("Source must be a valid IP address or CIDR network") from exc


class FirewallDelete(BaseModel):
    rule_number: int = Field(ge=1, le=999)
    confirm: str = Field(min_length=5, max_length=80)


class FirewallToggle(BaseModel):
    enabled: bool
    confirm: str = Field(min_length=4, max_length=80)


class PackageAction(BaseModel):
    action: str = Field(pattern=r"^(install|remove|upgrade)$")
    packages: list[str] = Field(min_length=1, max_length=50)

    @field_validator("packages")
    @classmethod
    def validate_packages(cls, values: list[str]) -> list[str]:
        result=[]
        for value in values:
            value=value.strip()
            if not PACKAGE_RE.fullmatch(value):
                raise ValueError(f"Invalid package name: {value}")
            result.append(value)
        return list(dict.fromkeys(result))


class UpgradeAll(BaseModel):
    confirm: str = Field(min_length=8, max_length=80)


class RebootRequest(BaseModel):
    confirm_hostname: str = Field(min_length=1, max_length=255)


class CronCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    schedule: str = Field(min_length=9, max_length=120)
    run_as: str = Field(default="root", min_length=1, max_length=32)
    command: str = Field(min_length=1, max_length=2000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not CRON_NAME_RE.fullmatch(value):
            raise ValueError("Cron job name must use letters, numbers, dot, underscore or dash")
        return value

    @field_validator("schedule")
    @classmethod
    def validate_schedule(cls, value: str) -> str:
        value=" ".join(value.strip().split())
        if len(value.split()) != 5 or not re.fullmatch(r"[0-9*/?,\-]+(?:\s+[0-9*/?,\-]+){4}", value):
            raise ValueError("Schedule must contain five numeric cron fields")
        return value

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: str) -> str:
        if "\n" in value or "\r" in value or "\x00" in value:
            raise ValueError("Cron command must be a single line")
        return value.strip()


class CronDelete(BaseModel):
    confirm_name: str = Field(min_length=1, max_length=80)


def install_system_admin_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    @app.get("/vps/{server_id}/system-admin", response_class=HTMLResponse, include_in_schema=False)
    def system_admin_page(server_id: int) -> str:
        server=dict(server_lookup(server_id))
        return ADMIN_HTML.replace("__SERVER_ID__",str(server_id)).replace("__SERVER_NAME__",str(server["name"]))

    @app.get("/api/vps/servers/{server_id}/system-admin/users")
    def list_users(server_id: int) -> dict[str, Any]:
        server=dict(server_lookup(server_id))
        script=r'''
set -e
getent passwd | while IFS=: read -r user x uid gid gecos home shell; do
  groups=$(id -nG "$user" 2>/dev/null | tr ' ' ',' || true)
  locked=$(passwd -S "$user" 2>/dev/null | awk '{print $2}' || true)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$user" "$uid" "$gid" "$home" "$shell" "$groups" "$locked" "$gecos"
done
'''.strip()
        try: raw=_run(server,script,45)
        except RuntimeError as exc: raise HTTPException(status_code=502,detail=str(exc)) from exc
        users=[]
        for line in raw.splitlines():
            parts=line.split("\t")
            if len(parts)<8: continue
            users.append({"username":parts[0],"uid":int(parts[1]),"gid":int(parts[2]),"home":parts[3],"shell":parts[4],"groups":[x for x in parts[5].split(',') if x],"password_state":parts[6],"display_name":parts[7],"system":int(parts[1])<1000 and parts[0]!="root"})
        return {"users":users,"ssh_user":server["ssh_user"],"checked_at":_utc_now()}

    @app.get("/api/vps/servers/{server_id}/system-admin/users/{username}/keys")
    def user_keys(server_id: int, username: str) -> dict[str, Any]:
        server=dict(server_lookup(server_id)); username=_user(username)
        script=f'''
home=$(getent passwd {shlex.quote(username)} | cut -d: -f6)
[ -n "$home" ] || exit 44
file="$home/.ssh/authorized_keys"
[ -f "$file" ] || exit 0
while IFS= read -r key; do
  [ -n "$key" ] || continue
  encoded=$(printf '%s' "$key" | base64 -w0)
  fp=$(printf '%s\n' "$key" | ssh-keygen -lf - 2>/dev/null | awk '{{print $2}}')
  type=$(printf '%s' "$key" | awk '{{print $1}}')
  comment=$(printf '%s' "$key" | cut -d' ' -f3-)
  printf '%s\t%s\t%s\t%s\n' "$fp" "$type" "$comment" "$encoded"
done < "$file"
'''.strip()
        try: raw=_run(server,_sudo(f"sh -c {shlex.quote(script)}"),30)
        except RuntimeError as exc: raise HTTPException(status_code=502,detail=str(exc)) from exc
        keys=[]
        for line in raw.splitlines():
            parts=line.split("\t")
            if len(parts)!=4: continue
            try: public=base64.b64decode(parts[3]).decode("utf-8",errors="replace")
            except Exception: public=""
            keys.append({"fingerprint":parts[0],"type":parts[1],"comment":parts[2],"public_key":public})
        return {"username":username,"keys":keys}

    @app.post("/api/vps/servers/{server_id}/system-admin/users",status_code=201)
    def create_user(server_id:int,payload:LinuxUserCreate,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));username=_user(payload.username)
        if username in {"root",server["ssh_user"]}: raise HTTPException(status_code=409,detail="Refusing to create/replace protected account")
        groups=list(payload.groups)
        if payload.sudo and "sudo" not in groups: groups.append("sudo")
        group_arg=f"-G {shlex.quote(','.join(groups))}" if groups else ""
        gecos=shlex.quote(payload.display_name.strip())
        key=_public_key(payload.public_key) if payload.public_key else None
        script=f"set -eu\ngetent passwd {shlex.quote(username)} >/dev/null && {{ echo 'User already exists' >&2; exit 41; }}\nuseradd -m -s {shlex.quote(payload.shell)} -c {gecos} {group_arg} {shlex.quote(username)}\npasswd -l {shlex.quote(username)} >/dev/null 2>&1 || true"
        if key:
            encoded=base64.b64encode(key.encode()).decode()
            script+=f"\nhome=$(getent passwd {shlex.quote(username)} | cut -d: -f6)\ninstall -d -m 0700 -o {shlex.quote(username)} -g {shlex.quote(username)} \"$home/.ssh\"\nprintf '%s\\n' {shlex.quote(encoded)} | base64 -d > \"$home/.ssh/authorized_keys\"\nchown {shlex.quote(username)}:{shlex.quote(username)} \"$home/.ssh/authorized_keys\"\nchmod 0600 \"$home/.ssh/authorized_keys\""
        try:_run(server,_sudo(f"sh -c {shlex.quote(script)}"),90)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.user.created","server",server_id,f"Created Linux user {username}");_event(db_factory,server_id,"success","Linux user created",username)
        return {"username":username,"created":True,"groups":groups}

    @app.post("/api/vps/servers/{server_id}/system-admin/users/{username}/keys",status_code=201)
    def add_key(server_id:int,username:str,payload:SshKeyAdd,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));username=_user(username);key=_public_key(payload.public_key)
        encoded=base64.b64encode(key.encode()).decode()
        script=f'''
set -eu
home=$(getent passwd {shlex.quote(username)} | cut -d: -f6)
[ -n "$home" ] || {{ echo "User not found" >&2; exit 44; }}
install -d -m 0700 -o {shlex.quote(username)} -g {shlex.quote(username)} "$home/.ssh"
touch "$home/.ssh/authorized_keys"
chown {shlex.quote(username)}:{shlex.quote(username)} "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"
key=$(printf '%s' {shlex.quote(encoded)} | base64 -d)
grep -Fqx -- "$key" "$home/.ssh/authorized_keys" || printf '%s\n' "$key" >> "$home/.ssh/authorized_keys"
'''.strip()
        try:_run(server,_sudo(f"sh -c {shlex.quote(script)}"),45)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.ssh_key.added","server",server_id,f"Added SSH key for {username}");_event(db_factory,server_id,"success","SSH key added",username)
        return {"username":username,"added":True}

    @app.delete("/api/vps/servers/{server_id}/system-admin/users/{username}/keys")
    def remove_key(server_id:int,username:str,payload:SshKeyAdd,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));username=_user(username);key=_public_key(payload.public_key)
        if username==server["ssh_user"]: raise HTTPException(status_code=409,detail="Refusing to remove keys from the SSH account used by Custom GitHub")
        encoded=base64.b64encode(key.encode()).decode()
        script=f'''
set -eu
home=$(getent passwd {shlex.quote(username)} | cut -d: -f6)
file="$home/.ssh/authorized_keys"
[ -f "$file" ] || exit 44
key=$(printf '%s' {shlex.quote(encoded)} | base64 -d)
tmp=$(mktemp)
grep -Fvx -- "$key" "$file" > "$tmp" || true
cat "$tmp" > "$file"
rm -f "$tmp"
chmod 0600 "$file"
'''.strip()
        try:_run(server,_sudo(f"sh -c {shlex.quote(script)}"),45)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.ssh_key.removed","server",server_id,f"Removed SSH key from {username}");_event(db_factory,server_id,"warning","SSH key removed",username)
        return {"username":username,"removed":True}

    @app.post("/api/vps/servers/{server_id}/system-admin/users/{username}/action")
    def user_action(server_id:int,username:str,payload:UserAction,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));username=_user(username)
        if username in {"root",server["ssh_user"]}:raise HTTPException(status_code=409,detail="Protected account cannot be disabled from the UI")
        command=f"usermod -L -e 1 {shlex.quote(username)}" if payload.action=="disable" else f"usermod -e -1 {shlex.quote(username)}"
        try:_run(server,_sudo(command),45)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn(f"vps.user.{payload.action}","server",server_id,f"{payload.action} {username}");_event(db_factory,server_id,"warning",f"User {payload.action}d",username)
        return {"username":username,"action":payload.action}

    @app.delete("/api/vps/servers/{server_id}/system-admin/users/{username}")
    def delete_user(server_id:int,username:str,payload:UserDelete,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));username=_user(username)
        if payload.confirm_username.strip().lower()!=username:raise HTTPException(status_code=400,detail="Username confirmation does not match")
        if username in {"root",server["ssh_user"]}:raise HTTPException(status_code=409,detail="Protected account cannot be deleted")
        try:
            uid=int(_run(server,f"id -u {shlex.quote(username)}",20).strip())
            if uid<1000:raise HTTPException(status_code=409,detail="System accounts cannot be deleted from this UI")
            _run(server,_sudo(f"userdel {'-r ' if payload.remove_home else ''}{shlex.quote(username)}"),120)
        except HTTPException:raise
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.user.deleted","server",server_id,f"Deleted Linux user {username}");_event(db_factory,server_id,"warning","Linux user deleted",username)
        return {"username":username,"deleted":True}

    @app.get("/api/vps/servers/{server_id}/system-admin/firewall")
    def firewall(server_id:int)->dict[str,Any]:
        server=dict(server_lookup(server_id))
        try:
            installed=_run(server,"command -v ufw >/dev/null 2>&1 && echo yes || echo no",15).strip()=="yes"
            if not installed:return {"installed":False,"active":False,"rules":"","listening":_run(server,"ss -lntupH 2>/dev/null || true",20),"checked_at":_utc_now()}
            rules=_run(server,_sudo("ufw status numbered"),30)
            verbose=_run(server,_sudo("ufw status verbose"),30)
            listening=_run(server,"ss -lntupH 2>/dev/null || true",30)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        return {"installed":True,"active":"Status: active" in verbose,"rules":rules,"verbose":verbose,"listening":listening,"ssh_port":server["port"],"checked_at":_utc_now()}

    @app.post("/api/vps/servers/{server_id}/system-admin/firewall/rules",status_code=201)
    def add_firewall_rule(server_id:int,payload:FirewallRule,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id))
        if payload.action=="deny" and payload.port==int(server["port"]):raise HTTPException(status_code=409,detail="Refusing to deny the SSH port used by Custom GitHub")
        source=f"from {shlex.quote(payload.source)} " if payload.source else ""
        comment=f" comment {shlex.quote(payload.comment)}" if payload.comment else ""
        command=f"ufw {payload.action} {source}to any port {payload.port} proto {payload.protocol}{comment}"
        try:output=_run(server,_sudo(command),45)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.firewall.rule.added","server",server_id,f"{payload.action} {payload.source or 'any'} -> {payload.port}/{payload.protocol}");_event(db_factory,server_id,"success","Firewall rule added",f"{payload.action} {payload.port}/{payload.protocol}")
        return {"created":True,"output":output.strip()}

    @app.delete("/api/vps/servers/{server_id}/system-admin/firewall/rules")
    def delete_firewall_rule(server_id:int,payload:FirewallDelete,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));expected=f"DELETE RULE {payload.rule_number}"
        if payload.confirm!=expected:raise HTTPException(status_code=400,detail=f"Confirmation must be exactly: {expected}")
        try:
            rules=_run(server,_sudo("ufw status numbered"),30)
            target=next((line for line in rules.splitlines() if re.match(rf"^\[\s*{payload.rule_number}\]",line.strip())),"")
            if not target:raise HTTPException(status_code=404,detail="Firewall rule not found; refresh first")
            if re.search(rf"\b{int(server['port'])}(?:/tcp)?\b",target) and "ALLOW" in target.upper():raise HTTPException(status_code=409,detail="Refusing to remove an SSH allow rule from the UI")
            output=_run(server,_sudo(f"ufw --force delete {payload.rule_number}"),45)
        except HTTPException:raise
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.firewall.rule.deleted","server",server_id,f"Deleted UFW rule {payload.rule_number}: {target}");_event(db_factory,server_id,"warning","Firewall rule deleted",target)
        return {"deleted":True,"rule_number":payload.rule_number,"output":output.strip()}

    @app.post("/api/vps/servers/{server_id}/system-admin/firewall/toggle")
    def toggle_firewall(server_id:int,payload:FirewallToggle,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));expected="ENABLE FIREWALL" if payload.enabled else "DISABLE FIREWALL"
        if payload.confirm!=expected:raise HTTPException(status_code=400,detail=f"Confirmation must be exactly: {expected}")
        try:
            if payload.enabled:
                rules=_run(server,_sudo("ufw status"),30)
                if not re.search(rf"\b{int(server['port'])}(?:/tcp)?\b.*ALLOW",rules,re.I):raise HTTPException(status_code=409,detail=f"Add an ALLOW rule for SSH port {server['port']} before enabling UFW")
                output=_run(server,_sudo("ufw --force enable"),45)
            else:output=_run(server,_sudo("ufw disable"),45)
        except HTTPException:raise
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.firewall.toggle","server",server_id,expected);_event(db_factory,server_id,"warning","Firewall state changed",expected)
        return {"enabled":payload.enabled,"output":output.strip()}

    @app.get("/api/vps/servers/{server_id}/system-admin/packages")
    def packages(server_id:int)->dict[str,Any]:
        server=dict(server_lookup(server_id))
        script=r'''
set -e
printf '%s\n' '__OS__'
. /etc/os-release 2>/dev/null || true
printf '%s\n' "${PRETTY_NAME:-Linux}"
printf '%s\n' '__UPGRADES__'
apt list --upgradable 2>/dev/null | tail -n +2 || true
printf '%s\n' '__REBOOT__'
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required || echo no
printf '%s\n' '__AUTO__'
systemctl is-enabled unattended-upgrades.service 2>/dev/null || true
'''.strip()
        try:raw=_run(server,script,60)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        sections={"os":[],"upgrades":[],"reboot":[],"auto":[]};current=None;markers={"__OS__":"os","__UPGRADES__":"upgrades","__REBOOT__":"reboot","__AUTO__":"auto"}
        for line in raw.splitlines():
            if line in markers:current=markers[line]
            elif current:sections[current].append(line)
        upgrades=[]
        for line in sections["upgrades"]:
            m=re.match(r"([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]",line)
            upgrades.append({"name":m.group(1) if m else line.split('/')[0],"new_version":m.group(2) if m else "","old_version":m.group(3) if m else "","raw":line})
        return {"os":" ".join(sections["os"]),"upgrades":upgrades,"count":len(upgrades),"reboot_required":bool(sections["reboot"] and sections["reboot"][0]!="no"),"automatic_updates":sections["auto"][0] if sections["auto"] else "unknown","checked_at":_utc_now()}

    @app.post("/api/vps/servers/{server_id}/system-admin/packages/refresh")
    def refresh_packages(server_id:int,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id))
        try:output=_run(server,_sudo("DEBIAN_FRONTEND=noninteractive apt-get update"),900)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.packages.refresh","server",server_id,"Refreshed APT package indexes");return {"success":True,"output":output[-8000:]}

    @app.post("/api/vps/servers/{server_id}/system-admin/packages/action")
    def package_action(server_id:int,payload:PackageAction,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));pkgs=" ".join(shlex.quote(x) for x in payload.packages)
        if payload.action=="install":cmd=f"DEBIAN_FRONTEND=noninteractive apt-get install -y -- {pkgs}"
        elif payload.action=="remove":cmd=f"DEBIAN_FRONTEND=noninteractive apt-get remove -y -- {pkgs}"
        else:cmd=f"DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -- {pkgs}"
        try:output=_run(server,_sudo(cmd),1800)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn(f"vps.packages.{payload.action}","server",server_id,f"{payload.action}: {', '.join(payload.packages)}");_event(db_factory,server_id,"success","Package operation completed",f"{payload.action}: {', '.join(payload.packages)}")
        return {"success":True,"action":payload.action,"packages":payload.packages,"output":output[-12000:]}

    @app.post("/api/vps/servers/{server_id}/system-admin/packages/upgrade-all")
    def upgrade_all(server_id:int,payload:UpgradeAll,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id))
        if payload.confirm!="UPGRADE ALL":raise HTTPException(status_code=400,detail="Confirmation must be exactly: UPGRADE ALL")
        try:output=_run(server,_sudo("DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"),3600)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.packages.upgrade_all","server",server_id,"Upgraded all available APT packages");_event(db_factory,server_id,"success","OS packages upgraded","Completed apt-get upgrade")
        return {"success":True,"output":output[-16000:]}

    @app.post("/api/vps/servers/{server_id}/system-admin/reboot")
    def reboot(server_id:int,payload:RebootRequest,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id))
        try:hostname=_run(server,"hostname",15).strip()
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        if payload.confirm_hostname!=hostname:raise HTTPException(status_code=400,detail=f"Confirmation must be exactly the VPS hostname: {hostname}")
        try:_run(server,_sudo("shutdown -r +1 'Scheduled by Custom GitHub control plane'"),30)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.reboot.scheduled","server",server_id,f"Scheduled reboot for {hostname}");_event(db_factory,server_id,"warning","Server reboot scheduled",hostname)
        return {"scheduled":True,"hostname":hostname,"delay_minutes":1}

    @app.get("/api/vps/servers/{server_id}/system-admin/cron")
    def cron_jobs(server_id:int)->dict[str,Any]:
        server=dict(server_lookup(server_id))
        script=r'''
set +e
for f in /etc/cron.d/custom-github-*; do
  [ -f "$f" ] || continue
  name=$(basename "$f" | sed 's/^custom-github-//')
  content=$(grep -vE '^\s*(#|$)' "$f" | head -n1)
  printf '%s\t%s\n' "$name" "$(printf '%s' "$content" | base64 -w0)"
done
'''.strip()
        try:raw=_run(server,_sudo(f"sh -c {shlex.quote(script)}"),30)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        jobs=[]
        for line in raw.splitlines():
            parts=line.split("\t",1)
            if len(parts)!=2:continue
            try:content=base64.b64decode(parts[1]).decode("utf-8",errors="replace")
            except Exception:content=""
            fields=content.split(None,6)
            jobs.append({"name":parts[0],"schedule":" ".join(fields[:5]) if len(fields)>=7 else "","run_as":fields[5] if len(fields)>=7 else "","command":fields[6] if len(fields)>=7 else content,"raw":content})
        return {"jobs":jobs,"checked_at":_utc_now()}

    @app.post("/api/vps/servers/{server_id}/system-admin/cron",status_code=201)
    def create_cron(server_id:int,payload:CronCreate,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id));run_as=_user(payload.run_as) if payload.run_as!="root" else "root"
        line=f"{payload.schedule} {run_as} {payload.command}\n";encoded=base64.b64encode(line.encode()).decode();path=f"/etc/cron.d/custom-github-{payload.name}"
        script=f"set -eu\n[ ! -e {shlex.quote(path)} ] || {{ echo 'Managed cron job already exists' >&2; exit 41; }}\nprintf '%s' {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}\nchmod 0644 {shlex.quote(path)}\nchown root:root {shlex.quote(path)}"
        try:_run(server,_sudo(f"sh -c {shlex.quote(script)}"),45)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.cron.created","server",server_id,f"Created cron {payload.name}: {payload.schedule}");_event(db_factory,server_id,"success","Cron job created",payload.name)
        return {"name":payload.name,"schedule":payload.schedule,"run_as":run_as,"command":payload.command}

    @app.delete("/api/vps/servers/{server_id}/system-admin/cron/{name}")
    def delete_cron(server_id:int,name:str,payload:CronDelete,request:Request)->dict[str,Any]:
        _require_admin(request);server=dict(server_lookup(server_id))
        if not CRON_NAME_RE.fullmatch(name):raise HTTPException(status_code=400,detail="Invalid cron name")
        if payload.confirm_name!=name:raise HTTPException(status_code=400,detail="Cron name confirmation does not match")
        path=f"/etc/cron.d/custom-github-{name}"
        try:_run(server,_sudo(f"test -f {shlex.quote(path)} && rm -f -- {shlex.quote(path)}"),30)
        except RuntimeError as exc:raise HTTPException(status_code=502,detail=str(exc)) from exc
        audit_fn("vps.cron.deleted","server",server_id,f"Deleted cron {name}");_event(db_factory,server_id,"warning","Cron job deleted",name)
        return {"name":name,"deleted":True}


ADMIN_HTML=r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>System Administration</title><style>
:root{font-family:Inter,system-ui;color:#17231f;background:#f6f8f7}body{margin:0}.top{height:64px;background:#173c38;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 24px}.top a{color:#fff}.stage{max-width:1450px;margin:auto;padding:24px}.tabs{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:15px}button{border:1px solid #dfe7e2;background:#fff;border-radius:9px;padding:9px 11px;font-weight:750;cursor:pointer}.tabs button.active,.primary{background:#183f3b;color:#fff}.danger{color:#b42335}.card{background:#fff;border:1px solid #dfe7e2;border-radius:16px;overflow:hidden;margin-bottom:14px}.head{padding:15px 17px;border-bottom:1px solid #e8eeea;display:flex;justify-content:space-between}.pad{padding:17px}.sub{font-size:11px;color:#718078}.row{display:flex;gap:8px;flex-wrap:wrap;margin:9px 0}input,select,textarea{border:1px solid #dfe7e2;border-radius:9px;padding:9px 10px;font:inherit}input,select{height:38px}.item{padding:11px 0;border-bottom:1px solid #edf1ef}.tag{display:inline-block;padding:4px 8px;border-radius:99px;background:#eef4f1;font-size:10px}.panel{display:none}.panel.active{display:block}pre{background:#101815;color:#d9e7e0;border-radius:10px;padding:12px;white-space:pre-wrap;max-height:360px;overflow:auto;font-size:11px}</style></head><body><div class="top"><b>Custom GitHub · System Administration · __SERVER_NAME__</b><a href="/vps/__SERVER_ID__">Back to VPS</a></div><div class="stage"><h1>Linux System Administration</h1><p class="sub">Users/SSH, firewall, packages/updates and managed cron jobs. Mutating actions require Admin when RBAC is enabled.</p><div class="tabs"><button class="active" data-p="users">Users & SSH</button><button data-p="firewall">Firewall</button><button data-p="packages">Packages & OS</button><button data-p="cron">Cron Jobs</button></div><section id="users" class="panel active"><div class="card"><div class="head"><b>Linux users</b><button onclick="loadUsers()">↻</button></div><div class="pad"><div class="row"><input id="newUser" placeholder="username"><input id="newName" placeholder="display name"><input id="newGroups" placeholder="groups: docker,www-data"><label><input id="newSudo" type="checkbox"> sudo</label><textarea id="newKey" placeholder="optional SSH public key"></textarea><button class="primary" onclick="createUser()">Create user</button></div><div id="userList"></div></div></div><div class="card"><div class="head"><b>SSH keys</b></div><div class="pad"><div class="row"><input id="keyUser" placeholder="username"><button onclick="loadKeys()">Load keys</button><textarea id="sshKey" placeholder="ssh-ed25519 AAAA... comment"></textarea><button class="primary" onclick="addKey()">Add key</button></div><div id="keyList"></div></div></div></section><section id="firewall" class="panel"><div class="card"><div class="head"><b>UFW firewall</b><button onclick="loadFirewall()">↻</button></div><div class="pad"><div class="row"><select id="fwAction"><option>allow</option><option>deny</option></select><input id="fwPort" type="number" placeholder="port"><select id="fwProto"><option>tcp</option><option>udp</option></select><input id="fwSource" placeholder="source CIDR (optional)"><input id="fwComment" placeholder="comment"><button class="primary" onclick="addRule()">Add rule</button></div><pre id="fwRules">Loading…</pre><h3>Listening ports</h3><pre id="listening"></pre></div></div></section><section id="packages" class="panel"><div class="card"><div class="head"><b>APT & operating system</b><button onclick="loadPackages()">↻</button></div><div class="pad"><div id="pkgState"></div><div class="row"><button onclick="refreshApt()">apt update</button><input id="pkgNames" placeholder="package1,package2"><select id="pkgAction"><option>install</option><option>upgrade</option><option>remove</option></select><button class="primary" onclick="pkgActionRun()">Run</button><button class="danger" onclick="upgradeAll()">Upgrade all</button><button class="danger" onclick="reboot()">Schedule reboot</button></div><div id="upgradeList"></div><pre id="pkgOut">No package operation yet.</pre></div></div></section><section id="cron" class="panel"><div class="card"><div class="head"><b>Managed cron jobs</b><button onclick="loadCron()">↻</button></div><div class="pad"><div class="row"><input id="cronName" placeholder="backup-nightly"><input id="cronSchedule" placeholder="0 2 * * *"><input id="cronUser" value="root"><input id="cronCommand" placeholder="/usr/local/bin/backup"><button class="primary" onclick="createCron()">Create</button></div><div id="cronList"></div></div></div></section></div><script>
const sid=__SERVER_ID__;async function api(p,o={}){const r=await fetch(p,{headers:{'Content-Type':'application/json'},...o});const t=await r.text();let d={};try{d=t?JSON.parse(t):{}}catch{d={detail:t}}if(!r.ok)throw new Error(d.detail||t);return d}document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('active',x.id===b.dataset.p));({users:loadUsers,firewall:loadFirewall,packages:loadPackages,cron:loadCron}[b.dataset.p])()});async function loadUsers(){try{const d=await api(`/api/vps/servers/${sid}/system-admin/users`);userList.innerHTML=d.users.map(u=>`<div class=item><b>${u.username}</b> <span class=tag>UID ${u.uid}</span>${u.username===d.ssh_user?' <span class=tag>CONTROL PLANE SSH</span>':''}<div class=sub>${u.display_name||''} · ${u.home} · ${u.shell} · ${u.groups.join(', ')}</div>${u.uid>=1000&&u.username!==d.ssh_user?`<div class=row><button onclick="userAct('${u.username}','disable')">Disable</button><button onclick="userAct('${u.username}','enable')">Enable</button><button class=danger onclick="deleteUser('${u.username}')">Delete</button></div>`:''}</div>`).join('')}catch(e){userList.textContent=e.message}}async function createUser(){try{await api(`/api/vps/servers/${sid}/system-admin/users`,{method:'POST',body:JSON.stringify({username:newUser.value,display_name:newName.value,groups:newGroups.value.split(',').map(x=>x.trim()).filter(Boolean),sudo:newSudo.checked,public_key:newKey.value||null,shell:'/bin/bash'})});loadUsers()}catch(e){alert(e.message)}}async function userAct(u,a){try{await api(`/api/vps/servers/${sid}/system-admin/users/${u}/action`,{method:'POST',body:JSON.stringify({action:a})});loadUsers()}catch(e){alert(e.message)}}async function deleteUser(u){if(prompt(`Type username to delete ${u}`)!==u)return;try{await api(`/api/vps/servers/${sid}/system-admin/users/${u}`,{method:'DELETE',body:JSON.stringify({confirm_username:u,remove_home:true})});loadUsers()}catch(e){alert(e.message)}}async function loadKeys(){try{const d=await api(`/api/vps/servers/${sid}/system-admin/users/${keyUser.value}/keys`);keyList.innerHTML=d.keys.map(k=>`<div class=item><b>${k.type}</b> ${k.fingerprint}<div class=sub>${k.comment}</div><button class=danger onclick='removeKey(${JSON.stringify(k.public_key)})'>Revoke</button></div>`).join('')||'<p class=sub>No authorized keys.</p>'}catch(e){keyList.textContent=e.message}}async function addKey(){try{await api(`/api/vps/servers/${sid}/system-admin/users/${keyUser.value}/keys`,{method:'POST',body:JSON.stringify({public_key:sshKey.value})});sshKey.value='';loadKeys()}catch(e){alert(e.message)}}async function removeKey(k){if(!confirm('Revoke this public key?'))return;try{await api(`/api/vps/servers/${sid}/system-admin/users/${keyUser.value}/keys`,{method:'DELETE',body:JSON.stringify({public_key:k})});loadKeys()}catch(e){alert(e.message)}}async function loadFirewall(){try{const d=await api(`/api/vps/servers/${sid}/system-admin/firewall`);fwRules.textContent=d.installed?d.verbose+'\n\n'+d.rules:'UFW is not installed.';listening.textContent=d.listening||''}catch(e){fwRules.textContent=e.message}}async function addRule(){try{await api(`/api/vps/servers/${sid}/system-admin/firewall/rules`,{method:'POST',body:JSON.stringify({action:fwAction.value,port:Number(fwPort.value),protocol:fwProto.value,source:fwSource.value||null,comment:fwComment.value||null})});loadFirewall()}catch(e){alert(e.message)}}async function loadPackages(){try{const d=await api(`/api/vps/servers/${sid}/system-admin/packages`);pkgState.innerHTML=`<b>${d.os}</b><p>${d.count} update(s) · reboot ${d.reboot_required?'required':'not required'} · unattended-upgrades ${d.automatic_updates}</p>`;upgradeList.innerHTML=d.upgrades.map(x=>`<div class=item><b>${x.name}</b> ${x.old_version} → ${x.new_version}</div>`).join('')||'<p class=sub>No upgrades reported.</p>'}catch(e){pkgState.textContent=e.message}}async function refreshApt(){try{const d=await api(`/api/vps/servers/${sid}/system-admin/packages/refresh`,{method:'POST'});pkgOut.textContent=d.output;loadPackages()}catch(e){pkgOut.textContent=e.message}}async function pkgActionRun(){try{const d=await api(`/api/vps/servers/${sid}/system-admin/packages/action`,{method:'POST',body:JSON.stringify({action:pkgAction.value,packages:pkgNames.value.split(',').map(x=>x.trim()).filter(Boolean)})});pkgOut.textContent=d.output;loadPackages()}catch(e){pkgOut.textContent=e.message}}async function upgradeAll(){if(prompt('Type exactly: UPGRADE ALL')!=='UPGRADE ALL')return;try{const d=await api(`/api/vps/servers/${sid}/system-admin/packages/upgrade-all`,{method:'POST',body:JSON.stringify({confirm:'UPGRADE ALL'})});pkgOut.textContent=d.output;loadPackages()}catch(e){pkgOut.textContent=e.message}}async function reboot(){let h=prompt('Enter the VPS hostname to schedule reboot in 1 minute');if(!h)return;try{const d=await api(`/api/vps/servers/${sid}/system-admin/reboot`,{method:'POST',body:JSON.stringify({confirm_hostname:h})});alert(`Reboot scheduled for ${d.hostname}`)}catch(e){alert(e.message)}}async function loadCron(){try{const d=await api(`/api/vps/servers/${sid}/system-admin/cron`);cronList.innerHTML=d.jobs.map(j=>`<div class=item><b>${j.name}</b><div class=sub>${j.schedule} · ${j.run_as} · ${j.command}</div><button class=danger onclick="delCron('${j.name}')">Delete</button></div>`).join('')||'<p class=sub>No Custom GitHub managed cron jobs.</p>'}catch(e){cronList.textContent=e.message}}async function createCron(){try{await api(`/api/vps/servers/${sid}/system-admin/cron`,{method:'POST',body:JSON.stringify({name:cronName.value,schedule:cronSchedule.value,run_as:cronUser.value,command:cronCommand.value})});loadCron()}catch(e){alert(e.message)}}async function delCron(n){if(prompt(`Type cron name: ${n}`)!==n)return;try{await api(`/api/vps/servers/${sid}/system-admin/cron/${n}`,{method:'DELETE',body:JSON.stringify({confirm_name:n})});loadCron()}catch(e){alert(e.message)}}loadUsers();</script></body></html>"""


__all__=["install_system_admin_routes","FirewallRule","CronCreate","LinuxUserCreate"]
