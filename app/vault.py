from __future__ import annotations

import hashlib
import html
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

SECRET_TYPES = {"password", "token", "api-key", "env", "database", "webhook", "other"}
SCOPES = {"global", "server", "project"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _master_key_path(data_dir: Path) -> Path:
    configured = os.getenv("CUSTOM_GITHUB_VAULT_KEY_FILE", "").strip()
    return Path(configured).expanduser().resolve() if configured else data_dir / "vault.key"


def _load_fernet(data_dir: Path, *, create: bool = False) -> Fernet:
    env_key = os.getenv("CUSTOM_GITHUB_VAULT_KEY", "").strip()
    if env_key:
        try:
            return Fernet(env_key.encode("ascii"))
        except Exception as exc:
            raise RuntimeError("CUSTOM_GITHUB_VAULT_KEY is not a valid Fernet key") from exc

    path = _master_key_path(data_dir)
    if not path.exists():
        if not create:
            raise RuntimeError("Vault master key has not been initialized")
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key + b"\n")
        finally:
            os.close(fd)
    try:
        raw = path.read_text(encoding="ascii").strip().encode("ascii")
        return Fernet(raw)
    except Exception as exc:
        raise RuntimeError(f"Unable to load vault key from {path}") from exc


def _security_ready(db_factory: Callable[[], sqlite3.Connection]) -> bool:
    try:
        with db_factory() as connection:
            settings = connection.execute("SELECT enabled FROM security_settings WHERE id=1").fetchone()
            users = int(connection.execute("SELECT COUNT(*) FROM security_users WHERE active=1").fetchone()[0])
        return bool(settings and settings["enabled"] and users > 0)
    except sqlite3.OperationalError:
        return False


def _role(request: Request) -> str:
    user = getattr(request.state, "security_user", None)
    return str(user["role"]) if user else ""


def _require_role(request: Request, allowed: set[str]) -> None:
    if _role(request) not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient role for this vault action")


def _scope(scope: str, scope_id: int | None) -> tuple[str, int | None]:
    if scope not in SCOPES:
        raise HTTPException(status_code=400, detail="Invalid secret scope")
    if scope == "global":
        return scope, None
    if scope_id is None or scope_id <= 0:
        raise HTTPException(status_code=400, detail=f"{scope} scope requires a positive scope_id")
    return scope, scope_id


class SecretCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120, pattern=r"^[A-Za-z0-9._/-]+$")
    secret_type: str = Field(default="other", pattern=r"^(password|token|api-key|env|database|webhook|other)$")
    scope: str = Field(default="global", pattern=r"^(global|server|project)$")
    scope_id: int | None = Field(default=None, ge=1)
    description: str = Field(default="", max_length=500)
    value: str = Field(min_length=1, max_length=65536)


class SecretUpdate(BaseModel):
    value: str = Field(min_length=1, max_length=65536)
    description: str | None = Field(default=None, max_length=500)


class RevealRequest(BaseModel):
    confirm: str = Field(min_length=1, max_length=180)


class DeleteRequest(BaseModel):
    confirm: str = Field(min_length=1, max_length=180)


def install_vault_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    audit_fn: Callable[[str, str, int | None, str], None],
    data_dir: Path,
) -> None:
    def init_db() -> None:
        with db_factory() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS vault_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    scope_id INTEGER,
                    description TEXT NOT NULL DEFAULT '',
                    ciphertext TEXT NOT NULL,
                    value_fingerprint TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(name, scope, scope_id)
                );
                CREATE INDEX IF NOT EXISTS idx_vault_scope ON vault_items(scope, scope_id, name);
                """
            )

    @app.on_event("startup")
    def startup_vault() -> None:
        init_db()

    def require_ready() -> None:
        if not _security_ready(db_factory):
            raise HTTPException(status_code=409, detail="Create the Owner account and enable control-plane security before using the vault")

    def row_or_404(item_id: int) -> sqlite3.Row:
        with db_factory() as connection:
            row = connection.execute("SELECT * FROM vault_items WHERE id=?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Secret not found")
        return row

    def metadata(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "secret_type": row["secret_type"],
            "scope": row["scope"],
            "scope_id": row["scope_id"],
            "description": row["description"],
            "fingerprint": row["value_fingerprint"],
            "version": row["version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @app.get("/vault", response_class=HTMLResponse, include_in_schema=False)
    def vault_page(request: Request) -> str:
        require_ready()
        _require_role(request, {"owner", "admin"})
        return _vault_html()

    @app.get("/api/vault/status")
    def vault_status(request: Request) -> dict[str, Any]:
        require_ready()
        _require_role(request, {"owner", "admin"})
        path = _master_key_path(data_dir)
        key_source = "environment" if os.getenv("CUSTOM_GITHUB_VAULT_KEY", "").strip() else "file"
        try:
            _load_fernet(data_dir, create=False)
            unlocked = True
            error = None
        except Exception as exc:
            unlocked = False
            error = str(exc)
        with db_factory() as connection:
            count = int(connection.execute("SELECT COUNT(*) FROM vault_items").fetchone()[0])
        return {
            "initialized": unlocked,
            "items": count,
            "key_source": key_source,
            "key_file": None if key_source == "environment" else str(path),
            "error": error,
            "note": "The master key is separate from SQLite. Back it up securely; encrypted values cannot be recovered without it.",
        }

    @app.post("/api/vault/initialize", status_code=201)
    def initialize_vault(request: Request) -> dict[str, Any]:
        require_ready()
        _require_role(request, {"owner"})
        _load_fernet(data_dir, create=True)
        path = _master_key_path(data_dir)
        audit_fn("vault.initialized", "vault", None, f"Secrets vault initialized; key source {'environment' if os.getenv('CUSTOM_GITHUB_VAULT_KEY') else path}")
        return {"initialized": True, "key_file": None if os.getenv("CUSTOM_GITHUB_VAULT_KEY") else str(path)}

    @app.get("/api/vault/items")
    def list_items(request: Request) -> list[dict[str, Any]]:
        require_ready()
        _require_role(request, {"owner", "admin"})
        with db_factory() as connection:
            rows = connection.execute("SELECT * FROM vault_items ORDER BY scope, scope_id, name").fetchall()
        return [metadata(row) for row in rows]

    @app.post("/api/vault/items", status_code=201)
    def create_item(payload: SecretCreate, request: Request) -> dict[str, Any]:
        require_ready()
        _require_role(request, {"owner", "admin"})
        scope, scope_id = _scope(payload.scope, payload.scope_id)
        fernet = _load_fernet(data_dir, create=True)
        ciphertext = fernet.encrypt(payload.value.encode("utf-8")).decode("ascii")
        fingerprint = hashlib.sha256(payload.value.encode("utf-8")).hexdigest()[:12]
        now = _now()
        try:
            with db_factory() as connection:
                cursor = connection.execute(
                    "INSERT INTO vault_items(name,secret_type,scope,scope_id,description,ciphertext,value_fingerprint,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,1,?,?)",
                    (payload.name, payload.secret_type, scope, scope_id, payload.description, ciphertext, fingerprint, now, now),
                )
                item_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="A secret with this name already exists in that scope") from exc
        audit_fn("vault.secret.created", "vault", item_id, f"Created {scope} secret {payload.name}; value not logged")
        return metadata(row_or_404(item_id))

    @app.put("/api/vault/items/{item_id}")
    def update_item(item_id: int, payload: SecretUpdate, request: Request) -> dict[str, Any]:
        require_ready()
        _require_role(request, {"owner", "admin"})
        row = row_or_404(item_id)
        fernet = _load_fernet(data_dir, create=False)
        ciphertext = fernet.encrypt(payload.value.encode("utf-8")).decode("ascii")
        fingerprint = hashlib.sha256(payload.value.encode("utf-8")).hexdigest()[:12]
        description = row["description"] if payload.description is None else payload.description
        with db_factory() as connection:
            connection.execute(
                "UPDATE vault_items SET ciphertext=?,value_fingerprint=?,description=?,version=version+1,updated_at=? WHERE id=?",
                (ciphertext, fingerprint, description, _now(), item_id),
            )
        audit_fn("vault.secret.rotated", "vault", item_id, f"Rotated secret {row['name']}; value not logged")
        return metadata(row_or_404(item_id))

    @app.post("/api/vault/items/{item_id}/reveal")
    def reveal_item(item_id: int, payload: RevealRequest, request: Request) -> dict[str, Any]:
        require_ready()
        _require_role(request, {"owner"})
        row = row_or_404(item_id)
        expected = f"REVEAL {row['name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected}")
        try:
            value = _load_fernet(data_dir).decrypt(str(row["ciphertext"]).encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise HTTPException(status_code=500, detail="Secret cannot be decrypted with the current vault master key") from exc
        audit_fn("vault.secret.revealed", "vault", item_id, f"Revealed secret {row['name']}; value not logged")
        return {"id": item_id, "name": row["name"], "value": value, "warning": "Secret values are never returned by list endpoints and should not be copied into logs."}

    @app.delete("/api/vault/items/{item_id}")
    def delete_item(item_id: int, payload: DeleteRequest, request: Request) -> dict[str, Any]:
        require_ready()
        _require_role(request, {"owner"})
        row = row_or_404(item_id)
        expected = f"DELETE {row['name']}"
        if payload.confirm != expected:
            raise HTTPException(status_code=400, detail=f"Type exactly: {expected}")
        with db_factory() as connection:
            connection.execute("DELETE FROM vault_items WHERE id=?", (item_id,))
        audit_fn("vault.secret.deleted", "vault", item_id, f"Deleted secret {row['name']}; value not logged")
        return {"deleted": True, "id": item_id}


def _vault_html() -> str:
    return """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Secrets Vault</title>
<style>body{margin:0;background:#08101d;color:#e8eef8;font:14px system-ui}.wrap{max-width:1180px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;align-items:center}.muted{color:#93a4bb}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:20px 0}.card,.panel{background:#111c2b;border:1px solid #26364c;border-radius:14px;padding:18px}.big{font-size:28px;font-weight:800}.btn{background:#1c2a3d;color:#fff;border:1px solid #34465e;border-radius:9px;padding:9px 13px;cursor:pointer}.primary{background:#2878ff}.danger{background:#8c2633}.row{display:flex;gap:10px;flex-wrap:wrap}.item{display:grid;grid-template-columns:1.5fr .7fr .7fr .7fr 1.2fr auto;gap:10px;align-items:center;border-top:1px solid #26364c;padding:12px 0}.pill{padding:4px 8px;border:1px solid #3b4d66;border-radius:999px;font-size:12px}.ok{color:#69dda4}.bad{color:#ff8b96}input,select,textarea{background:#08101d;color:#fff;border:1px solid #34465e;border-radius:8px;padding:9px}dialog{background:#111c2b;color:#fff;border:1px solid #34465e;border-radius:14px;max-width:620px;width:90%}code{color:#9cc4ff}@media(max-width:800px){.cards{grid-template-columns:1fr}.item{grid-template-columns:1fr 1fr}}</style></head><body><div class='wrap'>
<div class='top'><div><div class='muted'>CUSTOM GITHUB / SECURITY</div><h1>Encrypted Secrets Vault</h1><div class='muted'>Encrypted at rest. Secret values never appear in inventory responses or audit logs.</div></div><div class='row'><a class='btn' href='/security'>Security Center</a><a class='btn' href='/'>Control Center</a></div></div>
<div class='cards'><div class='card'><div class='muted'>VAULT STATE</div><div id='state' class='big'>Loading…</div></div><div class='card'><div class='muted'>SECRETS</div><div id='count' class='big'>—</div></div><div class='card'><div class='muted'>MASTER KEY</div><div id='source' class='big'>—</div></div></div>
<div class='panel'><div class='top'><div><h2>Secrets</h2><div class='muted'>Scopes can be global, server-specific or project-specific.</div></div><div class='row'><button class='btn' onclick='initVault()'>Initialize vault</button><button class='btn primary' onclick='openCreate()'>+ Add secret</button></div></div><div id='items'></div></div></div>
<dialog id='create'><h2>Add encrypted secret</h2><div style='display:grid;gap:10px'><input id='name' placeholder='Name e.g. loanhub/database/password'><select id='type'><option>password</option><option>token</option><option>api-key</option><option>env</option><option>database</option><option>webhook</option><option>other</option></select><select id='scope'><option>global</option><option>server</option><option>project</option></select><input id='scopeid' type='number' placeholder='Scope ID (leave empty for global)'><textarea id='desc' placeholder='Description'></textarea><textarea id='value' placeholder='Secret value'></textarea><div class='row'><button class='btn primary' onclick='saveSecret()'>Encrypt & save</button><button class='btn' onclick='create.close()'>Cancel</button></div></div></dialog>
<script>const $=id=>document.getElementById(id);async function api(url,opt={}){const r=await fetch(url,{...opt,headers:{'content-type':'application/json',...(opt.headers||{})}});const x=await r.json().catch(()=>({}));if(!r.ok)throw Error(x.detail||r.statusText);return x}function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function load(){try{const s=await api('/api/vault/status');$('state').textContent=s.initialized?'UNLOCKED':'NOT INITIALIZED';$('state').className='big '+(s.initialized?'ok':'bad');$('count').textContent=s.items;$('source').textContent=s.key_source.toUpperCase();const items=await api('/api/vault/items');$('items').innerHTML=items.length?items.map(i=>`<div class='item'><div><b>${esc(i.name)}</b><div class='muted'>${esc(i.description)}</div></div><span class='pill'>${esc(i.secret_type)}</span><span>${esc(i.scope)}${i.scope_id?' #'+i.scope_id:''}</span><span>v${i.version}</span><code>${esc(i.fingerprint)}</code><div class='row'><button class='btn' onclick='reveal(${i.id},${JSON.stringify(i.name)})'>Reveal</button><button class='btn danger' onclick='del(${i.id},${JSON.stringify(i.name)})'>Delete</button></div></div>`).join(''):`<p class='muted'>No secrets stored.</p>`}catch(e){$('items').innerHTML=`<p class='bad'>${esc(e.message)}</p>`}}async function initVault(){try{await api('/api/vault/initialize',{method:'POST',body:'{}'});await load()}catch(e){alert(e.message)}}function openCreate(){$('create').showModal()}async function saveSecret(){try{await api('/api/vault/items',{method:'POST',body:JSON.stringify({name:$('name').value,secret_type:$('type').value,scope:$('scope').value,scope_id:$('scopeid').value?Number($('scopeid').value):null,description:$('desc').value,value:$('value').value})});$('value').value='';$('create').close();await load()}catch(e){alert(e.message)}}async function reveal(id,name){const confirm=prompt(`Owner-only reveal. Type: REVEAL ${name}`);if(!confirm)return;try{const x=await api(`/api/vault/items/${id}/reveal`,{method:'POST',body:JSON.stringify({confirm})});prompt('Secret value (will not be logged by Custom GitHub):',x.value)}catch(e){alert(e.message)}}async function del(id,name){const confirm=prompt(`Type: DELETE ${name}`);if(!confirm)return;try{await api(`/api/vault/items/${id}`,{method:'DELETE',body:JSON.stringify({confirm})});await load()}catch(e){alert(e.message)}}load()</script></body></html>"""
