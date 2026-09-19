from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import secrets
import sqlite3
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

ROLE_LEVEL = {"viewer": 10, "operator": 20, "developer": 30, "admin": 40, "owner": 50}
SESSION_COOKIE = "cg_session"
PBKDF2_ITERATIONS = 310_000
_security_db_factory: Callable[[], sqlite3.Connection] | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _future(hours: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii")


def _password_ok(password: str, salt_b64: str, expected_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(expected_b64)
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(actual, expected)


def _totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp(secret: str, counter: int) -> str:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode((secret + padding).upper())
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _totp_ok(secret: str, code: str, now: int | None = None) -> bool:
    if not code.isdigit() or len(code) != 6:
        return False
    counter = int((now or int(time.time())) // 30)
    return any(hmac.compare_digest(_totp(secret, counter + drift), code) for drift in (-1, 0, 1))


def _init_security_db(db_factory: Callable[[], sqlite3.Connection]) -> None:
    with db_factory() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS security_settings (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                session_hours INTEGER NOT NULL DEFAULT 12,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                totp_secret TEXT,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS security_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                user_agent TEXT,
                remote_addr TEXT,
                FOREIGN KEY(user_id) REFERENCES security_users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_security_sessions_token ON security_sessions(token_hash);
            CREATE INDEX IF NOT EXISTS idx_security_sessions_user ON security_sessions(user_id, id DESC);
            """
        )
        now = _utc_now()
        connection.execute(
            "INSERT OR IGNORE INTO security_settings(id, enabled, session_hours, created_at, updated_at) VALUES (1, 0, 12, ?, ?)",
            (now, now),
        )


def _settings(db_factory: Callable[[], sqlite3.Connection]) -> dict[str, Any]:
    with db_factory() as connection:
        row = connection.execute("SELECT * FROM security_settings WHERE id = 1").fetchone()
        count = int(connection.execute("SELECT COUNT(*) FROM security_users WHERE active = 1").fetchone()[0])
    return {"enabled": bool(row["enabled"]) if row else False, "session_hours": int(row["session_hours"]) if row else 12, "users": count}


def _session(db_factory: Callable[[], sqlite3.Connection], raw_token: str | None) -> dict[str, Any] | None:
    if not raw_token:
        return None
    now = datetime.now(timezone.utc)
    with db_factory() as connection:
        row = connection.execute(
            """
            SELECT s.*, u.username, u.display_name, u.role, u.active, u.mfa_enabled
            FROM security_sessions s JOIN security_users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (_token_hash(raw_token),),
        ).fetchone()
        if not row or not row["active"]:
            return None
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except Exception:
            return None
        if expires <= now:
            connection.execute("DELETE FROM security_sessions WHERE id = ?", (row["id"],))
            return None
        connection.execute("UPDATE security_sessions SET last_seen_at = ? WHERE id = ?", (_utc_now(), row["id"]))
        return dict(row)


def _required_role(path: str, method: str) -> str:
    method = method.upper()
    if path.startswith("/api/security/users") or path.startswith("/api/security/settings"):
        return "owner"
    if path.startswith("/api/security"):
        return "viewer"
    if "/domains" in path or "/ssl" in path:
        return "admin" if method != "GET" else "viewer"
    if "/backups" in path:
        if "/restore" in path or method == "DELETE":
            return "admin"
        return "operator" if method != "GET" else "viewer"
    if "/terminal/" in path:
        return "developer"
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "viewer"
    if "/file" in path or "/files" in path or "/databases" in path:
        return "developer"
    if method in {"PUT", "PATCH", "DELETE"}:
        return "developer"
    return "operator"


def _same_origin(request: Request) -> bool:
    host = request.headers.get("host", "")
    origin = request.headers.get("origin", "")
    referer = request.headers.get("referer", "")
    sec_fetch_site = request.headers.get("sec-fetch-site", "")
    expected_http = f"http://{host}"
    expected_https = f"https://{host}"
    if origin in {expected_http, expected_https}:
        return True
    if referer.startswith(expected_http + "/") or referer.startswith(expected_https + "/"):
        return True
    return sec_fetch_site in {"same-origin", "same-site"}


class ControlPlaneSecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, db_factory: Callable[[], sqlite3.Connection]):
        super().__init__(app)
        self.db_factory = db_factory

    async def dispatch(self, request: Request, call_next: Callable[..., Any]):
        path = request.url.path
        if path.startswith("/auth/") or path in {"/auth", "/health", "/favicon.ico"}:
            return await call_next(request)
        state = _settings(self.db_factory)
        if not state["enabled"] or state["users"] == 0:
            return await call_next(request)
        session = _session(self.db_factory, request.cookies.get(SESSION_COOKIE))
        if not session:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Authentication required"}, status_code=401)
            return RedirectResponse(url=f"/auth/login?next={quote(path)}", status_code=303)
        request.state.security_user = session
        required = _required_role(path, request.method)
        if ROLE_LEVEL.get(session["role"], 0) < ROLE_LEVEL[required]:
            if path.startswith("/api/"):
                return JSONResponse({"detail": f"{required} role required"}, status_code=403)
            return HTMLResponse("<h1>403</h1><p>Insufficient role.</p>", status_code=403)
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            csrf = request.headers.get("x-csrf-token", "")
            if not hmac.compare_digest(csrf, str(session["csrf_token"])) and not _same_origin(request):
                return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return response


class BootstrapPayload(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=256)


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp: str | None = Field(default=None, max_length=12)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern=r"^(owner|admin|developer|operator|viewer)$")


class UserRoleUpdate(BaseModel):
    role: str = Field(pattern=r"^(owner|admin|developer|operator|viewer)$")


class TotpEnable(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class PasswordConfirm(BaseModel):
    password: str = Field(min_length=1, max_length=256)


def _client_is_loopback(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


def authorize_websocket(websocket: WebSocket, minimum_role: str = "developer") -> tuple[bool, str]:
    if _security_db_factory is None:
        return True, "security-not-configured"
    state = _settings(_security_db_factory)
    if not state["enabled"] or state["users"] == 0:
        return True, "bootstrap-mode"
    session = _session(_security_db_factory, websocket.cookies.get(SESSION_COOKIE))
    if not session:
        return False, "Authentication required"
    if ROLE_LEVEL.get(session["role"], 0) < ROLE_LEVEL[minimum_role]:
        return False, f"{minimum_role} role required"
    return True, session["username"]


LOGIN_HTML = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Custom GitHub · Sign in</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f8f6;font-family:Inter,system-ui;color:#17231f}.card{width:min(430px,calc(100vw - 36px));background:#fff;border:1px solid #dfe7e2;border-radius:18px;padding:28px;box-shadow:0 20px 60px rgba(18,50,40,.12)}h1{margin:0 0 5px}.sub{color:#718078;font-size:13px;margin-bottom:22px}.row{display:grid;gap:6px;margin:13px 0}label{font-size:11px;font-weight:800}input{height:42px;border:1px solid #dfe7e2;border-radius:10px;padding:0 12px;font:inherit}button{width:100%;height:43px;border:0;border-radius:10px;background:#183f3b;color:white;font-weight:800;margin-top:10px;cursor:pointer}.err{color:#b42335;font-size:12px;min-height:18px}.brand{color:#285b55;font-weight:900;font-size:12px;letter-spacing:.08em;text-transform:uppercase}</style></head><body><div class='card'><div class='brand'>Custom GitHub</div><h1>Sign in</h1><div class='sub'>Infrastructure control plane</div><div class='row'><label>Username</label><input id='u' autocomplete='username'></div><div class='row'><label>Password</label><input id='p' type='password' autocomplete='current-password'></div><div class='row'><label>Authenticator code <span style='font-weight:400;color:#718078'>(when enabled)</span></label><input id='t' inputmode='numeric' maxlength='6'></div><div class='err' id='e'></div><button id='b'>Sign in</button></div><script>
const q=new URLSearchParams(location.search);document.getElementById('b').onclick=async()=>{const b=document.getElementById('b');b.disabled=true;document.getElementById('e').textContent='';try{const r=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value,totp:t.value||null})});const d=await r.json();if(!r.ok)throw new Error(d.detail||'Sign in failed');location.href=q.get('next')||'/';}catch(x){document.getElementById('e').textContent=x.message;b.disabled=false;}};</script></body></html>"""


def security_center_html() -> str:
    return """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Security Center</title><style>
:root{font-family:Inter,system-ui;color:#17231f;background:#f5f8f6}body{margin:0}.top{padding:18px 24px;background:#173c38;color:white;display:flex;justify-content:space-between}.stage{max-width:1200px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{grid-column:span 6;background:white;border:1px solid #dfe7e2;border-radius:16px;padding:18px}.wide{grid-column:span 12}h1,h2{margin-top:0}input,select{height:38px;border:1px solid #dfe7e2;border-radius:9px;padding:0 10px}button,.btn{border:1px solid #dfe7e2;background:white;border-radius:9px;padding:9px 11px;font-weight:750;cursor:pointer}.primary{background:#183f3b;color:white}.row{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}.muted{color:#718078;font-size:12px}.user{display:flex;justify-content:space-between;border-top:1px solid #edf1ef;padding:11px 0}.tag{font-size:10px;border-radius:99px;padding:4px 8px;background:#eef4f1}.good{color:#167347}.warn{color:#a45f00}@media(max-width:800px){.card{grid-column:span 12}}</style></head><body><div class='top'><b>Custom GitHub · Security Center</b><a href='/' style='color:white'>Back to control plane</a></div><div class='stage'><h1>Security & access</h1><p class='muted'>Authentication, roles, sessions and MFA. Local bootstrap is allowed only before the first Owner is created.</p><div class='grid'><div class='card'><h2>Security state</h2><div id='state'>Loading…</div><div id='bootstrap' style='display:none'><h3>Create first Owner</h3><div class='row'><input id='bu' placeholder='username'><input id='bn' placeholder='display name'></div><div class='row'><input id='bp' type='password' placeholder='password (12+ characters)'><button class='primary' onclick='bootstrapOwner()'>Bootstrap Owner</button></div></div></div><div class='card'><h2>My account</h2><div id='me'>Loading…</div><div class='row'><button onclick='setupMfa()'>Set up MFA</button><button onclick='logout()'>Sign out</button></div><pre id='mfa' style='white-space:pre-wrap;font-size:11px'></pre></div><div class='card wide'><h2>Users & roles</h2><div class='row'><input id='nu' placeholder='username'><input id='nn' placeholder='display name'><input id='np' type='password' placeholder='temporary password'><select id='nr'><option>viewer</option><option>operator</option><option>developer</option><option>admin</option><option>owner</option></select><button class='primary' onclick='createUser()'>Add user</button></div><div id='users'></div></div></div></div><script>
async function api(p,o={}){const r=await fetch(p,{headers:{'Content-Type':'application/json',...(o.headers||{})},...o});const t=await r.text();let d={};try{d=t?JSON.parse(t):{}}catch{d={detail:t}}if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);return d}async function load(){const s=await api('/auth/status');state.innerHTML=`<p><span class='tag ${s.enabled?'good':'warn'}'>${s.enabled?'ENABLED':'BOOTSTRAP MODE'}</span></p><p>${s.users} active user(s) · ${s.session_hours}h sessions</p>`;bootstrap.style.display=s.users?'none':'block';try{const m=await api('/api/security/me');me.innerHTML=`<b>${m.display_name}</b><p>${m.username} · ${m.role} · MFA ${m.mfa_enabled?'enabled':'not enabled'}</p>`;}catch{me.innerHTML='Not signed in.'}try{const u=await api('/api/security/users');users.innerHTML=u.map(x=>`<div class='user'><div><b>${x.display_name}</b><div class='muted'>${x.username} · ${x.role} · MFA ${x.mfa_enabled?'on':'off'}</div></div><span class='tag'>${x.active?'ACTIVE':'DISABLED'}</span></div>`).join('')}catch(e){users.innerHTML=`<p class='muted'>${e.message}</p>`}}async function bootstrapOwner(){await api('/auth/bootstrap',{method:'POST',body:JSON.stringify({username:bu.value,display_name:bn.value,password:bp.value})});location.href='/auth/login'}async function createUser(){try{await api('/api/security/users',{method:'POST',body:JSON.stringify({username:nu.value,display_name:nn.value,password:np.value,role:nr.value})});load()}catch(e){alert(e.message)}}async function setupMfa(){try{const d=await api('/api/security/mfa/setup',{method:'POST'});mfa.textContent=`Secret: ${d.secret}\n\nURI: ${d.otpauth_uri}\n\nAdd this to your authenticator, then enter the 6-digit code:`;const c=prompt('Authenticator code');if(c){await api('/api/security/mfa/enable',{method:'POST',body:JSON.stringify({code:c})});mfa.textContent='MFA enabled.';load()}}catch(e){alert(e.message)}}async function logout(){await api('/auth/logout',{method:'POST'});location.href='/auth/login'}load();</script></body></html>"""


def install_security_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    audit_fn: Callable[[str, str, int | None, str], None],
) -> None:
    global _security_db_factory
    _security_db_factory = db_factory
    _init_security_db(db_factory)
    app.add_middleware(ControlPlaneSecurityMiddleware, db_factory=db_factory)

    @app.get("/auth/status")
    def auth_status() -> dict[str, Any]:
        return _settings(db_factory)

    @app.get("/auth/login", response_class=HTMLResponse, include_in_schema=False)
    def login_page() -> str:
        return LOGIN_HTML

    @app.get("/security", response_class=HTMLResponse, include_in_schema=False)
    def security_center() -> str:
        return security_center_html()

    @app.post("/auth/bootstrap", status_code=201)
    def bootstrap(payload: BootstrapPayload, request: Request) -> dict[str, Any]:
        if not _client_is_loopback(request):
            raise HTTPException(status_code=403, detail="Initial Owner bootstrap is allowed only from the local machine")
        with db_factory() as connection:
            if connection.execute("SELECT 1 FROM security_users LIMIT 1").fetchone():
                raise HTTPException(status_code=409, detail="Security has already been bootstrapped")
            salt, digest = _password_hash(payload.password)
            now = _utc_now()
            cursor = connection.execute(
                "INSERT INTO security_users(username, display_name, password_salt, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, 'owner', ?, ?)",
                (payload.username.lower(), payload.display_name.strip(), salt, digest, now, now),
            )
            connection.execute("UPDATE security_settings SET enabled = 1, updated_at = ? WHERE id = 1", (now,))
            user_id = int(cursor.lastrowid)
        audit_fn("security.bootstrap", "security_user", user_id, f"Bootstrapped Owner {payload.username.lower()}")
        return {"id": user_id, "username": payload.username.lower(), "role": "owner", "security_enabled": True}

    @app.post("/auth/login")
    def login(payload: LoginPayload, request: Request):
        username = payload.username.strip().lower()
        with db_factory() as connection:
            user = connection.execute("SELECT * FROM security_users WHERE username = ? AND active = 1", (username,)).fetchone()
            if not user or not _password_ok(payload.password, user["password_salt"], user["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid username or password")
            if user["mfa_enabled"]:
                if not user["totp_secret"] or not payload.totp or not _totp_ok(user["totp_secret"], payload.totp):
                    raise HTTPException(status_code=401, detail="Valid authenticator code required")
            state = _settings(db_factory)
            raw_token = secrets.token_urlsafe(36)
            csrf = secrets.token_urlsafe(24)
            now = _utc_now()
            connection.execute(
                "INSERT INTO security_sessions(user_id, token_hash, csrf_token, expires_at, created_at, last_seen_at, user_agent, remote_addr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    user["id"], _token_hash(raw_token), csrf, _future(state["session_hours"]), now, now,
                    request.headers.get("user-agent", "")[:500], request.client.host if request.client else None,
                ),
            )
            connection.execute("UPDATE security_users SET last_login_at = ?, updated_at = ? WHERE id = ?", (now, now, user["id"]))
        audit_fn("security.login", "security_user", int(user["id"]), f"Login for {username}")
        response = JSONResponse({"ok": True, "username": username, "role": user["role"], "csrf_token": csrf})
        response.set_cookie(
            SESSION_COOKIE, raw_token, max_age=state["session_hours"] * 3600, httponly=True,
            secure=request.url.scheme == "https", samesite="strict", path="/",
        )
        response.set_cookie("cg_csrf", csrf, max_age=state["session_hours"] * 3600, httponly=False, secure=request.url.scheme == "https", samesite="strict", path="/")
        return response

    @app.post("/auth/logout")
    def logout(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            with db_factory() as connection:
                connection.execute("DELETE FROM security_sessions WHERE token_hash = ?", (_token_hash(token),))
        response = JSONResponse({"ok": True})
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie("cg_csrf", path="/")
        return response

    @app.get("/api/security/me")
    def me(request: Request) -> dict[str, Any]:
        user = getattr(request.state, "security_user", None)
        if not user:
            state = _settings(db_factory)
            if not state["enabled"]:
                return {"username": "local-bootstrap", "display_name": "Local operator", "role": "owner", "mfa_enabled": False, "bootstrap_mode": True}
            raise HTTPException(status_code=401, detail="Authentication required")
        return {"id": user["user_id"], "username": user["username"], "display_name": user["display_name"], "role": user["role"], "mfa_enabled": bool(user["mfa_enabled"]), "csrf_token": user["csrf_token"]}

    @app.get("/api/security/users")
    def users() -> list[dict[str, Any]]:
        with db_factory() as connection:
            rows = connection.execute("SELECT id, username, display_name, role, mfa_enabled, active, created_at, last_login_at FROM security_users ORDER BY username").fetchall()
        return [{**dict(row), "mfa_enabled": bool(row["mfa_enabled"]), "active": bool(row["active"])} for row in rows]

    @app.post("/api/security/users", status_code=201)
    def create_user(payload: UserCreate) -> dict[str, Any]:
        salt, digest = _password_hash(payload.password)
        now = _utc_now()
        try:
            with db_factory() as connection:
                cursor = connection.execute(
                    "INSERT INTO security_users(username, display_name, password_salt, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (payload.username.lower(), payload.display_name.strip(), salt, digest, payload.role, now, now),
                )
                user_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Username already exists") from exc
        audit_fn("security.user.created", "security_user", user_id, f"Created {payload.role} user {payload.username.lower()}")
        return {"id": user_id, "username": payload.username.lower(), "role": payload.role}

    @app.patch("/api/security/users/{user_id}/role")
    def update_role(user_id: int, payload: UserRoleUpdate) -> dict[str, Any]:
        with db_factory() as connection:
            user = connection.execute("SELECT * FROM security_users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            if user["role"] == "owner" and payload.role != "owner":
                owner_count = int(connection.execute("SELECT COUNT(*) FROM security_users WHERE role='owner' AND active=1").fetchone()[0])
                if owner_count <= 1:
                    raise HTTPException(status_code=409, detail="At least one active Owner must remain")
            connection.execute("UPDATE security_users SET role = ?, updated_at = ? WHERE id = ?", (payload.role, _utc_now(), user_id))
            connection.execute("DELETE FROM security_sessions WHERE user_id = ?", (user_id,))
        audit_fn("security.user.role", "security_user", user_id, f"Changed role to {payload.role}")
        return {"id": user_id, "role": payload.role, "sessions_revoked": True}

    @app.post("/api/security/mfa/setup")
    def mfa_setup(request: Request) -> dict[str, Any]:
        user = getattr(request.state, "security_user", None)
        if not user:
            raise HTTPException(status_code=409, detail="Bootstrap security and sign in before configuring MFA")
        secret = _totp_secret()
        with db_factory() as connection:
            connection.execute("UPDATE security_users SET totp_secret = ?, mfa_enabled = 0, updated_at = ? WHERE id = ?", (secret, _utc_now(), user["user_id"]))
        label = quote(f"Custom GitHub:{user['username']}")
        uri = f"otpauth://totp/{label}?secret={secret}&issuer=Custom%20GitHub&digits=6&period=30"
        return {"secret": secret, "otpauth_uri": uri}

    @app.post("/api/security/mfa/enable")
    def mfa_enable(request: Request, payload: TotpEnable) -> dict[str, Any]:
        user = getattr(request.state, "security_user", None)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        with db_factory() as connection:
            row = connection.execute("SELECT totp_secret FROM security_users WHERE id = ?", (user["user_id"],)).fetchone()
            if not row or not row["totp_secret"] or not _totp_ok(row["totp_secret"], payload.code):
                raise HTTPException(status_code=400, detail="Authenticator code is invalid")
            connection.execute("UPDATE security_users SET mfa_enabled = 1, updated_at = ? WHERE id = ?", (_utc_now(), user["user_id"]))
        audit_fn("security.mfa.enabled", "security_user", int(user["user_id"]), "MFA enabled")
        return {"enabled": True}


__all__ = ["authorize_websocket", "install_security_routes", "ROLE_LEVEL"]
