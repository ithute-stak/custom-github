from __future__ import annotations

import base64
import json
import os
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.deployment import ssh_command


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
READ_ONLY_SQL = {"select", "show", "describe", "desc", "explain", "values"}
MAX_SQL_BYTES = 256 * 1024
MAX_ROWS = 500


class SqlRequest(BaseModel):
    container: str = Field(min_length=1, max_length=128)
    database: str = Field(min_length=1, max_length=128)
    sql: str = Field(min_length=1, max_length=MAX_SQL_BYTES)
    confirm_write: bool = False


class DatabaseCreate(BaseModel):
    container: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=63)


class DatabaseDrop(BaseModel):
    container: str = Field(min_length=1, max_length=128)
    database: str = Field(min_length=1, max_length=128)
    confirm_database: str = Field(min_length=1, max_length=128)


class RowInsert(BaseModel):
    container: str
    database: str
    schema_name: str = "public"
    table: str
    values: dict[str, Any]


class RowUpdate(BaseModel):
    container: str
    database: str
    schema_name: str = "public"
    table: str
    key_column: str
    key_value: Any
    values: dict[str, Any]


class RowDelete(BaseModel):
    container: str
    database: str
    schema_name: str = "public"
    table: str
    key_column: str
    key_value: Any
    confirm: bool = False


class BackupRequest(BaseModel):
    container: str
    database: str


class RestoreRequest(BaseModel):
    container: str
    database: str
    backup_path: str = Field(min_length=1, max_length=4096)
    confirm_database: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_container(value: str) -> str:
    if not CONTAINER_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid database container name")
    return value


def _ident(value: str) -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail=f"Unsupported SQL identifier: {value!r}")
    return value


def _pg_ident(value: str) -> str:
    return '"' + _ident(value).replace('"', '""') + '"'


def _my_ident(value: str) -> str:
    return "`" + _ident(value).replace("`", "``") + "`"


def _literal(value: Any, engine: str) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    text = str(value)
    if "\x00" in text:
        raise HTTPException(status_code=400, detail="NUL is not allowed in SQL values")
    return "'" + text.replace("'", "''") + "'"


def _run_remote(server: dict[str, Any], command: str, timeout: int = 120) -> str:
    code, output = ssh_command(server, command, timeout=timeout)
    if code != 0:
        raise RuntimeError(output.strip()[-6000:] or f"Remote command failed with exit code {code}")
    return output


def _engine_from_image(image: str) -> str | None:
    value = image.lower()
    if "postgres" in value or "postgis" in value:
        return "postgresql"
    if "mariadb" in value:
        return "mariadb"
    if re.search(r"(^|[/:-])mysql([/:@-]|$)", value):
        return "mysql"
    return None


def _instances(server: dict[str, Any]) -> list[dict[str, Any]]:
    output = _run_remote(server, "docker ps -a --no-trunc --format '{{json .}}'", timeout=45)
    result: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        image = str(row.get("Image") or "")
        engine = _engine_from_image(image)
        if not engine:
            continue
        name = str(row.get("Names") or row.get("ID") or "")
        if not name:
            continue
        inspect_cmd = (
            "docker inspect --format "
            + shlex.quote("{{json .Mounts}}")
            + " "
            + shlex.quote(name)
            + " 2>/dev/null || printf '[]'"
        )
        try:
            mounts_raw = _run_remote(server, inspect_cmd, timeout=20).strip() or "[]"
            mounts = json.loads(mounts_raw)
        except Exception:
            mounts = []
        result.append(
            {
                "container": name,
                "id": str(row.get("ID") or ""),
                "engine": engine,
                "image": image,
                "state": str(row.get("State") or ""),
                "status": str(row.get("Status") or ""),
                "ports": str(row.get("Ports") or ""),
                "mounts": [
                    {"type": m.get("Type"), "source": m.get("Source"), "destination": m.get("Destination")}
                    for m in mounts
                    if isinstance(m, dict)
                ],
            }
        )
    return result


def _instance(server: dict[str, Any], container: str) -> dict[str, Any]:
    target = _safe_container(container)
    for item in _instances(server):
        if item["container"] == target or str(item["id"]).startswith(target):
            if item["state"].lower() != "running":
                raise HTTPException(status_code=409, detail="Database container is not running")
            return item
    raise HTTPException(status_code=404, detail="Database container not found")


def _db_command(container: str, engine: str, database: str | None = None) -> str:
    c = shlex.quote(_safe_container(container))
    if engine == "postgresql":
        if database:
            db = shlex.quote(database)
            inner = f'user="${{POSTGRES_USER:-postgres}}"; exec psql -X -v ON_ERROR_STOP=1 -q -A -t -U "$user" -d {db}'
        else:
            inner = 'user="${POSTGRES_USER:-postgres}"; db="${POSTGRES_DB:-postgres}"; exec psql -X -v ON_ERROR_STOP=1 -q -A -t -U "$user" -d "$db"'
        return f"docker exec -i {c} sh -lc {shlex.quote(inner)}"
    if engine in {"mysql", "mariadb"}:
        db_arg = f" {shlex.quote(database)}" if database else ""
        inner = (
            'pw="${MYSQL_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}"; '
            '[ -z "$pw" ] || export MYSQL_PWD="$pw"; '
            f'exec mysql --batch --skip-column-names -u root{db_arg}'
        )
        return f"docker exec -i {c} sh -lc {shlex.quote(inner)}"
    raise HTTPException(status_code=400, detail="Unsupported database engine")


def _sql(server: dict[str, Any], instance: dict[str, Any], sql: str, database: str | None = None, timeout: int = 90) -> str:
    encoded = base64.b64encode(sql.encode("utf-8")).decode("ascii")
    command = f"printf %s {shlex.quote(encoded)} | base64 -d | {_db_command(instance['container'], instance['engine'], database)}"
    return _run_remote(server, command, timeout=timeout)


def _json_lines(output: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _mysql_unescape(value: str) -> str | None:
    if value == "NULL":
        return None
    return value.replace("\\t", "\t").replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\")


def _databases(server: dict[str, Any], instance: dict[str, Any]) -> list[dict[str, Any]]:
    if instance["engine"] == "postgresql":
        sql = """
SELECT json_build_object(
 'name', d.datname,
 'owner', pg_get_userbyid(d.datdba),
 'size_bytes', pg_database_size(d.datname),
 'connections', (SELECT count(*) FROM pg_stat_activity a WHERE a.datname=d.datname)
)::text
FROM pg_database d
WHERE NOT d.datistemplate
ORDER BY d.datname;
"""
        return _json_lines(_sql(server, instance, sql))
    sql = """
SELECT JSON_OBJECT(
 'name', s.SCHEMA_NAME,
 'owner', '',
 'size_bytes', COALESCE(SUM(t.DATA_LENGTH+t.INDEX_LENGTH),0),
 'connections', 0
)
FROM INFORMATION_SCHEMA.SCHEMATA s
LEFT JOIN INFORMATION_SCHEMA.TABLES t ON t.TABLE_SCHEMA=s.SCHEMA_NAME
GROUP BY s.SCHEMA_NAME
ORDER BY s.SCHEMA_NAME;
"""
    return _json_lines(_sql(server, instance, sql))


def _tables(server: dict[str, Any], instance: dict[str, Any], database: str) -> list[dict[str, Any]]:
    if instance["engine"] == "postgresql":
        sql = """
SELECT json_build_object(
 'schema', n.nspname,
 'name', c.relname,
 'kind', CASE c.relkind WHEN 'r' THEN 'table' WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view' ELSE c.relkind::text END,
 'estimated_rows', GREATEST(c.reltuples::bigint,0),
 'size_bytes', CASE WHEN c.relkind IN ('r','m') THEN pg_total_relation_size(c.oid) ELSE 0 END
)::text
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE c.relkind IN ('r','v','m') AND n.nspname NOT IN ('pg_catalog','information_schema')
ORDER BY n.nspname,c.relname;
"""
        return _json_lines(_sql(server, instance, sql, database))
    sql = f"""
SELECT JSON_OBJECT(
 'schema', TABLE_SCHEMA,
 'name', TABLE_NAME,
 'kind', TABLE_TYPE,
 'estimated_rows', COALESCE(TABLE_ROWS,0),
 'size_bytes', COALESCE(DATA_LENGTH+INDEX_LENGTH,0)
)
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA={_literal(database, instance['engine'])}
ORDER BY TABLE_NAME;
"""
    return _json_lines(_sql(server, instance, sql, database))


def _columns(server: dict[str, Any], instance: dict[str, Any], database: str, schema_name: str, table: str) -> list[dict[str, Any]]:
    schema_name, table = _ident(schema_name), _ident(table)
    if instance["engine"] == "postgresql":
        sql = f"""
SELECT json_build_object(
 'name', c.column_name,
 'type', c.data_type,
 'nullable', c.is_nullable='YES',
 'default', c.column_default,
 'primary_key', EXISTS (
   SELECT 1 FROM information_schema.table_constraints tc
   JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name AND tc.constraint_schema=kcu.constraint_schema
   WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema=c.table_schema AND tc.table_name=c.table_name AND kcu.column_name=c.column_name
 )
)::text
FROM information_schema.columns c
WHERE c.table_schema={_literal(schema_name,'postgresql')} AND c.table_name={_literal(table,'postgresql')}
ORDER BY c.ordinal_position;
"""
        return _json_lines(_sql(server, instance, sql, database))
    sql = f"""
SELECT JSON_OBJECT(
 'name', COLUMN_NAME,
 'type', COLUMN_TYPE,
 'nullable', IF(IS_NULLABLE='YES',TRUE,FALSE),
 'default', COLUMN_DEFAULT,
 'primary_key', IF(COLUMN_KEY='PRI',TRUE,FALSE)
)
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA={_literal(database,instance['engine'])} AND TABLE_NAME={_literal(table,instance['engine'])}
ORDER BY ORDINAL_POSITION;
"""
    return _json_lines(_sql(server, instance, sql, database))


def _table_rows(server: dict[str, Any], instance: dict[str, Any], database: str, schema_name: str, table: str, limit: int, offset: int) -> dict[str, Any]:
    columns = _columns(server, instance, database, schema_name, table)
    if not columns:
        raise HTTPException(status_code=404, detail="Table not found or contains no visible columns")
    if instance["engine"] == "postgresql":
        target = f"{_pg_ident(schema_name)}.{_pg_ident(table)}"
        sql = f"SELECT row_to_json(t)::text FROM (SELECT * FROM {target} LIMIT {limit} OFFSET {offset}) t;"
        rows = _json_lines(_sql(server, instance, sql, database))
    else:
        names = [_ident(str(c["name"])) for c in columns]
        select_cols = ",".join(_my_ident(n) for n in names)
        target = f"{_my_ident(database)}.{_my_ident(table)}"
        raw = _sql(server, instance, f"SELECT {select_cols} FROM {target} LIMIT {limit} OFFSET {offset};", database)
        rows = []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) < len(names):
                parts.extend([""] * (len(names) - len(parts)))
            rows.append({name: _mysql_unescape(parts[idx]) for idx, name in enumerate(names)})
    primary = [str(c["name"]) for c in columns if c.get("primary_key")]
    return {"columns": columns, "primary_keys": primary, "rows": rows, "limit": limit, "offset": offset}


def _roles(server: dict[str, Any], instance: dict[str, Any], database: str) -> list[dict[str, Any]]:
    if instance["engine"] == "postgresql":
        sql = """
SELECT json_build_object('name',rolname,'login',rolcanlogin,'superuser',rolsuper,'createdb',rolcreatedb,'createrole',rolcreaterole)::text
FROM pg_roles ORDER BY rolname;
"""
        return _json_lines(_sql(server, instance, sql, database))
    sql = """
SELECT JSON_OBJECT('name',User,'host',Host,'locked',IF(account_locked='Y',TRUE,FALSE),'plugin',plugin)
FROM mysql.user ORDER BY User,Host;
"""
    try:
        return _json_lines(_sql(server, instance, sql, database))
    except RuntimeError:
        fallback = "SELECT JSON_OBJECT('name',User,'host',Host) FROM mysql.user ORDER BY User,Host;"
        return _json_lines(_sql(server, instance, fallback, database))


def _is_write_sql(sql: str) -> bool:
    cleaned = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    cleaned = re.sub(r"--[^\n]*", " ", cleaned).strip()
    match = re.match(r"([A-Za-z]+)", cleaned)
    if not match:
        return True
    return match.group(1).lower() not in READ_ONLY_SQL


def install_database_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
    audit_fn: Callable[[str, str, int | None, str], None],
    app_root: Path,
) -> None:
    page_path = app_root / "app" / "static" / "database-manager.html"

    def event(server_id: int, severity: str, title: str, message: str, data: dict[str, Any] | None = None) -> None:
        with db_factory() as connection:
            connection.execute(
                "INSERT INTO server_events(server_id,category,severity,title,message,data_json,created_at) VALUES (?,'database',?,?,?,?,?)",
                (server_id, severity, title[:240], message[:4000], json.dumps(data) if data else None, utc_now()),
            )

    def operation(server_id: int, title: str) -> int:
        with db_factory() as connection:
            cur = connection.execute(
                "INSERT INTO server_operations(server_id,kind,title,status,progress,message,created_at) VALUES (?,'database',?,'queued',0,'Queued',?)",
                (server_id, title[:240], utc_now()),
            )
            op_id = int(cur.lastrowid)
        event(server_id, "info", title, "Queued", {"operation_id": op_id, "status": "queued"})
        return op_id

    def op_update(op_id: int, server_id: int, status: str, progress: int, message: str, result: dict[str, Any] | None = None, error: str | None = None) -> None:
        now = utc_now()
        with db_factory() as connection:
            connection.execute(
                """UPDATE server_operations SET status=?,progress=?,message=?,result_json=?,error=?,
                started_at=COALESCE(started_at,?),finished_at=CASE WHEN ? IN ('success','failed') THEN ? ELSE finished_at END WHERE id=?""",
                (status, progress, message[:2000], json.dumps(result) if result else None, error[:4000] if error else None,
                 now if status == "running" else None, status, now, op_id),
            )
        event(server_id, "success" if status == "success" else "error" if status == "failed" else "info", "Database operation", message, {"operation_id": op_id, "status": status, "progress": progress})

    @app.get("/vps/{server_id}/databases", response_class=HTMLResponse, include_in_schema=False)
    def database_page(server_id: int) -> str:
        server_lookup(server_id)
        return page_path.read_text(encoding="utf-8")

    @app.get("/api/vps/servers/{server_id}/databases/instances")
    def instances(server_id: int) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id))
        try:
            return _instances(server)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/databases/catalog")
    def databases(server_id: int, container: str) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id)); inst = _instance(server, container)
        try:
            return _databases(server, inst)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/databases/tables")
    def tables(server_id: int, container: str, database: str) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id)); inst = _instance(server, container)
        try:
            return _tables(server, inst, database)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/databases/table")
    def table_data(server_id: int, container: str, database: str, schema_name: str = "public", table: str = "", limit: int = Query(default=100, ge=1, le=MAX_ROWS), offset: int = Query(default=0, ge=0)) -> dict[str, Any]:
        server = dict(server_lookup(server_id)); inst = _instance(server, container)
        try:
            return _table_rows(server, inst, database, schema_name, _ident(table), limit, offset)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/vps/servers/{server_id}/databases/roles")
    def roles(server_id: int, container: str, database: str) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id)); inst = _instance(server, container)
        try:
            return _roles(server, inst, database)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.post("/api/vps/servers/{server_id}/databases/sql")
    def execute_sql(server_id: int, payload: SqlRequest) -> dict[str, Any]:
        server = dict(server_lookup(server_id)); inst = _instance(server, payload.container)
        write = _is_write_sql(payload.sql)
        if write and not payload.confirm_write:
            raise HTTPException(status_code=409, detail="Write-capable SQL requires explicit confirmation")
        try:
            output = _sql(server, inst, payload.sql, payload.database, timeout=120)
        except RuntimeError as exc:
            event(server_id, "error", "SQL failed", f"{inst['engine']} / {payload.database}: {str(exc)[:1000]}")
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.database.sql", "server", server_id, f"{inst['engine']} {payload.database}: {'write' if write else 'read-only'} SQL executed")
        event(server_id, "warning" if write else "info", "SQL executed", f"{payload.database} · {'write' if write else 'read-only'}")
        return {"output": output[-200000:], "write": write}

    @app.post("/api/vps/servers/{server_id}/databases", status_code=201)
    def create_database(server_id: int, payload: DatabaseCreate) -> dict[str, Any]:
        server = dict(server_lookup(server_id)); inst = _instance(server, payload.container); name = _ident(payload.name)
        sql = f"CREATE DATABASE {_pg_ident(name)};" if inst["engine"] == "postgresql" else f"CREATE DATABASE {_my_ident(name)};"
        try:
            _sql(server, inst, sql)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.database.created", "server", server_id, f"{payload.container}/{name}")
        event(server_id, "success", "Database created", name)
        return {"status": "created", "database": name}

    @app.post("/api/vps/servers/{server_id}/databases/drop")
    def drop_database(server_id: int, payload: DatabaseDrop) -> dict[str, Any]:
        if payload.database != payload.confirm_database:
            raise HTTPException(status_code=400, detail="Database name confirmation does not match")
        server = dict(server_lookup(server_id)); inst = _instance(server, payload.container); name = _ident(payload.database)
        protected = {"postgres", "template0", "template1", "mysql", "information_schema", "performance_schema", "sys"}
        if name.lower() in protected:
            raise HTTPException(status_code=409, detail="Refusing to drop a protected system database")
        sql = f"DROP DATABASE {_pg_ident(name)};" if inst["engine"] == "postgresql" else f"DROP DATABASE {_my_ident(name)};"
        try:
            _sql(server, inst, sql)
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.database.dropped", "server", server_id, f"{payload.container}/{name}")
        event(server_id, "warning", "Database dropped", name)
        return {"status": "dropped", "database": name}

    @app.post("/api/vps/servers/{server_id}/databases/row/insert", status_code=201)
    def insert_row(server_id: int, payload: RowInsert) -> dict[str, Any]:
        if not payload.values:
            raise HTTPException(status_code=400, detail="Provide at least one value")
        server = dict(server_lookup(server_id)); inst = _instance(server, payload.container)
        quote = _pg_ident if inst["engine"] == "postgresql" else _my_ident
        columns = [quote(_ident(k)) for k in payload.values]
        values = [_literal(v, inst["engine"]) for v in payload.values.values()]
        target = f"{quote(_ident(payload.schema_name))}.{quote(_ident(payload.table))}" if inst["engine"] == "postgresql" else f"{quote(_ident(payload.database))}.{quote(_ident(payload.table))}"
        sql = f"INSERT INTO {target} ({','.join(columns)}) VALUES ({','.join(values)});"
        try: _sql(server, inst, sql, payload.database)
        except RuntimeError as exc: raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.database.row.inserted", "server", server_id, f"{payload.database}/{payload.table}")
        return {"status": "inserted"}

    @app.post("/api/vps/servers/{server_id}/databases/row/update")
    def update_row(server_id: int, payload: RowUpdate) -> dict[str, Any]:
        if not payload.values:
            raise HTTPException(status_code=400, detail="Provide at least one changed value")
        server = dict(server_lookup(server_id)); inst = _instance(server, payload.container)
        quote = _pg_ident if inst["engine"] == "postgresql" else _my_ident
        assignments = [f"{quote(_ident(k))}={_literal(v,inst['engine'])}" for k,v in payload.values.items()]
        target = f"{quote(_ident(payload.schema_name))}.{quote(_ident(payload.table))}" if inst["engine"] == "postgresql" else f"{quote(_ident(payload.database))}.{quote(_ident(payload.table))}"
        sql = f"UPDATE {target} SET {','.join(assignments)} WHERE {quote(_ident(payload.key_column))}={_literal(payload.key_value,inst['engine'])};"
        try: _sql(server, inst, sql, payload.database)
        except RuntimeError as exc: raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.database.row.updated", "server", server_id, f"{payload.database}/{payload.table}")
        return {"status": "updated"}

    @app.post("/api/vps/servers/{server_id}/databases/row/delete")
    def delete_row(server_id: int, payload: RowDelete) -> dict[str, Any]:
        if not payload.confirm:
            raise HTTPException(status_code=400, detail="Row deletion requires confirmation")
        server = dict(server_lookup(server_id)); inst = _instance(server, payload.container)
        quote = _pg_ident if inst["engine"] == "postgresql" else _my_ident
        target = f"{quote(_ident(payload.schema_name))}.{quote(_ident(payload.table))}" if inst["engine"] == "postgresql" else f"{quote(_ident(payload.database))}.{quote(_ident(payload.table))}"
        sql = f"DELETE FROM {target} WHERE {quote(_ident(payload.key_column))}={_literal(payload.key_value,inst['engine'])};"
        try: _sql(server, inst, sql, payload.database)
        except RuntimeError as exc: raise HTTPException(status_code=502, detail=str(exc)) from exc
        audit_fn("vps.database.row.deleted", "server", server_id, f"{payload.database}/{payload.table}")
        event(server_id, "warning", "Database row deleted", f"{payload.database}.{payload.table}")
        return {"status": "deleted"}

    @app.get("/api/vps/servers/{server_id}/databases/backups")
    def backups(server_id: int, container: str | None = None) -> list[dict[str, Any]]:
        server = dict(server_lookup(server_id))
        base = "$HOME/.custom-github-backups/databases"
        name_filter = _safe_container(container) if container else ""
        path = f"{base}/{shlex.quote(name_filter)}" if name_filter else base
        script = f"mkdir -p {base}; find {path} -type f -name '*.sql.gz' -printf '%T@\\t%s\\t%p\\n' 2>/dev/null | sort -nr | head -n 200"
        try: output = _run_remote(server, f"bash -lc {shlex.quote(script)}", timeout=45)
        except RuntimeError as exc: raise HTTPException(status_code=502, detail=str(exc)) from exc
        result=[]
        for line in output.splitlines():
            parts=line.split("\t",2)
            if len(parts)==3:
                result.append({"modified_epoch":float(parts[0]),"size_bytes":int(parts[1]),"path":parts[2]})
        return result

    @app.post("/api/vps/servers/{server_id}/databases/backup", status_code=202)
    def backup_database(server_id: int, payload: BackupRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        server = dict(server_lookup(server_id)); inst = _instance(server,payload.container); dbname=_ident(payload.database)
        op_id=operation(server_id,f"Backup database {dbname}")
        def task() -> None:
            try:
                op_update(op_id,server_id,"running",15,"Preparing database backup")
                c=shlex.quote(inst["container"]); stamp=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                rel=f".custom-github-backups/databases/{inst['container']}/{dbname}-{stamp}.sql.gz"
                dest=f"$HOME/{rel}"; parent=f"$HOME/.custom-github-backups/databases/{shlex.quote(inst['container'])}"
                if inst["engine"]=="postgresql":
                    inner=f'user="${{POSTGRES_USER:-postgres}}"; exec pg_dump -U "$user" --no-owner --no-privileges {shlex.quote(dbname)}'
                else:
                    inner=f'pw="${{MYSQL_ROOT_PASSWORD:-${{MARIADB_ROOT_PASSWORD:-}}}}"; [ -z "$pw" ] || export MYSQL_PWD="$pw"; exec mysqldump -u root --single-transaction --routines --triggers {shlex.quote(dbname)}'
                cmd=f"mkdir -p {parent}; docker exec {c} sh -lc {shlex.quote(inner)} | gzip -c > {dest}; test -s {dest}; stat -c '%s' {dest}"
                size=int(_run_remote(server,f"bash -lc {shlex.quote(cmd)}",timeout=900).strip().splitlines()[-1])
                result={"path":f"~/{rel}","size_bytes":size,"database":dbname}
                op_update(op_id,server_id,"success",100,"Database backup completed",result=result)
                audit_fn("vps.database.backup", "server", server_id, f"{inst['container']}/{dbname} -> ~/{rel}")
            except Exception as exc:
                op_update(op_id,server_id,"failed",100,"Database backup failed",error=str(exc))
        background_tasks.add_task(task)
        return {"operation_id":op_id,"status":"queued"}

    @app.post("/api/vps/servers/{server_id}/databases/restore", status_code=202)
    def restore_database(server_id: int, payload: RestoreRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
        if payload.database != payload.confirm_database:
            raise HTTPException(status_code=400,detail="Database confirmation does not match")
        if not (payload.backup_path.startswith("~/.custom-github-backups/databases/") or payload.backup_path.startswith("$HOME/.custom-github-backups/databases/")):
            raise HTTPException(status_code=400,detail="Restore path must be a Custom GitHub database backup")
        if ".." in payload.backup_path:
            raise HTTPException(status_code=400,detail="Invalid backup path")
        server=dict(server_lookup(server_id));inst=_instance(server,payload.container);dbname=_ident(payload.database);op_id=operation(server_id,f"Restore database {dbname}")
        def task() -> None:
            try:
                op_update(op_id,server_id,"running",10,"Validating backup")
                path=payload.backup_path.replace("~/","$HOME/")
                c=shlex.quote(inst["container"])
                if inst["engine"]=="postgresql":
                    inner=f'user="${{POSTGRES_USER:-postgres}}"; exec psql -X -v ON_ERROR_STOP=1 -U "$user" -d {shlex.quote(dbname)}'
                else:
                    inner=f'pw="${{MYSQL_ROOT_PASSWORD:-${{MARIADB_ROOT_PASSWORD:-}}}}"; [ -z "$pw" ] || export MYSQL_PWD="$pw"; exec mysql -u root {shlex.quote(dbname)}'
                cmd=f"test -s {path}; gzip -dc {path} | docker exec -i {c} sh -lc {shlex.quote(inner)}"
                op_update(op_id,server_id,"running",35,"Restoring SQL backup")
                _run_remote(server,f"bash -lc {shlex.quote(cmd)}",timeout=1800)
                op_update(op_id,server_id,"success",100,"Database restore completed",result={"database":dbname,"backup_path":payload.backup_path})
                audit_fn("vps.database.restore", "server", server_id, f"{inst['container']}/{dbname} from {payload.backup_path}")
            except Exception as exc:
                op_update(op_id,server_id,"failed",100,"Database restore failed",error=str(exc))
        background_tasks.add_task(task)
        return {"operation_id":op_id,"status":"queued"}


__all__ = ["install_database_routes", "_engine_from_image", "_is_write_sql", "_literal"]
