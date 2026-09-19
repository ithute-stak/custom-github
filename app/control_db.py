from __future__ import annotations

import os
import re
import sqlite3
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql as pgsql
from psycopg.errors import CheckViolation, ForeignKeyViolation, NotNullViolation, UniqueViolation
from psycopg.pq import TransactionStatus

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
INSERT_RE = re.compile(r"^\s*INSERT\s+(?:OR\s+IGNORE\s+)?INTO\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
PRAGMA_TABLE_INFO_RE = re.compile(r"^\s*PRAGMA\s+table_info\((?:\"|')?([A-Za-z_][A-Za-z0-9_]*)(?:\"|')?\)\s*$", re.I)
SQLITE_MASTER_TABLE_RE = re.compile(r"sqlite_master", re.I)


class CompatRow(Mapping[str, Any]):
    def __init__(self, names: list[str], values: tuple[Any, ...]):
        self._names = names
        self._values = values
        self._map = dict(zip(names, values))

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._map[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._names)

    def __len__(self) -> int:
        return len(self._names)

    def keys(self):
        return self._map.keys()


class CompatCursor:
    def __init__(self, connection: "PostgresCompatConnection", cursor: psycopg.Cursor | None = None):
        self.connection = connection
        self.cursor = cursor
        self.lastrowid: int | None = None
        self._synthetic: list[CompatRow] | None = None
        self._synthetic_index = 0
        self.rowcount = -1

    @property
    def description(self):
        if self.cursor is not None:
            return self.cursor.description
        if self._synthetic:
            return [(name, None, None, None, None, None, None) for name in self._synthetic[0].keys()]
        return None

    def _names(self) -> list[str]:
        if self.cursor is None or not self.cursor.description:
            return []
        return [str(item.name) for item in self.cursor.description]

    def fetchone(self) -> CompatRow | None:
        if self._synthetic is not None:
            if self._synthetic_index >= len(self._synthetic):
                return None
            row = self._synthetic[self._synthetic_index]
            self._synthetic_index += 1
            return row
        if self.cursor is None:
            return None
        raw = self.cursor.fetchone()
        if raw is None:
            return None
        return CompatRow(self._names(), tuple(raw))

    def fetchall(self) -> list[CompatRow]:
        if self._synthetic is not None:
            rows = self._synthetic[self._synthetic_index :]
            self._synthetic_index = len(self._synthetic)
            return rows
        if self.cursor is None:
            return []
        names = self._names()
        return [CompatRow(names, tuple(row)) for row in self.cursor.fetchall()]

    def __iter__(self):
        while True:
            row = self.fetchone()
            if row is None:
                return
            yield row


class PostgresCompatConnection:
    def __init__(self, dsn: str, schema: str):
        if not IDENT_RE.fullmatch(schema):
            raise ValueError("CUSTOM_GITHUB_POSTGRES_SCHEMA must be a simple identifier")
        self.schema = schema
        self.raw = psycopg.connect(dsn, autocommit=False)
        self._identity_cache: dict[str, bool] = {}
        self.row_factory = None
        with self.raw.cursor() as cur:
            cur.execute(pgsql.SQL("SET search_path TO {}, public").format(pgsql.Identifier(schema)))
        self.raw.commit()

    def __enter__(self) -> "PostgresCompatConnection":
        self._ensure_transaction()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type is None:
                self.raw.commit()
            else:
                self.raw.rollback()
        finally:
            self.raw.close()

    def close(self) -> None:
        self.raw.close()

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def cursor(self) -> "PostgresCursorProxy":
        return PostgresCursorProxy(self)

    def _ensure_transaction(self) -> None:
        # psycopg starts the transaction automatically on the first statement when
        # autocommit=False. SET LOCAL both starts it and pins the migrated schema.
        if self.raw.info.transaction_status == TransactionStatus.IDLE:
            with self.raw.cursor() as cur:
                cur.execute(pgsql.SQL("SET LOCAL search_path TO {}, public").format(pgsql.Identifier(self.schema)))

    @staticmethod
    def _qmark_to_percent(query: str) -> str:
        out: list[str] = []
        quote: str | None = None
        escaped = False
        for char in query:
            if escaped:
                out.append(char)
                escaped = False
                continue
            if char == "\\" and quote:
                out.append(char)
                escaped = True
                continue
            if quote:
                out.append(char)
                if char == quote:
                    quote = None
                continue
            if char in {"'", '"'}:
                quote = char
                out.append(char)
            elif char == "?":
                out.append("%s")
            else:
                out.append(char)
        return "".join(out)

    def _statement(self, query: str) -> str:
        value = query.strip()
        value = re.sub(
            r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
            "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
            value,
            flags=re.I,
        )
        value = re.sub(r"\bAUTOINCREMENT\b", "", value, flags=re.I)
        was_ignore = bool(re.match(r"^\s*INSERT\s+OR\s+IGNORE\s+", value, re.I))
        value = re.sub(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", value, flags=re.I)
        value = self._qmark_to_percent(value)
        if was_ignore and "ON CONFLICT" not in value.upper():
            value = value.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        return value

    def _table_has_identity(self, table: str) -> bool:
        cached = self._identity_cache.get(table)
        if cached is not None:
            return cached
        self._ensure_transaction()
        with self.raw.cursor() as cur:
            # psycopg treats every literal % in a parameterized query specially;
            # %% is the escaped SQL wildcard passed to PostgreSQL.
            cur.execute(
                "SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name='id' AND (is_identity='YES' OR column_default LIKE 'nextval(%%') LIMIT 1",
                (self.schema, table),
            )
            found = cur.fetchone() is not None
        self._identity_cache[table] = found
        return found

    def _pragma_table_info(self, table: str) -> CompatCursor:
        self._ensure_transaction()
        with self.raw.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT ON (c.ordinal_position)
                       c.ordinal_position-1,c.column_name,c.data_type,
                       CASE WHEN c.is_nullable='NO' THEN 1 ELSE 0 END,
                       c.column_default,
                       CASE WHEN tc.constraint_type='PRIMARY KEY' THEN 1 ELSE 0 END
                FROM information_schema.columns c
                LEFT JOIN information_schema.key_column_usage kcu
                  ON kcu.table_schema=c.table_schema AND kcu.table_name=c.table_name AND kcu.column_name=c.column_name
                LEFT JOIN information_schema.table_constraints tc
                  ON tc.constraint_schema=kcu.constraint_schema AND tc.constraint_name=kcu.constraint_name AND tc.table_name=kcu.table_name
                WHERE c.table_schema=%s AND c.table_name=%s
                ORDER BY c.ordinal_position, CASE WHEN tc.constraint_type='PRIMARY KEY' THEN 0 ELSE 1 END
                """,
                (self.schema, table),
            )
            rows = cur.fetchall()
        result = CompatCursor(self)
        names = ["cid", "name", "type", "notnull", "dflt_value", "pk"]
        result._synthetic = [CompatRow(names, tuple(row)) for row in rows]
        result.rowcount = len(rows)
        return result

    def execute(self, query: str, params: tuple[Any, ...] | list[Any] = ()) -> CompatCursor:
        stripped = query.strip()
        pragma = PRAGMA_TABLE_INFO_RE.match(stripped)
        if pragma:
            return self._pragma_table_info(pragma.group(1))
        if re.match(r"^PRAGMA\s+(foreign_keys|busy_timeout)", stripped, re.I):
            return CompatCursor(self)

        if SQLITE_MASTER_TABLE_RE.search(stripped):
            transformed = re.sub(
                r"SELECT\s+1\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s*=\s*\?",
                "SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name=%s",
                query,
                flags=re.I,
            )
        else:
            transformed = self._statement(query)

        self._ensure_transaction()
        savepoint = "cg_stmt"
        control = self.raw.cursor()
        cur = self.raw.cursor()
        try:
            control.execute(f"SAVEPOINT {savepoint}")
            insert = INSERT_RE.match(stripped)
            wants_last_id = bool(insert and self._table_has_identity(insert.group(1)) and "RETURNING" not in transformed.upper())
            if wants_last_id:
                transformed = transformed.rstrip().rstrip(";") + " RETURNING id"
            cur.execute(transformed, tuple(params))
            result = CompatCursor(self, cur)
            result.rowcount = cur.rowcount
            if wants_last_id:
                row = cur.fetchone()
                result.lastrowid = int(row[0]) if row else None
            control.execute(f"RELEASE SAVEPOINT {savepoint}")
            control.close()
            return result
        except (UniqueViolation, ForeignKeyViolation, NotNullViolation, CheckViolation) as exc:
            try:
                control.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                control.execute(f"RELEASE SAVEPOINT {savepoint}")
            finally:
                control.close()
                cur.close()
            raise sqlite3.IntegrityError(str(exc)) from exc
        except psycopg.Error as exc:
            try:
                control.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                control.execute(f"RELEASE SAVEPOINT {savepoint}")
            finally:
                control.close()
                cur.close()
            raise sqlite3.OperationalError(str(exc)) from exc

    def executemany(self, query: str, seq_of_params) -> CompatCursor:
        result = CompatCursor(self)
        count = 0
        for params in seq_of_params:
            one = self.execute(query, params)
            result.lastrowid = one.lastrowid
            count += max(one.rowcount, 0)
        result.rowcount = count
        return result

    def executescript(self, script: str) -> None:
        for statement in _split_sql(script):
            if statement.strip():
                self.execute(statement)


class PostgresCursorProxy:
    def __init__(self, connection: PostgresCompatConnection):
        self.connection = connection
        self._result: CompatCursor | None = None
        self.lastrowid: int | None = None
        self.rowcount = -1

    @property
    def description(self):
        return self._result.description if self._result else None

    def execute(self, query: str, params=()):
        self._result = self.connection.execute(query, params)
        self.lastrowid = self._result.lastrowid
        self.rowcount = self._result.rowcount
        return self

    def executemany(self, query: str, seq):
        self._result = self.connection.executemany(query, seq)
        self.lastrowid = self._result.lastrowid
        self.rowcount = self._result.rowcount
        return self

    def fetchone(self):
        return self._result.fetchone() if self._result else None

    def fetchall(self):
        return self._result.fetchall() if self._result else []

    def close(self) -> None:
        if self._result and self._result.cursor:
            self._result.cursor.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def _split_sql(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in script:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quote:
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == ";":
            value = "".join(current).strip()
            if value:
                statements.append(value)
            current = []
        else:
            current.append(char)
    value = "".join(current).strip()
    if value:
        statements.append(value)
    return statements


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def backend_name() -> str:
    configured = os.getenv("CUSTOM_GITHUB_DB_BACKEND", "sqlite").strip().lower()
    if configured not in {"sqlite", "postgres", "postgresql"}:
        raise RuntimeError("CUSTOM_GITHUB_DB_BACKEND must be sqlite or postgres")
    return "postgres" if configured in {"postgres", "postgresql"} else "sqlite"


def _verify_postgres_target(dsn: str, schema: str) -> None:
    allow_empty = _truthy(os.getenv("CUSTOM_GITHUB_POSTGRES_ALLOW_EMPTY"))
    with psycopg.connect(dsn, autocommit=True) as connection:
        with connection.cursor() as cur:
            cur.execute("SELECT 1 FROM information_schema.schemata WHERE schema_name=%s", (schema,))
            schema_exists = cur.fetchone() is not None
            if not schema_exists:
                if not allow_empty:
                    raise RuntimeError(
                        f"PostgreSQL schema {schema!r} does not exist. Run scripts/migrate-control-db-to-postgres.py first, "
                        "or set CUSTOM_GITHUB_POSTGRES_ALLOW_EMPTY=1 only for a brand-new control plane."
                    )
                cur.execute(pgsql.SQL("CREATE SCHEMA {}").format(pgsql.Identifier(schema)))
                return
            cur.execute(
                "SELECT 1 FROM information_schema.tables WHERE table_schema=%s AND table_name='_migration_meta'",
                (schema,),
            )
            migrated = cur.fetchone() is not None
            cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=%s", (schema,))
            table_count = int(cur.fetchone()[0])
            if table_count and not migrated and not allow_empty:
                raise RuntimeError(
                    f"PostgreSQL schema {schema!r} has tables but no verified Custom GitHub migration marker. "
                    "Refusing runtime switch."
                )


def make_db_factory(sqlite_path: Path):
    backend = backend_name()
    if backend == "sqlite":
        def sqlite_factory() -> sqlite3.Connection:
            connection = sqlite3.connect(sqlite_path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
            return connection
        setattr(sqlite_factory, "backend", "sqlite")
        setattr(sqlite_factory, "location", str(sqlite_path))
        return sqlite_factory

    dsn = os.getenv("CUSTOM_GITHUB_POSTGRES_DSN", "").strip()
    schema = os.getenv("CUSTOM_GITHUB_POSTGRES_SCHEMA", "custom_github").strip()
    if not dsn:
        raise RuntimeError("CUSTOM_GITHUB_POSTGRES_DSN is required when CUSTOM_GITHUB_DB_BACKEND=postgres")
    if not IDENT_RE.fullmatch(schema):
        raise RuntimeError("CUSTOM_GITHUB_POSTGRES_SCHEMA must be a simple identifier")
    _verify_postgres_target(dsn, schema)

    def postgres_factory() -> PostgresCompatConnection:
        return PostgresCompatConnection(dsn, schema)

    setattr(postgres_factory, "backend", "postgres")
    setattr(postgres_factory, "location", f"schema:{schema}")
    return postgres_factory
