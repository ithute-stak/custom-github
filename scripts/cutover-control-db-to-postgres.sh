#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${CUSTOM_GITHUB_DATA_DIR:-$ROOT_DIR/data}"
SQLITE_DB="$DATA_DIR/custom-github.db"
SCHEMA="${CUSTOM_GITHUB_POSTGRES_SCHEMA:-custom_github}"
DSN="${CUSTOM_GITHUB_POSTGRES_DSN:-}"
APPLY=0
REPLACE=0

usage() {
  cat <<'EOF'
Usage:
  CUSTOM_GITHUB_POSTGRES_DSN='postgresql://...' \
    bash scripts/cutover-control-db-to-postgres.sh [--schema custom_github] [--apply] [--replace-schema]

Without --apply this performs only migration discovery/dry-run.
With --apply it first creates a consistent SQLite backup, then migrates and verifies PostgreSQL.
--replace-schema is destructive to the target PostgreSQL schema and is never implied.

Stop Custom GitHub before an --apply cutover so no SQLite writes occur during the snapshot/migration.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema)
      [[ $# -ge 2 ]] || { echo "--schema requires a value" >&2; exit 2; }
      SCHEMA="$2"; shift 2 ;;
    --dsn)
      [[ $# -ge 2 ]] || { echo "--dsn requires a value" >&2; exit 2; }
      DSN="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --replace-schema) REPLACE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$SCHEMA" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "Unsafe PostgreSQL schema name: $SCHEMA" >&2; exit 2; }
[[ -f "$SQLITE_DB" ]] || { echo "SQLite control database not found: $SQLITE_DB" >&2; exit 2; }

PYTHON="$ROOT_DIR/.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" ]] || { echo "Python 3 is required." >&2; exit 2; }

cd "$ROOT_DIR"

echo "==> Source control database"
echo "$SQLITE_DB"
echo
echo "==> Discovery / dry run"
"$PYTHON" scripts/migrate-control-db-to-postgres.py --sqlite "$SQLITE_DB" --schema "$SCHEMA"

if [[ "$APPLY" -ne 1 ]]; then
  echo
  echo "Dry run complete. No PostgreSQL data was written."
  echo "For cutover, stop Custom GitHub and rerun with --apply plus CUSTOM_GITHUB_POSTGRES_DSN."
  exit 0
fi

[[ -n "$DSN" ]] || { echo "CUSTOM_GITHUB_POSTGRES_DSN or --dsn is required with --apply." >&2; exit 2; }

mkdir -p "$DATA_DIR/control-db-snapshots"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="$DATA_DIR/control-db-snapshots/custom-github-before-postgres-$STAMP.db"

echo
echo "==> Creating consistent SQLite snapshot"
"$PYTHON" - "$SQLITE_DB" "$SNAPSHOT" <<'PY'
import sqlite3, sys
source, destination = sys.argv[1:3]
src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
dst = sqlite3.connect(destination)
with dst:
    src.backup(dst)
check = dst.execute("PRAGMA integrity_check").fetchone()[0]
src.close(); dst.close()
if check != "ok":
    raise SystemExit(f"SQLite snapshot integrity_check failed: {check}")
print(destination)
PY

ARGS=(--sqlite "$SNAPSHOT" --dsn "$DSN" --schema "$SCHEMA" --apply)
if [[ "$REPLACE" -eq 1 ]]; then
  echo "WARNING: --replace-schema will drop PostgreSQL schema '$SCHEMA' before migration."
  read -r -p "Type REPLACE $SCHEMA to continue: " CONFIRM
  [[ "$CONFIRM" == "REPLACE $SCHEMA" ]] || { echo "Cancelled."; exit 1; }
  ARGS+=(--replace-schema)
fi

echo
echo "==> Migrating snapshot to PostgreSQL"
"$PYTHON" scripts/migrate-control-db-to-postgres.py "${ARGS[@]}"

echo
echo "==> Cutover migration verified"
echo "SQLite snapshot preserved at: $SNAPSHOT"
echo
echo "Start Custom GitHub with:"
printf 'export CUSTOM_GITHUB_DB_BACKEND=postgres\n'
printf 'export CUSTOM_GITHUB_POSTGRES_DSN=%q\n' "$DSN"
printf 'export CUSTOM_GITHUB_POSTGRES_SCHEMA=%q\n' "$SCHEMA"
printf 'bash scripts/start-local.sh\n'
echo
echo "Rollback is immediate: stop Custom GitHub, unset CUSTOM_GITHUB_DB_BACKEND/CUSTOM_GITHUB_POSTGRES_DSN, and start again on SQLite."
