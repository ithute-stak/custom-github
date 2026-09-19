#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PUBLIC_URL="${CUSTOM_GITHUB_PUBLIC_URL:-}"
TRUSTED_HOSTS="${CUSTOM_GITHUB_TRUSTED_HOSTS:-}"
FORWARDED_ALLOW_IPS="${CUSTOM_GITHUB_FORWARDED_ALLOW_IPS:-127.0.0.1}"
PORT="${CUSTOM_GITHUB_PORT:-8787}"

if [[ "$PUBLIC_URL" != https://* ]]; then
  echo "CUSTOM_GITHUB_PUBLIC_URL must be an HTTPS URL in production mode." >&2
  exit 2
fi
if [[ -z "$TRUSTED_HOSTS" ]]; then
  echo "CUSTOM_GITHUB_TRUSTED_HOSTS is required (comma-separated hostnames)." >&2
  exit 2
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

export CUSTOM_GITHUB_DATA_DIR="${CUSTOM_GITHUB_DATA_DIR:-$ROOT_DIR/data}"
export CUSTOM_GITHUB_WORKSPACE_ROOT="${CUSTOM_GITHUB_WORKSPACE_ROOT:-$ROOT_DIR/data/workspaces}"
export CUSTOM_GITHUB_REMOTE_MODE=1
export CUSTOM_GITHUB_COOKIE_SECURE=1

DB_PATH="$CUSTOM_GITHUB_DATA_DIR/custom-github.db"
if [[ ! -f "$DB_PATH" ]]; then
  echo "Control-plane database does not exist at $DB_PATH." >&2
  echo "Bootstrap locally first, create an Owner, and enable MFA before remote production mode." >&2
  exit 2
fi

python - "$DB_PATH" <<'PY'
import sqlite3, sys
path=sys.argv[1]
con=sqlite3.connect(path)
try:
    enabled=con.execute("SELECT enabled FROM security_settings WHERE id=1").fetchone()
    owners=con.execute("SELECT COUNT(*) FROM security_users WHERE active=1 AND role='owner'").fetchone()[0]
    mfa=con.execute("SELECT COUNT(*) FROM security_users WHERE active=1 AND role IN ('owner','admin') AND mfa_enabled=1").fetchone()[0]
except sqlite3.Error as exc:
    raise SystemExit(f"Security is not initialized: {exc}")
if not enabled or not enabled[0]:
    raise SystemExit("Authentication is not enabled; refusing remote production mode.")
if owners < 1:
    raise SystemExit("At least one active Owner is required.")
if mfa < 1:
    raise SystemExit("At least one Owner/Admin with MFA enabled is required.")
PY

cat <<EOF
Starting Custom GitHub production control plane on loopback only.
Public URL: $PUBLIC_URL
Trusted hosts: $TRUSTED_HOSTS
Reverse proxy must terminate HTTPS and forward only to 127.0.0.1:$PORT.
EOF

exec uvicorn app.platform:app \
  --host 127.0.0.1 \
  --port "$PORT" \
  --proxy-headers \
  --forwarded-allow-ips "$FORWARDED_ALLOW_IPS"
