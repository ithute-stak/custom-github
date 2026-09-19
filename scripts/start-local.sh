#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

export CUSTOM_GITHUB_DATA_DIR="${CUSTOM_GITHUB_DATA_DIR:-$ROOT_DIR/data}"
export CUSTOM_GITHUB_WORKSPACE_ROOT="${CUSTOM_GITHUB_WORKSPACE_ROOT:-$ROOT_DIR/data/workspaces}"

exec uvicorn app.platform:app --host 127.0.0.1 --port "${CUSTOM_GITHUB_PORT:-8787}" --reload
