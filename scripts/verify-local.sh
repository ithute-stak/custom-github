#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

say() { printf '\n==> %s\n' "$*"; }
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'ERROR: required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

say "Checking required local control-plane tools"
need git
need python3
need ssh
need docker

git --version
python3 --version
ssh -V 2>&1 | head -n 1
docker --version

say "Checking Docker daemon"
docker info >/dev/null
printf 'Docker daemon: OK\n'

say "Preparing isolated Python environment"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt >/dev/null

say "Compiling Python sources"
python -m compileall -q app tests
printf 'Python compile: OK\n'

say "Running control-plane test suite"
# Runtime repository clones live under data/workspaces and may contain their own
# test suites and dependency graphs. Only the control plane's tests belong here.
python -m pytest -q tests

say "Checking local Git identity/auth readiness"
if git config --global user.email >/dev/null 2>&1; then
  printf 'Git identity: configured\n'
else
  printf 'WARNING: global Git user.email is not configured. Repository cloning may still work, but commits from this PC may not.\n'
fi

if command -v gh >/dev/null 2>&1; then
  if gh auth status >/dev/null 2>&1; then
    printf 'GitHub CLI auth: OK\n'
  else
    printf 'WARNING: GitHub CLI is installed but not authenticated. Private HTTPS clones need a working Git credential helper or gh auth login.\n'
  fi
else
  printf 'INFO: GitHub CLI not installed; normal Git credential helpers are also supported.\n'
fi

say "Verification complete"
printf 'Local control plane checks passed. Start with: bash scripts/start-local.sh\n'
