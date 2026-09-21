#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT_DIR/scripts/vps/custom-github-privileged"

HOST=""
USER_NAME=""
PORT="22"
IDENTITY=""

usage() {
  cat <<'EOF'
Usage:
  bash scripts/bootstrap-vps-privileges.sh --host <host> --user <ssh-user> [--port 22] [--identity ~/.ssh/key]

This is intentionally interactive. It copies the root-owned Custom GitHub privilege helper
and then opens SSH with a TTY so sudo can ask for the VPS sudo password once during setup.
It does NOT configure NOPASSWD: ALL. The SSH user receives passwordless sudo only for the
root-owned /usr/local/sbin/custom-github-privileged helper, which applies its own operation policy.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --user) USER_NAME="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --identity) IDENTITY="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$HOST" && -n "$USER_NAME" ]] || { usage >&2; exit 2; }
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { echo "Invalid SSH port" >&2; exit 2; }
[[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "Invalid SSH username" >&2; exit 2; }
[[ -f "$HELPER" ]] || { echo "Privilege helper not found: $HELPER" >&2; exit 2; }

SSH_OPTS=(-p "$PORT" -o BatchMode=no -o StrictHostKeyChecking=accept-new)
SCP_OPTS=(-P "$PORT" -o BatchMode=no -o StrictHostKeyChecking=accept-new)
if [[ -n "$IDENTITY" ]]; then
  IDENTITY="${IDENTITY/#\~/$HOME}"
  [[ -r "$IDENTITY" ]] || { echo "SSH identity is not readable: $IDENTITY" >&2; exit 2; }
  SSH_OPTS+=(-i "$IDENTITY")
  SCP_OPTS+=(-i "$IDENTITY")
fi

TARGET="$USER_NAME@$HOST"
REMOTE_TMP="/tmp/custom-github-privileged.$$"

echo "==> Copying privilege helper to $TARGET"
scp "${SCP_OPTS[@]}" "$HELPER" "$TARGET:$REMOTE_TMP"

# The sudoers rule intentionally grants only the root-owned helper. The helper itself rejects
# commands outside the System Administration policy.
REMOTE_SCRIPT=$(cat <<EOF
set -euo pipefail
sudo install -o root -g root -m 0755 '$REMOTE_TMP' /usr/local/sbin/custom-github-privileged
rm -f '$REMOTE_TMP'
printf '%s\n' '$USER_NAME ALL=(root) NOPASSWD: /usr/local/sbin/custom-github-privileged *' | sudo tee /etc/sudoers.d/custom-github-control-plane >/dev/null
sudo chmod 0440 /etc/sudoers.d/custom-github-control-plane
sudo visudo -cf /etc/sudoers.d/custom-github-control-plane
sudo -n /usr/local/sbin/custom-github-privileged probe
EOF
)

echo "==> Installing root-owned helper and validating sudoers"
ssh -tt "${SSH_OPTS[@]}" "$TARGET" "$REMOTE_SCRIPT"

echo
echo "Privilege bridge installed successfully."
echo "Return to Custom GitHub -> System Admin and press Recheck privileged access."
