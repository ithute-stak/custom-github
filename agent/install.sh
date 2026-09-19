#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root (sudo)." >&2
  exit 2
fi

CONTROL_URL="${1:-${CG_CONTROL_URL:-}}"
ENROLLMENT_TOKEN="${2:-${CG_ENROLLMENT_TOKEN:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_AGENT="$SCRIPT_DIR/custom_github_agent.py"

if [[ -z "$CONTROL_URL" || -z "$ENROLLMENT_TOKEN" ]]; then
  echo "Usage: sudo bash install.sh https://control.example.com <one-time-enrollment-token>" >&2
  exit 2
fi

case "$CONTROL_URL" in
  https://*) ;;
  http://127.0.0.1*|http://localhost*) ;;
  *) echo "Control URL must use HTTPS unless it is loopback." >&2; exit 2 ;;
esac

if [[ ! -f "$SOURCE_AGENT" ]]; then
  echo "Missing $SOURCE_AGENT" >&2
  exit 2
fi

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

install -d -m 0755 /usr/local/lib/custom-github-agent
install -m 0755 "$SOURCE_AGENT" /usr/local/lib/custom-github-agent/agent.py
install -d -m 0700 /etc/custom-github-agent /var/lib/custom-github-agent

umask 077
cat >/etc/custom-github-agent/agent.env <<EOF
CG_CONTROL_URL=$CONTROL_URL
CG_ENROLLMENT_TOKEN=$ENROLLMENT_TOKEN
CG_AGENT_STATE=/var/lib/custom-github-agent/state.json
CG_HEARTBEAT_SECONDS=30
CG_HTTP_TIMEOUT=20
EOF
chmod 0600 /etc/custom-github-agent/agent.env

cat >/etc/systemd/system/custom-github-agent.service <<'EOF'
[Unit]
Description=Custom GitHub restricted VPS agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/custom-github-agent/agent.env
ExecStart=/usr/bin/python3 /usr/local/lib/custom-github-agent/agent.py
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/custom-github-agent
# Root is currently required for the deliberately small allowlist of systemd/Docker actions.
# The service does not accept arbitrary commands.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now custom-github-agent.service
sleep 2
systemctl --no-pager --full status custom-github-agent.service || true

echo
echo "Custom GitHub agent installed."
echo "After successful enrollment, remove CG_ENROLLMENT_TOKEN from /etc/custom-github-agent/agent.env if desired; the long-lived token is kept in /var/lib/custom-github-agent/state.json with mode 0600."
