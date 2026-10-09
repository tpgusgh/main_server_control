#!/usr/bin/env bash
# Install server-agent on a Linux machine in the same Tailscale network as the dashboard.
# Usage (on the new server):   bash install.sh <dashboard-tailscale-ip> [port]
# Runs as your normal user (no sudo) and manages that user's systemd services.
set -euo pipefail

DASHBOARD_IP="${1:?usage: bash install.sh <dashboard-tailscale-ip> [port]}"
PORT="${2:-8101}"
DIR="$HOME/server-agent"
SRC="$(cd "$(dirname "$0")" && pwd)"

command -v python3 >/dev/null || { echo "python3 가 필요합니다"; exit 1; }
command -v tailscale >/dev/null || { echo "tailscale 이 설치·로그인되어 있어야 합니다"; exit 1; }
TS_IP="$(tailscale ip -4 | head -1)"
[ -n "$TS_IP" ] || { echo "Tailscale IP를 찾지 못했습니다 (tailscale up 했나요?)"; exit 1; }

mkdir -p "$DIR"
install -m 700 "$SRC/server_agent.py" "$DIR/server_agent.py"
install -m 600 "$SRC/hostsec.py" "$DIR/hostsec.py"

if [ -f "$DIR/config.json" ]; then
  TOKEN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["token"])' "$DIR/config.json")"
else
  TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
fi
( umask 077; python3 - "$DIR/config.json" "$TOKEN" "$TS_IP" "$PORT" "$DASHBOARD_IP" <<'EOF'
import json, sys
path, token, bind, port, dash = sys.argv[1:]
json.dump({"token": token, "bind": bind, "port": int(port), "allow_from": [dash],
           "scope": "user", "units": [], "protected": ["server-agent.service"]}, open(path, "w"), indent=2)
EOF
)

mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/server-agent.service" <<EOF
[Unit]
Description=server-agent for hi.mieung.kr dashboard
After=network-online.target tailscaled.service

[Service]
ExecStart=/usr/bin/env python3 $DIR/server_agent.py
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=yes

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable server-agent.service
systemctl --user restart server-agent.service   # reinstall/upgrade must load the new code
sleep 2
systemctl --user is-active server-agent.service >/dev/null && echo "✓ server-agent 실행 중"

if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
  echo
  echo "⚠ 부팅 후 로그인 없이 자동 실행하려면 한 번만 실행하세요:  sudo loginctl enable-linger $USER"
fi

cat <<EOF

대시보드(hi.mieung.kr → 서버 목록 → 서버 추가)에 아래 값을 입력하세요:
  주소 : $TS_IP:$PORT
  토큰 : $TOKEN
EOF
