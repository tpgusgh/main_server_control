#!/usr/bin/env bash
# Update server-agent on remote servers over SSH (key login set up once, e.g. `ssh sub` works).
#   scripts/update-agent.sh sub                 # one server (ssh alias or user@host)
#   scripts/update-agent.sh sub other           # several
#   scripts/update-agent.sh --blocker sub       # also re-install sm-block (asks for that server's sudo password)
# Copies this repo's node_agent/ and re-runs install.sh there: token and settings are kept.
set -euo pipefail
cd "$(dirname "$0")/.."
BLOCKER=0
[ "${1:-}" = "--blocker" ] && { BLOCKER=1; shift; }
[ $# -ge 1 ] || { sed -n '2,6p' "$0"; exit 1; }
DASH_IP="$(tailscale ip -4 | head -1)"
[ -n "$DASH_IP" ] || { echo "이 서버의 Tailscale IP를 찾지 못했습니다"; exit 1; }
LATEST="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' node_agent/server_agent.py)"

for HOST in "$@"; do
  echo "── $HOST → 에이전트 $LATEST"
  # BatchMode: never hang on a password prompt — key login must already work
  if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$HOST" true 2>/dev/null; then
    echo "✗ $HOST: 키로 접속할 수 없습니다 (ssh-copy-id 로 먼저 키를 등록하세요)"; continue
  fi
  tar -C node_agent --exclude='__pycache__' -cf - . | ssh -o BatchMode=yes "$HOST" 'umask 022; mkdir -p ~/node_agent && tar -C ~/node_agent -xf -'
  ssh -o BatchMode=yes "$HOST" "bash ~/node_agent/install.sh $DASH_IP" | grep -E '✓|⚠|실패|오류' || true
  if [ "$BLOCKER" = 1 ]; then
    ssh -t "$HOST" 'sudo bash ~/node_agent/install-blocker.sh'
  fi
  sleep 3
  ssh -o BatchMode=yes "$HOST" 'journalctl --user -u server-agent -n 20 --no-pager -o cat | grep -o "server-agent [0-9.]* listening" | tail -1' \
    | sed "s/^/✓ $HOST: /" || echo "⚠ $HOST: 시작 로그를 확인하지 못했습니다"
done
