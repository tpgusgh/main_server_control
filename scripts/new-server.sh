#!/usr/bin/env bash
# Bring a new server (same Tailscale network) under this dashboard in one go.
#   scripts/new-server.sh [--dry-run] [--no-sudo] <ssh-host> "<표시 이름>"
# Steps: key login → agent install → register in dashboard → reverse key (this server can be reached only from
# the new server's Tailscale IP) → root helper (one sudo prompt) → checklist. Re-running is safe.
set -euo pipefail
cd "$(dirname "$0")/.."
DRY=0; SUDO=1
while [[ "${1:-}" == --* ]]; do
  case "$1" in --dry-run) DRY=1;; --no-sudo) SUDO=0;; *) echo "알 수 없는 옵션 $1"; exit 1;; esac; shift
done
[ $# -eq 2 ] || { sed -n '2,5p' "$0"; exit 1; }
HOST="$1"; NAME="$2"
run() { if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else "$@"; fi; }
step() { echo; echo "── $*"; }

step "1/5 키 로그인 확인"
if ssh -o BatchMode=yes -o ConnectTimeout=8 "$HOST" true 2>/dev/null; then echo "✓ 이미 키로 접속돼요"
else echo "키가 없어요 — 그 서버의 비밀번호를 한 번 물어봅니다"; run ssh-copy-id "$HOST"; fi

step "2/5 에이전트 설치"
run scripts/update-agent.sh "$HOST"

step "3/5 대시보드에 등록"
if [ "$DRY" = 1 ]; then echo "  [dry-run] 새 서버의 config.json 에서 주소·토큰을 읽어 manage.py add-node 실행"
else
  # token goes through ssh stdout and a pipe, never through a command line (ps)
  CFG="$(ssh -o BatchMode=yes "$HOST" 'python3 -c "import json,os;c=json.load(open(os.path.expanduser(\"~/server-agent/config.json\")));print(c[\"bind\"]+\":\"+str(c[\"port\"]));print(c[\"token\"])"')"
  ADDR="$(sed -n 1p <<<"$CFG")"
  sed -n 2p <<<"$CFG" | venv/bin/python manage.py add-node "$NAME" "$ADDR" || echo "(이미 등록돼 있으면 괜찮아요)"
  NEW_IP="${ADDR%%:*}"
fi

step "4/5 새 서버 → 이 서버 키 교환 (새 서버의 Tailscale IP에서만 허용)"
if [ "$DRY" = 1 ]; then echo "  [dry-run] 새 서버 공개키를 from=<새 서버 IP> 제한을 붙여 ~/.ssh/authorized_keys 에 추가"
else
  PUB="$(ssh -o BatchMode=yes "$HOST" '[ -f ~/.ssh/id_ed25519.pub ] || ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519; cat ~/.ssh/id_ed25519.pub')"
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  KEYBODY="$(awk '{print $2}' <<<"$PUB")"
  if grep -qF "$KEYBODY" ~/.ssh/authorized_keys 2>/dev/null; then echo "✓ 이미 등록돼 있어요"
  else echo "from=\"$NEW_IP\" $PUB" >> ~/.ssh/authorized_keys; echo "✓ 등록 (from=$NEW_IP)"; fi
fi

step "5/5 루트 도우미(sm-block) 설치"
if [ "$SUDO" = 0 ]; then echo "건너뜀 (--no-sudo) — 나중에: scripts/update-agent.sh --blocker $HOST"
else run ssh -t "$HOST" 'sudo bash ~/node_agent/install-blocker.sh'; fi

cat <<DONE

✅ 끝났어요. 직접 확인할 것:
  □ 대시보드에서 '$NAME' 이 온라인인지 (서버 선택 메뉴)
  □ Cloudflare Access에서 2단계(TOTP) 켜져 있는지
  □ Tailscale ACL: 이 서버만 새 서버 8101 포트에 접근 가능하게
  □ CCTV·카메라 기기는 별도 네트워크(VLAN)로 분리하고 인터넷 직접 노출 금지
  □ 부팅이 느리면: ssh -t $HOST 'sudo bash ~/node_agent/fix-wait-online.sh'
DONE
