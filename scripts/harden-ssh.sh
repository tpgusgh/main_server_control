#!/usr/bin/env bash
# One-time host hardening (needs sudo). Safe to re-run.
#   1) SSH: keys only, no root, no passwords   2) firewall: SSH only from Tailscale + home LAN
#   3) time zone → Asia/Seoul (logs and systemd times match the dashboard)
# It refuses to touch SSH until a key is installed, so you can't lock yourself out.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo bash $0 로 실행하세요"; exit 1; }
USER_HOME=$(getent passwd "${SUDO_USER:-hyunho}" | cut -d: -f6)
KEYS="$USER_HOME/.ssh/authorized_keys"
# home LAN = the subnet of the first non-Tailscale global IPv4 (override with LAN_CIDR=...)
LAN="${LAN_CIDR:-$(ip -o -4 addr show scope global | awk '$2 != "tailscale0" {print $4; exit}' | python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.stdin.read().strip()).network)')}"
TS_IP="$(tailscale ip -4 2>/dev/null | head -1)"

if ! grep -qE '^(ssh-|ecdsa-|sk-)' "$KEYS" 2>/dev/null; then
  cat <<MSG
✋ 등록된 SSH 키가 없어 중단합니다 (지금 비밀번호로 접속 중이라 바로 끄면 잠깁니다).
   맥북 터미널에서 먼저 실행하세요:
     ssh-keygen -t ed25519            # 키가 없을 때만
     ssh-copy-id ${SUDO_USER:-$USER}@${TS_IP:-<이 서버의 Tailscale IP>}
   그 다음 '비밀번호 없이' 접속되는지 확인하고 이 스크립트를 다시 실행하세요.
MSG
  exit 1
fi

echo "▶ SSH: 키 로그인만 허용"
cat > /etc/ssh/sshd_config.d/10-hardening.conf <<CONF
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
MaxAuthTries 3
CONF
sshd -t                                   # abort (set -e) if the config is invalid
systemctl reload ssh

echo "▶ 방화벽: 들어오는 연결 기본 차단, SSH는 Tailscale·집 LAN 에서만"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow in on tailscale0 to any port 22 proto tcp
ufw allow from "$LAN" to any port 22 proto tcp
ufw allow 41641/udp                       # Tailscale direct connections (it works without, but slower)
ufw --force enable
ufw status verbose

echo "▶ 시간대: Asia/Seoul"
timedatectl set-timezone Asia/Seoul
echo "✓ 완료. 새 터미널에서 SSH 재접속이 되는지 꼭 확인하세요 (이 창은 닫지 말고)."
