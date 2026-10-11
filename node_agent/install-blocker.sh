#!/usr/bin/env bash
# One-time (sudo): install sm-block so the dashboard/AI can auto-block attacker IPs on this machine
# and run "apt-get upgrade" when you press the button (re-run after updating to get new features).
# No sudo rights are handed out: the user may only drop request files into /var/lib/sm-block/requests,
# and a root systemd path unit runs sm-block, which re-checks every IP (never LAN/Tailscale/your SSH IP).
#   sudo bash ~/node_agent/install-blocker.sh                 (on a node)
#   sudo bash ~/server-monitor/node_agent/install-blocker.sh  (on the dashboard server)
# Undo: sudo systemctl disable --now sm-block.service sm-block-queue.path; sudo nft delete table inet sm_block;
#       sudo rm -r /var/lib/sm-block /usr/local/sbin/sm-block /etc/systemd/system/sm-block*
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo bash $0 로 실행하세요"; exit 1; }
U="${SUDO_USER:?sudo 로 실행해야 대상 사용자를 알 수 있습니다}"
G="$(id -gn "$U")"
SRC="$(cd "$(dirname "$0")" && pwd)"
command -v nft >/dev/null || { echo "nftables 가 필요합니다: sudo apt install nftables"; exit 1; }

install -o root -g root -m 755 "$SRC/sm-block" /usr/local/sbin/sm-block
install -d -o root -g root -m 755 /var/lib/sm-block
install -d -o root -g "$G" -m 730 /var/lib/sm-block/requests   # user may create files, not read/list others

cat > /etc/systemd/system/sm-block.service <<UNIT
[Unit]
Description=sm-block: re-apply blocked attacker IPs at boot
After=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sm-block restore
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/sm-block-queue.service <<UNIT
[Unit]
Description=sm-block: handle block/unblock requests from the dashboard
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sm-block process
TimeoutStartSec=2h
UNIT
cat > /etc/systemd/system/sm-block-queue.path <<UNIT
[Unit]
Description=sm-block: watch for block/unblock requests
[Path]
PathExistsGlob=/var/lib/sm-block/requests/*.json
[Install]
WantedBy=paths.target
UNIT
systemctl daemon-reload
systemctl enable --now sm-block.service sm-block-queue.path >/dev/null
sleep 1
[ -r /var/lib/sm-block/public.json ] && echo "✓ sm-block 설치 완료 (차단 0개로 시작)"
nft list table inet sm_block | head -3
