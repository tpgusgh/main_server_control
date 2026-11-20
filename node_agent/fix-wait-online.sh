#!/usr/bin/env bash
# Boot "wait for network" fails (and delays boot ~2 min) when netplan lists a NIC with no cable (enp1s0).
# Fix: be online as soon as ANY link is up, give up after 30 s. Undo: sudo bash fix-wait-online.sh --undo
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo bash $0 로 실행하세요"; exit 1; }
DIR=/etc/systemd/system/systemd-networkd-wait-online.service.d
CONF=$DIR/zz-sm-any.conf   # sorts after netplan's generated 10-netplan.conf, so its ExecStart wins
if [ "${1:-}" = "--undo" ]; then
  rm -f "$CONF"; systemctl daemon-reload; echo "✓ 되돌렸습니다"; exit 0
fi
mkdir -p "$DIR"
printf '[Service]\nExecStart=\nExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=30\n' > "$CONF"
systemctl daemon-reload
if systemctl restart systemd-networkd-wait-online.service && systemctl is-active --quiet systemd-networkd-wait-online.service; then
  systemctl reset-failed systemd-networkd-wait-online.service 2>/dev/null || true
  echo "✓ 해결됨 — 네트워크 하나만 연결돼도 정상 (부팅 대기 최대 30초)"
else
  rm -f "$CONF"; systemctl daemon-reload
  echo "✗ 여전히 실패해서 되돌렸습니다 — networkctl 로 연결 상태를 확인하세요"; exit 1
fi
