#!/usr/bin/env bash
# SSH: keys from anywhere, passwords only from LAN / Tailscale / localhost (one-time, sudo).
#   sudo bash ssh-password-internal.sh          apply
#   sudo bash ssh-password-internal.sh --undo   back to how it was
# Before reloading sshd it asks sshd itself what an internet address and a LAN/Tailscale address would get;
# if that isn't exactly "internet: no password, inside: password", every change is rolled back. Any unexpected
# error rolls back too. Open SSH sessions are never dropped (reload, not restart).
# Tests (tests/test_ssh_script.py) point SSHD_CONFIG / SSHD_DROPIN at a scratch sshd and set SM_TEST=1 (no root, no reload).
set -Eeuo pipefail
[ "$(id -u)" -eq 0 ] || [ -n "${SM_TEST:-}" ] || { echo "sudo bash $0 로 실행하세요"; exit 1; }
MAIN="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
DROP="${SSHD_DROPIN:-/etc/ssh/sshd_config.d/10-sm-password-internal.conf}"   # sorts before 50-cloud-init.conf: first value wins
BEGIN="# >>> sm: passwords only from LAN or Tailscale"   # no '/' in the markers: they are sed addresses
END="# <<< sm"
NETS="127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fd7a:115c:a1e0::/48,fe80::/10"
USER_NAME="${SUDO_USER:-root}"
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"

sshd_() { "$SSHD_BIN" -f "$MAIN" "$@"; }
strip_block() { sed -i "/^$BEGIN\$/,/^$END\$/d" "$MAIN"; }
reload() { if [ -z "${SM_TEST:-}" ]; then systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; fi; }
setting_for() { sshd_ -T -C "user=$USER_NAME,host=test,addr=$2" 2>/dev/null | awk -v k="$1" '$1==k{print $2}'; }

if [ "${1:-}" = "--undo" ]; then
  rm -f "$DROP"; strip_block
  sshd_ -t && reload && echo "✓ 원래대로 되돌렸습니다 (비밀번호 로그인 어디서나 가능)"
  exit 0
fi

cp -p "$MAIN" "$MAIN.sm-backup"
rollback() { trap - ERR; rm -f "$DROP"; cp -p "$MAIN.sm-backup" "$MAIN"; echo "✗ $1 — 바꾼 것을 모두 되돌렸습니다 (변화 없음)"; exit 1; }
trap 'rollback "예상치 못한 오류 (스크립트 $LINENO번째 줄)"' ERR

before_pubkey="$(setting_for pubkeyauthentication 8.8.8.8)"
printf '# managed by server-monitor: passwords only from LAN or Tailscale (see %s)\nPasswordAuthentication no\n' "$MAIN" > "$DROP"
chmod 644 "$DROP"
strip_block
cat >> "$MAIN" <<EOF
$BEGIN
Match Address $NETS
    PasswordAuthentication yes
$END
EOF

sshd_ -t 2>/dev/null                                  || rollback "sshd 설정 검사 실패"
[ "$(setting_for passwordauthentication 8.8.8.8)" = "no" ]       || rollback "인터넷 주소의 비밀번호가 꺼지지 않음"
[ "$(setting_for passwordauthentication 2001:4860::1)" = "no" ]  || rollback "인터넷 IPv6 주소의 비밀번호가 꺼지지 않음"
[ "$(setting_for passwordauthentication 192.168.0.10)" = "yes" ] || rollback "LAN 비밀번호가 막힘"
[ "$(setting_for passwordauthentication 100.64.1.1)" = "yes" ]   || rollback "Tailscale 비밀번호가 막힘"
[ "$(setting_for pubkeyauthentication 8.8.8.8)" = "$before_pubkey" ] || rollback "키 로그인 설정이 바뀜"
[ "$before_pubkey" = "yes" ]                          || rollback "키 로그인이 꺼져 있어 적용하지 않음"
trap - ERR
reload
echo "✓ 적용됨 — 인터넷: 키만 · LAN/Tailscale/로컬: 키 또는 비밀번호 (되돌리기: sudo bash $0 --undo)"
