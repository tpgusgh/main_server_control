#!/usr/bin/env bash
# SSH: keys from anywhere, passwords only from LAN / Tailscale / localhost (one-time, sudo).
#   sudo bash ssh-password-internal.sh          apply
#   sudo bash ssh-password-internal.sh --undo   back to how it was
# Before reloading sshd it asks sshd itself what an internet address and a LAN/Tailscale address would get;
# if that isn't exactly "internet: no password, inside: password", every change is rolled back.
# Open SSH sessions are never dropped (reload, not restart).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo bash $0 로 실행하세요"; exit 1; }
MAIN=/etc/ssh/sshd_config
DROP=/etc/ssh/sshd_config.d/10-sm-password-internal.conf   # sorts before 50-cloud-init.conf: first value wins
BEGIN="# >>> sm: passwords only from LAN/Tailscale"
END="# <<< sm"
NETS="127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fd7a:115c:a1e0::/48,fe80::/10"
USER_NAME="${SUDO_USER:-root}"

strip_block() { sed -i "/^$BEGIN\$/,/^$END\$/d" "$MAIN"; }
reload() { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; }
pw_for() { sshd -T -C "user=$USER_NAME,host=test,addr=$1" 2>/dev/null | awk '$1=="passwordauthentication"{print $2}'; }

if [ "${1:-}" = "--undo" ]; then
  rm -f "$DROP"; strip_block
  sshd -t && reload && echo "✓ 원래대로 되돌렸습니다 (비밀번호 로그인 어디서나 가능)"
  exit 0
fi

cp -p "$MAIN" "$MAIN.sm-backup"
before_pubkey="$(sshd -T -C "user=$USER_NAME,host=test,addr=8.8.8.8" | awk '$1=="pubkeyauthentication"{print $2}')"
rollback() { rm -f "$DROP"; cp -p "$MAIN.sm-backup" "$MAIN"; echo "✗ $1 — 바꾼 것을 모두 되돌렸습니다 (변화 없음)"; exit 1; }

printf '# managed by server-monitor: passwords only from LAN/Tailscale (see %s)\nPasswordAuthentication no\n' "$MAIN" > "$DROP"
chmod 644 "$DROP"
strip_block
cat >> "$MAIN" <<EOF
$BEGIN
Match Address $NETS
    PasswordAuthentication yes
$END
EOF

sshd -t 2>/dev/null || rollback "sshd 설정 검사 실패"
[ "$(pw_for 8.8.8.8)" = "no" ]          || rollback "인터넷 주소의 비밀번호가 꺼지지 않음"
[ "$(pw_for 2001:4860::1)" = "no" ]     || rollback "인터넷 IPv6 주소의 비밀번호가 꺼지지 않음"
[ "$(pw_for 192.168.0.10)" = "yes" ]    || rollback "LAN 비밀번호가 막힘"
[ "$(pw_for 100.94.77.73)" = "yes" ]    || rollback "Tailscale 비밀번호가 막힘"
[ "$(sshd -T -C "user=$USER_NAME,host=test,addr=8.8.8.8" | awk '$1=="pubkeyauthentication"{print $2}')" = "$before_pubkey" ] \
                                        || rollback "키 로그인 설정이 바뀜"
[ "$before_pubkey" = "yes" ]            || rollback "키 로그인이 꺼져 있어 적용하지 않음"
reload
echo "✓ 적용됨 — 인터넷: 키만 · LAN/Tailscale/로컬: 키 또는 비밀번호 (되돌리기: sudo bash $0 --undo)"
