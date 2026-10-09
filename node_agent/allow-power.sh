#!/usr/bin/env bash
# One-time (sudo): let this user reboot / power off the machine without a password prompt,
# so the dashboard's 재부팅/종료 buttons work. Only the power actions are allowed, nothing else.
#   sudo bash ~/node_agent/allow-power.sh          (on a node)
#   sudo bash ~/server-monitor/node_agent/allow-power.sh   (on the dashboard server)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo bash $0 로 실행하세요"; exit 1; }
U="${SUDO_USER:?sudo 로 실행해야 대상 사용자를 알 수 있습니다}"
RULE=/etc/polkit-1/rules.d/50-server-monitor-power.rules
cat > "$RULE" <<JS
// server-monitor: allow '$U' to reboot / power off (dashboard buttons). Remove this file to revoke.
polkit.addRule(function (action, subject) {
  var ids = ["org.freedesktop.login1.reboot", "org.freedesktop.login1.reboot-multiple-sessions",
             "org.freedesktop.login1.reboot-ignore-inhibit", "org.freedesktop.login1.power-off",
             "org.freedesktop.login1.power-off-multiple-sessions", "org.freedesktop.login1.power-off-ignore-inhibit"];
  if (ids.indexOf(action.id) >= 0 && subject.user == "$U") { return polkit.Result.YES; }
});
JS
chmod 644 "$RULE"
sleep 1
for m in CanReboot CanPowerOff; do
  printf "%s → " "$m"; sudo -u "$U" busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager "$m"
done
echo "✓ 완료 (둘 다 \"yes\" 여야 합니다). 되돌리기: sudo rm $RULE"
