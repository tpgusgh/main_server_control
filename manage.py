#!/usr/bin/env python3
"""Admin CLI for the server monitor.

  manage.py set-password        prompt for a new password, write it to .env and restart (logs out every session)
  manage.py totp-enable         enable 2-step login (prints an otpauth:// URI for your authenticator app)
  manage.py totp-disable        disable 2-step login
  manage.py logout-all          revoke all sessions
  manage.py bans                list permanently banned IPs
  manage.py unban <ip|key>      lift a ban (use when you locked yourself out)
  manage.py test-alert          send a test message to the configured Telegram/Discord
"""
import getpass
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import security

DB_PATH = Path(__file__).resolve().parent / "data" / "monitor.db"
ENV_PATH = Path(__file__).resolve().parent / ".env"
MIN_LEN = 11


def logout_all():
    if DB_PATH.exists():
        con = sqlite3.connect(DB_PATH)
        con.execute("DELETE FROM sessions")
        con.commit()
        con.close()


def set_password():
    pw = getpass.getpass("새 비밀번호 (11자 이상): ")
    if len(pw) < MIN_LEN:
        sys.exit(f"비밀번호는 최소 {MIN_LEN}자 이상이어야 합니다.")
    if pw != getpass.getpass("한 번 더 입력: "):
        sys.exit("두 비밀번호가 일치하지 않습니다.")
    if "'" in pw or "\n" in pw:
        sys.exit("작은따옴표(')와 줄바꿈은 쓸 수 없습니다.")
    lines = ENV_PATH.read_text().splitlines() if ENV_PATH.exists() else []
    lines = [l for l in lines if not l.startswith("SM_PASSWORD=")] + [f"SM_PASSWORD='{pw}'"]
    fd = os.open(ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    subprocess.run(["systemctl", "--user", "restart", "server-monitor.service"], check=False)
    print(".env 에 저장하고 서비스를 재시작했습니다. 모든 세션이 로그아웃됩니다.")


def totp_enable():
    cfg = security.load_config()
    secret = security.new_totp_secret()
    print("인증 앱(Google Authenticator 등)에 아래 키를 등록하세요:\n")
    print(f"  키: {secret}")
    print(f"  URI: otpauth://totp/hi.mieung.kr:admin?secret={secret}&issuer=hi.mieung.kr\n")
    code = input("앱에 표시된 6자리 코드를 입력해 확인: ")
    if security.totp_match(secret, code, 0) is None:
        sys.exit("코드가 맞지 않아 2단계 인증을 켜지 않았습니다.")
    cfg["totp_secret"], cfg["totp_last"] = secret, 0
    security.save_config(cfg)
    logout_all()
    print("2단계 인증을 켰습니다. 모든 세션을 로그아웃했습니다.")


def totp_disable():
    cfg = security.load_config()
    cfg.pop("totp_secret", None)
    cfg.pop("totp_last", None)
    security.save_config(cfg)
    print("2단계 인증을 껐습니다.")


def list_bans():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("SELECT key, country, datetime(ts,'unixepoch','localtime'), fails FROM bans ORDER BY ts DESC").fetchall()
    for key, country, when, fails in rows:
        print(f"{key:<40} {country or '-':<4} {when}  실패 {fails}회")
    print(f"총 {len(rows)}개")


def unban(target: str):
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT key, ip, country FROM bans WHERE key=? OR ip=?", (target, target)).fetchone()
    if not row:
        sys.exit("차단 목록에 없습니다.")
    con.execute("DELETE FROM bans WHERE key=?", (row[0],))
    con.execute("INSERT INTO access_log(ts,ip,country,method,path,status,ua,event,detail) "
                "VALUES(strftime('%s','now'),?,?,'-','-',0,'','unban','해제: manage.py')", (row[1], row[2]))
    con.commit()
    subprocess.run(["systemctl", "--user", "restart", "server-monitor.service"], check=False)
    print(f"{row[0]} 차단을 해제하고 서비스를 재시작했습니다.")


def test_alert():
    for line in ENV_PATH.read_text().splitlines():  # same values systemd passes to the service
        k, sep, v = line.partition("=")
        if sep and not k.startswith("#"):
            os.environ[k.strip()] = v.strip().strip("'")
    import alerts
    if not alerts.CHANNELS:
        sys.exit(".env 에 텔레그램/디스코드 설정이 없습니다.")
    alerts.send_now("✅ hi.mieung.kr 서버 모니터 알림 테스트입니다.",
                    alerts.card("✅ 알림 테스트", "이 카드가 보이면 디스코드 알림 설정이 끝난 겁니다.", "good",
                                [("예시 IP", "`203.0.113.7`", True), ("국가", "🇳🇱 NL", True)], footer="hi.mieung.kr"))
    print("보냈습니다:", ", ".join(alerts.CHANNELS))


COMMANDS = {"test-alert": test_alert, "set-password": set_password, "totp-enable": totp_enable,
            "totp-disable": totp_disable, "logout-all": logout_all, "bans": list_bans}

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "unban":
        unban(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] in COMMANDS:
        COMMANDS[sys.argv[1]]()
    else:
        sys.exit(__doc__)
