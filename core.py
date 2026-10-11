"""Shared state for the dashboard: config, database, IP trust/ban lists, alerts."""

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import HTTPException, Request

import alerts
import cfaccess
import security

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
DB_PATH = BASE / "data" / "monitor.db"

PUBLIC_HOST = os.environ.get("SM_HOST", "hi.mieung.kr")
LOCAL_PORT = int(os.environ.get("SM_PORT", "8100"))
ALLOWED_HOSTS = {PUBLIC_HOST, f"127.0.0.1:{LOCAL_PORT}", f"localhost:{LOCAL_PORT}"}
ALLOWED_ORIGINS = {f"https://{PUBLIC_HOST}", f"http://127.0.0.1:{LOCAL_PORT}", f"http://localhost:{LOCAL_PORT}"}

SAMPLE_INTERVAL = 10                 # seconds between metric samples
METRIC_RETENTION = 24 * 3600         # 24h load history
ACCESS_RETENTION = 183 * 86400       # ~6 months access log
SESSION_IDLE = 30 * 60
SESSION_MAX = 12 * 3600
FAIL_WINDOW = 15 * 60
BAN_AFTER_FAILS = 3                  # wrong passwords before an untrusted IP is banned for good
GLOBAL_FAIL_SLOWDOWN = 30
MAX_BODY = 8 * 1024
COOKIE = "__Host-sm_session"

# Units the dashboard itself depends on: restart is allowed, stop is not (it would lock you out).
PROTECTED_UNITS = {"server-monitor.service", "hi-tunnel.service"}
USER_UNIT_DIR = Path.home() / ".config" / "systemd" / "user"
UNIT_RE = re.compile(r"^[A-Za-z0-9@._-]+\.service$")

# Load-event thresholds
CPU_HOT, MEM_HOT, TEMP_HOT = 80.0, 90.0, 85.0

# ---------------------------------------------------------------- database

_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_db.row_factory = sqlite3.Row
_db.executescript("""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS metrics(
  ts INTEGER PRIMARY KEY, cpu REAL, mem REAL, swap REAL, temp REAL,
  load1 REAL, disk REAL, net_rx REAL, net_tx REAL);
CREATE TABLE IF NOT EXISTS access_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, ip TEXT, country TEXT,
  method TEXT, path TEXT, status INTEGER, ua TEXT, event TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_access_ts ON access_log(ts);
CREATE INDEX IF NOT EXISTS idx_access_ip ON access_log(ip, ts);
CREATE INDEX IF NOT EXISTS idx_access_event ON access_log(event, ts);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE, csrf TEXT,
  ip TEXT, ua TEXT, created INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS bans(
  key TEXT PRIMARY KEY, ip TEXT, country TEXT, ts INTEGER, fails INTEGER, ua TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, ip TEXT, country TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
""")
for _table in ("access_log", "sessions"):
    if "email" not in {r[1] for r in _db.execute(f"PRAGMA table_info({_table})")}:
        _db.execute(f"ALTER TABLE {_table} ADD COLUMN email TEXT")
os.chmod(DB_PATH, 0o600)


def db(sql, params=(), one=False):
    with _db_lock:
        cur = _db.execute(sql, params)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def country_of(request: Request) -> str:
    return request.headers.get("cf-ipcountry", "")[:4]


def log_access(request: Request, status: int, event: str, detail: str = ""):
    db("INSERT INTO access_log(ts,ip,country,method,path,status,ua,event,detail,email) VALUES(?,?,?,?,?,?,?,?,?,?)",
       (int(time.time()), request.state.ip, country_of(request),
        request.method, request.url.path[:200], status,
        request.headers.get("user-agent", "")[:300], event, detail[:300], request.state.email))

# ---------------------------------------------------------------- password (from .env)

MIN_PASSWORD_LEN = 11


def _init_password() -> str | None:
    """Hash SM_PASSWORD (loaded from .env by systemd) once at startup and drop it from the
    environment so child processes never inherit it. A changed password revokes every session."""
    pw = os.environ.pop("SM_PASSWORD", "")
    if len(pw) < MIN_PASSWORD_LEN:
        print(f"SM_PASSWORD is missing or shorter than {MIN_PASSWORD_LEN} chars; login disabled", flush=True)
        return None
    cfg = security.load_config()
    cfg.pop("password_hash", None)
    pepper = cfg.setdefault("pw_pepper", secrets.token_hex(16))
    fingerprint = hmac.new(pepper.encode(), pw.encode(), hashlib.sha256).hexdigest()
    if cfg.get("pw_fingerprint") != fingerprint:
        db("DELETE FROM sessions")
        cfg["pw_fingerprint"] = fingerprint
    security.save_config(cfg)
    return security.hash_password(pw)


PASSWORD_HASH = _init_password()


def _parse_ip_labels(raw: str) -> dict[str, str]:
    """SM_IP_LABELS="1.2.3.4=나,5.6.7.8=회사" → display labels for known IPs (cosmetic only, grants nothing)."""
    out = {}
    for part in raw.split(","):
        ip, sep, label = part.partition("=")
        try:
            if sep and label.strip():
                out[str(ipaddress.ip_address(ip.strip()))] = label.strip()[:20]
        except ValueError:
            print(f"SM_IP_LABELS: ignoring invalid IP {ip.strip()!r}", flush=True)
    return out


IP_LABELS = _parse_ip_labels(os.environ.get("SM_IP_LABELS", ""))


def _parse_trusted(raw: str) -> list:
    nets = []
    for part in raw.split(","):
        if part.strip():
            try:
                nets.append(ipaddress.ip_network(part.strip(), strict=False))
            except ValueError:
                print(f"SM_TRUSTED_IPS: ignoring invalid entry {part.strip()!r}", flush=True)
    return nets


TRUSTED_NETS = _parse_trusted(os.environ.get("SM_TRUSTED_IPS", ""))
# IPs trusted from the dashboard ("영구 등록" on a session), kept in config.json next to the .env list.
TRUSTED_EXTRA: dict[str, str] = security.load_config().get("trusted_extra", {})
for _ip, _label in TRUSTED_EXTRA.items():
    IP_LABELS.setdefault(_ip, _label)


def is_trusted(ip: str) -> bool:
    """Trusted IPs (and the machine itself) are never banned. They still need the password."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or str(addr) in TRUSTED_EXTRA or any(addr in n for n in TRUSTED_NETS)


def ban_key(ip: str) -> str:
    """IPv6 hosts usually own a whole /64, so ban the /64 rather than one rotating address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


BANNED: set[str] = {r["key"] for r in db("SELECT key FROM bans")}
# Ban/unban events for secops to mirror onto every server's firewall (append-only, drained by its loop).
BAN_EVENTS: list[tuple[str, str, str]] = []  # (op 'add'|'del', ip or key, reason)


def labeled(row) -> dict:
    d = dict(row)
    ip = d.get("ip") or ""
    d["label"] = IP_LABELS.get(ip) or ("로컬" if ip in ("127.0.0.1", "::1") else None)
    d["trusted"] = is_trusted(ip) if ip else False
    d["banned"] = ban_key(ip) in BANNED if ip else False
    return d


ALERT_TITLES = {"new_ip": "🔔 새 IP 로그인", "login_fail": "⚠️ 로그인 실패", "ban": "⛔ IP 영구 차단",
                "unban": "✅ IP 차단 해제", "node_down": "🔴 서버 연결 끊김", "node_up": "🟢 서버 다시 연결",
                "node_hot": "🔥 원격 서버 고부하", "ai_fix": "🤖 AI 자동 조치", "needs_you": "🚨 직접 확인 필요",
                "power": "⚡ 서버 전원 조작", "site_down": "🌐 웹사이트 접속 불가", "site_up": "🌐 웹사이트 복구",
                "login_risk": "🕵️ AI: 수상한 로그인", "ai_risk": "🛡️ AI 위험 감지",
                "config_change": "🧩 서버 설정 변경", "disk_forecast": "💽 디스크 가득 참 예상", "monthly": "📈 월간 가동률",
                "upgrade": "📦 패키지 업그레이드", "ai_case": "🔎 AI 보안 조사 결과"}
ALERT_LEVEL = {"ban": "critical", "login_fail": "critical", "node_down": "critical", "needs_you": "critical",
               "new_ip": "warning", "node_hot": "warning", "power": "warning",
               "unban": "good", "node_up": "good", "ai_fix": "good", "site_down": "critical", "site_up": "good",
               "login_risk": "critical", "ai_risk": "warning",
               "config_change": "warning", "disk_forecast": "warning", "monthly": "info", "upgrade": "info", "ai_case": "critical"}

def raise_alert(kind: str, ip: str, country: str, message: str, throttle: int = 0, push: bool = True):
    """Store an alert for the dashboard and push it to Telegram/Discord (if configured)."""
    now = time.time()
    if throttle:
        last = db("SELECT MAX(ts) t FROM alerts WHERE kind=? AND ip=?", (kind, ip), one=True)["t"] or 0
        if now - last < throttle:
            return
    db("INSERT INTO alerts(ts,kind,ip,country,message) VALUES(?,?,?,?,?)", (int(now), kind, ip, country, message[:300]))
    label = f" ({IP_LABELS[ip]})" if ip in IP_LABELS else ""
    if push:
        title = ALERT_TITLES.get(kind, kind)
        lines = [l for l in message.split("\n") if l.strip()]
        body = "\n".join(f"• {l}" for l in lines) if len(lines) > 1 else message
        is_ip = bool(ip) and not ip.startswith("http")  # node alerts carry the agent URL, not a client IP
        flag = "".join(chr(0x1F1E6 + ord(c) - 65) for c in country) if len(country) == 2 and country.isalpha() else ""
        alerts.push(f"{title} · {PUBLIC_HOST}\nIP: {ip}{label} [{country or '?'}]\n{message}\n"
                    f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}",
                    alerts.card(title, body, ALERT_LEVEL.get(kind, "info"),
                                [("IP", f"`{ip}`{label}" if is_ip else None, True),
                                 ("국가", f"{flag} {country}".strip() if country else None, True),
                                 ("서버", ip.removeprefix("http://") if not is_ip and ip else None, True)],
                                footer=PUBLIC_HOST))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def require_auth(request: Request) -> dict:
    if request.state.session is None:
        raise HTTPException(401, "unauthorized")
    return request.state.session


_cfg_lock = threading.Lock()


def fails_since_reset(ip: str) -> int:
    """Wrong passwords from this IP since its last successful login or unban."""
    return db("SELECT COUNT(*) c FROM access_log WHERE ip=? AND event='login_fail' AND id > "
              "COALESCE((SELECT MAX(id) FROM access_log WHERE ip=? AND event IN ('login_ok','unban')), 0)",
              (ip, ip), one=True)["c"]


def ban(ip: str, country: str, ua: str, fails: int, reason: str, push: bool = True) -> str:
    key = ban_key(ip)
    db("INSERT OR REPLACE INTO bans(key,ip,country,ts,fails,ua,reason) VALUES(?,?,?,?,?,?,?)",
       (key, ip, country, int(time.time()), fails, ua[:300], reason[:200]))
    BANNED.add(key)
    BAN_EVENTS.append(("add", ip, reason))
    db("DELETE FROM sessions WHERE ip=?", (ip,))
    raise_alert("ban", ip, country, f"{reason} → 영구 차단 ({key})", push=push)
    return key


def ban_ip(request: Request, fails: int):
    ban(request.state.ip, country_of(request), request.headers.get("user-agent", ""), fails, f"로그인 {fails}회 실패")


# ---------------------------------------------------------------- AI analyst (read-only)


def _security_config():
    return {"cf_access": cfaccess.ENABLED, "totp": bool(security.load_config().get("totp_secret")),
            "trusted_count": len(TRUSTED_NETS)}


def local_name() -> str:
    return security.load_config().get("local_name") or socket.gethostname()


def confirm_password(request: Request, password: str) -> bool:
    """Re-auth for destructive actions (reboot/power off). Wrong guesses count toward the same
    3-strike ban as the login form, so a stolen session can't be used to brute-force the password."""
    if PASSWORD_HASH and security.verify_password(password, PASSWORD_HASH):
        return True
    log_access(request, 403, "login_fail", "re-auth")
    request.state.event = "logged"
    fails = fails_since_reset(request.state.ip)
    if not is_trusted(request.state.ip) and fails >= BAN_AFTER_FAILS:
        ban_ip(request, fails)
    return False
