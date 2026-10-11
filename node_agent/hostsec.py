"""Host security helpers shared by the dashboard and server-agent (standard library only)."""
import ipaddress
import json
import re
import subprocess
from pathlib import Path

SM_BLOCK = "/usr/local/sbin/sm-block"
INTERNAL = [ipaddress.ip_network(n) for n in ("100.64.0.0/10", "fd7a:115c:a1e0::/48")]

SSH_PATTERNS = [
    (re.compile(r"Accepted (\S+) for (\S+) from (\S+) port"), "login_ok"),
    (re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port"), "login_fail"),
    (re.compile(r"Invalid user (\S*) from (\S+) port"), "invalid_user"),
]


def ssh_events(days=7):
    """SSH logins (ok/failed) from the system journal. None if this user can't read it (needs group adm)."""
    try:
        res = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", f"-{days}d", "--no-pager", "-q",
                              "-o", "short-unix"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if not res.stdout and "permission" in res.stderr.lower():
        return None
    out = []
    for line in res.stdout.splitlines():
        ts, _, rest = line.partition(" ")
        msg = rest.split(": ", 1)[-1]
        for rx, kind in SSH_PATTERNS:
            m = rx.search(msg)
            if m:
                g = m.groups()
                user, ip, method = (g[0], g[1], "") if kind == "invalid_user" else (g[1], g[2], g[0])
                try:
                    out.append({"ts": int(float(ts)), "event": kind, "user": user[:32], "ip": ip, "method": method})
                except ValueError:
                    pass
                break
    return out[-300:]


def internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable: treat as "don't touch"
    return a.is_private or a.is_loopback or a.is_link_local or any(a in n for n in INTERNAL)


def ssh_attackers(events, min_fails: int = 5, window: int = 3600, now: float | None = None) -> dict:
    """{ip: failures in the last `window`s} for outside IPs that never logged in successfully."""
    import time
    now = now or time.time()
    good = {e["ip"] for e in events or [] if e["event"] == "login_ok"}
    fails = {}
    for e in events or []:
        if e["event"] != "login_ok" and e["ts"] >= now - window and e["ip"] not in good and not internal(e["ip"]):
            fails[e["ip"]] = fails.get(e["ip"], 0) + 1
    return {ip: c for ip, c in fails.items() if c >= min_fails}


SM_DIR = "/var/lib/sm-block"


def blocked():
    """Current block list, or None when install-blocker.sh hasn't been run on this machine."""
    try:
        with open(f"{SM_DIR}/public.json") as f:
            return json.load(f)["blocked"]
    except (OSError, ValueError, KeyError):
        return None


def _request(payload: dict, wait: float = 8.0):
    """Drop a request for the root sm-block service, then wait briefly for its verdict."""
    import os
    import secrets
    import time
    rid = secrets.token_hex(8)
    tmp, final = f"{SM_DIR}/requests/{rid}.tmp", f"{SM_DIR}/requests/{rid}.json"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        os.rename(tmp, final)  # complete file appears at once; the path unit only watches *.json
    except OSError:
        return False, "차단 도구가 설치되지 않았습니다 (그 서버에서 sudo bash ~/node_agent/install-blocker.sh)"
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.4)
        try:
            with open(f"{SM_DIR}/public.json") as f:
                res = json.load(f).get("results", {}).get(rid)
        except (OSError, ValueError):
            res = None
        if res:
            return bool(res["ok"]), res.get("msg", "")
    return True, "요청함 (처리 대기 중)"


def block(ip: str, reason: str = ""):
    return _request({"op": "add", "ip": ip, "reason": reason[:150]})


def unblock(key: str):
    return _request({"op": "del", "key": key})


def delete_user_unit(unit: str, unit_dir, systemctl):
    """Retire a STOPPED user unit: disable it and move its file into <unit_dir>/.deleted (restorable with mv).
    `systemctl` is the caller's runner (dashboard and agent each have their own)."""
    import shutil
    import time
    from pathlib import Path
    state = systemctl("show", unit, "-p", "ActiveState", "--value").stdout.strip()
    if state not in ("inactive", "failed"):
        return False, "실행 중인 서비스는 삭제할 수 없습니다. 먼저 종료하세요."
    src = Path(unit_dir) / unit
    if not src.is_file():
        return False, "서비스 파일이 없습니다."
    systemctl("disable", unit)
    trash = Path(unit_dir) / ".deleted"
    trash.mkdir(mode=0o700, exist_ok=True)
    dst = trash / f"{unit}.{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.move(str(src), str(dst))
    systemctl("daemon-reload")
    systemctl("reset-failed", unit)
    return True, f"휴지통으로 옮김: {dst} (되살리기: mv 로 원래 자리에 두고 systemctl --user daemon-reload)"


def update_status():
    """Live apt state (no root needed). The update-notifier text file goes stale, so it isn't used."""
    import os
    import time
    from pathlib import Path
    try:
        r = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=90,
                           env={**os.environ, "LANG": "C"})
        lines = [l for l in r.stdout.splitlines() if "[upgradable" in l]
    except (OSError, subprocess.SubprocessError):
        lines = None
    try:
        auto = 'Unattended-Upgrade "1"' in Path("/etc/apt/apt.conf.d/20auto-upgrades").read_text()
    except OSError:
        auto = False
    return {"ts": int(time.time()), "pending": None if lines is None else len(lines),
            "security": None if lines is None else sum(1 for l in lines if "-security" in l.split()[0]),
            "auto_security": auto, "reboot_required": Path("/var/run/reboot-required").exists()}


def service_logs(unit: str, lines: int = 200, user: bool = True) -> str:
    """Recent journal lines of one unit (user journal, or the system journal — readable via group adm)."""
    if not re.fullmatch(r"[A-Za-z0-9@._-]+\.service", unit):
        return "잘못된 서비스 이름"
    cmd = ["journalctl", *(["--user"] if user else []), "-u", unit, "-n", str(max(10, min(lines, 1000))),
           "--no-pager", "-o", "short-iso"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as e:
        return f"로그를 읽지 못했습니다 ({type(e).__name__})"
    out = (r.stdout or r.stderr or "").strip() or "기록된 로그가 없습니다."
    return out[-200_000:]


def _read(path, default=""):
    try:
        return Path(path).read_text()
    except OSError:
        return default


def sshd_value(key, default):
    """First match wins, Include files are read in place, Match blocks end the global section (sshd semantics)."""
    def walk(path):
        for raw in _read(path).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition(" ")
            if k.lower() == "match":
                return "stop"
            if k.lower() == "include":
                for pat in v.split():
                    pat = pat if pat.startswith("/") else "/etc/ssh/" + pat
                    for inc in sorted(Path("/").glob(pat.lstrip("/"))):
                        r = walk(inc)
                        if r is not None:
                            return r
            elif k.lower() == key.lower():
                return v.strip()
        return None
    r = walk("/etc/ssh/sshd_config")
    return default if r in (None, "stop") else r


def security_facts():
    keys = Path.home() / ".ssh" / "authorized_keys"
    return {"ssh_password_auth": sshd_value("PasswordAuthentication", "yes"),
            "ssh_root_login": sshd_value("PermitRootLogin", "prohibit-password"),
            "authorized_keys": sum(1 for l in _read(keys).splitlines() if l.strip() and not l.startswith("#")),
            "firewall": "on" if re.search(r"^ENABLED=yes", _read("/etc/ufw/ufw.conf"), re.M) else "off",
            "reboot_required": Path("/var/run/reboot-required").exists()}


# ---------------------------------------------------------------- integrity (what an intruder changes to stay)

def _run(cmd, timeout=15) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _digest(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()[:16] if text else ""


def integrity_snapshot() -> dict:
    """Short, comparable facts: login users, sudo members, SSH keys, cron, enabled services, sshd config,
    public listening ports. Values are names/short hashes only (never key material or file contents)."""
    import grp
    import os
    import pwd
    users = sorted(f"{p.pw_name}(uid {p.pw_uid})" for p in pwd.getpwall()
                   if p.pw_uid == 0 or (p.pw_uid >= 1000 and not p.pw_shell.endswith(("nologin", "false"))))
    sudo = []
    for g in ("sudo", "wheel", "admin"):
        try:
            sudo += [f"{g}:{m}" for m in grp.getgrnam(g).gr_mem]
        except KeyError:
            pass
    keys = []
    for line in _read(Path.home() / ".ssh" / "authorized_keys").splitlines():
        parts = line.split()
        blob = next((p for p in parts if p.startswith("AAAA")), None)
        if blob:  # fingerprint-like id + the comment, so a new key is recognisable without exposing it
            keys.append(f"{_digest(blob)[:12]} {' '.join(parts[parts.index(blob) + 1:])[:40]}".strip())
    cron = [f"crontab:{_digest(_run(['crontab', '-l']))}"] if _run(["crontab", "-l"]).strip() else []
    try:
        cron += [f"cron.d/{n}" for n in sorted(os.listdir("/etc/cron.d")) if not n.startswith(".")]
    except OSError:
        pass
    cron.append(f"/etc/crontab:{_digest(_read('/etc/crontab'))}")
    units = sorted(l.split()[0] for l in _run(["systemctl", "list-unit-files", "--type=service", "--state=enabled",
                                               "--no-legend", "--no-pager"]).splitlines() if l.strip())
    user_dir = Path.home() / ".config" / "systemd" / "user"
    user_units = sorted(p.name for p in user_dir.glob("*.service")) if user_dir.is_dir() else []
    sshd = _read("/etc/ssh/sshd_config") + "".join(_read(p) for p in sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")))
    ports = set()
    for l in _run(["ss", "-Hlnt"]).splitlines():  # TCP only: UDP is full of ephemeral client ports
        f = l.split()
        if len(f) >= 4:
            host, _, port = f[3].rpartition(":")
            host = host.split("%")[0].strip("[]")
            if host in ("*", "0.0.0.0", "::") or not internal(host):  # skip loopback/LAN-only/Tailscale binds
                ports.add(f"tcp/{port}")
    return {"users": users, "sudo": sorted(sudo), "ssh_keys": sorted(keys), "cron": cron, "units": units,
            "user_units": user_units, "sshd_config": _digest(sshd), "ports": sorted(ports, key=lambda p: int(p.split("/")[1]))}


def integrity_diff(old: dict, new: dict) -> list[str]:
    """Human-readable changes between two snapshots (empty when nothing changed)."""
    labels = {"users": "로그인 가능 사용자", "sudo": "sudo 권한", "ssh_keys": "SSH 공개키", "cron": "예약 작업(cron)",
              "units": "부팅 시 켜지는 시스템 서비스", "user_units": "사용자 서비스", "sshd_config": "SSH 서버 설정",
              "ports": "외부에서 열린 포트"}
    out = []
    for k, label in labels.items():
        a, b = old.get(k), new.get(k)
        if a is None or b is None or a == b:
            continue
        if isinstance(a, list):
            add, rem = sorted(set(b) - set(a)), sorted(set(a) - set(b))
            if add:
                out.append(f"{label} 추가: {', '.join(add)[:300]}")
            if rem:
                out.append(f"{label} 제거: {', '.join(rem)[:300]}")
        else:
            out.append(f"{label} 변경됨")
    return out


def macs() -> list[dict]:
    """Physical NICs (for Wake-on-LAN). Virtual interfaces (docker, tailscale, bridges) have no device link."""
    out = []
    for dev in sorted(Path("/sys/class/net").glob("*")):
        if not (dev / "device").exists():
            continue
        mac = _read(dev / "address").strip()
        if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac) and mac != "00:00:00:00:00:00":
            out.append({"iface": dev.name, "mac": mac, "up": _read(dev / "operstate").strip() == "up"})
    return out


def wake(mac: str) -> int:
    """Send a Wake-on-LAN magic packet to every IPv4 broadcast address of this machine. Returns packets sent."""
    import socket
    if not re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", mac):
        raise ValueError("MAC 주소 형식이 아닙니다")
    packet = b"\xff" * 6 + bytes.fromhex(re.sub(r"[:-]", "", mac)) * 16
    targets = {"255.255.255.255"}
    for l in _run(["ip", "-4", "-o", "addr", "show"]).splitlines():
        m = re.search(r" brd (\d+\.\d+\.\d+\.\d+)", l)
        if m and not l.split()[1].startswith(("tailscale", "docker", "br-", "veth", "lo")):
            targets.add(m.group(1))
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for t in targets:
            for port in (9, 7):
                try:
                    s.sendto(packet, (t, port))
                    sent += 1
                except OSError:
                    pass
    return sent


def request_upgrade():
    """Ask the root sm-block service to run apt-get update + upgrade (no parameters can be passed)."""
    return _request({"op": "upgrade"}, wait=3.0)


def upgrade_status():
    try:
        with open(f"{SM_DIR}/public.json") as f:
            return json.load(f).get("upgrade")
    except (OSError, ValueError):
        return None
