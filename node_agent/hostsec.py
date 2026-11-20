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


def exposed(ip: str) -> bool:
    """Can a listening address be reached from outside the LAN/Tailscale? 0.0.0.0/:: (all interfaces) or a
    public address yes; loopback, LAN-only and Tailscale-only binds no."""
    ip = (ip or "").split("%")[0].strip("[]")
    if ip in ("0.0.0.0", "::", "*", ""):
        return True
    return not internal(ip)


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


def phased_packages(sim: str) -> list[str]:
    """Packages Ubuntu deliberately holds back for staged rollout ('deferred due to phasing'); they install
    by themselves in a few days, so they aren't 'pending' work."""
    out, inside = [], False
    for line in sim.splitlines():
        if "deferred due to phasing" in line:
            inside = True
        elif inside and line.startswith(" "):
            out += line.split()
        else:
            inside = False
    return out


def update_status():
    """Live apt state (no root needed). The update-notifier text file goes stale, so it isn't used."""
    import os
    import time
    from pathlib import Path
    try:
        r = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=90,
                           env={**os.environ, "LANG": "C"})
        lines = [l for l in r.stdout.splitlines() if "[upgradable" in l]
        sim = subprocess.run(["apt-get", "-s", "-q", "upgrade"], capture_output=True, text=True, timeout=90,
                             env={**os.environ, "LANG": "C"}).stdout
        phased = set(phased_packages(sim))
        lines = [l for l in lines if l.split("/")[0] not in phased]
    except (OSError, subprocess.SubprocessError):
        lines, phased = None, set()
    try:
        auto = 'Unattended-Upgrade "1"' in Path("/etc/apt/apt.conf.d/20auto-upgrades").read_text()
    except OSError:
        auto = False
    return {"ts": int(time.time()), "pending": None if lines is None else len(lines), "phased": len(phased),
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
            "firewall": "on" if re.search(r"^ENABLED=yes", _read("/etc/ufw/ufw.conf"), re.M) else
                        "on (외부 차단 모드)" if (guard_status() or {}).get("lockdown") else "off",
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
            "user_units": user_units, "sshd_config": _digest(sshd), "ports": sorted(ports, key=lambda p: int(p.split("/")[1])),
            "upnp": upnp_mappings() or [], "tunnels": sorted(f"{t['host']} → {t['service']}" for t in tunnel_hosts())}


def integrity_diff(old: dict, new: dict) -> list[str]:
    """Human-readable changes between two snapshots (empty when nothing changed)."""
    labels = {"users": "로그인 가능 사용자", "sudo": "sudo 권한", "ssh_keys": "SSH 공개키", "cron": "예약 작업(cron)",
              "units": "부팅 시 켜지는 시스템 서비스", "user_units": "사용자 서비스", "sshd_config": "SSH 서버 설정",
              "ports": "외부에서 열린 포트", "upnp": "공유기 포트포워딩(UPnP)", "tunnels": "Cloudflare 터널 공개 주소"}
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


def upgraded_since(ts: float) -> bool:
    """An upgrade finished after `ts` → cached apt counts are stale (re-read now, not at the next hourly check)."""
    return ((upgrade_status() or {}).get("finished") or 0) > ts


def upgrade_status():
    try:
        with open(f"{SM_DIR}/public.json") as f:
            return json.load(f).get("upgrade")
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- exposure: port guard, router UPnP, tunnels

def guard_status():
    """Port guard (외부 차단 모드) state from sm-block, or None when sm-block is missing/too old."""
    try:
        with open(f"{SM_DIR}/public.json") as f:
            return json.load(f).get("guard")
    except (OSError, ValueError):
        return None


def guard_request(config: dict):
    keys = ("lockdown", "allow_tcp", "allow_udp", "internal_tcp", "internal_udp", "rate")
    return _request({"op": "guard", "config": {k: config[k] for k in keys if k in config}})


def guard_refresh():
    return _request({"op": "stats"}, wait=4.0)


def upnp_mappings(timeout: float = 3.0):
    """Port forwards the LAN router opened via UPnP (cameras love doing this). None = no UPnP router answered."""
    import socket
    import urllib.parse
    import urllib.request
    from xml.etree import ElementTree as ET
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    loc = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(msg, ("239.255.255.250", 1900))
            data, addr = s.recvfrom(4096)
            m = re.search(rb"(?i)^location:\s*(\S+)", data, re.M)
            if m and internal(addr[0]):
                loc = m.group(1).decode()
    except OSError:
        return None
    if not loc or not internal(urllib.parse.urlsplit(loc).hostname or ""):  # only ever talk to the LAN router
        return None
    try:
        desc = urllib.request.urlopen(loc, timeout=5).read(200_000)
        root = ET.fromstring(desc)
    except Exception:
        return None
    ns = "{urn:schemas-upnp-org:device-1-0}"
    ctrl = stype = None
    for svc in root.iter(f"{ns}service"):
        t = (svc.findtext(f"{ns}serviceType") or "")
        if "WANIPConnection" in t or "WANPPPConnection" in t:
            ctrl, stype = urllib.parse.urljoin(loc, svc.findtext(f"{ns}controlURL") or ""), t
            break
    if not ctrl:
        return None
    out = []
    for i in range(64):
        body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:GetGenericPortMappingEntry xmlns:u="{stype}"><NewPortMappingIndex>{i}</NewPortMappingIndex>'
                f'</u:GetGenericPortMappingEntry></s:Body></s:Envelope>').encode()
        req = urllib.request.Request(ctrl, data=body, headers={
            "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{stype}#GetGenericPortMappingEntry"'})
        try:
            x = ET.fromstring(urllib.request.urlopen(req, timeout=5).read(50_000))
        except Exception:
            break  # SpecifiedArrayIndexInvalid (end of list) comes back as an HTTP 500
        val = lambda tag: next((e.text or "" for e in x.iter() if e.tag.endswith(tag)), "")
        out.append(f"{val('NewProtocol')} {val('NewExternalPort')} → {val('NewInternalClient')}:{val('NewInternalPort')} "
                   f"({val('NewPortMappingDescription')[:40]})")
    return out


def tunnel_hosts() -> list[dict]:
    """Hostnames this machine publishes through Cloudflare Tunnel: the configs of the cloudflared processes that
    are actually running (backup/candidate .yml files are ignored); all configs only if none is running."""
    import glob
    running = []
    for cmd in glob.glob("/proc/[0-9]*/cmdline"):
        parts = _read(cmd).split("\0")
        if parts and parts[0].endswith("cloudflared") and "--config" in parts:
            i = parts.index("--config")
            if i + 1 < len(parts):
                running.append(parts[i + 1])
    paths = running or glob.glob(str(Path.home() / ".cloudflared" / "*.yml")) + glob.glob("/etc/cloudflared/*.yml")
    out, seen = [], set()
    for path in dict.fromkeys(paths):
        host = None
        for line in _read(path).splitlines():
            m = re.match(r"\s*-?\s*hostname:\s*([A-Za-z0-9.-]+)", line)
            if m:
                host = m.group(1).lower()
                continue
            m = re.match(r"\s*-?\s*service:\s*(\S+)", line)
            if m and host and not m.group(1).startswith("http_status:") and (host, m.group(1)) not in seen:
                seen.add((host, m.group(1)))
                out.append({"host": host, "service": m.group(1)[:80], "config": Path(path).name})
            if m:
                host = None
    return out


# ---------------------------------------------------------------- processes (what started it, may we stop it)

PROTECTED_PROCS = {"systemd", "(sd-pam)", "sshd", "sshd-session", "dbus-daemon", "dbus-broker", "tailscaled", "init"}


def _comm(pid: int) -> str | None:
    stat = _read(f"/proc/{pid}/stat")
    return stat[stat.index("(") + 1:stat.rindex(")")] if "(" in stat else None


def proc_info(pid: int) -> dict | None:
    """Who/what a process is: owner, parent, command line and the systemd unit (cgroup) that started it."""
    import os
    import pwd
    stat = _read(f"/proc/{pid}/stat")
    if not stat or ")" not in stat:
        return None
    fields = stat[stat.rindex(")") + 2:].split()
    try:
        uid = os.stat(f"/proc/{pid}").st_uid
        user = pwd.getpwuid(uid).pw_name
    except (OSError, KeyError):
        uid, user = None, None
    unit = None
    for line in _read(f"/proc/{pid}/cgroup").splitlines():
        parts = [p for p in line.split(":", 2)[-1].split("/") if p.endswith((".service", ".scope"))]
        if parts:
            unit = parts[-1]
    ppid = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None
    return {"pid": pid, "name": stat[stat.index("(") + 1:stat.rindex(")")], "uid": uid, "user": user, "ppid": ppid,
            "parent": _comm(ppid) if ppid else None, "unit": unit,
            "cmd": _read(f"/proc/{pid}/cmdline").replace("\0", " ").strip()[:300] or None}


def killable(pid: int, protected_units=(), protected_pids=()) -> tuple[bool, str]:
    """May this dashboard/agent send SIGTERM? Only our own user's processes, never the session/system plumbing
    or anything belonging to a protected unit (the dashboard, its tunnel, the agent itself)."""
    import os
    info = proc_info(pid)
    if not info:
        return False, "프로세스가 없습니다."
    if pid <= 1 or pid in (os.getpid(), os.getppid()) or pid in set(protected_pids):
        return False, "이 프로세스는 종료할 수 없습니다 (보호됨)."
    if info["uid"] != os.getuid():
        return False, "다른 사용자의 프로세스입니다."
    if info["name"] in PROTECTED_PROCS or (info["unit"] or "") in set(protected_units):
        return False, f"보호된 프로세스입니다 ({info['unit'] or info['name']})."
    return True, info["name"]


def caps() -> list:
    """What the installed sm-block can do ([] when missing; 'svc' = system-service control)."""
    try:
        with open(f"{SM_DIR}/public.json") as f:
            return json.load(f).get("caps") or []
    except (OSError, ValueError):
        return []


def system_service(action: str, unit: str):
    """Ask root sm-block to start/stop/restart/enable/disable an existing system service (it re-checks the deny list)."""
    if "svc" not in caps():
        return False, "시스템 서비스 제어 도구가 없습니다 — 그 서버에서 install-blocker.sh 를 다시 실행하세요"
    ok, msg = _request({"op": "svc", "action": action, "unit": unit}, wait=80.0)  # sm-block allows a job 15 s + 60 s
    if ok and msg.startswith("요청함"):  # no answer yet: the job is still running
        return True, f"{unit} {action} 이(가) 80초 안에 끝나지 않았습니다 — 계속 진행 중일 수 있으니 잠시 뒤 서비스 목록에서 확인하세요"
    return ok, msg


# ---------------------------------------------------------------- network quality

def parse_wireless(text: str) -> dict | None:
    """/proc/net/wireless → {"iface", "dbm"} of the first interface; None when there is no Wi-Fi."""
    for line in text.splitlines()[2:]:
        parts = line.replace(":", " ", 1).split()
        if len(parts) >= 5:
            try:
                return {"iface": parts[0], "dbm": int(float(parts[3]))}
            except ValueError:
                continue
    return None


def wifi() -> dict | None:
    return parse_wireless(_read("/proc/net/wireless"))


def wifi_events(hours: int = 24) -> dict:
    """Wi-Fi drops from wpa_supplicant's journal: lost beacons (the router went silent) and disconnects that were
    not our own (a reboot disconnects on purpose, locally_generated=1)."""
    out = _run(["journalctl", "-t", "wpa_supplicant", "--since", f"-{hours}h", "--no-pager", "-o", "cat"], timeout=15)
    return {"beacon_loss": out.count("CTRL-EVENT-BEACON-LOSS"),
            "disconnects": sum(1 for l in out.splitlines() if "CTRL-EVENT-DISCONNECTED" in l and "locally_generated=1" not in l)}


def internet_ok(timeout: float = 2.0) -> tuple[bool, float | None]:
    """Can this machine open a TCP connection to the internet? (ok, milliseconds)"""
    import socket
    import time
    for host in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        t0 = time.monotonic()
        try:
            with socket.create_connection((host, 443), timeout=timeout):
                return True, round((time.monotonic() - t0) * 1000, 1)
        except OSError:
            continue
    return False, None


# ---------------------------------------------------------------- boot, kernel and disk health

def _secs(text: str) -> float:
    """'2min 3.670s' → 123.67 (systemd's duration notation)."""
    units = {"h": 3600, "min": 60, "s": 1, "ms": 0.001}
    return sum(float(n) * units[u] for n, u in re.findall(r"(\d+(?:\.\d+)?)\s*(h|min|ms|s)\b", text))


def parse_boot(analyze: str, chain: str, failed: list) -> dict:
    """`systemd-analyze time` + `critical-chain` + (unit, seconds-it-ran-before-failing) → one dict. The unit that
    really delays a boot (e.g. wait-online timing out) is often missing from `blame`/`critical-chain`, which is why
    failed units carry their own duration."""
    out = {"parts": {}, "failed": [{"unit": u, "secs": s} for u, s in failed], "slow": []}
    m = re.search(r"Startup finished in (.+)", analyze)
    if m:
        body, _, total = m.group(1).partition(" = ")
        out["total_s"] = round(_secs(total), 1)
        for seg in body.split(" + "):
            mm = re.match(r"(.+?)\s*\((\w+)\)", seg.strip())
            if mm:
                out["parts"][mm.group(2)] = round(_secs(mm.group(1)), 1)
    time_re = r"(?:[\d.]+(?:min|ms|s|h)\s*)+"
    slow = {}
    for mm in re.finditer(rf"([\w@.\-]+\.(?:service|mount|socket|target|device))\s+@{time_re}\+\s*({time_re})", chain):
        secs = _secs(mm.group(2))
        if secs >= 3:
            slow[mm.group(1)] = round(secs, 1)
    out["slow"] = sorted(slow.items(), key=lambda kv: -kv[1])[:3]
    return out


def boot_info() -> dict | None:
    """This boot's timing and the units that failed. None while boot is still in progress."""
    import time
    analyze = _run(["systemd-analyze", "time"], timeout=20)
    if "Startup finished" not in analyze:
        return None
    failed = []
    for line in _run(["systemctl", "--failed", "--no-legend", "--plain"]).splitlines():
        unit = line.split()[0] if line.split() else ""
        if not unit.endswith(".service"):
            continue
        show = dict(l.split("=", 1) for l in _run(["systemctl", "show", unit, "-p", "ExecMainStartTimestampMonotonic",
                                                     "-p", "ExecMainExitTimestampMonotonic"]).splitlines() if "=" in l)
        try:
            a, b = int(show.get("ExecMainStartTimestampMonotonic") or 0), int(show.get("ExecMainExitTimestampMonotonic") or 0)
        except ValueError:
            a = b = 0
        failed.append((unit, round((b - a) / 1e6, 1) if a and b > a else 0.0))
    info = parse_boot(analyze, _run(["systemd-analyze", "critical-chain", "--no-pager"], timeout=20), failed)
    info["boot_time"] = int(time.time() - float(_read("/proc/uptime", "0 0").split()[0]))
    return info


KERNEL_RULES = [
    ("oom", re.compile(r"out of memory|oom-kill|invoked oom-killer|killed process \d+|due to memory pressure", re.I)),
    ("disk", re.compile(r"i/o error|ext4-fs error|xfs.*(error|corruption)|btrfs.*(error|corrupt)|"
                        r"nvme\d+.*(timeout|reset controller|abort)|ata\d+(\.\d+)?: .*(failed command|error|exception)", re.I)),
    ("hardware", re.compile(r"machine check|hardware error|\bmce:|edac .*(error|\bue\b|\bce\b)", re.I)),
    ("thermal", re.compile(r"(thermal|temperature).*(throttl|above threshold)|cpu clock throttled", re.I)),
]
# journalctl -g filters on the server side, so firewall-log floods never reach us
KERNEL_GREP = ("out of memory|oom-kill|oom-killer|killed process|i/o error|fs error|nvme.*(timeout|reset|abort)|"
               "ata[0-9].*(failed|error|exception)|machine check|hardware error|mce:|edac|throttl|above threshold")


def classify_kernel(lines: list) -> list:
    """journalctl `-o short-unix` lines → [{"ts", "kind", "line"}] for the few messages that mean trouble."""
    out = []
    for line in lines:
        ts, _, rest = line.partition(" ")
        try:
            t = int(float(ts))
        except ValueError:
            continue
        msg = rest.split(": ", 1)[-1]
        for kind, rx in KERNEL_RULES:
            if rx.search(msg):
                out.append({"ts": t, "kind": kind, "line": " ".join(msg.split())[:200]})
                break
    return out


def kernel_events(hours: int = 1) -> dict:
    kern = _run(["journalctl", "-k", "--since", f"-{hours}h", "-g", KERNEL_GREP, "--no-pager", "-o", "short-unix", "-n", "400"], timeout=20)
    oomd = _run(["journalctl", "-u", "systemd-oomd", "--since", f"-{hours}h", "-g", "killed", "--no-pager", "-o", "short-unix", "-n", "50"], timeout=20)
    events = sorted(classify_kernel(kern.splitlines()) + classify_kernel(oomd.splitlines()), key=lambda e: e["ts"])[-40:]
    counts = {}
    for e in events:
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    return {"events": events, "counts": counts}


def request_smart():
    """Ask root sm-block to read every disk's SMART data (needs smartmontools); read the answer with smart_status()."""
    return _request({"op": "smart"}, wait=25.0)


def smart_status():
    try:
        with open(f"{SM_DIR}/public.json") as f:
            return json.load(f).get("smart")
    except (OSError, ValueError):
        return None
