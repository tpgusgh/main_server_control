#!/usr/bin/env python3
"""server-agent: lets the hi.mieung.kr dashboard monitor and control this Linux machine over Tailscale.

Standard library only (no pip install needed). Security model:
  * listens only on this machine's Tailscale address
  * accepts requests only from the dashboard's Tailscale IP(s) in `allow_from`
  * every request needs the per-node bearer token (constant-time compare)
  * control is limited to systemd units in the whitelist; the agent's own unit can't be stopped/disabled
  * repeated bad tokens from an IP are ignored for 10 minutes
"""
import hmac
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # hostsec.py ships next to this file
import hostsec  # noqa: E402

VERSION = "2.0"
CONFIG_PATH = Path(os.environ.get("AGENT_CONFIG", Path(__file__).resolve().parent / "config.json"))
UNIT_RE = re.compile(r"^[A-Za-z0-9@._-]+\.service$")
SAMPLE_INTERVAL = 10
PAGE = os.sysconf("SC_PAGE_SIZE")
CLK = os.sysconf("SC_CLK_TCK")

cfg = json.loads(CONFIG_PATH.read_text())
TOKEN = cfg["token"]
ALLOW = [ipaddress.ip_network(a, strict=False) for a in cfg.get("allow_from", [])]
SCOPE = cfg.get("scope", "user")  # "user": systemctl --user ; "system": systemctl (agent must run as root)
PROTECTED = set(cfg.get("protected", ["server-agent.service"]))


# ---------------------------------------------------------------- metrics from /proc

def read(path, default=""):
    try:
        return Path(path).read_text()
    except OSError:
        return default


def cpu_times():
    per = []
    for line in read("/proc/stat").splitlines():
        if line.startswith("cpu") and line[3:4].isdigit():
            v = [int(x) for x in line.split()[1:]]
            idle = v[3] + (v[4] if len(v) > 4 else 0)
            per.append((sum(v[:8]), idle))
    return per


def meminfo():
    m = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, rest = line.partition(":")
        m[k] = int(rest.split()[0]) * 1024 if rest.split() else 0
    total, avail = m.get("MemTotal", 0), m.get("MemAvailable", 0)
    st, sf = m.get("SwapTotal", 0), m.get("SwapFree", 0)
    return {"mem_total": total, "mem_used": total - avail, "mem": round((total - avail) / total * 100, 1) if total else 0,
            "swap_total": st, "swap_used": st - sf, "swap": round((st - sf) / st * 100, 1) if st else 0}


def temps():
    out = []
    for hw in Path("/sys/class/hwmon").glob("hwmon*"):
        chip = read(hw / "name").strip() or hw.name
        for f in hw.glob("temp*_input"):
            try:
                v = int(read(f).strip()) / 1000
            except ValueError:
                continue
            label = read(str(f).replace("_input", "_label")).strip() or chip
            out.append({"chip": chip, "label": label, "current": v})
    if not out:
        for z in Path("/sys/class/thermal").glob("thermal_zone*"):
            try:
                out.append({"chip": read(z / "type").strip(), "label": read(z / "type").strip(),
                            "current": int(read(z / "temp").strip()) / 1000})
            except ValueError:
                pass
    return out


def main_temp(ts):
    for t in ts:
        if t["chip"] in ("coretemp", "k10temp", "zenpower") and ("Package" in t["label"] or "Tctl" in t["label"]):
            return t["current"]
    vals = [t["current"] for t in ts if 0 < t["current"] < 150]
    return max(vals) if vals else None


def disks():
    seen, out = set(), []
    for line in read("/proc/mounts").splitlines():
        dev, mnt, fs = line.split()[:3]
        if fs not in ("ext4", "ext3", "xfs", "btrfs", "zfs", "f2fs", "vfat") or mnt.startswith("/snap") or dev in seen:
            continue
        seen.add(dev)
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        if total:
            out.append({"mount": mnt, "total": total, "used": total - free, "percent": round((total - free) / total * 100, 1)})
    return out


def net_bytes():
    rx = tx = 0
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, data = line.partition(":")
        if name.strip() in ("lo",) or name.strip().startswith(("docker", "veth", "br-")):
            continue
        f = data.split()
        rx, tx = rx + int(f[0]), tx + int(f[8])
    return rx, tx


def proc_snapshot():
    snap = {}
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            stat = (d / "stat").read_text()
            name = stat[stat.index("(") + 1:stat.rindex(")")]
            f = stat[stat.rindex(")") + 2:].split()
            snap[int(d.name)] = (name, int(f[11]) + int(f[12]), int(f[21]) * PAGE, d.stat().st_uid)
        except (OSError, ValueError, IndexError):
            continue
    return snap


def os_name():
    for line in read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return os.uname().sysname


def username(uid, _cache={}):
    if uid not in _cache:
        try:
            import pwd
            _cache[uid] = pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            _cache[uid] = str(uid)
    return _cache[uid]


def login_sessions():
    try:
        res = subprocess.run(["loginctl", "list-sessions", "--no-legend"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for sid in [l.split()[0] for l in res.stdout.splitlines() if l.split()][:30]:
        r = subprocess.run(["loginctl", "show-session", sid, "-p", "Name", "-p", "RemoteHost", "-p", "TTY",
                            "-p", "Service", "-p", "TimestampMonotonic"], capture_output=True, text=True, timeout=5)
        d = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
        if d.get("Service") == "systemd-user":  # the per-user service manager, not a real login
            continue
        mono = d.get("TimestampMonotonic", "")
        boot = time.time() - float(read("/proc/uptime", "0").split()[0])  # loginctl has no unix-timestamp option
        out.append({"name": d.get("Name"), "host": d.get("RemoteHost") or None, "terminal": d.get("TTY") or d.get("Service"),
                    "started": int(boot + int(mono) / 1e6) if mono.isdigit() else None})
    return out


def power_state():
    """logind's answer for this user: "yes" (allowed), "challenge" (needs allow-power.sh once), "no"."""
    out = {}
    for key, method in (("reboot", "CanReboot"), ("poweroff", "CanPowerOff")):
        try:
            r = subprocess.run(["busctl", "call", "org.freedesktop.login1", "/org/freedesktop/login1",
                                "org.freedesktop.login1.Manager", method], capture_output=True, text=True, timeout=5)
            out[key] = r.stdout.split('"')[1] if '"' in r.stdout else "unknown"
        except (OSError, subprocess.SubprocessError):
            out[key] = "unknown"
    return out


def power(action):
    if action not in ("reboot", "poweroff"):
        return 400, {"detail": "unknown action"}
    if power_state().get(action) != "yes":
        return 409, {"detail": "이 서버에서 먼저 한 번 실행하세요: sudo bash ~/node_agent/allow-power.sh"}
    # answer first, act 2s later, so the dashboard gets a reply before the machine goes down
    threading.Timer(2, lambda: subprocess.run(["systemctl", action])).start()
    return 200, {"ok": True}


def home_du():
    """Top-level folder sizes in $HOME (one du pass at idle CPU/IO priority; slow, so run hourly in a thread)."""
    home = str(Path.home())
    try:
        r = subprocess.run(["nice", "-n", "19", "ionice", "-c3", "du", "-xB1", "--max-depth=1", home],
                           capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ts": int(time.time()), "error": type(e).__name__, "dirs": []}
    sizes = {}
    for line in r.stdout.splitlines():
        size, _, path = line.partition("\t")
        if size.isdigit():
            sizes[path] = int(size)
    total = sizes.pop(home, None)
    dirs = sorted(({"path": p.replace(home, "~", 1), "size": v} for p, v in sizes.items()), key=lambda d: -d["size"])
    return {"ts": int(time.time()), "home": home, "total": total, "dirs": dirs[:20]}


class Sampler(threading.Thread):
    daemon = True

    def __init__(self):
        super().__init__()
        self.latest = {}
        self._cpu = cpu_times()
        self._net = (net_bytes(), time.time())
        self._procs = (proc_snapshot(), time.time())
        self.host = {}
        self.du = None
        self._du_t = self._upd_t = 0.0
        self.updates = None
        self._host_t = 0.0
        self.integrity, self._int_t = None, 0.0

    def sample(self):
        now = time.time()
        cur = cpu_times()
        per_core = []
        for (t1, i1), (t0, i0) in zip(cur, self._cpu):
            dt = t1 - t0
            per_core.append(round(100 * (1 - (i1 - i0) / dt), 1) if dt > 0 else 0.0)
        self._cpu = cur
        (rx0, tx0), t0 = self._net
        rx, tx = net_bytes()
        dt = max(now - t0, 0.001)
        self._net = ((rx, tx), now)
        procs0, pt0 = self._procs
        procs = proc_snapshot()
        self._procs = (procs, now)
        mem = meminfo()
        top = []
        for pid, (name, ticks, rss, uid) in procs.items():
            prev = procs0.get(pid)
            cpu = (ticks - prev[1]) / CLK / max(now - pt0, 0.001) * 100 if prev and prev[0] == name else 0.0
            top.append({"pid": pid, "name": name, "user": username(uid), "cpu": round(cpu, 1),
                        "mem": round(rss / mem["mem_total"] * 100, 1) if mem["mem_total"] else 0})
        top.sort(key=lambda p: (p["cpu"], p["mem"]), reverse=True)
        ts = temps()
        root = next((d for d in disks() if d["mount"] == "/"), None)
        self.latest = {"ts": int(now), "cpu": round(sum(per_core) / len(per_core), 1) if per_core else 0,
                       "per_core": per_core, **mem, "temp": main_temp(ts), "temps": ts,
                       "load": list(os.getloadavg()), "disk": root["percent"] if root else None, "disks": disks(),
                       "net_rx": (rx - rx0) / dt, "net_tx": (tx - tx0) / dt, "top": top[:12]}
        self.latest["ports"], self.latest["inbound"], self.latest["outbound"] = sockets()
        if now - self._host_t > 60:  # journal/loginctl are slower: once a minute is plenty
            self._host_t = now
            self.host = {"ssh": hostsec.ssh_events(), "sessions": login_sessions(), "security": hostsec.security_facts(),
                         "power": power_state(), "blocker": hostsec.blocked(),  # None = install-blocker.sh not run
                         "macs": hostsec.macs(), "upgrade": hostsec.upgrade_status()}

    def run(self):
        while True:
            if time.time() - self._upd_t > 3600:  # apt list: hourly is plenty
                self._upd_t = time.time()
                threading.Thread(target=lambda: setattr(self, "updates", hostsec.update_status()), daemon=True).start()
            if time.time() - self._int_t > 3600:
                self._int_t = time.time()
                threading.Thread(target=lambda: setattr(self, "integrity", hostsec.integrity_snapshot()), daemon=True).start()
            if time.time() - self._du_t > 3600:
                self._du_t = time.time()
                threading.Thread(target=lambda: setattr(self, "du", home_du()), daemon=True).start()
            time.sleep(SAMPLE_INTERVAL)
            try:
                self.sample()
            except Exception as e:  # keep sampling
                print("sample error:", e, flush=True)


# ---------------------------------------------------------------- systemd

def systemctl_as(system: bool, *args, timeout=10):
    if system:  # reading system units needs no root; changing them does
        return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=timeout)
    env = dict(os.environ, XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}")
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=timeout, env=env)


def systemctl(*args, timeout=10):
    return systemctl_as(SCOPE == "system", *args, timeout=timeout)


def managed_units():
    if cfg.get("units"):
        return sorted(u for u in cfg["units"] if UNIT_RE.match(u))
    d = Path.home() / ".config" / "systemd" / "user"
    return sorted(p.name for p in d.glob("*.service") if p.is_file() and UNIT_RE.match(p.name)) if SCOPE == "user" else []


def _show(units, system):
    props = "Id,Description,ActiveState,SubState,MainPID,ActiveEnterTimestamp,UnitFileState,NRestarts"
    res = systemctl_as(system, "show", *units, "-p", props, "--timestamp=unix")
    if res.returncode != 0:  # systemd < 247 has no --timestamp
        res = systemctl_as(system, "show", *units, "-p", props)
    out = []
    for block in res.stdout.strip().split("\n\n"):
        d = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if not d.get("Id"):
            continue
        out.append({"unit": d["Id"], "description": d.get("Description"), "active": d.get("ActiveState"),
                    "sub": d.get("SubState"), "pid": int(d.get("MainPID") or 0) or None,
                    "since": int(d["ActiveEnterTimestamp"][1:]) if d.get("ActiveEnterTimestamp", "").startswith("@")
                    else d.get("ActiveEnterTimestamp") or None, "enabled": d.get("UnitFileState"),
                    "restarts": d.get("NRestarts"), "protected": d["Id"] in PROTECTED})
    return out


def system_units():
    """Running or failed system services (web servers, databases, docker, ...)."""
    res = systemctl_as(True, "list-units", "--type=service", "--state=running,failed", "--no-legend", "--plain")
    names = {line.split()[0] for line in res.stdout.splitlines() if line.split() and UNIT_RE.match(line.split()[0])}
    return sorted(names)[:100]


def services():
    """User units are controllable; system units are view-only unless the agent runs as root (scope=system)."""
    managed = set(managed_units())
    out = []
    if SCOPE == "user":
        if managed:
            out += [dict(x, scope="user", controllable=True) for x in _show(sorted(managed), False)]
        sysu = system_units()
        if sysu:
            out += [dict(x, scope="system", controllable=False) for x in _show(sysu, True)]
    else:
        units = sorted(set(system_units()) | managed)
        if units:
            out += [dict(x, scope="system", controllable=x["unit"] in managed) for x in _show(units, True)]
    return out


def _proc_ip(hexaddr: str) -> str:
    """/proc/net/tcp{,6} addresses are little-endian per 32-bit word."""
    b = bytes.fromhex(hexaddr)
    if len(b) == 4:
        return socket.inet_ntop(socket.AF_INET, b[::-1])
    return socket.inet_ntop(socket.AF_INET6, b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4)))


def sockets():
    """Listening ports and established connections from /proc/net/tcp{,6}, with the owning process."""
    listen, est = {}, {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in read(path).splitlines()[1:]:
            f = line.split()
            if len(f) <= 9:
                continue
            (lh, lp), (rh, rp) = f[1].split(":"), f[2].split(":")
            if f[3] == "0A":  # LISTEN
                listen[f[9]] = (_proc_ip(lh), int(lp, 16))
            elif f[3] == "01":  # ESTABLISHED
                est[f[9]] = (_proc_ip(lh), int(lp, 16), _proc_ip(rh), int(rp, 16))
    owner = {}
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:  # other users' processes are unreadable without root: shown without a name
            for fd in (d / "fd").iterdir():
                link = os.readlink(fd)
                if link.startswith("socket:[") and (link[8:-1] in listen or link[8:-1] in est):
                    owner[link[8:-1]] = int(d.name)
        except OSError:
            continue

    def who(inode):
        pid = owner.get(inode)
        name = (read(f"/proc/{pid}/comm").strip() or None) if pid else None
        return pid, name

    ports, seen = [], set()
    for inode, (ip, port) in listen.items():
        if (ip, port) in seen:
            continue
        seen.add((ip, port))
        pid, name = who(inode)
        cwd = None
        if pid:
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                pass
        ports.append({"ip": ip, "port": port, "pid": pid, "process": name, "cwd": cwd,
                      "public": not ipaddress.ip_address(ip).is_loopback})
    listen_ports = {p["port"] for p in ports}
    inbound, outbound = [], []
    for inode, (lip, lport, rip, rport) in est.items():
        if ipaddress.ip_address(rip).is_loopback:
            continue
        pid, name = who(inode)
        item = {"remote": rip, "rport": rport, "lport": lport, "pid": pid, "process": name}
        (inbound if lport in listen_ports else outbound).append(item)
    return sorted(ports, key=lambda x: x["port"]), inbound, outbound[:200]


def service_action(unit, action):
    if action not in ("start", "stop", "restart", "enable", "disable", "delete"):
        return 400, {"detail": "unknown action"}
    if not UNIT_RE.match(unit) or unit not in managed_units():
        return 404, {"detail": "unknown unit"}
    if action == "delete":
        if unit in PROTECTED or SCOPE != "user":
            return 409, {"detail": "이 서비스는 삭제할 수 없습니다."}
        ok, msg = hostsec.delete_user_unit(unit, Path.home() / ".config" / "systemd" / "user", systemctl)
        return (200, {"ok": True, "detail": msg}) if ok else (409, {"detail": msg})
    if action in ("stop", "disable") and unit in PROTECTED:
        return 409, {"detail": "에이전트 자신은 종료하거나 자동 실행을 끌 수 없습니다."}
    res = systemctl(action, unit) if action in ("enable", "disable") else systemctl("--no-block", action, unit)
    if res.returncode != 0:
        return 500, {"detail": res.stderr.strip()[:300] or "systemctl failed"}
    return 200, {"ok": True}


# ---------------------------------------------------------------- dashboard backups kept on this machine

BACKUP_DIR = Path(__file__).resolve().parent / "backups"
BACKUP_KEEP = 183  # daily backups → about 6 months
BACKUP_MAX = 500 * 1024 * 1024


def list_backups():
    if not BACKUP_DIR.is_dir():
        return []
    return [{"name": p.name, "size": p.stat().st_size, "ts": int(p.stat().st_mtime)}
            for p in sorted(BACKUP_DIR.iterdir()) if p.suffix in (".db", ".json")]


# ---------------------------------------------------------------- http

_bad: dict[str, list[float]] = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "server-agent"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        ip = self.client_address[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ALLOW and not any(addr in n for n in ALLOW):
            return False
        recent = [t for t in _bad.get(ip, []) if time.time() - t < 600]
        _bad[ip] = recent
        if len(recent) >= 5:
            return False
        token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if hmac.compare_digest(token.encode(), TOKEN.encode()):
            return True
        recent.append(time.time())
        print(f"bad token from {ip}", flush=True)
        return False

    def do_GET(self):
        if not self.authorized():
            return self.reply(403, {"detail": "forbidden"})
        if self.path == "/v1/status":
            up = float(read("/proc/uptime", "0").split()[0])
            return self.reply(200, {"version": VERSION, "host": socket.gethostname(),
                                    "os": os_name(),
                                    "kernel": os.uname().release, "uptime": up, "boot_time": time.time() - up,
                                    "cpu_count": os.cpu_count(), "now": sampler.latest, "services": services(),
                                    "scope": SCOPE, "host_facts": sampler.host, "home_du": sampler.du,
                                    "updates": sampler.updates, "backups": list_backups(),
                                    "integrity": sampler.integrity})
        m = re.fullmatch(r"/v1/logs/([A-Za-z0-9@._-]+\.service)(?:\?lines=(\d+))?", self.path)
        if m:  # this user's units come from the user journal, everything else from the system journal
            unit = m.group(1)
            text = hostsec.service_logs(unit, int(m.group(2) or 200), user=unit in managed_units())
            return self.reply(200, {"unit": unit, "log": text})
        self.reply(404, {"detail": "not found"})

    def do_POST(self):
        if not self.authorized():
            return self.reply(403, {"detail": "forbidden"})
        if self.path == "/v1/upgrade":  # fixed apt-get update+upgrade, run by the root sm-block service
            ok, msg = hostsec.request_upgrade()
            print(f"apt upgrade requested from {self.client_address[0]} -> {ok}", flush=True)
            return self.reply(200 if ok else 409, {"ok": True, "detail": msg} if ok else {"detail": msg})
        if self.path == "/v1/wake":  # relay a Wake-on-LAN packet onto this server's LAN
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if 0 < n <= 512 else {}
                sent = hostsec.wake(str(body.get("mac", "")))
            except ValueError as e:
                return self.reply(400, {"detail": str(e) if "MAC" in str(e) else "bad request"})
            return self.reply(200, {"ok": True, "sent": sent})
        b = re.fullmatch(r"/v1/backup/([a-z0-9-]+-\d{8}\.(?:db|json))", self.path)
        if b:  # dashboard backup copy (off-machine), sent over Tailscale
            n = int(self.headers.get("Content-Length") or 0)
            if not 0 < n <= BACKUP_MAX:
                return self.reply(413, {"detail": "too large"})
            BACKUP_DIR.mkdir(mode=0o700, exist_ok=True)
            tmp = BACKUP_DIR / (b.group(1) + ".part")
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
                left = n
                while left:
                    chunk = self.rfile.read(min(left, 1 << 20))
                    if not chunk:
                        break
                    f.write(chunk)
                    left -= len(chunk)
            if left:
                tmp.unlink(missing_ok=True)
                return self.reply(400, {"detail": "incomplete upload"})
            os.replace(tmp, BACKUP_DIR / b.group(1))
            prefix, ext = b.group(1).rsplit("-", 1)[0], b.group(1).rsplit(".", 1)[1]
            for old in sorted(BACKUP_DIR.glob(f"{prefix}-*.{ext}"))[:-BACKUP_KEEP]:
                old.unlink()
            print(f"backup {b.group(1)} ({n} bytes) from {self.client_address[0]}", flush=True)
            return self.reply(200, {"ok": True})
        if self.path in ("/v1/block", "/v1/unblock"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) if 0 < n <= 2048 else b"{}")
            except ValueError:
                return self.reply(400, {"detail": "bad json"})
            if self.path == "/v1/block":
                ok, out = hostsec.block(str(body.get("ip", "")), str(body.get("reason", "")))
            else:
                ok, out = hostsec.unblock(str(body.get("key", "")))
            print(f"{self.path} {body} from {self.client_address[0]} -> {ok}", flush=True)
            sampler.host["blocker"] = hostsec.blocked()
            return self.reply(200 if ok else 409, {"ok": True, "detail": out} if ok else {"detail": out or "실패"})
        pw = re.fullmatch(r"/v1/power/(reboot|poweroff)", self.path)
        if pw:
            code, data = power(pw.group(1))
            print(f"power {pw.group(1)} from {self.client_address[0]} -> {code}", flush=True)
            return self.reply(code, data)
        t = re.fullmatch(r"/v1/process/(\d+)/terminate", self.path)
        if t:
            pid = int(t.group(1))
            listen_pids = {p["pid"] for p in sampler.latest.get("ports", []) if p.get("pid")}
            if pid not in listen_pids or pid == os.getpid():
                return self.reply(403, {"detail": "이 프로세스는 종료할 수 없습니다."})
            try:
                os.kill(pid, 15)  # SIGTERM; the kernel only allows our own processes
            except PermissionError:
                return self.reply(403, {"detail": "다른 사용자의 프로세스입니다."})
            except ProcessLookupError:
                return self.reply(404, {"detail": "프로세스가 없습니다."})
            print(f"terminate pid {pid} from {self.client_address[0]}", flush=True)
            return self.reply(200, {"ok": True})
        m = re.fullmatch(r"/v1/services/([A-Za-z0-9@._-]+\.service)/([a-z]+)", self.path)
        if not m:
            return self.reply(404, {"detail": "not found"})
        code, data = service_action(m.group(1), m.group(2))
        print(f"action {m.group(2)} {m.group(1)} from {self.client_address[0]} -> {code}", flush=True)
        self.reply(code, data)


if __name__ == "__main__":
    sampler = Sampler()
    sampler.sample()
    time.sleep(1)
    sampler.sample()
    sampler.start()
    bind, port = cfg["bind"], int(cfg.get("port", 8101))
    ThreadingHTTPServer.address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    srv = ThreadingHTTPServer((bind, port), Handler)
    print(f"server-agent {VERSION} listening on {bind}:{port} (scope={SCOPE})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
