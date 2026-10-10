"""Local machine: metric sampler, backups/heartbeat, services, network, folder sizes."""

import asyncio
import ipaddress
import os
import platform
import signal
import socket
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

import psutil
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import security
from node_agent import hostsec
from core import confirm_password, country_of, raise_alert
from core import ACCESS_RETENTION, BASE, CPU_HOT, MEM_HOT, METRIC_RETENTION, PROTECTED_UNITS, SAMPLE_INTERVAL, SESSION_IDLE, SESSION_MAX, TEMP_HOT, UNIT_RE, USER_UNIT_DIR, _db, _db_lock, db, local_name, require_auth


router = APIRouter()

# ---------------------------------------------------------------- sampler


class Sampler:
    def __init__(self):
        self.latest: dict = {}
        self.top_procs: list = []
        self._net = psutil.net_io_counters()
        self._net_t = time.time()
        psutil.cpu_percent(percpu=True)
        for p in psutil.process_iter(["cpu_percent"]):
            pass

    @staticmethod
    def main_temp():
        try:
            temps = psutil.sensors_temperatures()
        except Exception:
            return None
        for key in ("coretemp", "k10temp", "zenpower"):
            if temps.get(key):
                pkg = [t.current for t in temps[key] if "Package" in (t.label or "") or "Tctl" in (t.label or "")]
                return pkg[0] if pkg else max(t.current for t in temps[key])
        allv = [t.current for v in temps.values() for t in v if t.current]
        return max(allv) if allv else None

    def sample(self):
        now = time.time()
        per_core = psutil.cpu_percent(percpu=True)
        cpu = sum(per_core) / len(per_core) if per_core else 0.0
        vm, sw = psutil.virtual_memory(), psutil.swap_memory()
        net = psutil.net_io_counters()
        dt = max(now - self._net_t, 0.001)
        rx = (net.bytes_recv - self._net.bytes_recv) / dt
        tx = (net.bytes_sent - self._net.bytes_sent) / dt
        self._net, self._net_t = net, now
        temp = self.main_temp()
        load1 = os.getloadavg()[0]
        disk = psutil.disk_usage("/").percent

        procs = []
        for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "cmdline"]):
            i = p.info
            procs.append({"pid": i["pid"], "name": i["name"], "user": i["username"],
                          "cpu": round(i["cpu_percent"] or 0, 1),
                          "mem": round(i["memory_percent"] or 0, 1),
                          "cmd": " ".join(i["cmdline"] or [])[:160]})
        procs.sort(key=lambda x: (x["cpu"], x["mem"]), reverse=True)
        self.top_procs = procs[:12]

        self.latest = {"ts": int(now), "cpu": round(cpu, 1), "per_core": per_core,
                       "mem": vm.percent, "mem_used": vm.used, "mem_total": vm.total,
                       "swap": sw.percent, "swap_used": sw.used, "swap_total": sw.total,
                       "temp": temp, "load": os.getloadavg(), "disk": disk,
                       "net_rx": rx, "net_tx": tx}
        db("INSERT OR REPLACE INTO metrics VALUES(?,?,?,?,?,?,?,?,?)",
           (int(now), cpu, vm.percent, sw.percent, temp, load1, disk, rx, tx))


sampler = Sampler()


def prune():
    now = int(time.time())
    db("DELETE FROM metrics WHERE ts < ?", (now - 48 * 3600,))  # 24h shown; 48h kept so a late daily report has data
    db("DELETE FROM access_log WHERE ts < ?", (now - ACCESS_RETENTION,))
    db("DELETE FROM sessions WHERE last_seen < ? OR created < ?", (now - SESSION_IDLE, now - SESSION_MAX))
    db("DELETE FROM alerts WHERE ts < ?", (now - ACCESS_RETENTION,))


BACKUP_DIR = BASE / "data" / "backups"
AFTER_BACKUP: list = []  # async callables run hourly after backup_db (routes_nodes registers the off-site copy)
BACKUP_KEEP = 183  # daily backups → about 6 months
HEARTBEAT_URL = os.environ.get("SM_HEARTBEAT_URL", "").strip()


def backup_db():
    """One consistent copy per day (sqlite online backup) + config.json; the oldest beyond BACKUP_KEEP (~6 months) are removed.
    shortcut: copies stay on this disk, so they cover mistakes/corruption, not disk death — copy them
    to another server once one is added."""
    BACKUP_DIR.mkdir(mode=0o700, exist_ok=True)
    day = time.strftime("%Y%m%d")
    dst = BACKUP_DIR / f"monitor-{day}.db"
    if dst.exists():
        return
    tmp = dst.with_suffix(".tmp")
    out = sqlite3.connect(tmp)
    with _db_lock:
        _db.backup(out)
    out.close()
    os.chmod(tmp, 0o600)
    os.replace(tmp, dst)
    cfg_copy = BACKUP_DIR / f"config-{day}.json"
    cfg_copy.write_bytes(security.CONFIG_PATH.read_bytes())
    os.chmod(cfg_copy, 0o600)
    for pattern in ("monitor-*.db", "config-*.json"):
        for old in sorted(BACKUP_DIR.glob(pattern))[:-BACKUP_KEEP]:
            old.unlink()


def heartbeat():
    """Outbound-only ping (e.g. healthchecks.io): if it stops arriving, that service alerts you that
    this whole machine is down — the one case the dashboard can't report itself. Sends no data."""
    if HEARTBEAT_URL.startswith("https://"):
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(HEARTBEAT_URL, headers={"User-Agent": "server-monitor"}),
                               timeout=10).read(64)


async def sampler_loop():
    last_prune = last_beat = 0.0
    while True:
        try:
            await asyncio.to_thread(sampler.sample)
            if time.time() - last_prune > 3600:
                await asyncio.to_thread(prune)
                await asyncio.to_thread(backup_db)
                last_prune = time.time()
                for hook in AFTER_BACKUP:  # e.g. copy the newest backup to other servers
                    try:
                        await hook()
                    except Exception as e:
                        print("backup hook error:", type(e).__name__, e, flush=True)
            if HEARTBEAT_URL and time.time() - last_beat > 300:
                last_beat = time.time()
                await asyncio.to_thread(heartbeat)
        except Exception as e:  # keep sampling even if one round fails
            print("sampler error:", e, flush=True)
        await asyncio.sleep(SAMPLE_INTERVAL)

# ---------------------------------------------------------------- monitoring


def status_data():
    temps = []
    try:
        for chip, entries in psutil.sensors_temperatures().items():
            for t in entries:
                sane = lambda v: v if v and 0 < v < 200 else None  # some drivers report 65262°C
                temps.append({"chip": chip, "label": t.label or chip, "current": t.current,
                              "high": sane(t.high), "critical": sane(t.critical)})
    except Exception:
        pass
    disks = []
    for part in psutil.disk_partitions():
        if part.fstype in ("squashfs", "tmpfs", "overlay") or part.mountpoint.startswith("/snap"):
            continue
        try:
            u = psutil.disk_usage(part.mountpoint)
            disks.append({"mount": part.mountpoint, "total": u.total, "used": u.used, "percent": u.percent})
        except OSError:
            pass
    freq = psutil.cpu_freq()
    boot = psutil.boot_time()
    return {"host": socket.gethostname(), "name": local_name(), "os": platform.platform(), "boot_time": boot,
            "uptime": time.time() - boot, "cpu_count": psutil.cpu_count(),
            "cpu_freq": freq.current if freq else None,
            "now": sampler.latest, "temps": temps, "disks": disks, "top": sampler.top_procs}




@router.get("/api/status")
def status(request: Request):
    require_auth(request)
    return status_data()
@router.get("/api/metrics")
def metrics(request: Request, hours: float = 24):
    require_auth(request)
    hours = min(max(hours, 0.25), 24)
    since = int(time.time() - hours * 3600)
    bucket = max(SAMPLE_INTERVAL, int(hours * 3600 / 720))
    rows = db("SELECT (ts/?)*? t, AVG(cpu) cpu, MAX(cpu) cpu_max, AVG(mem) mem, AVG(temp) temp, MAX(temp) temp_max, "
              "AVG(load1) load1, AVG(net_rx) rx, AVG(net_tx) tx FROM metrics WHERE ts>=? GROUP BY t ORDER BY t",
              (bucket, bucket, since))
    return {"bucket": bucket, "points": [dict(r) for r in rows]}


def load_events_data():
    """Contiguous periods in the last 24h where CPU/memory/temperature crossed the hot thresholds."""
    rows = db("SELECT ts,cpu,mem,temp FROM metrics WHERE ts>=? ORDER BY ts", (int(time.time()) - METRIC_RETENTION,))
    events, cur = [], None
    for r in rows:
        reasons = [k for k, v, lim in (("CPU", r["cpu"], CPU_HOT), ("메모리", r["mem"], MEM_HOT),
                                       ("온도", r["temp"], TEMP_HOT)) if v is not None and v >= lim]
        if reasons:
            if cur and r["ts"] - cur["end"] <= SAMPLE_INTERVAL * 6:
                cur["end"] = r["ts"]
                cur["reasons"] |= set(reasons)
                cur["cpu_max"] = max(cur["cpu_max"], r["cpu"] or 0)
                cur["mem_max"] = max(cur["mem_max"], r["mem"] or 0)
                cur["temp_max"] = max(cur["temp_max"], r["temp"] or 0)
            else:
                cur = {"start": r["ts"], "end": r["ts"], "reasons": set(reasons),
                       "cpu_max": r["cpu"] or 0, "mem_max": r["mem"] or 0, "temp_max": r["temp"] or 0}
                events.append(cur)
    for e in events:
        e["reasons"] = sorted(e["reasons"])
    peaks = db("SELECT (SELECT ts FROM metrics WHERE ts>=?1 ORDER BY cpu DESC LIMIT 1) cpu_ts, "
               "(SELECT MAX(cpu) FROM metrics WHERE ts>=?1) cpu, "
               "(SELECT ts FROM metrics WHERE ts>=?1 ORDER BY mem DESC LIMIT 1) mem_ts, "
               "(SELECT MAX(mem) FROM metrics WHERE ts>=?1) mem, "
               "(SELECT ts FROM metrics WHERE ts>=?1 AND temp IS NOT NULL ORDER BY temp DESC LIMIT 1) temp_ts, "
               "(SELECT MAX(temp) FROM metrics WHERE ts>=?1) temp",
               (int(time.time()) - METRIC_RETENTION,), one=True)
    return {"thresholds": {"cpu": CPU_HOT, "mem": MEM_HOT, "temp": TEMP_HOT},
            "events": list(reversed(events))[:100], "peaks": dict(peaks) if peaks else {}}



@router.get("/api/metrics/events")
def load_events(request: Request):
    require_auth(request)
    return load_events_data()
# ---------------------------------------------------------------- services & processes


def _systemctl(*args, timeout=10):
    env = dict(os.environ, XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}")
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=timeout, env=env)


def managed_units() -> list[str]:
    if not USER_UNIT_DIR.is_dir():
        return []
    return sorted(p.name for p in USER_UNIT_DIR.glob("*.service") if p.is_file() and UNIT_RE.match(p.name))


def services_data():
    units = managed_units()
    out = []
    if units:
        props = "Id,Description,ActiveState,SubState,MainPID,ActiveEnterTimestamp,UnitFileState,NRestarts"
        res = _systemctl("show", *units, "-p", props, "--timestamp=unix")
        for block in res.stdout.strip().split("\n\n"):
            d = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            pid = int(d.get("MainPID") or 0)
            cpu = mem = None
            if pid:
                try:
                    p = psutil.Process(pid)
                    rss = p.memory_info().rss
                    for c in p.children(recursive=True):
                        try:
                            rss += c.memory_info().rss
                        except psutil.Error:
                            pass
                    mem = rss
                    cpu = p.cpu_percent(interval=None)
                except psutil.Error:
                    pass
            out.append({"unit": d.get("Id"), "description": d.get("Description"),
                        "active": d.get("ActiveState"), "sub": d.get("SubState"), "pid": pid or None,
                        "since": int(d["ActiveEnterTimestamp"][1:]) if d.get("ActiveEnterTimestamp", "").startswith("@") else None,
                        "enabled": d.get("UnitFileState"),
                        "restarts": d.get("NRestarts"), "mem": mem, "cpu": cpu,
                        "protected": d.get("Id") in PROTECTED_UNITS})
    try:
        linger = subprocess.run(["loginctl", "show-user", str(os.getuid()), "-p", "Linger", "--value"],
                                capture_output=True, text=True, timeout=5).stdout.strip() == "yes"
    except (OSError, subprocess.SubprocessError):
        linger = None
    return {"services": out, "linger": linger}




@router.get("/api/services")
def services(request: Request):
    require_auth(request)
    return services_data()
@router.post("/api/services/{unit}/{action}")
def service_action(request: Request, unit: str, action: str):
    require_auth(request)
    if action not in ("start", "stop", "restart", "enable", "disable", "delete"):
        raise HTTPException(400, "unknown action")
    if not UNIT_RE.match(unit) or unit not in managed_units():
        raise HTTPException(404, "unknown unit")
    if action == "delete":
        if unit in PROTECTED_UNITS:
            raise HTTPException(409, "이 서비스는 대시보드에 필요해서 삭제할 수 없습니다.")
        request.state.event, request.state.detail = "action", f"delete {unit}"
        ok, msg = hostsec.delete_user_unit(unit, USER_UNIT_DIR, _systemctl)
        if not ok:
            raise HTTPException(409, msg)
        return {"ok": True, "detail": msg}
    if action == "stop" and unit in PROTECTED_UNITS:
        raise HTTPException(409, "이 서비스는 대시보드 접속에 필요해서 종료할 수 없습니다 (재시작만 가능).")
    if action == "disable" and unit in PROTECTED_UNITS:
        raise HTTPException(409, "이 서비스는 대시보드 접속에 필요해서 부팅 시 자동 실행을 끌 수 없습니다.")
    request.state.event = "action"
    request.state.detail = f"{action} {unit}"
    if action in ("enable", "disable"):
        # Only toggles start-at-boot; does not start/stop the service right now.
        res = _systemctl(action, unit)
    else:
        # --no-block: restarting ourselves must not wait on our own death.
        res = _systemctl("--no-block", action, unit)
    if res.returncode != 0:
        raise HTTPException(500, res.stderr.strip()[:300] or "systemctl failed")
    return {"ok": True}


def _protected_pids() -> set[int]:
    pids = {os.getpid()}
    for u in PROTECTED_UNITS:
        try:
            pid = int(_systemctl("show", u, "-p", "MainPID", "--value").stdout.strip() or 0)
            if pid:
                pids.add(pid)
        except (ValueError, subprocess.SubprocessError):
            pass
    return pids


@router.get("/api/network")
def network(request: Request):
    require_auth(request)
    conns = psutil.net_connections(kind="inet")
    names: dict[int, str] = {}

    def pname(pid):
        if not pid:
            return None
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except psutil.Error:
                names[pid] = None
        return names[pid]

    my_uid = os.getuid()
    protected = _protected_pids()
    listening, seen = [], set()
    listen_ports = set()
    for c in conns:
        if c.status == psutil.CONN_LISTEN:
            listen_ports.add(c.laddr.port)
            key = (c.laddr.ip, c.laddr.port)
            if key in seen:
                continue
            seen.add(key)
            killable, cwd = False, None
            if c.pid:
                try:
                    proc = psutil.Process(c.pid)
                    cwd = proc.cwd()
                    killable = c.pid not in protected and proc.uids().real == my_uid
                except psutil.Error:  # other users' processes: no access without root
                    pass
            listening.append({"ip": c.laddr.ip, "port": c.laddr.port, "pid": c.pid, "process": pname(c.pid),
                              "cwd": cwd, "public": not ipaddress.ip_address(c.laddr.ip.split("%")[0]).is_loopback,
                              "killable": killable})
    listening.sort(key=lambda x: x["port"])

    inbound, outbound = [], []
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        rip = ipaddress.ip_address(c.raddr.ip.split("%")[0])
        if rip.is_loopback:
            continue
        item = {"remote": c.raddr.ip, "rport": c.raddr.port, "lport": c.laddr.port,
                "pid": c.pid, "process": pname(c.pid)}
        (inbound if c.laddr.port in listen_ports else outbound).append(item)

    users = [{"name": u.name, "terminal": u.terminal, "host": u.host, "started": u.started}
             for u in psutil.users()]
    return {"listening": listening, "inbound": inbound, "outbound": outbound[:200], "users": users}


@router.post("/api/process/{pid}/terminate")
def terminate(request: Request, pid: int):
    require_auth(request)
    listen_pids = {c.pid for c in psutil.net_connections(kind="inet") if c.status == psutil.CONN_LISTEN}
    if pid not in listen_pids or pid in _protected_pids():
        raise HTTPException(403, "이 프로세스는 종료할 수 없습니다.")
    try:
        p = psutil.Process(pid)
        if p.uids().real != os.getuid():
            raise HTTPException(403, "다른 사용자의 프로세스입니다.")
        request.state.event = "action"
        request.state.detail = f"terminate pid {pid} ({p.name()})"
        p.send_signal(signal.SIGTERM)
    except psutil.NoSuchProcess:
        raise HTTPException(404, "프로세스가 없습니다.")
    return {"ok": True}


# ---------------------------------------------------------------- folder sizes under /home

_home_du = {"ts": 0, "running": False, "dirs": [], "total": None, "error": None}


def _compute_home_du():
    """du is slow on big trees: run it at idle CPU/IO priority in a thread and cache for an hour."""
    try:
        home = Path.home()
        # one pass: every top-level folder plus the total (du never counts a directory twice)
        res = subprocess.run(["nice", "-n", "19", "ionice", "-c3", "du", "-xB1", "--max-depth=1", str(home)],
                             capture_output=True, text=True, timeout=600)
        sizes = {}
        for line in res.stdout.splitlines():
            size, _, path = line.partition("\t")
            if size.isdigit():
                sizes[path] = int(size)
        total = sizes.pop(str(home), None)
        _home_du.update(dirs=sorted(({"path": p.replace(str(home), "~", 1), "size": v} for p, v in sizes.items()),
                                    key=lambda d: -d["size"]),
                        total=total, ts=int(time.time()), error=None)
    except (OSError, subprocess.SubprocessError) as e:
        _home_du["error"] = type(e).__name__
    finally:
        _home_du["running"] = False


def _start_home_du():
    if not _home_du["running"]:
        _home_du["running"] = True
        threading.Thread(target=_compute_home_du, daemon=True).start()


@router.get("/api/disk/home")
def disk_home(request: Request):
    require_auth(request)
    if time.time() - _home_du["ts"] > 3600:
        _start_home_du()
    return {**_home_du, "home": str(Path.home()), "disk": psutil.disk_usage(str(Path.home()))._asdict()}


@router.post("/api/disk/home/refresh")
def disk_home_refresh(request: Request):
    require_auth(request)
    _start_home_du()
    return {"ok": True}


# ---------------------------------------------------------------- machine power (reboot / power off)

POWER_LABEL = {"reboot": "재부팅", "poweroff": "종료"}


class PowerBody(BaseModel):
    action: str = Field(pattern="^(reboot|poweroff)$")
    password: str = Field(max_length=256)
    confirm: str = Field(max_length=40)


def power_state() -> dict:
    """logind's answer for this user: "yes", or "challenge" until allow-power.sh has been run once."""
    out = {}
    for key, method in (("reboot", "CanReboot"), ("poweroff", "CanPowerOff")):
        try:
            r = subprocess.run(["busctl", "call", "org.freedesktop.login1", "/org/freedesktop/login1",
                                "org.freedesktop.login1.Manager", method], capture_output=True, text=True, timeout=5)
            out[key] = r.stdout.split('"')[1] if '"' in r.stdout else "unknown"
        except (OSError, subprocess.SubprocessError):
            out[key] = "unknown"
    return out


@router.get("/api/power")
def power_get(request: Request):
    require_auth(request)
    return {"name": local_name(), **power_state()}


@router.post("/api/power")
def power_post(request: Request, body: PowerBody):
    require_auth(request)
    if power_state().get(body.action) != "yes":
        raise HTTPException(409, "먼저 이 서버에서 한 번 실행하세요: sudo bash ~/server-monitor/node_agent/allow-power.sh")
    if body.confirm.strip() != local_name():
        raise HTTPException(400, "서버 이름이 일치하지 않습니다.")
    if not confirm_password(request, body.password):
        raise HTTPException(403, "비밀번호가 틀렸습니다.")
    label = POWER_LABEL[body.action]
    request.state.event, request.state.detail = "action", f"power {body.action} (this server)"
    raise_alert("power", request.state.ip, country_of(request), f"이 서버({local_name()}) {label} 실행", push=True)
    # reply first, act 2s later: the browser gets an answer before this process goes down
    threading.Timer(2, lambda: subprocess.run(["systemctl", body.action])).start()
    return {"ok": True}


# ---------------------------------------------------------------- firewall block list (sm-block)


class KeyBody(BaseModel):
    key: str = Field(min_length=3, max_length=64)


@router.get("/api/hostblock")
def hostblock_list(request: Request):
    require_auth(request)
    lst = hostsec.blocked()
    return {"installed": lst is not None, "blocked": lst or []}


@router.post("/api/hostblock/remove")
def hostblock_remove(request: Request, body: KeyBody):
    require_auth(request)
    ok, msg = hostsec.unblock(body.key)
    request.state.event, request.state.detail = "action", f"firewall unblock {body.key}"
    if not ok:
        raise HTTPException(409, msg)
    return {"ok": True, "detail": msg}


# ---------------------------------------------------------------- service logs, apt status


@router.get("/api/services/{unit}/logs")
def service_logs(request: Request, unit: str, lines: int = 200):
    require_auth(request)
    if not UNIT_RE.match(unit) or unit not in managed_units():
        raise HTTPException(404, "unknown unit")
    return {"unit": unit, "log": hostsec.service_logs(unit, lines, user=True)}


_updates: dict = {"data": None, "t": 0.0}


def updates_cached():
    """apt state, refreshed in the background at most hourly (apt list takes a moment)."""
    if time.time() - _updates["t"] > 3600:
        _updates["t"] = time.time()
        threading.Thread(target=lambda: _updates.update(data=hostsec.update_status()), daemon=True).start()
    return _updates["data"]


REMOTE_BACKUPS: dict = {}  # node id -> {"ts", "ok", "name", "error"}, filled by routes_nodes


@router.get("/api/hoststatus")
def hoststatus(request: Request):
    require_auth(request)
    local = sorted((p.name for p in BACKUP_DIR.glob("monitor-*.db")), reverse=True) if BACKUP_DIR.is_dir() else []
    return {"updates": updates_cached(), "backups": {"local": local, "remote": REMOTE_BACKUPS}}
