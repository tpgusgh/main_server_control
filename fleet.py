"""Fleet management for the central server: uptime ledger, disk-full forecast, config-change detection,
Wake-on-LAN, apt upgrades, agent version check."""
import asyncio
import json
import re
import time
from datetime import datetime, timedelta

import httpx
import psutil
from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

import monitor
from agent import TZ
from core import confirm_password, db, local_name, raise_alert, require_auth
from node_agent import hostsec
from routes_nodes import hub

router = APIRouter()
MAIN = "main"
TICK = 60
DISK_KEEP = 60 * 86400
FORECAST_DAYS, FULL_AT, WARN_DAYS = 14, 95.0, 14
AGENT_LATEST = re.search(r'VERSION = "([\d.]+)"', (monitor.BASE / "node_agent" / "server_agent.py").read_text()).group(1)
ON_INTEGRITY: list = []  # callbacks(server_key, server_name, changes) — the AI investigator subscribes

db("""CREATE TABLE IF NOT EXISTS uptime_daily(
      day TEXT, server TEXT, up INTEGER DEFAULT 0, known INTEGER DEFAULT 0, outages INTEGER DEFAULT 0,
      longest INTEGER DEFAULT 0, PRIMARY KEY(day, server))""")
db("CREATE TABLE IF NOT EXISTS disk_hist(server TEXT, ts INTEGER, pct REAL, PRIMARY KEY(server, ts))")
db("CREATE TABLE IF NOT EXISTS integrity(server TEXT PRIMARY KEY, ts INTEGER, snap TEXT)")
db("""CREATE TABLE IF NOT EXISTS integrity_changes(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, server TEXT, name TEXT, changes TEXT)""")
db("CREATE TABLE IF NOT EXISTS fleet_kv(k TEXT PRIMARY KEY, v TEXT)")
db("CREATE TABLE IF NOT EXISTS power_daily(day TEXT, server TEXT, wh REAL DEFAULT 0, minutes INTEGER DEFAULT 0, "
   "PRIMARY KEY(day, server))")
db("""CREATE TABLE IF NOT EXISTS power_jobs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, server TEXT, kind TEXT, hhmm TEXT, weekday INTEGER, next_ts INTEGER,
      warned INTEGER DEFAULT 0, created INTEGER, last_run INTEGER, last_result TEXT)""")
if "macs" not in {r[1] for r in db("PRAGMA table_info(nodes)")}:
    db("ALTER TABLE nodes ADD COLUMN macs TEXT DEFAULT ''")


def _kv(k, v=None):
    if v is None:
        r = db("SELECT v FROM fleet_kv WHERE k=?", (k,), one=True)
        return r["v"] if r else None
    db("INSERT OR REPLACE INTO fleet_kv VALUES(?,?)", (k, str(v)))


def _today() -> str:
    return datetime.now(TZ).strftime("%Y-%m-%d")


def _add(server, up=0, known=0, outages=0, longest=0, day=None):
    day = day or _today()
    db("INSERT OR IGNORE INTO uptime_daily(day, server) VALUES(?,?)", (day, server))
    db("UPDATE uptime_daily SET up=up+?, known=known+?, outages=outages+?, longest=MAX(longest, ?) "
       "WHERE day=? AND server=?", (up, known, outages, longest, day, server))


def server_names() -> dict:
    return {MAIN: local_name(), **{f"node:{n['id']}": n["name"] for n in hub.nodes()}}


def version_lt(a: str | None, b: str) -> bool:
    try:
        return tuple(map(int, (a or "0").split("."))) < tuple(map(int, b.split(".")))
    except ValueError:
        return True


# ---------------------------------------------------------------- uptime

class Ledger:
    def __init__(self):
        self.down_since: dict[str, int] = {}
        self.prev: dict[str, bool] = {}

    def start(self):
        """A gap in the dashboard's own heartbeat = this server was down (or the dashboard was)."""
        now, last = int(time.time()), int(_kv("beat") or 0)
        if not _kv("since"):
            _kv("since", now)  # the ledger's birth: uptime before this is unknown, not "down"
        if last and now - last > 3 * TICK:
            _add(MAIN, outages=1, longest=now - last)
        _kv("beat", now)

    def tick(self):
        now = int(time.time())
        _kv("beat", now)
        _add(MAIN, up=TICK, known=TICK)
        for n in hub.nodes():
            key, st = f"node:{n['id']}", hub.state.get(n["id"]) or {}
            online = st.get("online")
            if online is None:
                continue
            _add(key, up=TICK if online else 0, known=TICK)
            if self.prev.get(key) is True and online is False:
                self.down_since[key] = now
                _add(key, outages=1)
            elif online and key in self.down_since:
                _add(key, longest=now - self.down_since.pop(key))
            self.prev[key] = online


def check_boots():
    """Boot time moved → the server rebooted (also catches reboots too quick to look 'offline')."""
    cur = {MAIN: (local_name(), psutil.boot_time())}
    for n in hub.nodes():
        st = hub.state.get(n["id"]) or {}
        if st.get("online") and (st.get("data") or {}).get("boot_time"):
            cur[f"node:{n['id']}"] = (n["name"], st["data"]["boot_time"])
    for key, (name, boot) in cur.items():
        prev = _kv(f"boot:{key}")
        if prev is not None and abs(float(prev) - boot) <= 120:  # agents compute boot time from uptime: allow jitter
            continue
        _kv(f"boot:{key}", boot)
        if prev is not None:
            raise_alert("reboot", "", "", f"서버 '{name}' 재부팅 완료 · {datetime.fromtimestamp(boot, TZ):%m-%d %H:%M} 부팅, "
                                          "다시 정상 연결됨")


def uptime(month: str) -> list[dict]:
    """month 'YYYY-MM'. The central server is measured against wall-clock time; the others against the
    time the central server could see them (while it was down itself, nothing is known)."""
    names = server_names()
    first = datetime.strptime(month + "-01", "%Y-%m-%d").replace(tzinfo=TZ)
    nxt = (first + timedelta(days=32)).replace(day=1)
    since = int(_kv("since") or time.time())
    rows = db("SELECT server, SUM(up) up, SUM(known) known, SUM(outages) outages, MAX(longest) longest "
              "FROM uptime_daily WHERE day LIKE ? GROUP BY server", (month + "-%",))
    out = []
    for r in rows:
        if r["server"] not in names:
            continue
        if r["server"] == MAIN:  # wall clock since the ledger started (or the 1st), so gaps count as down
            base = max(1, int(min(time.time(), nxt.timestamp()) - max(first.timestamp(), since)))
        else:
            base = max(r["known"], 1)
        out.append({"server": r["server"], "name": names[r["server"]], "pct": round(min(100, r["up"] / base * 100), 2),
                    "outages": r["outages"], "longest": r["longest"], "measured_h": round(base / 3600, 1)})
    return sorted(out, key=lambda x: (x["server"] != MAIN, x["name"]))


# ---------------------------------------------------------------- disk forecast

def record_disk():
    now = int(time.time())
    try:
        db("INSERT OR REPLACE INTO disk_hist VALUES(?,?,?)", (MAIN, now, psutil.disk_usage("/").percent))
    except OSError:
        pass
    for n in hub.nodes():
        d = ((hub.state.get(n["id"]) or {}).get("data") or {}).get("now") or {}
        if d.get("disk") is not None:
            db("INSERT OR REPLACE INTO disk_hist VALUES(?,?,?)", (f"node:{n['id']}", now, d["disk"]))
    db("DELETE FROM disk_hist WHERE ts < ?", (now - DISK_KEEP,))


def fit(points: list[tuple[int, float]]) -> dict | None:
    """Least-squares line through (ts, pct). None until there's a day of hourly data."""
    if len(points) < 12 or points[-1][0] - points[0][0] < 86400:
        return None
    n = len(points)
    mx = sum(t for t, _ in points) / n
    my = sum(p for _, p in points) / n
    var = sum((t - mx) ** 2 for t, _ in points)
    slope = sum((t - mx) * (p - my) for t, p in points) / var * 86400 if var else 0.0  # % per day
    last = points[-1][1]
    days = (FULL_AT - last) / slope if slope > 0.02 else None  # under 0.02%/day: effectively flat
    return {"now": round(last, 1), "per_day": round(slope, 3), "days_left": None if days is None else max(0.0, round(days, 1))}


def forecasts() -> list[dict]:
    since = int(time.time()) - FORECAST_DAYS * 86400
    out = []
    for key, name in server_names().items():
        pts = [(r["ts"], r["pct"]) for r in db("SELECT ts, pct FROM disk_hist WHERE server=? AND ts>=? ORDER BY ts",
                                               (key, since))]
        f = fit(pts) or {"now": pts[-1][1] if pts else None, "per_day": None, "days_left": None, "collecting": True}
        out.append({"server": key, "name": name, **f})
    return out


# ---------------------------------------------------------------- config-change detection

def check_integrity(key: str, name: str, snap: dict | None) -> list[str]:
    if not snap:
        return []
    row = db("SELECT snap FROM integrity WHERE server=?", (key,), one=True)
    db("INSERT OR REPLACE INTO integrity VALUES(?,?,?)", (key, int(time.time()), json.dumps(snap)))
    if not row:
        return []  # first snapshot = baseline
    changes = hostsec.integrity_diff(json.loads(row["snap"]), snap)
    if changes:
        db("INSERT INTO integrity_changes(ts, server, name, changes) VALUES(?,?,?,?)",
           (int(time.time()), key, name, json.dumps(changes, ensure_ascii=False)))
        db("DELETE FROM integrity_changes WHERE ts < ?", (int(time.time()) - 183 * 86400,))
        raise_alert("config_change", "", "", f"서버 '{name}' 설정 변경 감지:\n" + "\n".join(changes)[:600])
        for cb in ON_INTEGRITY:
            cb(key, name, changes)
    return changes


def integrity_all():
    check_integrity(MAIN, local_name(), hostsec.integrity_snapshot())
    for n in hub.nodes():
        data = (hub.state.get(n["id"]) or {}).get("data") or {}
        check_integrity(f"node:{n['id']}", n["name"], data.get("integrity"))


def remember_macs():
    for n in hub.nodes():
        macs = (((hub.state.get(n["id"]) or {}).get("data") or {}).get("host_facts") or {}).get("macs")
        if macs:
            db("UPDATE nodes SET macs=? WHERE id=?", (json.dumps(macs), n["id"]))


# ---------------------------------------------------------------- exposure: tunnels without Access

def all_tunnels() -> list[dict]:
    out = [{**t, "server": local_name()} for t in hostsec.tunnel_hosts()]
    for n in hub.nodes():
        snap = ((hub.state.get(n["id"]) or {}).get("data") or {}).get("integrity") or {}
        for line in snap.get("tunnels") or []:
            host, _, svc = line.partition(" → ")
            out.append({"host": host, "service": svc, "server": n["name"]})
    return out


async def probe(host: str) -> dict:
    """Unauthenticated request, no redirects: Access answers with a redirect to <team>.cloudflareaccess.com."""
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
            r = await c.get(f"https://{host}/")
        loc = r.headers.get("location", "")
        protected = (300 <= r.status_code < 400 and ".cloudflareaccess.com/" in loc) or "cf-access" in loc.lower()
        return {"state": "access" if protected else "public", "code": r.status_code}
    except httpx.HTTPError as e:
        return {"state": "error", "code": None, "error": type(e).__name__}


async def check_tunnels():
    allowed = set(json.loads(_kv("public_ok") or "[]"))
    prev = {t["host"]: t for t in json.loads(_kv("tunnels") or "[]")}
    out = []
    for t in await asyncio.to_thread(all_tunnels):
        res = await probe(t["host"])
        out.append({**t, **res, "checked": int(time.time())})
        was = prev.get(t["host"], {}).get("state")
        if res["state"] == "public" and was != "public" and t["host"] not in allowed:
            await asyncio.to_thread(raise_alert, "exposure", "", "",
                                    f"{t['host']} ({t['server']} → {t['service']}) 이(가) Cloudflare Access 로그인 없이 "
                                    f"인터넷에 공개돼 있습니다 (HTTP {res['code']}). 카메라·관리 화면이면 Zero Trust → Access 에 "
                                    "이 주소를 추가하세요. 일부러 공개한 거면 보안 탭에서 '공개 허용'을 누르세요.")
    _kv("tunnels", json.dumps(out))
    return out


# ---------------------------------------------------------------- energy estimate (no power meter: CPU-based model)

DEFAULT_W = {"idle": 8.0, "max": 35.0}  # whole-machine watts at 0% / 100% CPU (laptop-class box); editable per server
# 원/kWh. shortcut: one flat marginal rate (주택용 누진 2구간 + 기후환경·연료비 + 부가세·기금 ≈ 260), edit to your bill
DEFAULT_PRICE = 260


def power_cfg() -> dict:
    return {"price": DEFAULT_PRICE, "servers": {}, **json.loads(_kv("power_cfg") or "{}")}


def watts(cpu: float, prof: dict) -> float:
    p = {**DEFAULT_W, **(prof or {})}
    return p["idle"] + (p["max"] - p["idle"]) * min(max(cpu, 0.0), 100.0) / 100


def cpu_last_minute() -> dict:
    """Average CPU of the last minute per server; servers with no samples (off/unreachable) are left out."""
    since = int(time.time()) - TICK
    out = {}
    r = db("SELECT AVG(cpu) c FROM metrics WHERE ts>=?", (since,), one=True)
    if r and r["c"] is not None:
        out[MAIN] = r["c"]
    for n in hub.nodes():
        r = db("SELECT AVG(cpu) c FROM node_metrics WHERE node_id=? AND ts>=?", (n["id"], since), one=True)
        if r and r["c"] is not None:
            out[f"node:{n['id']}"] = r["c"]
    return out


def energy_tick():
    cfg, day = power_cfg(), _today()
    for key, cpu in cpu_last_minute().items():
        db("INSERT OR IGNORE INTO power_daily(day, server) VALUES(?,?)", (day, key))
        db("UPDATE power_daily SET wh=wh+?, minutes=minutes+1 WHERE day=? AND server=?",
           (watts(cpu, cfg["servers"].get(key)) * TICK / 3600, day, key))
    db("DELETE FROM power_daily WHERE day < ?", ((datetime.now(TZ) - timedelta(days=400)).strftime("%Y-%m-%d"),))


def energy_view() -> dict:
    cfg, now = power_cfg(), datetime.now(TZ)
    month, today = now.strftime("%Y-%m"), _today()
    days_in_month = ((now.replace(day=1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)).day
    cpu = cpu_last_minute()
    rows = []
    for key, name in server_names().items():
        m = db("SELECT COALESCE(SUM(wh),0) wh, COALESCE(SUM(minutes),0) mins FROM power_daily WHERE server=? AND day LIKE ?",
               (key, month + "-%"), one=True)
        t = db("SELECT wh FROM power_daily WHERE server=? AND day=?", (key, today), one=True)
        prof = {**DEFAULT_W, **cfg["servers"].get(key, {})}
        avg_w = m["wh"] / (m["mins"] / 60) if m["mins"] else None
        month_kwh = m["wh"] / 1000
        rows.append({"server": key, "name": name, "idle": prof["idle"], "max": prof["max"],
                     "watts_now": round(watts(cpu[key], prof), 1) if key in cpu else None,
                     "avg_w": round(avg_w, 1) if avg_w else None,
                     "today_kwh": round((t["wh"] if t else 0) / 1000, 3), "month_kwh": round(month_kwh, 2),
                     "month_won": round(month_kwh * cfg["price"]),
                     # a full month at the average draw so far (assumes it stays on 24h)
                     "projected_won": round(avg_w * 24 * days_in_month / 1000 * cfg["price"]) if avg_w else None})
    return {"price": cfg["price"], "month": month, "rows": rows,
            "total_month_won": sum(r["month_won"] for r in rows),
            "total_projected_won": sum(r["projected_won"] or 0 for r in rows)}


# ---------------------------------------------------------------- scheduled reboots

def next_run(kind: str, hhmm: str, weekday: int | None = None, date: str | None = None, now: datetime | None = None):
    """Next KST run time (unix) for a job; None when a one-off date/time is already past."""
    now = now or datetime.now(TZ)
    h, m = map(int, hhmm.split(":"))
    if kind == "once":
        t = datetime.strptime(date, "%Y-%m-%d").replace(hour=h, minute=m, tzinfo=TZ)
        return int(t.timestamp()) if t > now else None
    t = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if kind == "weekly":
        t += timedelta(days=(weekday - t.weekday()) % 7)
    while t <= now:
        t += timedelta(days=7 if kind == "weekly" else 1)
    return int(t.timestamp())


async def reboot_server(key: str) -> tuple[bool, str]:
    if key == MAIN:
        if monitor.power_state().get("reboot") != "yes":
            return False, "재부팅 권한 없음 — 이 서버에서 한 번: sudo bash ~/server-monitor/node_agent/allow-power.sh"
        import subprocess
        import threading
        threading.Timer(8, lambda: subprocess.run(["systemctl", "reboot"])).start()  # let the alert go out first
        return True, "8초 뒤 재부팅"
    node = hub.get(int(key.split(":")[1]))
    if not node:
        return False, "서버 없음"
    code, data = await hub._post(node, "/v1/power/reboot")
    return code == 200, data.get("detail", "") if code != 200 else "재부팅 시작"


async def run_jobs():
    now = time.time()
    names = server_names()
    for j in await asyncio.to_thread(db, "SELECT * FROM power_jobs WHERE next_ts IS NOT NULL"):
        name = names.get(j["server"])
        if not name:
            continue
        if not j["warned"] and 0 < j["next_ts"] - now <= 600:
            await asyncio.to_thread(db, "UPDATE power_jobs SET warned=1 WHERE id=?", (j["id"],))
            await asyncio.to_thread(raise_alert, "power", "", "", f"서버 '{name}' 예약 재부팅 10분 전 "
                                    f"({datetime.fromtimestamp(j['next_ts'], TZ):%m-%d %H:%M})")
        if now < j["next_ts"]:
            continue
        nxt = None if j["kind"] == "once" else next_run(j["kind"], j["hhmm"], j["weekday"])
        # saved BEFORE acting: rebooting this server ends this process
        await asyncio.to_thread(db, "UPDATE power_jobs SET next_ts=?, warned=0, last_run=? WHERE id=?", (nxt, int(now), j["id"]))
        if now - j["next_ts"] > 1800:  # the dashboard was down at the time: don't reboot hours late
            ok, msg = False, "건너뜀 — 예약 시각에 대시보드가 꺼져 있었음"
        else:
            ok, msg = await reboot_server(j["server"])
        await asyncio.to_thread(db, "UPDATE power_jobs SET last_result=? WHERE id=?", (("✓ " if ok else "✗ ") + msg, j["id"]))
        await asyncio.to_thread(raise_alert, "power" if ok else "needs_you", "", "",
                                f"서버 '{name}' 예약 재부팅 {'실행' if ok else '실패'} — {msg}")


# ---------------------------------------------------------------- monthly report + loop

def monthly_report_due() -> str | None:
    now = datetime.now(TZ)
    prev = (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    return prev if now.day == 1 and now.hour >= 1 and _kv("monthly") != prev else None


def send_monthly(month: str):
    rows = uptime(month)
    if rows:
        lines = [f"{r['name']}: {r['pct']}% · 끊김 {r['outages']}회" +
                 (f" (최장 {r['longest'] // 60}분)" if r["longest"] else "") for r in rows]
        raise_alert("monthly", "", "", f"{month} 월간 가동률\n" + "\n".join(lines))
    _kv("monthly", month)


async def loop():
    ledger = Ledger()
    await asyncio.to_thread(ledger.start)
    await asyncio.sleep(30)  # let the first node polls land
    last_hour = 0.0
    while True:
        try:
            await asyncio.to_thread(ledger.tick)
            await asyncio.to_thread(check_boots)
            await asyncio.to_thread(energy_tick)
            await run_jobs()
            if time.time() - last_hour >= 3600:
                last_hour = time.time()
                await asyncio.to_thread(record_disk)
                await asyncio.to_thread(integrity_all)
                await asyncio.to_thread(remember_macs)
                await check_tunnels()
                for f in await asyncio.to_thread(forecasts):
                    if f.get("days_left") is not None and f["days_left"] <= WARN_DAYS:
                        await asyncio.to_thread(raise_alert, "disk_forecast", "", "",
                                                f"서버 '{f['name']}' 디스크가 약 {f['days_left']:.0f}일 뒤 {FULL_AT:.0f}%에 도달 "
                                                f"(지금 {f['now']}%, 하루 +{f['per_day']}%)", 86400)
            month = await asyncio.to_thread(monthly_report_due)
            if month:
                await asyncio.to_thread(send_monthly, month)
        except Exception as e:
            print("fleet loop error:", type(e).__name__, e, flush=True)
        await asyncio.sleep(TICK)


# ---------------------------------------------------------------- API

@router.get("/api/fleet")
def fleet(request: Request):
    require_auth(request)
    now = datetime.now(TZ)
    this, last = now.strftime("%Y-%m"), (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    changes = [{**dict(r), "changes": json.loads(r["changes"])} for r in
               db("SELECT ts, server, name, changes FROM integrity_changes ORDER BY id DESC LIMIT 30")]
    macs = {f"node:{r['id']}": json.loads(r["macs"]) for r in db("SELECT id, macs FROM nodes") if r["macs"]}
    return {"uptime": {"this": {"month": this, "rows": uptime(this)}, "last": {"month": last, "rows": uptime(last)}},
            "forecast": forecasts(), "changes": changes,
            "baselines": {r["server"]: r["ts"] for r in db("SELECT server, ts FROM integrity")},
            "agent_latest": AGENT_LATEST, "macs": macs, "upgrade": {MAIN: hostsec.upgrade_status()}}


def _node(nid: int) -> dict:
    node = hub.get(nid)
    if not node:
        raise HTTPException(404, "서버가 없습니다.")
    return node


@router.post("/api/fleet/wake/{nid}")
async def wake(request: Request, nid: int):
    require_auth(request)
    node = _node(nid)
    row = db("SELECT macs FROM nodes WHERE id=?", (nid,), one=True)
    macs = [m["mac"] for m in json.loads(row["macs"])] if row and row["macs"] else []
    if not macs:
        raise HTTPException(409, "이 서버의 MAC 주소를 아직 모릅니다 (에이전트 2.0으로 한 번 연결돼야 기록됩니다).")
    sent = 0
    for mac in macs:  # from this machine's LAN, and relayed by every other online agent (other LANs)
        sent += await asyncio.to_thread(hostsec.wake, mac)
        for other in hub.nodes():
            st = hub.state.get(other["id"]) or {}
            if other["id"] != nid and st.get("online") and not version_lt((st.get("data") or {}).get("version"), "2.0"):
                code, data = await hub._post(other, "/v1/wake", {"mac": mac})
                sent += data.get("sent", 0) if code == 200 else 0
    request.state.event = "power"
    request.state.detail = f"wake {node['name']}"
    await asyncio.to_thread(raise_alert, "power", "", "", f"서버 '{node['name']}' Wake-on-LAN 신호 보냄 ({sent}개 패킷)",
                            0, False)
    return {"ok": True, "sent": sent}


class UpgradeBody(BaseModel):
    node: int | None = None


@router.post("/api/fleet/upgrade")
async def upgrade(request: Request, body: UpgradeBody):
    require_auth(request)
    if body.node is None:
        ok, msg = await asyncio.to_thread(hostsec.request_upgrade)
        name = local_name()
    else:
        node = _node(body.node)
        code, data = await hub._post(node, "/v1/upgrade")
        ok, msg, name = code == 200, data.get("detail", ""), node["name"]
        if code == 404:
            msg = "에이전트 2.0 이상이 필요합니다"
    if not ok:
        raise HTTPException(409, msg or "실패")
    if body.node is None:
        monitor._updates["t"] = 0  # re-read apt state on the next status call
    request.state.event = "upgrade"
    request.state.detail = name
    await asyncio.to_thread(raise_alert, "upgrade", "", "", f"서버 '{name}' 패키지 업그레이드 요청 — {msg}", 0, False)
    return {"ok": True, "detail": msg}


# ---------------------------------------------------------------- port guard (외부 차단 모드) + exposure API

def _guard_of(nid):
    if nid is None:
        return hostsec.guard_status()
    return (((hub.state.get(nid) or {}).get("data") or {}).get("host_facts") or {}).get("guard")


@router.get("/api/guard")
def guard_view(request: Request):
    require_auth(request)
    servers = [{"node": None, "name": local_name(), "online": True, "guard": hostsec.guard_status(), "version": None}]
    for n in hub.nodes():
        st = hub.state.get(n["id"]) or {}
        servers.append({"node": n["id"], "name": n["name"], "online": st.get("online"), "guard": _guard_of(n["id"]),
                        "version": (st.get("data") or {}).get("version")})
    snaps = {r["server"]: json.loads(r["snap"]) for r in db("SELECT server, snap FROM integrity")}
    upnp = {server_names().get(k, k): v.get("upnp") for k, v in snaps.items() if "upnp" in v}
    return {"servers": servers, "tunnels": json.loads(_kv("tunnels") or "[]"),
            "public_ok": json.loads(_kv("public_ok") or "[]"), "upnp": upnp}


class GuardBody(BaseModel):
    node: int | None = None
    lockdown: bool | None = None
    allow_tcp: list[int] | None = Field(default=None, max_length=100)
    allow_udp: list[int] | None = Field(default=None, max_length=100)
    internal_tcp: list[int] | None = Field(default=None, max_length=100)
    internal_udp: list[int] | None = Field(default=None, max_length=100)
    password: str = Field(default="", max_length=256)


def weakens(cur: dict | None, cfg: dict) -> bool:
    """Turning the guard off, opening a port to the internet, or un-restricting a port needs the password."""
    cur = cur or {}
    if cur.get("lockdown") and cfg.get("lockdown") is False:
        return True
    for k in ("allow_tcp", "allow_udp"):
        if k in cfg and set(cfg[k]) - set(cur.get(k) or []):
            return True
    for k in ("internal_tcp", "internal_udp"):
        if k in cfg and set(cur.get(k) or []) - set(cfg[k]):
            return True
    return False


async def apply_guard(nid, cfg: dict) -> tuple[bool, str]:
    if nid is None:
        return await asyncio.to_thread(hostsec.guard_request, cfg)
    node = _node(nid)
    code, data = await hub._post(node, "/v1/guard", cfg)
    if code == 404:
        return False, "에이전트 2.1 이상이 필요합니다"
    return code == 200, data.get("detail", "")


@router.post("/api/guard")
async def guard_set(request: Request, body: GuardBody):
    require_auth(request)
    cfg = body.model_dump(exclude={"node", "password"}, exclude_none=True)
    cur = _guard_of(body.node)
    if cur is None:
        raise HTTPException(409, "이 서버에 최신 sm-block 이 없습니다 — 그 서버에서 sudo bash .../node_agent/install-blocker.sh")
    if weakens(cur, cfg) and not await run_in_threadpool(confirm_password, request, body.password):
        raise HTTPException(403, "보안을 낮추는 변경이라 비밀번호가 필요합니다 (틀리면 로그인 실패로 셉니다).")
    ok, msg = await apply_guard(body.node, cfg)
    if not ok:
        raise HTTPException(409, msg or "실패")
    name = local_name() if body.node is None else _node(body.node)["name"]
    request.state.event = "action"
    request.state.detail = f"guard {name} {json.dumps(cfg)[:150]}"
    await asyncio.to_thread(raise_alert, "guard", "", "", f"서버 '{name}' 외부 차단 설정 변경: {json.dumps(cfg, ensure_ascii=False)[:300]}",
                            0, weakens(cur, cfg))
    return {"ok": True, "detail": msg}


class RefreshBody(BaseModel):
    node: int | None = None


@router.post("/api/guard/refresh")
async def guard_refresh(request: Request, body: RefreshBody):
    require_auth(request)
    if body.node is None:
        await asyncio.to_thread(hostsec.guard_refresh)
    else:
        await hub._post(_node(body.node), "/v1/guard/refresh")
    await check_tunnels()
    return {"ok": True}


class PublicOkBody(BaseModel):
    host: str = Field(min_length=3, max_length=200, pattern=r"^[A-Za-z0-9.-]+$")
    allowed: bool


@router.post("/api/exposure/allow")
def exposure_allow(request: Request, body: PublicOkBody):
    """'I published this on purpose' — only silences the alert, changes nothing on the network."""
    require_auth(request)
    cur = set(json.loads(_kv("public_ok") or "[]"))
    cur = cur | {body.host.lower()} if body.allowed else cur - {body.host.lower()}
    _kv("public_ok", json.dumps(sorted(cur)))
    request.state.event = "action"
    request.state.detail = f"public_ok {body.host} {body.allowed}"
    return {"ok": True}


# ---------------------------------------------------------------- energy + scheduled reboot API

WEEKDAYS = "월화수목금토일"


@router.get("/api/energy")
def power_view(request: Request):
    require_auth(request)
    names = server_names()
    jobs = [{**dict(r), "name": names.get(r["server"], "(삭제된 서버)")} for r in
            db("SELECT id, server, kind, hhmm, weekday, next_ts, last_run, last_result FROM power_jobs ORDER BY id")]
    return {**energy_view(), "jobs": jobs}


class EnergyBody(BaseModel):
    price: float | None = Field(default=None, ge=0, le=2000)
    server: str | None = Field(default=None, max_length=20)
    idle: float | None = Field(default=None, ge=0, le=2000)
    max: float | None = Field(default=None, ge=0, le=2000)


@router.post("/api/energy/settings")
def power_settings(request: Request, body: EnergyBody):
    require_auth(request)
    cfg = power_cfg()
    if body.price is not None:
        cfg["price"] = body.price
    if body.server:
        if body.server not in server_names():
            raise HTTPException(404, "서버가 없습니다.")
        prof = {**DEFAULT_W, **cfg["servers"].get(body.server, {})}
        prof.update({k: v for k, v in (("idle", body.idle), ("max", body.max)) if v is not None})
        if prof["idle"] > prof["max"]:
            raise HTTPException(400, "대기 전력이 최대 전력보다 클 수 없습니다.")
        cfg["servers"][body.server] = prof
    _kv("power_cfg", json.dumps(cfg))
    return {"ok": True}


class JobBody(BaseModel):
    server: str = Field(max_length=20)
    kind: str = Field(pattern="^(once|daily|weekly)$")
    hhmm: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    weekday: int | None = Field(default=None, ge=0, le=6)
    date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    password: str = Field(max_length=256)


@router.post("/api/energy/schedule")
async def power_schedule(request: Request, body: JobBody):
    require_auth(request)
    name = server_names().get(body.server)
    if not name:
        raise HTTPException(404, "서버가 없습니다.")
    if body.kind == "weekly" and body.weekday is None or body.kind == "once" and not body.date:
        raise HTTPException(400, "요일 또는 날짜를 정하세요.")
    try:
        nxt = next_run(body.kind, body.hhmm, body.weekday, body.date)
    except ValueError:
        raise HTTPException(400, "날짜가 올바르지 않습니다.")
    if nxt is None:
        raise HTTPException(400, "이미 지난 시각입니다.")
    if not await run_in_threadpool(confirm_password, request, body.password):
        raise HTTPException(403, "비밀번호가 틀렸습니다.")
    db("INSERT INTO power_jobs(server, kind, hhmm, weekday, next_ts, created) VALUES(?,?,?,?,?,?)",
       (body.server, body.kind, body.hhmm, body.weekday if body.kind == "weekly" else None, nxt, int(time.time())))
    when = {"once": body.date, "daily": "매일", "weekly": f"매주 {WEEKDAYS[body.weekday or 0]}요일"}[body.kind]
    request.state.event, request.state.detail = "action", f"schedule reboot {name} {when} {body.hhmm}"
    await asyncio.to_thread(raise_alert, "power", request.state.ip, "", f"서버 '{name}' 예약 재부팅 등록: {when} {body.hhmm}")
    return {"ok": True, "next_ts": nxt}


class JobDelBody(BaseModel):
    id: int


@router.post("/api/energy/schedule/delete")
def power_schedule_delete(request: Request, body: JobDelBody):
    require_auth(request)
    db("DELETE FROM power_jobs WHERE id=?", (body.id,))
    request.state.event, request.state.detail = "action", f"delete reboot schedule {body.id}"
    return {"ok": True}
