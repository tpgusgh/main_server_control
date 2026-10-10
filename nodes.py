"""Remote servers in the Tailscale network, each running node_agent/server_agent.py."""
import asyncio
import ipaddress
import re
import time

import httpx

POLL_INTERVAL = 10
OFFLINE_AFTER = 3              # consecutive failed polls (~30s) before a server counts as down
METRIC_KEEP = 48 * 3600
TAILNET_V4 = ipaddress.ip_network("100.64.0.0/10")
TAILNET_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.ts\.net$")
UNIT_RE = re.compile(r"^[A-Za-z0-9@._-]+\.service$")
HOT = {"cpu": 80.0, "mem": 90.0, "temp": 85.0}


def parse_address(raw: str) -> str:
    """Only Tailscale addresses are allowed, so the dashboard can't be turned into a proxy into
    the LAN or the internet (SSRF). Returns a normalised base URL."""
    raw = raw.strip().removeprefix("http://").rstrip("/")
    host, port = raw, "8101"
    if raw.startswith("["):                       # [v6]:port
        host, _, rest = raw[1:].partition("]")
        port = rest.lstrip(":") or port
    elif raw.count(":") == 1:                     # v4:port or name:port
        host, port = raw.split(":")
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("포트가 올바르지 않습니다.")
    try:
        ip = ipaddress.ip_address(host)
        if ip not in TAILNET_V4 and ip not in TAILNET_V6:
            raise ValueError("Tailscale 주소(100.x.y.z 또는 fd7a:115c:a1e0::)만 추가할 수 있습니다.")
        hostpart = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError as e:
        if "Tailscale" in str(e):
            raise
        if not HOST_RE.match(host.lower()):
            raise ValueError("Tailscale IP(100.x.y.z) 또는 *.ts.net 이름만 추가할 수 있습니다.")
        hostpart = host.lower()
    return f"http://{hostpart}:{int(port)}"


class NodeHub:
    def __init__(self, db, raise_alert):
        self.db, self.raise_alert = db, raise_alert
        self.state: dict[int, dict] = {}
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(6, connect=3))
        db("""CREATE TABLE IF NOT EXISTS nodes(
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, address TEXT, token TEXT, created INTEGER)""")
        db("""CREATE TABLE IF NOT EXISTS node_metrics(
              node_id INTEGER, ts INTEGER, cpu REAL, mem REAL, temp REAL, load1 REAL, disk REAL,
              net_rx REAL, net_tx REAL, PRIMARY KEY(node_id, ts))""")
        if "memo" not in {r[1] for r in db("PRAGMA table_info(nodes)")}:
            db("ALTER TABLE nodes ADD COLUMN memo TEXT DEFAULT ''")

    def nodes(self) -> list[dict]:
        return [dict(r) for r in self.db("SELECT id, name, memo, address, token, created FROM nodes ORDER BY id")]

    def public(self, n: dict) -> dict:
        st = self.state.get(n["id"], {})
        return {"id": n["id"], "name": n["name"], "memo": n.get("memo") or "", "address": n["address"].removeprefix("http://"),
                "created": n["created"], "online": st.get("online"), "last_ok": st.get("last_ok"),
                "error": st.get("error"), "data": st.get("data")}

    async def fetch(self, node: dict) -> dict:
        r = await self.client.get(f"{node['address']}/v1/status", headers={"Authorization": f"Bearer {node['token']}"})
        if r.status_code == 403:
            raise PermissionError("인증 실패 (토큰 또는 allow_from 확인)")
        r.raise_for_status()
        return r.json()

    async def poll(self, node: dict):
        st = self.state.setdefault(node["id"], {"online": None, "fails": 0})
        try:
            data = await self.fetch(node)
        except Exception as e:
            st["fails"] += 1
            st["error"] = str(e) if isinstance(e, PermissionError) else f"연결 실패 ({type(e).__name__})"
            if st["fails"] >= OFFLINE_AFTER and st["online"] is not False:
                if st["online"] is True:
                    await asyncio.to_thread(self.raise_alert, "node_down", node["address"], "",
                                            f"서버 '{node['name']}' 응답 없음 · {st['error']}")
                st["online"] = False
            return
        was_down = st["online"] is False
        st.update(online=True, fails=0, error=None, last_ok=int(time.time()), data=data)
        if was_down:
            await asyncio.to_thread(self.raise_alert, "node_up", node["address"], "", f"서버 '{node['name']}' 다시 연결됨")
        n = data.get("now") or {}
        if n:
            await asyncio.to_thread(self.db, "INSERT OR REPLACE INTO node_metrics VALUES(?,?,?,?,?,?,?,?,?)",
                                    (node["id"], n["ts"], n.get("cpu"), n.get("mem"), n.get("temp"),
                                     (n.get("load") or [None])[0], n.get("disk"), n.get("net_rx"), n.get("net_tx")))
            hot = [k for k, lim in HOT.items() if (n.get(k) or 0) >= lim]
            if hot:
                await asyncio.to_thread(self.raise_alert, "node_hot", node["address"], "",
                                        f"서버 '{node['name']}' 고부하: " + ", ".join(f"{k} {n[k]:.0f}" for k in hot), 1800)

    async def loop(self):
        last_prune = 0.0
        while True:
            nodes = await asyncio.to_thread(self.nodes)
            await asyncio.gather(*(self.poll(n) for n in nodes), return_exceptions=True)
            if time.time() - last_prune > 3600:
                await asyncio.to_thread(self.db, "DELETE FROM node_metrics WHERE ts < ?", (int(time.time()) - METRIC_KEEP,))
                last_prune = time.time()
            await asyncio.sleep(POLL_INTERVAL)

    # ------------------------------------------------------------ admin ops

    async def add(self, name: str, address: str, token: str) -> dict:
        url = parse_address(address)
        node = {"id": -1, "name": name, "address": url, "token": token}
        try:
            data = await self.fetch(node)
        except PermissionError as e:
            raise ValueError(str(e))
        except Exception as e:
            raise ValueError(f"에이전트에 연결할 수 없습니다 ({type(e).__name__}). 주소·포트·방화벽을 확인하세요.")
        if self.db("SELECT 1 FROM nodes WHERE address=?", (url,), one=True):
            raise ValueError("이미 추가된 서버입니다.")
        self.db("INSERT INTO nodes(name, address, token, created) VALUES(?,?,?,?)", (name, url, token, int(time.time())))
        nid = self.db("SELECT MAX(id) id FROM nodes", one=True)["id"]
        self.state[nid] = {"online": True, "fails": 0, "last_ok": int(time.time()), "data": data, "error": None}
        return {"id": nid, "host": data.get("host")}

    def get(self, nid: int) -> dict | None:
        r = self.db("SELECT id, name, memo, address, token, created FROM nodes WHERE id=?", (nid,), one=True)
        return dict(r) if r else None

    async def edit(self, nid: int, name: str, memo: str, address: str = "", token: str = ""):
        """Empty address/token keep the current value; a new address or token is verified before saving."""
        node = self.get(nid)
        url = parse_address(address) if address else node["address"]
        token = token or node["token"]
        if url != node["address"] or token != node["token"]:
            if url != node["address"] and self.db("SELECT 1 FROM nodes WHERE address=? AND id!=?", (url, nid), one=True):
                raise ValueError("이미 추가된 주소입니다.")
            try:
                await self.fetch({"address": url, "token": token})
            except PermissionError as e:
                raise ValueError(str(e))
            except Exception as e:
                raise ValueError(f"새 주소/토큰으로 연결할 수 없습니다 ({type(e).__name__}).")
            self.state.pop(nid, None)
        self.db("UPDATE nodes SET name=?, memo=?, address=?, token=? WHERE id=?", (name, memo, url, token, nid))

    def delete(self, nid: int):
        self.db("DELETE FROM nodes WHERE id=?", (nid,))
        self.db("DELETE FROM node_metrics WHERE node_id=?", (nid,))
        self.state.pop(nid, None)

    async def action(self, node: dict, unit: str, action: str) -> tuple[int, dict]:
        if not UNIT_RE.match(unit) or action not in ("start", "stop", "restart", "enable", "disable", "delete"):
            return 400, {"detail": "bad request"}
        return await self._post(node, f"/v1/services/{unit}/{action}")

    async def terminate(self, node: dict, pid: int) -> tuple[int, dict]:
        return await self._post(node, f"/v1/process/{int(pid)}/terminate")

    async def _post(self, node: dict, path: str, payload: dict | None = None) -> tuple[int, dict]:
        try:
            r = await self.client.post(f"{node['address']}{path}", json=payload,
                                       headers={"Authorization": f"Bearer {node['token']}"})
        except httpx.HTTPError as e:
            return 502, {"detail": f"서버에 연결할 수 없습니다 ({type(e).__name__})"}
        try:
            return r.status_code, r.json()
        except ValueError:
            return 502, {"detail": "잘못된 응답"}

    def history(self, nid: int, hours: float) -> dict:
        hours = min(max(hours, 0.25), 24)
        bucket = max(POLL_INTERVAL, int(hours * 3600 / 720))
        rows = self.db("SELECT (ts/?)*? t, AVG(cpu) cpu, MAX(cpu) cpu_max, AVG(mem) mem, AVG(temp) temp, MAX(temp) temp_max, "
                       "AVG(load1) load1 FROM node_metrics WHERE node_id=? AND ts>=? GROUP BY t ORDER BY t",
                       (bucket, bucket, nid, int(time.time() - hours * 3600)))
        return {"bucket": bucket, "points": [dict(r) for r in rows]}

    # ------------------------------------------------------------ for the AI analyst

    def window_stats(self, nid: int, start: int, end: int) -> dict:
        r = self.db("SELECT COUNT(*) n, ROUND(AVG(cpu),1) cpu_avg, ROUND(MAX(cpu),1) cpu_max, ROUND(AVG(mem),1) mem_avg, "
                    "ROUND(MAX(mem),1) mem_max, ROUND(MAX(temp),0) temp_max FROM node_metrics "
                    "WHERE node_id=? AND ts>=? AND ts<?", (nid, start, end), one=True)
        d = dict(r)
        d["수집률%"] = round(d.pop("n") * POLL_INTERVAL / max(end - start, 1) * 100)
        return d

    def summary(self, start: int | None = None, end: int | None = None) -> list[dict]:
        end = end or int(time.time())
        start = start or end - 86400
        out = []
        for n in self.nodes():
            st = self.state.get(n["id"], {})
            data = st.get("data") or {}
            cur = data.get("now") or {}
            svcs = data.get("services", [])
            out.append({"이름": n["name"], "메모": n.get("memo") or None, "온라인": st.get("online"), "오류": st.get("error"),
                        "현재": {"cpu%": cur.get("cpu"), "mem%": cur.get("mem"), "temp_c": cur.get("temp"),
                               "disk%": cur.get("disk")} if st.get("online") else None,
                        "기간통계": self.window_stats(n["id"], start, end),
                        "실행중서비스수": sum(1 for s in svcs if s.get("active") == "active"),  # full list only in that server's view
                        "문제서비스": [{"unit": s["unit"], "제어가능": s.get("controllable", True)}
                                  for s in svcs if s.get("active") == "failed"],
                        "외부노출포트": [{"port": p["port"], "process": p.get("process")}
                                    for p in cur.get("ports", []) if p.get("public")][:20],
                        "상위프로세스": [{"name": p["name"], "cpu%": p["cpu"], "mem%": p["mem"]} for p in cur.get("top", [])[:5]],
                        "에이전트버전": data.get("version")})
        return out
