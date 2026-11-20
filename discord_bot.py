"""Discord DM control for the owner: '차단 풀기' buttons under block alerts and a few DM commands.

The bot connects OUT to Discord's gateway (websocket), so nothing new is exposed to the internet and no
Cloudflare Access bypass is needed. Only the configured owner (SM_DISCORD_USER_ID) is obeyed, and every
unblock/restart takes a second click. Commands (DM to the bot):
  상태 / 서비스 [서버] / 전력        read-only summaries
  재시작 <서비스> [서버]             asks first (confirm button), then restarts
  차단목록 / 차단해제 <ip>           bans (unban asks first)
  도움                               help
"""
import asyncio
import ipaddress
import json
import re
import time
import urllib.request

import websockets

import alerts
import monitor
import uxrules
from core import BAN_EVENTS, BANNED, ban_key, db, local_name, raise_alert, unban_key
from node_agent import hostsec
from routes_nodes import hub

GATEWAY = "wss://gateway.discord.gg/?v=10&encoding=json"
INTENTS = 1 << 12  # DIRECT_MESSAGES (message content is always included for DMs)
KEY_RE = re.compile(r"^[0-9A-Fa-f:./]{3,64}$")
HELP = ("**조회**: `상태` (모든 서버 요약) · `서비스 [서버]` (실패한 서비스) · `전력` (전력·예상 요금)\n"
        "**조치**: `재시작 <서비스> [서버]` (확인 버튼 후 실행) · `차단목록` · `차단해제 <IP>`\n"
        "차단 알림 아래의 **차단 풀기** 버튼도 쓸 수 있어요. 조치는 모두 한 번 더 확인을 거칩니다.")
LOOP: asyncio.AbstractEventLoop | None = None  # the gateway's event loop (node calls are async, handlers run in threads)


def _post(path: str, payload: dict):
    return alerts._post(f"{alerts.DC_API}{path}", payload, alerts.bot_auth())


def _confirm_row(key: str) -> list:
    return [{"type": 1, "components": [
        {"type": 2, "style": 4, "label": f"정말 풀기 ({key})"[:80], "custom_id": f"confirm:{key}"[:100]},
        {"type": 2, "style": 2, "label": "취소", "custom_id": f"cancel:{key}"[:100]}]}]


def _valid_key(key: str) -> bool:
    if not KEY_RE.match(key):
        return False
    try:
        ipaddress.ip_network(key, strict=False)
        return True
    except ValueError:
        return False


def unblock(key: str) -> str:
    """Dashboard ban → unban (firewalls follow via BAN_EVENTS); firewall-only block → unblock everywhere."""
    if key in BANNED:
        ok, msg = unban_key(key, "디스코드")
        return f"✅ {msg} 차단을 풀었습니다 (대시보드 + 모든 서버 방화벽)." if ok else f"⚠️ {msg}"
    BAN_EVENTS.append(("del", key, ""))
    db("INSERT INTO access_log(ts,ip,country,method,path,status,ua,event,detail,email) VALUES(?,?,?,?,?,?,?,?,?,?)",
       (int(time.time()), key, "", "-", "-", 0, "", "unban", "해제: 디스코드 (방화벽)", None))
    raise_alert("unban", key, "", "디스코드에서 방화벽 차단 해제 요청")
    return f"✅ {key} 의 방화벽 차단 해제를 모든 서버에 요청했습니다."


def _patch(path: str, payload: dict):
    """Edit the interaction's original message (used after a deferred answer)."""
    req = urllib.request.Request(f"{alerts.DC_API}{path}", data=json.dumps(payload).encode(), method="PATCH",
                                 headers={"Content-Type": "application/json", "User-Agent": "server-monitor (hi.mieung.kr, 1.0)"})
    return urllib.request.urlopen(req, timeout=15).read()


def _server(name: str):
    """(found, node id or None for this server, display name)."""
    name = name.strip()
    if not name or name.lower() in (local_name().lower(), "중앙", "중앙서버", "본체", "main"):
        return True, None, local_name()
    for n in hub.nodes():
        if n["name"].lower() == name.lower():
            return True, n["id"], n["name"]
    return False, None, name


def _line(name: str, n: dict, uptime: float | None) -> str:
    parts = [f"CPU {n.get('cpu') or 0:.0f}%", f"메모리 {n.get('mem') or 0:.0f}%"]
    if n.get("temp") is not None:
        parts.append(f"{n['temp']:.0f}°C")
    if n.get("disk") is not None:
        parts.append(f"디스크 {n['disk']:.0f}%")
    if uptime:
        parts.append(f"가동 {int(uptime // 86400)}일 {int(uptime % 86400 // 3600)}시간")
    return f"**{name}** — " + " · ".join(parts)


def cmd_status() -> str:
    st = monitor.status_data()
    lines = ["🟢 " + _line(local_name(), st["now"], st.get("uptime"))]
    for n in hub.nodes():
        s = hub.state.get(n["id"]) or {}
        data = s.get("data") or {}
        if s.get("unknown"):
            lines.append(f"⚪ **{n['name']}** — 확인 불가 (중앙서버 네트워크 문제)")
        elif s.get("online"):
            lines.append("🟢 " + _line(n["name"], data.get("now") or {}, data.get("uptime")))
        elif s.get("online") is False:
            lines.append(f"🔴 **{n['name']}** — 연결 끊김 ({s.get('error') or '응답 없음'})")
        else:
            lines.append(f"⚪ **{n['name']}** — 확인 중")
    return "\n".join(lines)


def _services_of(nid):
    if nid is None:
        return monitor.services_data()["services"]
    return ((hub.state.get(nid) or {}).get("data") or {}).get("services") or []


def cmd_services(server: str) -> str:
    found, _, _ = _server(server)
    if server and not found:
        return f"'{server}' 서버를 찾지 못했어요. 이름: {', '.join([local_name()] + [n['name'] for n in hub.nodes()])}"
    targets = [(None, local_name())] if not server else [x[1:] for x in [_server(server)]]
    if not server:
        targets += [(n["id"], n["name"]) for n in hub.nodes()]
    out = []
    for nid, name in targets:
        svcs = _services_of(nid)
        failed = [s["unit"] for s in svcs if s.get("active") == "failed"]
        running = sum(1 for s in svcs if s.get("active") == "active")
        out.append(f"{'🔴' if failed else '🟢'} **{name}** — 실행 중 {running} · 실패 {len(failed)}" + (f"\n  ⚠️ {', '.join(failed[:8])}" if failed else ""))
    return "\n".join(out)


def cmd_power() -> str:
    import fleet  # late: fleet imports this module's neighbours
    v = fleet.energy_view()
    lines = [f"**{r['name']}** — 지금 약 {r['watts_now'] if r['watts_now'] is not None else '–'} W · 이번 달 {r['month_kwh']} kWh ≈ {r['month_won']:,}원"
             + (f" · 한 달 예상 {r['projected_won']:,}원" if r["projected_won"] else "") for r in v["rows"]]
    return "\n".join(lines) + f"\n합계 이번 달 약 {v['total_month_won']:,}원 (단가 {v['price']:g}원/kWh, CPU 기반 추정)"


def _restart_check(server: str, unit: str):
    """(node id, display name) when this unit may be restarted from Discord, else an error string."""
    found, nid, name = _server(server)
    if not found:
        return f"'{server}' 서버를 찾지 못했어요. 이름: {', '.join([local_name()] + [n['name'] for n in hub.nodes()])}"
    if nid is None and unit == "server-monitor.service":
        return "대시보드 자신은 디스코드에서 재시작하지 않아요 (결과를 전해 드릴 수 없어서). 대시보드 화면에서 해주세요."
    sv = next((s for s in _services_of(nid) if s.get("unit") == unit), None)
    if nid is None and not sv and unit in monitor.system_units(include_stopped=True) and "svc" in hostsec.caps():
        sv = {"root": True}
    if not sv or not (sv.get("controllable", True) or sv.get("root")):
        return f"{name} 에서 `{unit}` 은(는) 재시작할 수 없어요 (없거나 보기 전용 서비스예요). `서비스 {name}` 으로 확인해 보세요."
    return nid, name


def do_restart(nid, unit: str) -> str:
    name = local_name() if nid is None else (hub.get(nid) or {}).get("name", "?")
    if nid is None:
        if unit in monitor.managed_units():
            res = monitor._systemctl("--no-block", "restart", unit)
            ok, msg = res.returncode == 0, (res.stderr or "").strip()[:150]
            detail = f"restart {unit}"
        else:
            ok, msg = hostsec.system_service("restart", unit)
            detail = f"restart {unit} (system)"
    else:
        code, data = asyncio.run_coroutine_threadsafe(hub.action(hub.get(nid), unit, "restart"), LOOP).result(timeout=100)
        ok, msg, detail = code == 200, data.get("detail", ""), f"restart {unit} @ {name}"
    db("INSERT INTO access_log(ts,ip,country,method,path,status,ua,event,detail,email) VALUES(?,?,?,?,?,?,?,?,?,?)",
       (int(time.time()), "디스코드", "", "-", "-", 0, "", "action", detail, None))
    return f"✅ {name}: `{unit}` 재시작을 요청했어요" + (f" ({msg})" if msg and ok else "") if ok else f"⚠️ {name}: `{unit}` 재시작 실패 — {msg or '알 수 없는 오류'}"


def handle_interaction(d: dict):
    user = (d.get("user") or (d.get("member") or {}).get("user") or {}).get("id")
    cid = (d.get("data") or {}).get("custom_id", "")
    reply = lambda t, data: _post(f"/interactions/{d['id']}/{d['token']}/callback", {"type": t, "data": data})
    if user != alerts.DC_USER:
        return reply(4, {"content": "권한이 없습니다.", "flags": 64})
    if cid == "rsx":
        return reply(7, {"content": "취소했어요.", "components": []})
    rs = uxrules.parse_restart_id(cid)
    if rs:  # second click: answer within Discord's 3 s limit, do the (possibly slow) restart, then edit the message
        _post(f"/interactions/{d['id']}/{d['token']}/callback", {"type": 6})
        nid, unit = rs
        check = _restart_check("" if nid is None else (hub.get(nid) or {}).get("name", "?"), unit)  # re-check right before acting
        try:
            text = check if isinstance(check, str) else do_restart(nid, unit)
        except Exception as e:
            text = f"⚠️ 재시작 중 오류: {type(e).__name__}"
        print(f"discord: restart {unit} node={nid} by owner", flush=True)
        return _patch(f"/webhooks/{d['application_id']}/{d['token']}/messages/@original",
                      {"content": f"{text} ({time.strftime('%m-%d %H:%M')})", "components": []})
    action, _, key = cid.partition(":")
    if not _valid_key(key):
        return reply(4, {"content": "잘못된 요청입니다.", "flags": 64})
    if action == "unblock":
        return reply(7, {"components": _confirm_row(key)})
    if action == "cancel":
        return reply(7, {"components": [{"type": 1, "components": [
            {"type": 2, "style": 4, "label": "차단 풀기", "custom_id": f"unblock:{key}"[:100]}]}]})
    if action == "confirm":
        msg = unblock(key)
        print(f"discord: unblock {key} by owner", flush=True)
        return reply(7, {"content": f"{msg} ({time.strftime('%m-%d %H:%M')})", "components": []})
    return reply(4, {"content": "알 수 없는 버튼입니다.", "flags": 64})


def handle_message(d: dict):
    author = d.get("author") or {}
    if author.get("bot") or author.get("id") != alerts.DC_USER or d.get("guild_id"):
        return  # owner's DMs only
    parsed = uxrules.parse_command(d.get("content") or "")
    if not parsed:
        return
    cmd, args = parsed
    say = lambda content, components=None: _post(f"/channels/{d['channel_id']}/messages", {
        "content": content[:1900], "allowed_mentions": {"parse": []}, **({"components": components} if components else {})})
    if cmd == "help":
        return say(HELP)
    if cmd == "status":
        return say(cmd_status())
    if cmd == "services":
        return say(cmd_services(" ".join(args)))
    if cmd == "power":
        return say(cmd_power())
    if cmd == "restart":
        target = uxrules.restart_target(args)
        if not target:
            return say("사용법: `재시작 <서비스> [서버]` — 예) `재시작 worldrium 서브서버 1`")
        unit, server = target
        check = _restart_check(server, unit)
        if isinstance(check, str):
            return say(check)
        nid, name = check
        return say(f"**{name}** 의 `{unit}` 을(를) 재시작할까요?", [{"type": 1, "components": [
            {"type": 2, "style": 4, "label": f"정말 재시작 ({unit})"[:80], "custom_id": uxrules.restart_id(nid, unit)},
            {"type": 2, "style": 2, "label": "취소", "custom_id": "rsx"}]}])
    if cmd == "bans":
        rows = db("SELECT key, country, ts, reason FROM bans ORDER BY ts DESC LIMIT 15")
        if not rows:
            return say("영구 차단된 IP가 없습니다.")
        return say("**영구 차단 목록** (최근 15개)\n" + "\n".join(
            f"• `{r['key']}` {r['country'] or ''} · {time.strftime('%m-%d %H:%M', time.localtime(r['ts']))} · {(r['reason'] or '')[:60]}"
            for r in rows) + "\n풀려면: `차단해제 <IP>`")
    if cmd == "unban":
        if len(args) != 1:
            return say("사용법: `차단해제 <IP>` — 예) `차단해제 203.0.113.7`")
        try:
            key = args[0] if args[0] in BANNED else ban_key(str(ipaddress.ip_address(args[0])))
        except ValueError:
            return say("IP 형식이 아닙니다. 예) `차단해제 203.0.113.7`")
        where = "대시보드 차단 + 모든 서버 방화벽" if key in BANNED else "서버 방화벽 (대시보드 차단 목록에는 없음)"
        return say(f"`{key}` 의 차단을 풀까요? 대상: {where}", _confirm_row(key))


async def run():
    global LOOP
    if not (alerts.DC_BOT and alerts.DC_USER):
        return
    LOOP = asyncio.get_running_loop()
    backoff = 5
    while True:
        try:
            async with websockets.connect(GATEWAY, max_size=2 ** 22, open_timeout=20) as ws:
                hello = json.loads(await ws.recv())
                interval = hello["d"]["heartbeat_interval"] / 1000
                state = {"seq": None}

                async def beat():
                    while True:
                        await asyncio.sleep(interval)
                        await ws.send(json.dumps({"op": 1, "d": state["seq"]}))
                await ws.send(json.dumps({"op": 2, "d": {"token": alerts.DC_BOT, "intents": INTENTS,
                                                         "properties": {"os": "linux", "browser": "server-monitor",
                                                                        "device": "server-monitor"}}}))
                hb = asyncio.create_task(beat())
                try:
                    async for raw in ws:
                        m = json.loads(raw)
                        if m.get("s") is not None:
                            state["seq"] = m["s"]
                        if m["op"] == 1:
                            await ws.send(json.dumps({"op": 1, "d": state["seq"]}))
                        elif m["op"] in (7, 9):  # reconnect / invalid session: start over
                            break
                        elif m["op"] == 0:
                            if m["t"] == "READY":
                                backoff = 5
                                print("discord gateway ready", flush=True)
                            elif m["t"] in ("INTERACTION_CREATE", "MESSAGE_CREATE"):
                                fn = handle_interaction if m["t"] == "INTERACTION_CREATE" else handle_message
                                try:
                                    await asyncio.to_thread(fn, m["d"])
                                except Exception as e:  # one bad event must not drop the connection
                                    print("discord handler:", type(e).__name__, str(e)[:120], flush=True)
                finally:
                    hb.cancel()
        except Exception as e:
            print("discord gateway:", type(e).__name__, str(e)[:120], flush=True)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 600)
