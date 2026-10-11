"""Discord DM control for the owner: '차단 풀기' buttons under block alerts and a few DM commands.

The bot connects OUT to Discord's gateway (websocket), so nothing new is exposed to the internet and no
Cloudflare Access bypass is needed. Only the configured owner (SM_DISCORD_USER_ID) is obeyed, and every
unblock takes a second "정말 풀기" click. Commands (DM to the bot):
  차단목록            list current bans
  차단해제 <ip>       ask to unban (shows the confirm button)
  도움                help
"""
import asyncio
import ipaddress
import json
import re
import time

import websockets

import alerts
from core import BAN_EVENTS, BANNED, ban_key, db, raise_alert, unban_key

GATEWAY = "wss://gateway.discord.gg/?v=10&encoding=json"
INTENTS = 1 << 12  # DIRECT_MESSAGES (message content is always included for DMs)
KEY_RE = re.compile(r"^[0-9A-Fa-f:./]{3,64}$")
HELP = "명령: `차단목록` · `차단해제 <IP>` · `도움`\n차단 알림 아래의 **차단 풀기** 버튼도 쓸 수 있어요 (한 번 더 확인 후 실행)."


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


def handle_interaction(d: dict):
    user = (d.get("user") or (d.get("member") or {}).get("user") or {}).get("id")
    cid = (d.get("data") or {}).get("custom_id", "")
    reply = lambda t, data: _post(f"/interactions/{d['id']}/{d['token']}/callback", {"type": t, "data": data})
    if user != alerts.DC_USER:
        return reply(4, {"content": "권한이 없습니다.", "flags": 64})
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
    text = " ".join((d.get("content") or "").split())
    say = lambda content, components=None: _post(f"/channels/{d['channel_id']}/messages", {
        "content": content[:1900], "allowed_mentions": {"parse": []}, **({"components": components} if components else {})})
    if text in ("차단목록", "bans"):
        rows = db("SELECT key, country, ts, reason FROM bans ORDER BY ts DESC LIMIT 15")
        if not rows:
            return say("영구 차단된 IP가 없습니다.")
        return say("**영구 차단 목록** (최근 15개)\n" + "\n".join(
            f"• `{r['key']}` {r['country'] or ''} · {time.strftime('%m-%d %H:%M', time.localtime(r['ts']))} · {(r['reason'] or '')[:60]}"
            for r in rows) + "\n풀려면: `차단해제 <IP>`")
    m = re.fullmatch(r"(?:차단해제|unban)\s+(\S+)", text)
    if m:
        target = m.group(1)
        try:
            key = target if target in BANNED else ban_key(str(ipaddress.ip_address(target)))
        except ValueError:
            return say("IP 형식이 아닙니다. 예) `차단해제 203.0.113.7`")
        where = "대시보드 차단 + 모든 서버 방화벽" if key in BANNED else "서버 방화벽 (대시보드 차단 목록에는 없음)"
        return say(f"`{key}` 의 차단을 풀까요? 대상: {where}", _confirm_row(key))
    if text in ("도움", "help", "?"):
        return say(HELP)


async def run():
    if not (alerts.DC_BOT and alerts.DC_USER):
        return
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
