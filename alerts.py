"""Security alerts: always stored for the dashboard, optionally pushed to Telegram / Discord."""
import json
import os
import queue
import threading
import time
import urllib.request

# Secrets are popped so child processes (systemctl) never inherit them.
TG_TOKEN = os.environ.pop("SM_TELEGRAM_BOT_TOKEN", "").strip()
TG_CHAT = os.environ.pop("SM_TELEGRAM_CHAT_ID", "").strip()
DISCORD = os.environ.pop("SM_DISCORD_WEBHOOK", "").strip()
DC_BOT = os.environ.pop("SM_DISCORD_BOT_TOKEN", "").strip()
DC_CHANNEL = os.environ.get("SM_DISCORD_CHANNEL_ID", "").strip()
DC_USER = os.environ.get("SM_DISCORD_USER_ID", "").strip()   # DM is preferred: alerts contain IPs
DC_API = "https://discord.com/api/v10"

CHANNELS = [name for name, on in (("telegram", TG_TOKEN and TG_CHAT), ("discord", DISCORD),
                                  ("discord-bot", DC_BOT and (DC_CHANNEL or DC_USER))) if on]

_q: queue.Queue = queue.Queue(maxsize=200)


def _post(url: str, payload: dict, headers: dict | None = None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "server-monitor (hi.mieung.kr, 1.0)", **(headers or {})})
    return json.loads(urllib.request.urlopen(req, timeout=10).read() or b"{}")


_dm_channel = DC_CHANNEL


COLORS = {"critical": 0xD03B3B, "warning": 0xFAB219, "good": 0x0CA30C, "info": 0x3987E5}


def card(title: str, description: str = "", level: str = "info", fields: list | None = None, footer: str = "") -> dict:
    """A Discord embed: coloured bar by severity, short title, body, and small name/value columns."""
    e = {"title": title[:250], "color": COLORS.get(level, COLORS["info"]),
         "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if description:
        e["description"] = description[:3900]
    if fields:
        e["fields"] = [{"name": n[:250], "value": (str(v) or "–")[:1000], "inline": inline}
                       for n, v, inline in fields if v not in (None, "")][:25]
    if footer:
        e["footer"] = {"text": footer[:200]}
    return e


def _discord_payload(text: str, embed: dict | None) -> dict:
    p = {"allowed_mentions": {"parse": []}}
    if embed:
        p["embeds"] = [embed]
    else:
        p["content"] = text[:1900]
    return p


def bot_auth() -> dict:
    return {"Authorization": f"Bot {DC_BOT}"}


def _discord_bot(text: str, embed: dict | None = None, components: list | None = None):
    global _dm_channel
    if not _dm_channel:  # open (or reuse) the DM channel with the owner once
        _dm_channel = _post(f"{DC_API}/users/@me/channels", {"recipient_id": DC_USER}, bot_auth())["id"]
    payload = _discord_payload(text, embed)
    if components:  # buttons only work on messages sent by the bot itself (handled by discord_bot.py)
        payload["components"] = components
    _post(f"{DC_API}/channels/{_dm_channel}/messages", payload, bot_auth())


def send_now(text: str, embed: dict | None = None, components: list | None = None):
    """text is the plain fallback (Telegram); Discord gets the embed when one is given."""
    if TG_TOKEN and TG_CHAT:
        _post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
              {"chat_id": TG_CHAT, "text": text, "disable_web_page_preview": True})
    if DISCORD:
        _post(DISCORD, _discord_payload(text, embed))
    if DC_BOT and (DC_CHANNEL or DC_USER):
        _discord_bot(text, embed, components)


def _worker():
    while True:
        text, embed, components = _q.get()
        try:
            send_now(text, embed, components)
        except Exception as e:
            print("alert push failed:", type(e).__name__, flush=True)
        time.sleep(1)  # stay well under provider rate limits


if CHANNELS:
    threading.Thread(target=_worker, daemon=True).start()


def push(text: str, embed: dict | None = None, components: list | None = None):
    if CHANNELS:
        try:
            _q.put_nowait((text, embed, components))
        except queue.Full:
            pass
