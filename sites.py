"""Website uptime checks: GET each registered URL every 2 minutes; alert when it stays down / comes back."""
import asyncio
import socket
import ssl
import time
import urllib.parse

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import security
from core import _cfg_lock, raise_alert, require_auth

INTERVAL = 120
DOWN_AFTER = 2          # consecutive failures before alerting (one blip is not an outage)
CERT_EVERY, CERT_WARN_DAYS = 6 * 3600, 14
router = APIRouter()
state: dict[str, dict] = {}  # url -> {ok, code, ms, ts, fails, since, error}
_client = httpx.AsyncClient(timeout=httpx.Timeout(10, connect=5), follow_redirects=False,
                            headers={"User-Agent": "server-monitor uptime check"})


def sites() -> list[dict]:
    return security.load_config().get("sites", [])


def is_up(code: int | None) -> bool:
    """Reachable and not a server error. 3xx (e.g. a Cloudflare Access login redirect) and 4xx count as up."""
    return code is not None and code < 500


def cert_days(url: str) -> int | None:
    """Days until the HTTPS certificate expires (None for plain http). Raises ssl.SSLError when it doesn't verify."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        return None
    with socket.create_connection((u.hostname, u.port or 443), timeout=8) as raw, \
            ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname) as tls:
        expires = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
    return int((expires - time.time()) // 86400)


async def check_cert(site: dict, st: dict):
    st["cert_ts"] = int(time.time())
    try:
        days, st["cert_error"] = await asyncio.to_thread(cert_days, site["url"]), None
    except (OSError, ssl.SSLError, ValueError) as e:
        days = None
        st["cert_error"] = f"인증서 확인 실패 ({type(e).__name__})"
        if isinstance(e, ssl.SSLCertVerificationError):
            await asyncio.to_thread(raise_alert, "cert_expiry", urllib.parse.urlsplit(site["url"]).hostname or "", "",
                                    f"웹사이트 '{site['name']}' SSL 인증서가 유효하지 않음 — {e.verify_message} ({site['url']})", 86400)
    st["cert_days"] = days
    if days is not None and days <= CERT_WARN_DAYS:
        await asyncio.to_thread(raise_alert, "cert_expiry", urllib.parse.urlsplit(site["url"]).hostname or "", "",
                                f"웹사이트 '{site['name']}' SSL 인증서 {days}일 뒤 만료 — 갱신이 필요합니다 ({site['url']})", 86400)


async def check(site: dict):
    url, t0 = site["url"], time.monotonic()
    try:
        code, err = (await _client.get(url)).status_code, None
    except httpx.HTTPError as e:
        code, err = None, type(e).__name__
    st = state.setdefault(url, {"fails": 0, "ok": None, "since": int(time.time())})
    ok = is_up(code)
    st.update(code=code, error=err, ms=round((time.monotonic() - t0) * 1000), ts=int(time.time()))
    if time.time() - st.get("cert_ts", 0) > CERT_EVERY:
        await check_cert(site, st)
    if ok:
        if st["ok"] is False:
            await asyncio.to_thread(raise_alert, "site_up", "", "", f"웹사이트 '{site['name']}' 복구됨 ({url}, {code})")
        if st["ok"] is not True:
            st["since"] = int(time.time())
        st.update(ok=True, fails=0)
        return
    st["fails"] += 1
    if st["fails"] >= DOWN_AFTER and st["ok"] is not False:
        st.update(ok=False, since=int(time.time()))
        why = f"HTTP {code}" if code else f"응답 없음 ({err})"
        await asyncio.to_thread(raise_alert, "site_down", "", "", f"웹사이트 '{site['name']}' 접속 불가 — {why} ({url})")


async def loop():
    while True:
        await asyncio.gather(*(check(s) for s in sites()), return_exceptions=True)
        await asyncio.sleep(INTERVAL)


def summary() -> list[dict]:
    """For the AI analyst and the risk rules."""
    return [{"이름": s["name"], "url": s["url"], "정상": (state.get(s["url"]) or {}).get("ok"),
             "코드": (state.get(s["url"]) or {}).get("code")} for s in sites()]


class SiteBody(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    url: str = Field(min_length=8, max_length=300, pattern=r"^https?://[^\s]+$")


class UrlBody(BaseModel):
    url: str = Field(max_length=300)


@router.get("/api/sites")
def sites_list(request: Request):
    require_auth(request)
    return {"sites": [{**s, **state.get(s["url"], {})} for s in sites()], "interval": INTERVAL}


@router.post("/api/sites")
async def sites_add(request: Request, body: SiteBody):
    require_auth(request)
    with _cfg_lock:
        cfg = security.load_config()
        lst = cfg.setdefault("sites", [])
        if any(s["url"] == body.url for s in lst):
            raise HTTPException(400, "이미 등록된 주소입니다.")
        if len(lst) >= 50:
            raise HTTPException(400, "최대 50개까지 등록할 수 있습니다.")
        lst.append({"name": body.name.strip(), "url": body.url.strip()})
        security.save_config(cfg)
    request.state.event, request.state.detail = "action", f"site add {body.url}"
    await check({"name": body.name.strip(), "url": body.url.strip()})  # show a status right away
    return {"ok": True}


@router.post("/api/sites/delete")
def sites_delete(request: Request, body: UrlBody):
    require_auth(request)
    with _cfg_lock:
        cfg = security.load_config()
        cfg["sites"] = [s for s in cfg.get("sites", []) if s["url"] != body.url]
        security.save_config(cfg)
    state.pop(body.url, None)
    request.state.event, request.state.detail = "action", f"site delete {body.url}"
    return {"ok": True}
