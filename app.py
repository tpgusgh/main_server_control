"""hi.mieung.kr — server load monitor & control panel."""

import asyncio
import ipaddress
import secrets
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

import cfaccess
from core import ALLOWED_HOSTS, ALLOWED_ORIGINS, BANNED, COOKIE, MAX_BODY, PUBLIC_HOST, SESSION_IDLE, SESSION_MAX, STATIC, _hash_token, ban_key, db, is_trusted, log_access
from monitor import sampler, sampler_loop
from routes_nodes import hub
from routes_ai import analyst


@asynccontextmanager
async def lifespan(_app):
    await asyncio.to_thread(sampler.sample)
    tasks = [asyncio.create_task(sampler_loop()), asyncio.create_task(analyst.loop()), asyncio.create_task(hub.loop()),
             asyncio.create_task(sites.loop()), asyncio.create_task(fleet.loop()), asyncio.create_task(secops.loop()),
             asyncio.create_task(discord_bot.run())]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(GZipMiddleware, minimum_size=1024)  # skips text/event-stream, so AI chat still streams

# ---------------------------------------------------------------- request pipeline


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    # Only trust Cloudflare's header when the request arrived via the local cloudflared.
    if peer in ("127.0.0.1", "::1"):
        cf = request.headers.get("cf-connecting-ip", "").strip()
        if cf:
            try:
                return str(ipaddress.ip_address(cf))
            except ValueError:
                pass
    return peer


def lookup_session(request: Request):
    token = request.cookies.get(COOKIE)
    if not token or len(token) > 100:
        return None
    row = db("SELECT * FROM sessions WHERE token_hash=?", (_hash_token(token),), one=True)
    if not row:
        return None
    now = int(time.time())
    if now - row["last_seen"] > SESSION_IDLE or now - row["created"] > SESSION_MAX:
        db("DELETE FROM sessions WHERE id=?", (row["id"],))
        return None
    if now - row["last_seen"] > 30:
        db("UPDATE sessions SET last_seen=? WHERE id=?", (now, row["id"]))
    return dict(row)


SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "connect-src 'self'; font-src 'self'; form-action 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'"),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
}

QUIET_PREFIXES = ("/api/status", "/api/metrics", "/api/services", "/api/network", "/api/sites", "/api/hoststatus",
                  "/api/access", "/api/sessions", "/api/me", "/api/bans", "/api/alerts", "/api/ai/status", "/api/ai/memory", "/api/ai/chats", "/api/ai/report", "/api/ai/actions",
                  "/api/nodes", "/api/disk", "/static/")

BANNED_PAGE = """<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>접근 차단</title><body style="font-family:system-ui;padding:40px;text-align:center">
<h1>접근이 차단되었습니다</h1><p>이 IP는 로그인 실패가 반복되어 영구 차단되었습니다.</p></body></html>"""
_banned_log_last: dict[str, float] = {}


def came_through_tunnel(request: Request) -> bool:
    h = request.headers
    return h.get("host") == PUBLIC_HOST or "cf-ray" in h or "cf-connecting-ip" in h


@app.middleware("http")
async def pipeline(request: Request, call_next):
    request.state.ip = client_ip(request)
    request.state.session = None
    request.state.event = None
    request.state.email = None

    def finish(resp):
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
        return resp

    host = request.headers.get("host", "")
    if host not in ALLOWED_HOSTS:
        return finish(JSONResponse({"detail": "bad host"}, status_code=421))
    try:
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return finish(JSONResponse({"detail": "too large"}, status_code=413))
    except ValueError:
        return finish(JSONResponse({"detail": "bad length"}, status_code=400))

    ip = request.state.ip
    key = ban_key(ip)
    if key in BANNED and not is_trusted(ip):
        if time.time() - _banned_log_last.get(key, 0) > 60:  # don't let a banned bot flood the log
            _banned_log_last[key] = time.time()
            await run_in_threadpool(log_access, request, 403, "banned")
        resp = Response(BANNED_PAGE, status_code=403, media_type="text/html")
        finish(resp)
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
        return resp

    if cfaccess.ENABLED and came_through_tunnel(request):
        claims = await run_in_threadpool(cfaccess.verify, request.headers.get("cf-access-jwt-assertion", ""))
        if claims is None:
            await run_in_threadpool(log_access, request, 403, "denied", "cloudflare access")
            return finish(JSONResponse({"detail": "Cloudflare Access 인증이 필요합니다."}, status_code=403))
        request.state.email = (claims.get("email") or "")[:120] or None

    request.state.session = await run_in_threadpool(lookup_session, request)

    if request.method not in ("GET", "HEAD"):
        # CSRF: same-origin check + per-session token for authenticated writes.
        if request.headers.get("origin") not in ALLOWED_ORIGINS:
            resp = JSONResponse({"detail": "bad origin"}, status_code=403)
            await run_in_threadpool(log_access, request, 403, "denied", "origin")
            return finish(resp)
        if request.url.path != "/api/login":
            s = request.state.session
            if not s or not secrets.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
                await run_in_threadpool(log_access, request, 403, "denied", "csrf/session")
                return finish(JSONResponse({"detail": "forbidden"}, status_code=403))

    resp = await call_next(request)
    if request.url.path.startswith("/static/"):
        finish(resp)
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    authed = request.state.session is not None
    quiet = authed and request.method == "GET" and request.url.path.startswith(QUIET_PREFIXES)
    if request.state.event == "logged":
        pass
    elif request.state.event or not quiet:
        ev = request.state.event or ("page" if authed else "anon")
        await run_in_threadpool(log_access, request, resp.status_code, ev, getattr(request.state, "detail", ""))
    return finish(resp)


app.mount("/static", StaticFiles(directory=STATIC), name="static")


import monitor  # noqa: E402  (routers last: they import from modules above)
import routes_ai  # noqa: E402
import routes_auth  # noqa: E402
import routes_nodes  # noqa: E402
import sites  # noqa: E402
import fleet  # noqa: E402
import secops  # noqa: E402
import discord_bot  # noqa: E402

app.include_router(monitor.router)
app.include_router(routes_auth.router)
app.include_router(routes_nodes.router)
app.include_router(routes_ai.router)
app.include_router(sites.router)
app.include_router(fleet.router)
app.include_router(secops.router)
