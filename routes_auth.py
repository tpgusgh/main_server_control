"""Pages, login/logout, access log, sessions, trusted IPs and bans."""

import asyncio
import ipaddress
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

import alerts
import cfaccess
import security
from core import ACCESS_RETENTION, BANNED, BAN_AFTER_FAILS, COOKIE, FAIL_WINDOW, GLOBAL_FAIL_SLOWDOWN, IP_LABELS, MIN_PASSWORD_LEN, PASSWORD_HASH, SESSION_IDLE, SESSION_MAX, STATIC, TRUSTED_EXTRA, TRUSTED_NETS, _cfg_lock, _hash_token, ban_ip, country_of, db, fails_since_reset, is_trusted, labeled, log_access, raise_alert, require_auth


router = APIRouter()

# ---------------------------------------------------------------- pages & auth


def page(name: str) -> HTMLResponse:
    """Stamp asset URLs with their mtime so a page never runs with a stale cached app.js/style.css."""
    html = (STATIC / name).read_text()
    for asset in ("app.js", "login.js", "style.css"):
        html = html.replace(f'/static/{asset}"', f'/static/{asset}?v={int((STATIC / asset).stat().st_mtime)}"')
    return HTMLResponse(html)


@router.get("/")
def index(request: Request):
    if request.state.session is None:
        return RedirectResponse("/login", status_code=303)
    return page("index.html")


@router.get("/login")
def login_page(request: Request):
    if request.state.session is not None:
        return RedirectResponse("/", status_code=303)
    return page("login.html")


@router.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")


class LoginBody(BaseModel):
    password: str = Field(max_length=256)
    otp: str = Field(default="", max_length=10)


@router.post("/api/login")
async def login(request: Request, body: LoginBody):
    ip, now = request.state.ip, int(time.time())
    if not PASSWORD_HASH:
        raise HTTPException(503, f"서버 .env 의 SM_PASSWORD 가 없거나 {MIN_PASSWORD_LEN}자 미만입니다.")
    cfg = security.load_config()
    trusted = is_trusted(ip)
    country = country_of(request)
    if trusted:
        fails = await run_in_threadpool(fails_since_reset, ip)
        if fails >= BAN_AFTER_FAILS:
            gap = min(60, 2 ** (fails - BAN_AFTER_FAILS + 1))
            last = db("SELECT MAX(ts) t FROM access_log WHERE ip=? AND event='login_fail'", (ip,), one=True)["t"] or 0
            if now - last < gap:
                request.state.event = "login_slow"
                return JSONResponse({"detail": f"로그인 실패가 많습니다. {gap - (now - last)}초 후 다시 시도하세요."},
                                    status_code=429, headers={"Retry-After": str(gap - (now - last))})

    global_fails = db("SELECT COUNT(*) c FROM access_log WHERE event='login_fail' AND ts>?",
                      (now - FAIL_WINDOW,), one=True)["c"]

    ok = await run_in_threadpool(security.verify_password, body.password, PASSWORD_HASH)
    if ok and cfg.get("totp_secret"):
        with _cfg_lock:
            cfg = security.load_config()
            counter = security.totp_match(cfg["totp_secret"], body.otp, cfg.get("totp_last", 0))
            if counter is None:
                ok = False
                request.state.detail = "otp"
            else:
                cfg["totp_last"] = counter
                security.save_config(cfg)

    if not ok:
        request.state.event = "login_fail"
        # Write the failure now (not in the middleware) so the count below includes it.
        await run_in_threadpool(log_access, request, 401, "login_fail", getattr(request.state, "detail", ""))
        request.state.event = "logged"
        fails = await run_in_threadpool(fails_since_reset, ip)
        await asyncio.sleep(3.0 if global_fails >= GLOBAL_FAIL_SLOWDOWN else 1.0)
        if trusted:
            await run_in_threadpool(raise_alert, "login_fail", ip, country,
                                    f"신뢰 IP에서 로그인 실패 (누적 {fails}회, 차단 안 함)", 300)
            return JSONResponse({"detail": "인증에 실패했습니다."}, status_code=401)
        if fails >= BAN_AFTER_FAILS:
            await run_in_threadpool(ban_ip, request, fails)
            return JSONResponse({"detail": "로그인 실패가 반복되어 이 IP는 영구 차단되었습니다."}, status_code=403)
        await run_in_threadpool(raise_alert, "login_fail", ip, country,
                                f"로그인 실패 {fails}/{BAN_AFTER_FAILS}회" + (f" · {request.state.email}" if request.state.email else ""))
        return JSONResponse({"detail": f"인증에 실패했습니다. {BAN_AFTER_FAILS - fails}번 더 틀리면 이 IP는 영구 차단됩니다."},
                            status_code=401)

    known = db("SELECT 1 FROM access_log WHERE ip=? AND event='login_ok' LIMIT 1", (ip,), one=True)
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    db("INSERT INTO sessions(token_hash,csrf,ip,ua,created,last_seen,email) VALUES(?,?,?,?,?,?,?)",
       (_hash_token(token), csrf, ip, request.headers.get("user-agent", "")[:300], now, now, request.state.email))
    request.state.event = "login_ok"
    if not known and not ipaddress.ip_address(ip).is_loopback:
        await run_in_threadpool(raise_alert, "new_ip", ip, country,
                                "처음 보는 IP에서 로그인 성공" + (f" · {request.state.email}" if request.state.email else "") +
                                f"\n{request.headers.get('user-agent', '')[:120]}")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(COOKIE, token, max_age=SESSION_MAX, path="/", secure=True, httponly=True, samesite="strict")
    return resp


@router.post("/api/logout")
def logout(request: Request):
    s = require_auth(request)
    db("DELETE FROM sessions WHERE id=?", (s["id"],))
    request.state.event = "logout"
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return resp


@router.get("/api/me")
def me(request: Request):
    s = require_auth(request)
    cfg = security.load_config()
    return {"csrf": s["csrf"], "ip": request.state.ip, "label": labeled({"ip": request.state.ip})["label"],
            "trusted": is_trusted(request.state.ip), "email": request.state.email,
            "totp": bool(cfg.get("totp_secret")), "cf_access": cfaccess.ENABLED,
            "alert_channels": alerts.CHANNELS, "ban_after": BAN_AFTER_FAILS,
            "trusted_ips": [{"ip": str(n), "source": "env", "label": IP_LABELS.get(str(n.network_address))}
                            for n in TRUSTED_NETS] +
                           [{"ip": ip, "source": "dashboard", "label": lb} for ip, lb in TRUSTED_EXTRA.items()],
            "session_started": s["created"], "idle_timeout": SESSION_IDLE}

# ---------------------------------------------------------------- access log & sessions


@router.get("/api/access")
def access_log(request: Request, page: int = 0, ip: str = "", event: str = ""):
    require_auth(request)
    page = max(page, 0)
    where, params = ["1=1"], []
    if ip:
        where.append("ip = ?")
        params.append(ip[:64])
    if event:
        where.append("event = ?")
        params.append(event[:20])
    w = " AND ".join(where)
    total = db(f"SELECT COUNT(*) c FROM access_log WHERE {w}", params, one=True)["c"]
    rows = db(f"SELECT ts,ip,country,method,path,status,ua,event,detail,email FROM access_log WHERE {w} "
              "ORDER BY id DESC LIMIT 50 OFFSET ?", (*params, page * 50))
    return {"total": total, "page": page, "rows": [labeled(r) for r in rows]}


@router.get("/api/access/summary")
def access_summary(request: Request):
    require_auth(request)
    rows = db("SELECT ip, MAX(country) country, COUNT(*) hits, MIN(ts) first, MAX(ts) last, "
              "SUM(event='login_ok') logins, SUM(event='login_fail') fails "
              "FROM access_log GROUP BY ip ORDER BY last DESC LIMIT 200")
    return {"retention_days": ACCESS_RETENTION // 86400, "ips": [labeled(r) for r in rows]}


@router.get("/api/bans")
def bans(request: Request):
    require_auth(request)
    rows = db("SELECT key, ip, country, ts, fails, ua, reason FROM bans ORDER BY ts DESC")
    return {"bans": [labeled(r) for r in rows]}


class UnbanBody(BaseModel):
    key: str = Field(max_length=64)


@router.post("/api/bans/unban")
def unban(request: Request, body: UnbanBody):
    require_auth(request)
    row = db("SELECT ip, country FROM bans WHERE key=?", (body.key,), one=True)
    if not row:
        raise HTTPException(404, "차단 목록에 없습니다.")
    db("DELETE FROM bans WHERE key=?", (body.key,))
    BANNED.discard(body.key)
    # An 'unban' row for the target IP resets its failure count.
    db("INSERT INTO access_log(ts,ip,country,method,path,status,ua,event,detail,email) VALUES(?,?,?,?,?,?,?,?,?,?)",
       (int(time.time()), row["ip"], row["country"], "-", "-", 0, "", "unban", f"해제: {request.state.ip}", None))
    request.state.event = "action"
    request.state.detail = f"unban {body.key}"
    raise_alert("unban", row["ip"], row["country"], f"{request.state.ip} 에서 차단 해제")
    return {"ok": True}


@router.get("/api/alerts")
def alert_list(request: Request):
    require_auth(request)
    rows = db("SELECT ts, kind, ip, country, message FROM alerts ORDER BY id DESC LIMIT 100")
    return {"alerts": [labeled(r) for r in rows], "channels": alerts.CHANNELS}


@router.get("/api/sessions")
def sessions(request: Request):
    s = require_auth(request)
    rows = db("SELECT id, ip, ua, created, last_seen, email FROM sessions ORDER BY last_seen DESC")
    return {"sessions": [dict(labeled(r), current=(r["id"] == s["id"])) for r in rows]}


class TrustBody(BaseModel):
    ip: str = Field(max_length=64)
    label: str = Field(default="", max_length=20)


@router.post("/api/trusted/add")
def trusted_add(request: Request, body: TrustBody):
    require_auth(request)
    try:
        ip = str(ipaddress.ip_address(body.ip.strip()))  # single addresses only, never a whole range
    except ValueError:
        raise HTTPException(400, "IP 주소가 올바르지 않습니다.")
    label = body.label.strip() or "신뢰"
    with _cfg_lock:
        cfg = security.load_config()
        cfg.setdefault("trusted_extra", {})[ip] = label
        security.save_config(cfg)
    TRUSTED_EXTRA[ip] = label
    IP_LABELS[ip] = label
    request.state.event, request.state.detail = "action", f"trust ip {ip} ({label})"
    return {"ok": True}


@router.post("/api/trusted/remove")
def trusted_remove(request: Request, body: TrustBody):
    require_auth(request)
    ip = body.ip.strip()
    if ip not in TRUSTED_EXTRA:
        raise HTTPException(404, ".env 에 적힌 신뢰 IP는 .env 에서 지워야 합니다.")
    with _cfg_lock:
        cfg = security.load_config()
        cfg.get("trusted_extra", {}).pop(ip, None)
        security.save_config(cfg)
    if IP_LABELS.get(ip) == TRUSTED_EXTRA.pop(ip):
        IP_LABELS.pop(ip, None)
    request.state.event, request.state.detail = "action", f"untrust ip {ip}"
    return {"ok": True}


class RevokeBody(BaseModel):
    id: int | None = None
    others: bool = False


@router.post("/api/sessions/revoke")
def revoke(request: Request, body: RevokeBody):
    s = require_auth(request)
    request.state.event = "action"
    if body.others:
        db("DELETE FROM sessions WHERE id != ?", (s["id"],))
        request.state.detail = "revoke other sessions"
    elif body.id is not None:
        db("DELETE FROM sessions WHERE id = ?", (body.id,))
        request.state.detail = f"revoke session {body.id}"
    return {"ok": True}
