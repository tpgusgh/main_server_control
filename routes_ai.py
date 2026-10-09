"""AI analyst: reports, chat, memory, and the auto-fix executors it may call."""

import asyncio
import ipaddress
import json
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

import agent
from node_agent import hostsec
import nodes
from core import BANNED, IP_LABELS, _security_config, ban, ban_key, db, is_trusted, labeled, local_name, raise_alert, require_auth
from monitor import _systemctl, load_events_data, managed_units, services_data, status_data
from routes_nodes import hub


router = APIRouter()


# Auto-fix executors. Each re-checks its own precondition right before acting, so the model can only
# pick among fixes the rules already justify; nothing here opens ports, unbans, or stops services.
def _fix_restart_local(unit: str):
    if unit not in managed_units() or unit == "llm.service":
        return False, "허용되지 않은 서비스"
    if _systemctl("show", unit, "-p", "ActiveState", "--value").stdout.strip() != "failed":
        return False, "이미 정상 상태"
    res = _systemctl("--no-block", "restart", unit)
    return res.returncode == 0, res.stderr.strip()[:200]


async def _fix_restart_node(nid: int, unit: str):
    node = hub.get(nid)
    svc = next((x for x in ((hub.state.get(nid) or {}).get("data") or {}).get("services", []) if x["unit"] == unit), None)
    if not node or not svc or svc.get("active") != "failed" or not svc.get("controllable", True):
        return False, "이미 정상 상태이거나 서버 없음"
    code, data = await hub.action(node, unit, "restart")
    return code == 200, data.get("detail", "")


def _fix_ban(ip: str, reason: str):
    if is_trusted(ip) or ban_key(ip) in BANNED or ipaddress.ip_address(ip) in nodes.TAILNET_V4:
        return False, "신뢰 IP·이미 차단·내부 IP는 차단하지 않음"
    last = db("SELECT ua, (SELECT country FROM access_log WHERE ip=?1 AND country != '' ORDER BY id DESC LIMIT 1) c "
              "FROM access_log WHERE ip=?1 ORDER BY id DESC LIMIT 1", (ip,), one=True)
    ban(ip, (last["c"] or "") if last else "", last["ua"] if last else "", 0,
        f"AI 자동 차단: {reason.removesuffix(' → 영구 차단')}", push=False)
    return True, ""


def _node_problems():
    failed, down = [], []
    for n in hub.nodes():
        st = hub.state.get(n["id"]) or {}
        if st.get("online") is False:
            down.append({"id": n["id"], "name": n["name"], "error": st.get("error")})
        for x in (st.get("data") or {}).get("services", []):
            if x.get("active") != "failed" or x["unit"] in agent.IGNORE_FAILED:
                continue
            if x.get("controllable", True):
                failed.append({"id": n["id"], "name": n["name"], "unit": x["unit"]})
            else:  # system unit, agent has no root: the AI can only tell you
                down.append({"id": n["id"], "name": n["name"],
                             "error": f"시스템 서비스 {x['unit']} 실패 — root 권한이 필요해 자동 재시작 불가 "
                                      f"(그 서버에서: sudo systemctl restart {x['unit']})"})
        data = st.get("data") or {}
        now = data.get("now") or {}
        if st.get("online") and ((now.get("temp") or 0) >= 85 or (now.get("disk") or 0) >= 92):
            down.append({"id": n["id"], "name": n["name"], "key": "hot",
                         "error": f"온도 {now.get('temp')}°C / 디스크 {now.get('disk')}%"})
        for p in now.get("ports", []):
            if p.get("public") and p["port"] != 22 and not _tailnet(p["ip"]):
                down.append({"id": n["id"], "name": n["name"], "key": f"port:{p['port']}", "once": True,
                             "error": f"포트 {p['port']}({p.get('process') or '?'})가 모든 네트워크({p['ip']})에 열려 있음 — "
                                      f"필요 없으면 닫거나 127.0.0.1/Tailscale 주소에만 바인딩하세요"})
    return {"failed": failed, "issues": down}


def _ssh_attackers():
    """SSH brute force on this server and every node: [{node, name, ip, fails, blocker, blocked}]."""
    out = []
    lst = hostsec.blocked()
    keys = {b["key"] for b in lst or []}
    for ip, c in hostsec.ssh_attackers(hostsec.ssh_events(1)).items():
        out.append({"node": None, "name": local_name(), "ip": ip, "fails": c, "blocker": lst is not None,
                    "blocked": ip in keys})
    for n in hub.nodes():
        hf = ((hub.state.get(n["id"]) or {}).get("data") or {}).get("host_facts") or {}
        nl = hf.get("blocker")
        nkeys = {b["key"] for b in nl or []}
        for ip, c in hostsec.ssh_attackers(hf.get("ssh")).items():
            out.append({"node": n["id"], "name": n["name"], "ip": ip, "fails": c, "blocker": nl is not None,
                        "blocked": ip in nkeys})
    return out


async def _fix_block_host(nid, ip: str, reason: str):
    if nid is None:
        return await asyncio.to_thread(hostsec.block, ip, reason)
    node = hub.get(nid)
    if not node:
        return False, "서버 없음"
    code, data = await hub._post(node, "/v1/block", {"ip": ip, "reason": reason[:150]})
    return code == 200, data.get("detail", "")


def _tailnet(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_loopback or a in nodes.TAILNET_V4 or a in nodes.TAILNET_V6


analyst = agent.Analyst(db=db, services_fn=lambda: services_data()["services"], units_fn=managed_units,
                        status_fn=status_data, events_fn=load_events_data, ip_labels=IP_LABELS,
                        is_trusted=is_trusted, config_fn=_security_config,
                        nodes_fn=lambda start=None, end=None: hub.summary(start, end), local_name_fn=local_name,
                        fixers={"restart_local": _fix_restart_local, "restart_node": _fix_restart_node,
                                "ban_ip": _fix_ban, "node_problems": _node_problems, "alert": raise_alert,
                                "ssh_attackers": _ssh_attackers, "block_host": _fix_block_host},
                        node_fn=lambda nid: (hub.get(nid), (hub.state.get(nid) or {}).get("data")),
                        node_ids_fn=lambda: [n["id"] for n in hub.nodes()])


def _check_node(node: int | None):
    if node is not None and not hub.get(node):
        raise HTTPException(404, "서버가 없습니다.")
_briefing_task: asyncio.Task | None = None
_chatting: set[int] = set()


@router.get("/api/ai/status")
async def ai_status(request: Request, node: int | None = None):
    require_auth(request)
    _check_node(node)
    health = await analyst.health()
    def load(sql, params=()):
        out = []
        for r in db(sql, params):
            d = dict(r)
            c = json.loads(d.pop("content"))
            d["summary"] = c.get("summary", "")[:240]
            d["rule_reasons"] = c.get("rule_reasons", [])
            out.append(d)
        return out
    reports = load("SELECT id, ts, trigger, risk, content, duration, tps FROM ai_reports "
                   "WHERE trigger != '일일' AND COALESCE(node_id, 0) = ? ORDER BY id DESC LIMIT 30", (node or 0,))
    daily = load("SELECT id, ts, trigger, risk, content, duration, tps, day FROM ai_reports "
                 "WHERE trigger = '일일' AND COALESCE(node_id, 0) = ? AND ts >= ? ORDER BY day DESC",
                 (node or 0, int(time.time()) - agent.REPORT_RETENTION))
    return {**health, "reports": reports, "daily": daily}


@router.get("/api/ai/report/{rid}")
def ai_report(request: Request, rid: int):
    require_auth(request)
    r = db("SELECT id, ts, trigger, risk, content, duration, tps, day FROM ai_reports WHERE id=?", (rid,), one=True)
    if not r:
        raise HTTPException(404, "보고서가 없습니다.")
    d = dict(r)
    d["content"] = json.loads(d["content"])
    return d


@router.get("/api/ai/actions")
def ai_actions(request: Request, server: str = ""):
    require_auth(request)
    where, params = ("WHERE server = ?", (server[:40],)) if server else ("", ())
    return {"actions": [labeled(r) for r in db(
        f"SELECT ts, kind, target, server, status, reason, ip FROM ai_actions {where} ORDER BY id DESC LIMIT 50", params)]}


class BriefBody(BaseModel):
    node: int | None = None


@router.post("/api/ai/briefing")
async def ai_briefing(request: Request, body: BriefBody | None = None):
    global _briefing_task
    require_auth(request)
    node = body.node if body else None
    _check_node(node)
    if analyst.lock.locked() or (_briefing_task and not _briefing_task.done()):
        raise HTTPException(409, f"AI가 이미 작업 중입니다 ({analyst.busy or '대기'}).")
    if not (await analyst.health())["online"]:
        raise HTTPException(503, "AI 서버(llm.service)가 꺼져 있습니다.")
    request.state.event = "ai"
    request.state.detail = "briefing"
    _briefing_task = asyncio.create_task(analyst.briefing("수동", node))
    return {"started": True}


class ChatTurn(BaseModel):
    role: str = Field(max_length=10)
    content: str = Field(max_length=2000)


class ChatBody(BaseModel):
    question: str = Field(min_length=1, max_length=500)
    history: list[ChatTurn] = Field(default_factory=list, max_length=12)
    node: int | None = None


@router.post("/api/ai/chat")
async def ai_chat(request: Request, body: ChatBody):
    s = require_auth(request)
    _check_node(body.node)
    if s["id"] in _chatting:
        raise HTTPException(429, "이전 질문의 답변이 끝난 뒤 다시 시도하세요.")
    if not (await analyst.health())["online"]:
        raise HTTPException(503, "AI 서버(llm.service)가 꺼져 있습니다.")
    request.state.event = "ai"
    request.state.detail = body.question[:100]
    _chatting.add(s["id"])

    async def gen():
        try:
            async for chunk in analyst.chat_stream(body.question, [t.model_dump() for t in body.history],
                                                   session_id=s["id"], ip=request.state.ip, node_id=body.node):
                yield chunk
        finally:
            _chatting.discard(s["id"])

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})


@router.get("/api/ai/memory")
def ai_memory(request: Request):
    require_auth(request)
    return {"memories": analyst.memories(), "max": agent.MAX_MEMORIES}


class MemoryBody(BaseModel):
    content: str = Field(min_length=1, max_length=300)


@router.post("/api/ai/memory")
def ai_memory_add(request: Request, body: MemoryBody):
    require_auth(request)
    request.state.event = "action"
    request.state.detail = "ai memory add"
    return analyst.add_memory(body.content, "manual")


class IdBody(BaseModel):
    id: int


@router.post("/api/ai/memory/delete")
def ai_memory_delete(request: Request, body: IdBody):
    require_auth(request)
    db("DELETE FROM ai_memory WHERE id=?", (body.id,))
    request.state.event = "action"
    request.state.detail = f"ai memory delete {body.id}"
    return {"ok": True}


@router.get("/api/ai/chats")
def ai_chats(request: Request, q: str = "", page: int = 0):
    require_auth(request)
    q, page = q.strip()[:50], max(page, 0)
    where, params = ("WHERE INSTR(LOWER(question || ' ' || answer), ?) > 0", [q.lower()]) if q else ("", [])
    total = db(f"SELECT COUNT(*) c FROM ai_chat {where}", params, one=True)["c"]
    rows = db(f"SELECT id, ts, ip, question, answer FROM ai_chat {where} ORDER BY id DESC LIMIT 20 OFFSET ?",
              (*params, page * 20))
    return {"total": total, "page": page, "chats": [labeled(r) for r in rows]}
