"""Other servers in the Tailscale network."""

import socket
import subprocess
import time

import psutil
from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

import nodes
import security
from core import _cfg_lock, confirm_password, country_of, db, local_name, raise_alert, require_auth
from monitor import POWER_LABEL, KeyBody, PowerBody, sampler


router = APIRouter()


hub = nodes.NodeHub(db, raise_alert)


# ---------------------------------------------------------------- servers in the tailnet


class EditBody(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    memo: str = Field(default="", max_length=300)
    address: str = Field(default="", max_length=120)
    token: str = Field(default="", max_length=200)


class NodeBody(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    address: str = Field(min_length=3, max_length=120)
    token: str = Field(min_length=20, max_length=200)


_ts_cache: list = []


def _ts_ip() -> str | None:
    """This machine's Tailscale IPv4 (what new nodes must allow), looked up once."""
    if not _ts_cache:
        try:
            out = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=5).stdout.split()
        except (OSError, subprocess.SubprocessError):
            out = []
        _ts_cache.append(out[0] if out else None)
    return _ts_cache[0]


@router.get("/api/nodes")
def nodes_list(request: Request):
    require_auth(request)
    n = sampler.latest
    local = {"name": local_name(), "memo": security.load_config().get("local_memo", ""), "ts_ip": _ts_ip(),
             "host": socket.gethostname(), "uptime": time.time() - psutil.boot_time(),
             "now": {k: n.get(k) for k in ("cpu", "mem", "temp", "disk", "load")}, "online": True}
    return {"local": local, "nodes": [hub.public(x) for x in hub.nodes()]}


@router.post("/api/local/edit")
def local_edit(request: Request, body: EditBody):
    require_auth(request)
    with _cfg_lock:
        cfg = security.load_config()
        cfg["local_name"], cfg["local_memo"] = body.name.strip(), body.memo.strip()
        security.save_config(cfg)
    request.state.event, request.state.detail = "action", f"edit local server -> {body.name.strip()}"
    return {"ok": True}


@router.post("/api/nodes")
async def nodes_add(request: Request, body: NodeBody):
    require_auth(request)
    request.state.event, request.state.detail = "action", f"add server {body.name.strip()} {body.address.strip()}"
    try:
        return await hub.add(body.name.strip(), body.address, body.token.strip())
    except ValueError as e:
        raise HTTPException(400, str(e))


def _node_or_404(nid: int) -> dict:
    node = hub.get(nid)
    if not node:
        raise HTTPException(404, "서버가 없습니다.")
    return node


@router.post("/api/nodes/{nid}/edit")
async def nodes_edit(request: Request, nid: int, body: EditBody):
    require_auth(request)
    _node_or_404(nid)
    request.state.event, request.state.detail = "action", f"edit server {nid} -> {body.name.strip()}"
    try:
        await hub.edit(nid, body.name.strip(), body.memo.strip(), body.address.strip(), body.token.strip())
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@router.post("/api/nodes/{nid}/delete")
def nodes_delete(request: Request, nid: int):
    require_auth(request)
    node = _node_or_404(nid)
    hub.delete(nid)
    request.state.event, request.state.detail = "action", f"remove server {node['name']}"
    return {"ok": True}


@router.get("/api/nodes/{nid}/metrics")
def nodes_metrics(request: Request, nid: int, hours: float = 24):
    require_auth(request)
    _node_or_404(nid)
    return hub.history(nid, hours)


@router.post("/api/nodes/{nid}/process/{pid}/terminate")
async def nodes_terminate(request: Request, nid: int, pid: int):
    require_auth(request)
    node = _node_or_404(nid)
    request.state.event, request.state.detail = "action", f"terminate pid {pid} @ {node['name']}"
    code, data = await hub.terminate(node, pid)
    if code != 200:
        raise HTTPException(code if 400 <= code < 600 else 502, data.get("detail", "실패"))
    return data


@router.post("/api/nodes/{nid}/services/{unit}/{action}")
async def nodes_service_action(request: Request, nid: int, unit: str, action: str):
    require_auth(request)
    node = _node_or_404(nid)
    request.state.event, request.state.detail = "action", f"{action} {unit} @ {node['name']}"
    code, data = await hub.action(node, unit, action)
    if code != 200:
        raise HTTPException(code if 400 <= code < 600 else 502, data.get("detail", "실패"))
    return data


@router.post("/api/nodes/{nid}/power")
async def nodes_power(request: Request, nid: int, body: PowerBody):
    require_auth(request)
    node = _node_or_404(nid)
    if body.confirm.strip() != node["name"]:
        raise HTTPException(400, "서버 이름이 일치하지 않습니다.")
    if not await run_in_threadpool(confirm_password, request, body.password):
        raise HTTPException(403, "비밀번호가 틀렸습니다.")
    request.state.event, request.state.detail = "action", f"power {body.action} @ {node['name']}"
    code, data = await hub._post(node, f"/v1/power/{body.action}")
    if code != 200:
        raise HTTPException(code if 400 <= code < 600 else 502, data.get("detail", "실패"))
    await run_in_threadpool(raise_alert, "power", request.state.ip, country_of(request),
                            f"서버 '{node['name']}' {POWER_LABEL[body.action]} 실행", 0, True)
    return {"ok": True}


@router.post("/api/nodes/{nid}/hostblock/remove")
async def nodes_hostblock_remove(request: Request, nid: int, body: KeyBody):
    require_auth(request)
    node = _node_or_404(nid)
    request.state.event, request.state.detail = "action", f"firewall unblock {body.key} @ {node['name']}"
    code, data = await hub._post(node, "/v1/unblock", {"key": body.key})
    if code != 200:
        raise HTTPException(code if 400 <= code < 600 else 502, data.get("detail", "실패"))
    return data
