"""Host security helpers shared by the dashboard and server-agent (standard library only)."""
import ipaddress
import json
import re
import subprocess

SM_BLOCK = "/usr/local/sbin/sm-block"
INTERNAL = [ipaddress.ip_network(n) for n in ("100.64.0.0/10", "fd7a:115c:a1e0::/48")]

SSH_PATTERNS = [
    (re.compile(r"Accepted (\S+) for (\S+) from (\S+) port"), "login_ok"),
    (re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port"), "login_fail"),
    (re.compile(r"Invalid user (\S*) from (\S+) port"), "invalid_user"),
]


def ssh_events(days=7):
    """SSH logins (ok/failed) from the system journal. None if this user can't read it (needs group adm)."""
    try:
        res = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", f"-{days}d", "--no-pager", "-q",
                              "-o", "short-unix"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if not res.stdout and "permission" in res.stderr.lower():
        return None
    out = []
    for line in res.stdout.splitlines():
        ts, _, rest = line.partition(" ")
        msg = rest.split(": ", 1)[-1]
        for rx, kind in SSH_PATTERNS:
            m = rx.search(msg)
            if m:
                g = m.groups()
                user, ip, method = (g[0], g[1], "") if kind == "invalid_user" else (g[1], g[2], g[0])
                try:
                    out.append({"ts": int(float(ts)), "event": kind, "user": user[:32], "ip": ip, "method": method})
                except ValueError:
                    pass
                break
    return out[-300:]


def internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable: treat as "don't touch"
    return a.is_private or a.is_loopback or a.is_link_local or any(a in n for n in INTERNAL)


def ssh_attackers(events, min_fails: int = 5, window: int = 3600, now: float | None = None) -> dict:
    """{ip: failures in the last `window`s} for outside IPs that never logged in successfully."""
    import time
    now = now or time.time()
    good = {e["ip"] for e in events or [] if e["event"] == "login_ok"}
    fails = {}
    for e in events or []:
        if e["event"] != "login_ok" and e["ts"] >= now - window and e["ip"] not in good and not internal(e["ip"]):
            fails[e["ip"]] = fails.get(e["ip"], 0) + 1
    return {ip: c for ip, c in fails.items() if c >= min_fails}


SM_DIR = "/var/lib/sm-block"


def blocked():
    """Current block list, or None when install-blocker.sh hasn't been run on this machine."""
    try:
        with open(f"{SM_DIR}/public.json") as f:
            return json.load(f)["blocked"]
    except (OSError, ValueError, KeyError):
        return None


def _request(payload: dict, wait: float = 8.0):
    """Drop a request for the root sm-block service, then wait briefly for its verdict."""
    import os
    import secrets
    import time
    rid = secrets.token_hex(8)
    tmp, final = f"{SM_DIR}/requests/{rid}.tmp", f"{SM_DIR}/requests/{rid}.json"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        os.rename(tmp, final)  # complete file appears at once; the path unit only watches *.json
    except OSError:
        return False, "차단 도구가 설치되지 않았습니다 (그 서버에서 sudo bash ~/node_agent/install-blocker.sh)"
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.4)
        try:
            with open(f"{SM_DIR}/public.json") as f:
                res = json.load(f).get("results", {}).get(rid)
        except (OSError, ValueError):
            res = None
        if res:
            return bool(res["ok"]), res.get("msg", "")
    return True, "요청함 (처리 대기 중)"


def block(ip: str, reason: str = ""):
    return _request({"op": "add", "ip": ip, "reason": reason[:150]})


def unblock(key: str):
    return _request({"op": "del", "key": key})
