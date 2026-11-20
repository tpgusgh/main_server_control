"""Pure rules for notifications, the activity history and the Discord commands (no database, no network)."""
import re
from pathlib import Path

VERB_KR = {"start": "서비스 켜기", "stop": "서비스 끄기", "restart": "서비스 다시 켜기",
           "enable": "부팅 시 자동 실행 켜기", "disable": "부팅 시 자동 실행 끄기", "delete": "서비스 삭제"}
_VERBS = "|".join(VERB_KR)
_UNIT = r"[A-Za-z0-9@._-]+"
UNIT_RE = re.compile(rf"^{_UNIT}$")

# ---------------------------------------------------------------- quiet hours


def valid_hhmm(s) -> bool:
    return bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(s)))


def _mins(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def in_quiet(now_hhmm: str, start: str, end: str) -> bool:
    """Is `now` inside [start, end)? The window may wrap past midnight (23:00–07:00); start == end means never."""
    n, a, b = _mins(now_hhmm), _mins(start), _mins(end)
    if a == b:
        return False
    return a <= n < b if a < b else (n >= a or n < b)


def should_hold(level: str, cfg: dict | None, now_hhmm: str) -> bool:
    """Quiet hours hold everything except critical alerts (they always get through)."""
    if not cfg or not cfg.get("enabled") or level == "critical":
        return False
    return in_quiet(now_hhmm, cfg.get("start", "23:00"), cfg.get("end", "07:00"))


def digest(rows: list[tuple[str, str]]) -> tuple[str, list[str]]:
    """[(alert title, message)] held during quiet hours → (headline, bullet lines grouped by title)."""
    groups: dict[str, list[str]] = {}
    for title, message in rows:
        groups.setdefault(title, []).append((message or "").strip().split("\n", 1)[0])
    lines = []
    for title, msgs in list(groups.items())[:10]:
        lines.append(f"{title}" + (f" ×{len(msgs)}" if len(msgs) > 1 else "") + (f" — {msgs[-1][:80]}" if msgs[-1] else ""))
    return f"조용한 시간 동안 알림 {len(rows)}건", lines


# ---------------------------------------------------------------- activity history wording


def humanize_action(event: str, detail: str) -> str:
    """The dashboard logs actions in a terse English shorthand; say it in plain Korean."""
    d = (detail or "").strip()
    if event == "upgrade":
        return f"패키지 업그레이드: {d}"
    if event == "unban":
        return f"차단 해제: {d.removeprefix('해제: ')}"
    rules = [
        (rf"^({_VERBS}) ({_UNIT}) @ (.+)$", lambda m: f"{VERB_KR[m[1]]}: {m[2]} (서버 {m[3]})"),
        (rf"^({_VERBS}) ({_UNIT}) \(system\)$", lambda m: f"{VERB_KR[m[1]]}: {m[2]} (시스템 서비스)"),
        (rf"^({_VERBS}) ({_UNIT})$", lambda m: f"{VERB_KR[m[1]]}: {m[2]}"),
        (r"^power (reboot|poweroff) \((.+)\)$", lambda m: f"서버 {'재부팅' if m[1] == 'reboot' else '종료'} ({m[2]})"),
        (r"^power (reboot|poweroff) @ (.+)$", lambda m: f"서버 {'재부팅' if m[1] == 'reboot' else '종료'}: {m[2]}"),
        (r"^terminate pid (\d+) \((.*)\)$", lambda m: f"프로세스 종료: {m[2]} (PID {m[1]})"),
        (r"^unban (\S+)$", lambda m: f"차단 해제: {m[1]}"),
        (r"^schedule reboot (.+)$", lambda m: f"예약 재부팅 등록: {m[1]}"),
        (r"^delete reboot schedule (\d+)$", lambda m: "예약 재부팅 삭제"),
        (r"^guard (.+?) \{.*\}$", lambda m: f"외부 차단 설정 변경: {m[1]}"),
        (r"^wake (.+)$", lambda m: f"Wake-on-LAN: {m[1]}"),
        (r"^update agent (.+)$", lambda m: f"에이전트 업데이트: {m[1]}"),
        (r"^site (add|delete) (\S+)$", lambda m: f"웹사이트 감시 {'추가' if m[1] == 'add' else '삭제'}: {m[2]}"),
        (r"^remove server (.+)$", lambda m: f"서버 삭제: {m[1]}"),
        (r"^forget device (\d+)$", lambda m: "기억된 기기 삭제"),
        (r"^quiet hours (on|off) (\S+)-(\S+)$", lambda m: f"알림 조용한 시간 {'켜기' if m[1] == 'on' else '끄기'} ({m[2]}~{m[3]})"),
        (r"^discord (.+)$", lambda m: f"디스코드: {m[1]}"),
    ]
    for rx, fmt in rules:
        m = re.match(rx, d)
        if m:
            return fmt(m)
    return d


# ---------------------------------------------------------------- Discord commands

COMMANDS = {"상태": "status", "status": "status", "서비스": "services", "services": "services", "전력": "power", "power": "power",
            "재시작": "restart", "restart": "restart", "차단목록": "bans", "bans": "bans", "차단해제": "unban", "unban": "unban",
            "도움": "help", "help": "help", "?": "help"}


def parse_command(text: str) -> tuple[str, list[str]] | None:
    words = " ".join((text or "").split()).split(" ")
    cmd = COMMANDS.get(words[0].lower()) if words and words[0] else None
    return (cmd, words[1:]) if cmd else None


def restart_target(args: list[str]) -> tuple[str, str] | None:
    """`재시작 worldrium 서브서버 1` → ("worldrium.service", "서브서버 1"); the server name may contain spaces."""
    if not args or not UNIT_RE.match(args[0]):
        return None
    unit = args[0] if args[0].endswith(".service") else args[0] + ".service"
    return unit, " ".join(args[1:])


def restart_id(node: int | None, unit: str) -> str:
    return f"rs:{'main' if node is None else node}:{unit}"[:100]


def parse_restart_id(custom_id: str) -> tuple[int | None, str] | None:
    m = re.fullmatch(rf"rs:(main|\d+):({_UNIT})", custom_id)
    return (None if m[1] == "main" else int(m[1]), m[2]) if m else None


def admin_unit_files(directory: str = "/etc/systemd/system") -> set[str]:
    """Regular *.service files in /etc/systemd/system (symlinks are enable-links, not units made by the admin).
    A stopped service is unloaded and vanishes from `systemctl list-units`, but its file stays."""
    try:
        return {p.name for p in Path(directory).glob("*.service") if p.is_file() and not p.is_symlink() and UNIT_RE.match(p.name)}
    except OSError:
        return set()
