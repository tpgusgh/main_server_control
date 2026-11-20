"""Pure health rules for the dashboard (no database, no network): wording of the boot summary and the
SMART verdict. Kept apart from fleet.py so they can be unit-tested."""

RANK = {"ok": 0, "warn": 1, "crit": 2}


def fmt_secs(s: float) -> str:
    s = float(s or 0)
    return f"{int(s // 60)}분 {s % 60:.0f}초" if s >= 60 else f"{s:.1f}초"


def boot_lines(info: dict | None, ignore=()) -> list[str]:
    """Lines for the 'rebooted' alert: how long boot took, what was slow, what failed. [] when unknown."""
    if not info or not info.get("total_s"):
        return []
    p = info.get("parts") or {}
    lines = [f"부팅 {fmt_secs(info['total_s'])} (커널 {fmt_secs(p.get('kernel', 0))} + 유저 {fmt_secs(p.get('userspace', 0))})"]
    slow = [(f["unit"], f["secs"], True) for f in info.get("failed") or [] if f["secs"] >= 5]
    slow += [(u, s, False) for u, s in info.get("slow") or [] if s >= 5 and u not in {x[0] for x in slow}]
    slow.sort(key=lambda x: -x[1])
    if slow:
        lines.append("오래 걸린 서비스: " + ", ".join(f"{u} {fmt_secs(s)}{' (실패)' if failed else ''}" for u, s, failed in slow[:3]))
    if any(u.startswith("systemd-networkd-wait-online") for u, _, _ in slow):
        lines.append("💡 랜선이 없는 네트워크를 기다리는 중이에요 — node_agent/fix-wait-online.sh 로 해결돼요")
    elif p.get("userspace", 0) > 60 and not slow:
        lines.append("부팅이 오래 걸렸지만 원인 서비스를 찾지 못했어요 (systemd-analyze critical-chain 확인)")
    failed = [f["unit"] for f in info.get("failed") or [] if f["unit"] not in ignore]
    lines.append("실패한 서비스: " + ", ".join(failed) if failed else "실패한 서비스 없음 ✅")
    return lines


def smart_assess(dev: dict) -> dict:
    """{"level": ok|warn|crit, "notes": [...], "wear": % used or None} for one disk's SMART facts."""
    level, notes, wear = "ok", [], None

    def bump(to: str, note: str):
        nonlocal level
        if RANK[to] > RANK[level]:
            level = to
        notes.append(note)

    if dev.get("error"):
        return {"level": "warn", "notes": [dev["error"]], "wear": None}
    if dev.get("passed") is False:
        bump("crit", "SMART 자체 점검에서 실패로 판정됐어요")
    nv = dev.get("nvme")
    if nv:
        if nv.get("critical_warning"):
            bump("crit", f"NVMe 경고 플래그가 켜져 있어요 ({nv['critical_warning']})")
        wear = nv.get("percentage_used")
        if wear is not None:
            if wear >= 90:
                bump("crit", f"수명의 {wear}%를 썼어요")
            elif wear >= 80:
                bump("warn", f"수명의 {wear}%를 썼어요")
        spare, floor = nv.get("available_spare"), nv.get("available_spare_threshold", 10)
        if spare is not None and spare <= max(floor, 10):
            bump("crit", f"여유 공간(예비 셀)이 {spare}%로 바닥이에요")
        if nv.get("media_errors"):
            bump("warn", f"미디어 오류가 {nv['media_errors']}건 있어요")
    ata = dev.get("ata") or {}
    for aid, label in (("5", "재할당된 섹터"), ("197", "대기 중인 불량 섹터"), ("198", "수정 불가능한 섹터")):
        raw = (ata.get(aid) or {}).get("raw")
        if raw:
            bump("crit" if aid == "5" and raw >= 50 else "warn", f"{label}가 {raw}개 있어요")
    for aid in ("231", "233", "202", "177"):  # normalized value = remaining life, 100 when new
        v = (ata.get(aid) or {}).get("value")
        if v is not None and 0 < v <= 100:
            wear = 100 - v
            if v <= 10:
                bump("crit", f"남은 수명이 {v}%예요")
            elif v <= 20:
                bump("warn", f"남은 수명이 {v}%예요")
            break
    temp = dev.get("temp")
    if temp is not None:
        if temp >= 75:
            bump("crit", f"온도가 {temp}°C예요")
        elif temp >= 65:
            bump("warn", f"온도가 {temp}°C예요")
    return {"level": level, "notes": notes, "wear": wear}
