"use strict";

// ---------------------------------------------------------------- helpers

const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

/** Build an element. All text goes through textContent — never innerHTML — so logged
 *  values (User-Agent, paths) from strangers can't inject markup. */
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}
function s(tag, attrs) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}
/** replaceChildren that skips empty (null/false) slots instead of printing "null". */
function put(el, ...kids) { el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false)); }
function fill(tbody, rows, cols, emptyText) {
  tbody.replaceChildren(...(rows.length ? rows : [h("tr", { class: "empty-row" }, h("td", { colspan: cols }, emptyText))]));
}

const fmtBytes = (b) => {
  if (b == null) return "–";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(b >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
};
const fmtRate = (b) => `${fmtBytes(b)}/s`;
const pad = (n) => String(n).padStart(2, "0");
const fmtTime = (ts) => { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const fmtDateTime = (ts) => {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
/** systemd start time: unix seconds (shown in the viewer's time zone), or a raw string from an old agent. */
const fmtSince = (v) => (typeof v === "number" ? fmtDateTime(v) : v || "–");
const fmtAgo = (ts) => {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "방금";
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  return `${Math.floor(s / 86400)}일 전`;
};
const fmtDur = (sec) => {
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d}일 ${hh}시간` : hh ? `${hh}시간 ${m}분` : m ? `${m}분` : `${Math.max(0, Math.round(sec))}초`;
};
const ipCell = (r, text) => h("td", { class: "mono" }, text || r.ip,
  r.label ? h("span", { class: "pill me" }, r.label) : null,
  r.trusted && !r.label ? h("span", { class: "pill me" }, "신뢰") : null,
  r.banned ? h("span", { class: "pill crit" }, "차단됨") : null);
/** ISO country code (from Cloudflare) → "🇳🇱 네덜란드". Browser-built-in names, no data file needed. */
let regionNames = null;
try { regionNames = new Intl.DisplayNames(["ko"], { type: "region" }); } catch {}
function countryText(code) {
  if (!code) return "–";
  if (code === "T1") return "Tor 네트워크";
  if (!/^[A-Z]{2}$/.test(code)) return code;
  const flag = String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
  let name = code;
  try { name = (regionNames && regionNames.of(code)) || code; } catch {}
  return `${flag} ${name}`;
}
const countryCell = (code) => h("td", { title: code || "", class: "nowrap" }, countryText(code));
const level = (v, warn, crit) => (v == null ? "" : v >= crit ? "crit" : v >= warn ? "warn" : "");

function toast(msg, isErr) {
  const t = h("div", { class: "toast" + (isErr ? " err" : ""), role: "status" }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), 3500);
}

function confirmDialog(title, text, danger) {
  const dlg = $("confirm");
  $("confirmTitle").textContent = title;
  $("confirmText").textContent = text;
  $("confirmYes").className = "btn " + (danger ? "danger" : "primary");
  return new Promise((resolve) => {
    const done = (v) => { dlg.close(); $("confirmYes").onclick = $("confirmNo").onclick = null; resolve(v); };
    $("confirmYes").onclick = () => done(true);
    $("confirmNo").onclick = () => done(false);
    dlg.oncancel = () => done(false);
    dlg.showModal();
  });
}

// ---------------------------------------------------------------- api

let CSRF = "";
async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    ...opts,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF, ...(opts.headers || {}) },
  });
  if (res.status === 401) { location.replace("/login"); throw new Error("unauthorized"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `오류 ${res.status}`);
  return data;
}
const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

// ---------------------------------------------------------------- theme

const THEMES = ["auto", "light", "dark"];
const THEME_LABEL = { auto: "테마: 자동", light: "테마: 라이트", dark: "테마: 다크" };
let theme = "auto";
try { theme = localStorage.getItem("sm-theme") || "auto"; } catch {}
function applyTheme() {
  if (theme === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", theme);
  $("themeBtn").textContent = THEME_LABEL[theme];
}
$("themeBtn").addEventListener("click", () => {
  theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
  try { localStorage.setItem("sm-theme", theme); } catch {}
  applyTheme();
  renderCharts();
});
applyTheme();

// ---------------------------------------------------------------- line chart

/** Single-series line chart with threshold line, crosshair and tooltip.
 *  Gaps longer than 3 buckets (server was off) break the line instead of bridging it. */
function lineChart(box, pts, { yMax, unit, threshold, fmt, bucket, hours }) {
  box.replaceChildren();
  const W = box.clientWidth || 400, H = box.clientHeight || 170;
  const m = { l: 36, r: 8, t: 8, b: 22 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
  box.append(svg);

  const now = Date.now() / 1000, t0 = now - hours * 3600;
  const vals = pts.filter((p) => p.v != null);
  const top = yMax ?? Math.max(1, ...vals.map((p) => p.v)) * 1.15;
  const x = (t) => m.l + ((t - t0) / (now - t0)) * iw;
  const y = (v) => m.t + ih - (Math.min(v, top) / top) * ih;

  // grid + y ticks
  for (let i = 0; i <= 4; i++) {
    const v = (top / 4) * i, yy = y(v);
    svg.append(s("line", { x1: m.l, x2: W - m.r, y1: yy, y2: yy, class: i === 0 ? "baseline" : "gridline" }));
    const tk = s("text", { x: m.l - 6, y: yy + 3.5, "text-anchor": "end", class: "tick" });
    tk.textContent = fmt(v, true);
    svg.append(tk);
  }
  // x ticks
  const step = hours <= 1 ? 900 : hours <= 6 ? 3600 : 4 * 3600;
  for (let t = Math.ceil(t0 / step) * step; t <= now; t += step) {
    const tk = s("text", { x: x(t), y: H - 6, "text-anchor": "middle", class: "tick" });
    tk.textContent = fmtTime(t);
    svg.append(tk);
  }

  if (!vals.length) {
    const e = s("text", { x: m.l + iw / 2, y: m.t + ih / 2, "text-anchor": "middle", class: "empty" });
    e.textContent = "수집된 데이터가 아직 없습니다";
    svg.append(e);
    return;
  }

  // split into contiguous segments
  const segs = [];
  let cur = [];
  for (const p of vals) {
    if (cur.length && p.t - cur[cur.length - 1].t > bucket * 3) { segs.push(cur); cur = []; }
    cur.push(p);
  }
  if (cur.length) segs.push(cur);
  for (const seg of segs) {
    const d = seg.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join("");
    svg.append(s("path", { d: `${d}L${x(seg[seg.length - 1].t).toFixed(1)},${y(0)}L${x(seg[0].t).toFixed(1)},${y(0)}Z`, class: "area" }));
    svg.append(s("path", { d, class: "line" }));
  }

  if (threshold != null && threshold < top) {
    const ty = y(threshold);
    svg.append(s("line", { x1: m.l, x2: W - m.r, y1: ty, y2: ty, class: "thresh" }));
    const tl = s("text", { x: W - m.r - 2, y: ty - 4, "text-anchor": "end", class: "thresh-label" });
    tl.textContent = `경고 ${fmt(threshold)}`;
    svg.append(tl);
  }

  // hover layer
  const cross = s("line", { y1: m.t, y2: m.t + ih, class: "cross", visibility: "hidden" });
  const dot = s("circle", { r: 4.5, class: "marker", visibility: "hidden" });
  svg.append(cross, dot);
  const tip = h("div", { class: "tooltip hidden" });
  box.append(tip);
  const hit = s("rect", { x: m.l, y: 0, width: iw, height: H, fill: "transparent" });
  svg.append(hit);
  const hide = () => { cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); tip.classList.add("hidden"); };
  hit.addEventListener("pointerleave", hide);
  hit.addEventListener("pointermove", (ev) => {
    const r = svg.getBoundingClientRect();
    const px = ((ev.clientX - r.left) / r.width) * W;
    const t = t0 + ((px - m.l) / iw) * (now - t0);
    let best = vals[0];
    for (const p of vals) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
    if (Math.abs(best.t - t) > bucket * 3) return hide();
    const bx = x(best.t), by = y(best.v);
    cross.setAttribute("x1", bx); cross.setAttribute("x2", bx); cross.setAttribute("visibility", "visible");
    dot.setAttribute("cx", bx); dot.setAttribute("cy", by); dot.setAttribute("visibility", "visible");
    tip.replaceChildren(h("span", { class: "muted" }, fmtTime(best.t) + "  "), h("b", {}, fmt(best.v)),
      best.max != null && best.max - best.v >= 1 ? h("span", { class: "muted" }, `  (최대 ${fmt(best.max)})`) : null);
    tip.classList.remove("hidden");
    const left = (bx / W) * r.width;
    tip.style.left = `${Math.min(Math.max(left - tip.offsetWidth / 2, 0), r.width - tip.offsetWidth)}px`;
    tip.style.top = `${Math.max((by / H) * r.height - 40, -8)}px`;
  });
}

// ---------------------------------------------------------------- overview

let hours = 24, metricData = null, thresholds = { cpu: 80, mem: 90, temp: 85 };

function tile(label, value, unit, foot, pct, lvl) {
  const meter = pct != null ? h("div", { class: "meter" }, h("i", { class: lvl })) : null;
  if (meter) meter.firstChild.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  return h("div", { class: "card tile" },
    h("div", { class: "label" }, label, lvl === "crit" ? h("span", { class: "pill crit" }, "위험") : lvl === "warn" ? h("span", { class: "pill warn" }, "주의") : null),
    h("div", { class: "value num" }, value, h("span", { class: "unit" }, unit)),
    h("div", { class: "foot" }, foot), meter);
}

let lastStatusAt = 0;
let homeTimer;
async function loadHomeDu() {
  const d = await api("/api/disk/home");
  const max = d.dirs.length ? d.dirs[0].size : 1;
  $("homeMeta").textContent = d.running ? "계산 중… (낮은 우선순위로 실행)" : d.ts
    ? `${fmtAgo(d.ts)} 계산 · 홈 전체 ${fmtBytes(d.total)} · 디스크 여유 ${fmtBytes(d.disk.free)}` : "";
  $("homeRefresh").disabled = d.running;
  put($("homeDu"), d.dirs.length ? d.dirs.slice(0, 20).map((x) => {
    const bar = h("div", { class: "meter" }, h("i", {}));
    bar.firstChild.style.width = `${(x.size / max) * 100}%`;
    return h("li", {}, h("span", { class: "mono" }, x.path), h("span", { class: "num" }, fmtBytes(x.size)), bar);
  }) : h("li", { class: "muted" }, d.running ? "폴더 크기를 계산하는 중입니다…" : (d.error || "데이터 없음")));
  clearTimeout(homeTimer);
  if (d.running) homeTimer = setTimeout(() => loadHomeDu().catch(() => {}), 5000);
}
$("homeRefresh").addEventListener("click", async () => { await post("/api/disk/home/refresh"); loadHomeDu(); });

let lastStatus = null;
async function loadStatus() {
  const st = await api("/api/status");
  lastStatusAt = Date.now();
  lastStatus = st;
  const n = st.now;
  if (currentNode == null) applyView();
  $("tiles").replaceChildren(
    tile("CPU", n.cpu.toFixed(1), "%", `${st.cpu_count}코어${st.cpu_freq ? ` · ${(st.cpu_freq / 1000).toFixed(2)} GHz` : ""}`, n.cpu, level(n.cpu, 60, thresholds.cpu)),
    tile("메모리", n.mem.toFixed(1), "%", `${fmtBytes(n.mem_used)} / ${fmtBytes(n.mem_total)}`, n.mem, level(n.mem, 75, thresholds.mem)),
    tile("CPU 온도", n.temp != null ? n.temp.toFixed(0) : "–", "°C", "패키지 온도", n.temp, level(n.temp, 70, thresholds.temp)),
    tile("로드 평균", n.load[0].toFixed(2), "", `5분 ${n.load[1].toFixed(2)} · 15분 ${n.load[2].toFixed(2)}`, (n.load[0] / st.cpu_count) * 100, level(n.load[0] / st.cpu_count, 0.8, 1.2)),
    tile("스왑", n.swap.toFixed(1), "%", `${fmtBytes(n.swap_used)} / ${fmtBytes(n.swap_total)}`, n.swap, level(n.swap, 50, 80)),
    tile("디스크 /", n.disk.toFixed(0), "%", "루트 파티션", n.disk, level(n.disk, 80, 92)),
    tile("네트워크 수신", fmtRate(n.net_rx), "", `송신 ${fmtRate(n.net_tx)}`, null, ""),
  );
  $("cpuNow").textContent = `${n.cpu.toFixed(1)}%`;
  $("memNow").textContent = `${n.mem.toFixed(1)}%`;
  $("tempNow").textContent = n.temp != null ? `${n.temp.toFixed(0)}°C` : "–";
  $("loadNow").textContent = n.load[0].toFixed(2);

  fill($("procs"), st.top.map((p) => h("tr", {},
    h("td", { title: p.cmd }, p.name), h("td", { class: "num" }, p.pid), h("td", { class: "muted" }, p.user || "–"),
    h("td", { class: "r num" }, `${p.cpu.toFixed(1)}%`), h("td", { class: "r num" }, `${p.mem.toFixed(1)}%`))), 5, "–");
  fill($("temps"), st.temps.map((t) => h("tr", {},
    h("td", {}, t.label, h("span", { class: "muted" }, t.label !== t.chip ? ` · ${t.chip}` : "")),
    h("td", { class: "r num" }, `${t.current.toFixed(0)}°C`),
    h("td", { class: "r num muted" }, t.high ? `${t.high.toFixed(0)}°C` : "–"),
    h("td", { class: "r num muted" }, t.critical ? `${t.critical.toFixed(0)}°C` : "–"))), 4, "온도 센서를 찾지 못했습니다");
  fill($("disks"), st.disks.map((d) => {
    const bar = h("div", { class: "meter" }, h("i", { class: level(d.percent, 80, 92) }));
    bar.firstChild.style.width = `${d.percent}%`;
    return h("tr", {}, h("td", { class: "mono" }, d.mount), h("td", { class: "r num" }, fmtBytes(d.used)),
      h("td", { class: "r num" }, fmtBytes(d.total)), h("td", {}, h("span", { class: "num" }, `${d.percent}%`), bar));
  }), 4, "–");
}

async function loadMetrics() {
  metricData = await api(`/api/metrics?hours=${hours}`);
  renderCharts();
}

function renderCharts() {
  if (!metricData) return;
  const P = metricData.points, b = metricData.bucket;
  const pct = (v, short) => `${v.toFixed(short ? 0 : 1)}%`;
  const deg = (v, short) => `${v.toFixed(0)}${short ? "°" : "°C"}`;
  const ld = (v) => v.toFixed(2);
  const peak = (key, f) => {
    const vs = P.filter((p) => p[key] != null);
    if (!vs.length) return "";
    const top = vs.reduce((a, c) => (c[key] > a[key] ? c : a));
    return `최고 ${f(top[key])} · ${fmtTime(top.t)}`;
  };
  lineChart($("chartCpu"), P.map((p) => ({ t: p.t, v: p.cpu, max: p.cpu_max })), { yMax: 100, threshold: thresholds.cpu, fmt: pct, bucket: b, hours });
  lineChart($("chartMem"), P.map((p) => ({ t: p.t, v: p.mem })), { yMax: 100, threshold: thresholds.mem, fmt: pct, bucket: b, hours });
  lineChart($("chartTemp"), P.map((p) => ({ t: p.t, v: p.temp, max: p.temp_max })), { yMax: 100, threshold: thresholds.temp, fmt: deg, bucket: b, hours });
  lineChart($("chartLoad"), P.map((p) => ({ t: p.t, v: p.load1 })), { fmt: ld, bucket: b, hours });
  $("cpuPeak").textContent = peak("cpu_max", (v) => pct(v));
  $("memPeak").textContent = peak("mem", (v) => pct(v));
  $("tempPeak").textContent = peak("temp_max", (v) => deg(v));
  $("loadPeak").textContent = peak("load1", ld);
}

async function loadEvents() {
  const ev = await api("/api/metrics/events");
  thresholds = ev.thresholds;
  $("thresholds").textContent = `기준: CPU ≥ ${ev.thresholds.cpu}% · 메모리 ≥ ${ev.thresholds.mem}% · 온도 ≥ ${ev.thresholds.temp}°C`;
  const pk = ev.peaks || {};
  const peakBox = (k, v, ts) => h("div", {}, h("div", { class: "k" }, k), h("div", { class: "v num" }, v),
    h("div", { class: "muted" }, ts ? fmtDateTime(ts).slice(5, 16) : "–"));
  $("peaks").replaceChildren(
    peakBox("24시간 최고 CPU", pk.cpu != null ? `${pk.cpu.toFixed(1)}%` : "–", pk.cpu_ts),
    peakBox("24시간 최고 메모리", pk.mem != null ? `${pk.mem.toFixed(1)}%` : "–", pk.mem_ts),
    peakBox("24시간 최고 온도", pk.temp != null ? `${pk.temp.toFixed(0)}°C` : "–", pk.temp_ts));
  $("events").replaceChildren(...(ev.events.length ? ev.events.map((e) => h("li", {},
    h("span", { class: "when num" }, `${fmtDateTime(e.start).slice(5, 16)}${e.end > e.start ? ` ~ ${fmtTime(e.end)}` : ""}`),
    h("span", {}, e.reasons.map((r) => h("span", { class: "pill crit" }, r)), " "),
    h("span", { class: "muted num" }, `CPU ${e.cpu_max.toFixed(0)}% · 메모리 ${e.mem_max.toFixed(0)}% · ${e.temp_max.toFixed(0)}°C · ${fmtDur(e.end - e.start + 10)}`)))
    : [h("li", { class: "muted" }, "최근 24시간 동안 고부하 구간이 없었습니다 ✓")]));
}

$("range").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-h]");
  if (!btn) return;
  hours = Number(btn.dataset.h);
  for (const b of $("range").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b === btn));
  loadMetrics().catch((err) => toast(err.message, true));
});

// ---------------------------------------------------------------- services

async function serviceAction(unit, action) {
  const label = { start: "시작", stop: "종료", restart: "재시작", enable: "부팅 시 자동 실행 켜기", disable: "부팅 시 자동 실행 끄기", delete: "삭제" }[action];
  const text = action === "delete" ? `${unit} 을(를) 목록에서 삭제할까요? 서비스 파일은 ~/.config/systemd/user/.deleted/ 로 옮겨져서 되살릴 수 있습니다.`
    : action === "enable" ? `${unit} 을(를) 부팅할 때 자동으로 실행할까요? (지금 상태는 바뀌지 않습니다)`
    : action === "disable" ? `${unit} 을(를) 부팅 시 자동 실행에서 뺄까요? (지금 실행 중이면 계속 실행됩니다)`
    : `정말 ${unit} 서비스를 ${label}할까요?`;
  const ok = await confirmDialog(`${unit} ${label}`, text, action === "stop" || action === "disable" || action === "delete");
  if (!ok) return;
  try {
    await post(`/api/services/${encodeURIComponent(unit)}/${action}`);
    toast(`${unit} ${label} 요청을 보냈습니다.`);
    setTimeout(() => loadServices().catch(() => {}), 1500);
  } catch (err) { toast(err.message, true); }
}

async function loadServices() {
  if (currentNode != null) return renderNodeServices(await currentNodeData());
  const { services, linger } = await api("/api/services");
  $("lingerNote").textContent = linger === false
    ? "⚠ 사용자 linger 가 꺼져 있어, 자동 실행 서비스는 부팅 후 로그인해야 시작됩니다 (sudo loginctl enable-linger)."
    : "부팅하면 로그인 없이 자동 실행이 켜진 서비스가 시작됩니다.";
  fill($("services"), services.map((sv) => {
    const enabled = sv.enabled === "enabled";
    const canToggle = enabled || sv.enabled === "disabled";
    const boot = !canToggle
      ? h("span", { class: "muted", title: "[Install] 섹션이 없어 설정할 수 없음" }, sv.enabled || "–")
      : h("button", { class: "switch", role: "switch", "aria-checked": String(enabled),
          "aria-label": `${sv.unit} 부팅 시 자동 실행`, disabled: enabled && sv.protected,
          title: enabled && sv.protected ? "대시보드 접속에 필요해서 끌 수 없음" : null,
          onclick: () => serviceAction(sv.unit, enabled ? "disable" : "enable") },
          h("i", {}), h("span", {}, enabled ? "켜짐" : "꺼짐"));
    const running = sv.active === "active";
    const cls = running ? "good" : sv.active === "failed" ? "crit" : sv.active === "activating" || sv.active === "deactivating" ? "warn" : "";
    return h("tr", {},
      h("td", {}, h("div", {}, h("b", { class: "mono" }, sv.unit), sv.protected ? h("span", { class: "pill lock", title: "종료 불가" }, "보호") : null),
        h("div", { class: "muted" }, sv.description || "")),
      h("td", {}, h("span", { class: `pill ${cls}` }, `${sv.active} (${sv.sub})`)),
      h("td", { class: "num" }, sv.pid || "–"),
      h("td", { class: "r num" }, fmtBytes(sv.mem)),
      h("td", { class: "muted" }, running ? fmtSince(sv.since) : "–"),
      h("td", { class: "r num" }, sv.restarts ?? "–"),
      h("td", {}, boot),
      h("td", { class: "actions" },
        running ? null : h("button", { class: "btn", onclick: () => serviceAction(sv.unit, "start") }, "켜기"),
        h("button", { class: "btn", onclick: () => serviceAction(sv.unit, "restart") }, "다시 켜기"),
        running && !sv.protected ? h("button", { class: "btn danger", onclick: () => serviceAction(sv.unit, "stop") }, "종료") : null,
        !running && !sv.protected ? h("button", { class: "btn danger", onclick: () => serviceAction(sv.unit, "delete") }, "삭제") : null,
        h("button", { class: "btn", onclick: () => openLogs(sv.unit, null) }, "로그")));
  }), 8, "등록된 사용자 서비스가 없습니다");
}
$("svcRefresh").addEventListener("click", () => loadServices().catch((e) => toast(e.message, true)));

// ---------------------------------------------------------------- network

async function killProc(pid, name) {
  const ok = await confirmDialog(`프로세스 종료`, `PID ${pid} (${name || "?"}) 에 종료 신호(SIGTERM)를 보낼까요? systemd로 관리되는 서버라면 자동으로 다시 켜질 수 있습니다.`, true);
  if (!ok) return;
  try {
    await post(`/api/process/${pid}/terminate`);
    toast(`PID ${pid} 종료 신호를 보냈습니다.`);
    setTimeout(() => loadNetwork().catch(() => {}), 1200);
  } catch (err) { toast(err.message, true); }
}

async function loadNetwork() {
  if (currentNode != null) return renderNodeNetwork(await currentNodeData());
  const n = await api("/api/network");
  fill($("listening"), n.listening.map((l) => h("tr", {},
    h("td", { class: "num" }, h("b", {}, l.port)), h("td", { class: "mono" }, l.ip),
    h("td", {}, h("span", { class: `pill ${l.public ? "warn" : "good"}` }, l.public ? "외부 노출" : "로컬 전용")),
    h("td", {}, l.process || h("span", { class: "muted" }, "(다른 사용자)"),
      l.cwd ? h("div", { class: "muted mono", title: l.cwd }, `📁 ${l.cwd.replace(/^\/home\/[^/]+/, "~")}`) : null),
    h("td", { class: "num" }, l.pid || "–"),
    h("td", { class: "actions" }, l.killable ? h("button", { class: "btn danger", onclick: () => killProc(l.pid, l.process) }, "종료") : null))),
    6, "열린 포트가 없습니다");
  const connRow = (c) => h("tr", {}, h("td", { class: "mono" }, `${c.remote}:${c.rport}`), h("td", { class: "num" }, c.lport),
    h("td", {}, c.process || h("span", { class: "muted" }, "–")));
  fill($("inbound"), n.inbound.map(connRow), 3, "외부에서 직접 접속한 클라이언트가 없습니다 (웹 접속은 Cloudflare 터널 경유)");
  fill($("outbound"), n.outbound.map(connRow), 3, "–");
  fill($("users"), n.users.map((u) => h("tr", {}, h("td", {}, u.name), h("td", { class: "mono" }, u.terminal || "–"),
    h("td", { class: "mono" }, u.host || "로컬"), h("td", { class: "muted" }, fmtDateTime(u.started)))), 4, "로그인한 사용자가 없습니다");
}
$("netRefresh").addEventListener("click", () => loadNetwork().catch((e) => toast(e.message, true)));

// ---------------------------------------------------------------- access log

const EVENT_LABEL = { login_ok: ["로그인 성공", "good"], login_fail: ["로그인 실패", "crit"], login_locked: ["로그인 차단", "crit"], banned: ["차단 IP 접근", "crit"], unban: ["차단 해제", "good"],
  logout: ["로그아웃", ""], action: ["제어 작업", "warn"], page: ["페이지", ""], anon: ["비인증 요청", ""], denied: ["거부됨", "crit"] };
let accessPage = 0;

async function loadAccess() {
  toggleRemote("access", currentNode != null);
  if (currentNode != null) return renderNodeAccess(await currentNodeData());
  const ip = $("fIp").value.trim(), event = $("fEvent").value;
  const q = new URLSearchParams({ page: accessPage, ip, event });
  const [log, sum] = await Promise.all([api(`/api/access?${q}`), api("/api/access/summary")]);
  $("retention").textContent = `최근 ${sum.retention_days}일(6개월) 보관`;
  fill($("ipSummary"), sum.ips.map((r) => h("tr", {},
    ipCell(r), countryCell(r.country), h("td", { class: "r num" }, r.hits),
    h("td", { class: "r num" }, r.logins || 0), h("td", { class: "r num" }, r.fails ? h("b", {}, r.fails) : 0),
    h("td", { class: "muted" }, fmtDateTime(r.first)), h("td", {}, fmtDateTime(r.last)),
    h("td", { class: "actions" }, h("button", { class: "btn", onclick: () => { $("fIp").value = r.ip; accessPage = 0; loadAccess(); } }, "기록 보기")))),
    8, "기록이 없습니다");
  fill($("access"), log.rows.map((r) => {
    const [lbl, cls] = EVENT_LABEL[r.event] || [r.event, ""];
    return h("tr", {},
      h("td", { class: "num" }, fmtDateTime(r.ts)), ipCell(r), countryCell(r.country),
      h("td", {}, h("span", { class: `pill ${cls}` }, lbl)), h("td", { class: "mono" }, `${r.method} ${r.path}`),
      h("td", { class: "r num" }, r.status), h("td", {}, r.detail || "", r.email ? h("div", { class: "muted" }, r.email) : null), h("td", { class: "ua", title: r.ua }, r.ua));
  }), 8, "기록이 없습니다");
  const pages = Math.max(1, Math.ceil(log.total / 50));
  $("pageInfo").textContent = `${log.total.toLocaleString()}건 · ${accessPage + 1} / ${pages} 페이지`;
  $("prevPage").disabled = accessPage === 0;
  $("nextPage").disabled = accessPage + 1 >= pages;
}
let ipTimer;
$("fIp").addEventListener("input", () => { clearTimeout(ipTimer); ipTimer = setTimeout(() => { accessPage = 0; loadAccess(); }, 350); });
$("fEvent").addEventListener("change", () => { accessPage = 0; loadAccess(); });
$("prevPage").addEventListener("click", () => { accessPage--; loadAccess(); });
$("nextPage").addEventListener("click", () => { accessPage++; loadAccess(); });

// ---------------------------------------------------------------- security

const ALERT_KIND = { new_ip: ["새 IP 로그인", "warn"], login_fail: ["로그인 실패", "crit"], ban: ["영구 차단", "crit"], unban: ["차단 해제", "good"],
  ai_fix: ["AI 자동 조치", "good"], needs_you: ["직접 확인 필요", "crit"], node_down: ["서버 끊김", "crit"], node_up: ["서버 복구", "good"], node_hot: ["원격 고부하", "warn"],
  power: ["전원 조작", "warn"], site_down: ["사이트 다운", "crit"], site_up: ["사이트 복구", "good"],
  login_risk: ["수상한 로그인", "crit"], ai_risk: ["AI 위험 감지", "warn"],
  config_change: ["설정 변경", "warn"], disk_forecast: ["디스크 예측", "warn"], monthly: ["월간 가동률", ""],
  upgrade: ["업그레이드", ""], ai_case: ["AI 조사", "crit"], exposure: ["인터넷 공개", "crit"], guard: ["외부 차단 설정", "warn"],
  reboot: ["재부팅 완료", "good"] };

async function unbanIp(b) {
  if (!(await confirmDialog("차단 해제", `${b.key} 의 영구 차단을 풀까요? 실패 횟수도 0으로 초기화됩니다.`, false))) return;
  try { await post("/api/bans/unban", { key: b.key }); toast("차단을 해제했습니다."); loadSecurity(); }
  catch (err) { toast(err.message, true); }
}

async function loadAlertBadge() {
  const { alerts } = await api("/api/alerts");
  const recent = alerts.filter((a) => Date.now() / 1000 - a.ts < 86400 && a.kind !== "unban").length;
  $("alertBadge").textContent = recent;
  $("alertBadge").classList.toggle("hidden", !recent);
  return alerts;
}

const FIX_KIND = { restart_local: "서비스 재시작", restart_node: "원격 서비스 재시작", ban_ip: "IP 차단",
  block_host: "방화벽 차단", report: "직접 확인 필요" };

/** sm-block list for this server (node = null) or a remote one. list === null means "not installed". */
function renderHostBlocks(pre, list, node) {
  const cmd = node ? "sudo bash ~/node_agent/install-blocker.sh" : "sudo bash ~/server-monitor/node_agent/install-blocker.sh";
  $(`${pre}HbMeta`).textContent = list == null
    ? `차단 도구 미설치 — SSH 공격 IP를 자동으로 막으려면 그 서버에서 한 번: ${cmd}`
    : `nftables 로 이 서버에 들어오는 연결을 막습니다 · 내부망·Tailscale·접속 중인 SSH IP는 막지 않음 · ${list.length}개`;
  fill($(`${pre}HostBlocks`), (list || []).map((b) => h("tr", {},
    h("td", { class: "mono" }, b.key), h("td", { class: "num" }, fmtDateTime(b.ts)), h("td", {}, b.reason || "–"),
    h("td", { class: "actions" }, h("button", { class: "btn", onclick: async () => {
      if (!(await confirmDialog("방화벽 차단 해제", `${b.key} 의 차단을 풀까요?`, false))) return;
      try {
        await post(node ? `/api/nodes/${node.id}/hostblock/remove` : "/api/hostblock/remove", { key: b.key });
        toast("해제했습니다."); setTimeout(() => loadSecurity().catch(() => {}), 1500);
      } catch (err) { toast(err.message, true); }
    } }, "해제")))), 4, list == null ? "차단 도구가 설치되지 않았습니다" : "차단된 IP가 없습니다");
}
const FIX_STATUS = { done: ["완료", "good"], failed: ["실패", "crit"], skipped: ["보류", "warn"], needs_you: ["알림 보냄", "crit"] };
async function loadAiActions() {
  const { actions } = await api("/api/ai/actions");
  fill($("aiActions"), actions.map((a) => {
    const [sl, sc] = FIX_STATUS[a.status] || [a.status, ""];
    return h("tr", {}, h("td", { class: "num" }, fmtDateTime(a.ts)), h("td", {}, a.server || "–"),
      a.ip ? ipCell(a) : h("td", { class: "mono" }, a.kind === "report" ? "–" : a.target),
      h("td", {}, FIX_KIND[a.kind] || a.kind), h("td", {}, h("span", { class: `pill ${sc}` }, sl)), h("td", {}, a.reason));
  }), 6, "아직 자동 조치 기록이 없습니다");
}

function fillHostStatus() {
  return api("/api/hoststatus").then((s) => {
    const li = $("hostStatusLi"); if (!li) return;
    const remote = Object.values(s.backups.remote).map((r) => `${r.server} ${r.ok ? "✓" : "✗"} ${r.name}`).join(", ");
    li.replaceChildren(h("b", {}, "업데이트"), " — ", updatesText(s.updates), h("br"), h("b", {}, "백업"), " — ",
      `이 서버 ${s.backups.local.length}개 (최신 ${s.backups.local[0] || "없음"})`,
      remote ? ` · 다른 서버로 복사: ${remote}` : " · 다른 서버로 복사: 에이전트 1.7 이상인 서버가 생기면 자동");
  }).catch(() => {});
}
function updatesText(u) {
  if (!u) return "확인 중…";
  if (u.pending == null) return "apt 상태를 읽지 못했습니다";
  return `대기 ${u.pending}개 (보안 ${u.security}개) · 자동 보안 업데이트 ${u.auto_security ? "켜짐" : "꺼짐"}${u.reboot_required ? " · ⚠ 재부팅 필요" : ""}`;
}
async function loadSecurity() {
  toggleRemote("sec", currentNode != null);
  if (currentNode != null) return renderNodeSecurity(await currentNodeData());

  api("/api/hostblock").then((r) => renderHostBlocks("l", r.installed ? r.blocked : null, null)).catch(() => {});
  loadIntegrity().catch(() => {});
  loadGuard().catch(() => {});
  loadAiActions().catch(() => {});
  const [{ sessions }, me, { bans }, alertRows] = await Promise.all([api("/api/sessions"), api("/api/me"), api("/api/bans"), loadAlertBadge()]);
  $("banRule").textContent = `신뢰 IP가 아닌 곳에서 비밀번호를 ${me.ban_after}번 틀리면 영구 차단 · IPv6는 /64 대역 단위`;
  fill($("bans"), bans.map((b) => h("tr", {},
    ipCell(b, b.key), countryCell(b.country), h("td", { class: "num" }, fmtDateTime(b.ts)),
    h("td", { class: "r num" }, b.fails), h("td", {}, b.reason || ""), h("td", { class: "ua", title: b.ua }, b.ua),
    h("td", { class: "actions" }, h("button", { class: "btn", onclick: () => unbanIp(b) }, "해제")))), 7, "차단된 IP가 없습니다");
  $("alertChannels").textContent = me.alert_channels.length ? `푸시: ${me.alert_channels.join(", ")}` : "푸시 알림 미설정 (.env 에 텔레그램/디스코드 설정 시 전송)";
  fill($("alerts"), alertRows.map((a) => {
    const [lbl, cls] = ALERT_KIND[a.kind] || [a.kind, ""];
    return h("tr", {}, h("td", { class: "num" }, fmtDateTime(a.ts)), h("td", {}, h("span", { class: `pill ${cls}` }, lbl)),
      ipCell(a), countryCell(a.country), h("td", {}, a.message));
  }), 5, "알림이 없습니다");
  fill($("sessions"), sessions.map((ss) => h("tr", {},
    ipCell(ss), h("td", { class: "ua", title: ss.ua }, ss.email ? h("div", {}, ss.email) : null, ss.ua),
    h("td", {}, fmtDateTime(ss.created)), h("td", {}, fmtAgo(ss.last_seen)),
    h("td", { class: "actions" },
      ss.trusted ? null : h("button", { class: "btn", onclick: () => trustIp(ss.ip) }, "영구 등록"),
      ss.current ? h("span", { class: "pill good" }, "현재 세션")
        : h("button", { class: "btn danger", onclick: async () => {
          await post("/api/sessions/revoke", { id: ss.id }); toast("세션을 종료했습니다."); loadSecurity();
        } }, "로그아웃")))), 5, "–");
  const li = (k, v) => h("li", {}, h("b", {}, k), " — ", v);
  $("secInfo").replaceChildren(h("ul", {},
    li("현재 접속 IP", `${me.ip}${me.label ? ` (${me.label})` : ""}${me.trusted ? " · 신뢰 IP" : ""}`),
    li("Cloudflare Access", me.cf_access ? `켜짐 ✓ — 토큰 서명 검증 중${me.email ? ` · ${me.email}` : ""}` : "꺼짐"),
    li("2단계 인증(TOTP)", me.totp ? "켜짐 ✓" : "꺼짐 — 서버에서 `venv/bin/python manage.py totp-enable` 로 켤 수 있습니다"),
    li("영구 차단", `비밀번호 ${me.ban_after}회 실패 시 · 아래 신뢰 IP는 제외`),
    h("li", {}, h("b", {}, "신뢰 IP"), " — 차단되지 않는 IP (비밀번호는 여전히 필요)",
      h("ul", { class: "trust-list" }, me.trusted_ips.length ? me.trusted_ips.map((t) => h("li", {},
        h("span", { class: "mono" }, t.ip), t.label ? h("span", { class: "pill me" }, t.label) : null,
        t.source === "env" ? h("span", { class: "muted" }, " .env 에서 설정")
          : h("button", { class: "btn danger", onclick: () => untrustIp(t.ip) }, "해제"))) : h("li", { class: "muted" }, "없음"))),
    li("차단 해제(서버에서)", "venv/bin/python manage.py unban <IP>"),
    h("li", { id: "hostStatusLi" }, h("b", {}, "업데이트·백업"), " — 확인 중…"),
    li("세션", "HttpOnly · Secure · SameSite=Strict 쿠키, 30분 미사용 시 만료"),
    li("비밀번호 변경", "서버의 ~/server-monitor/.env 에서 SM_PASSWORD 를 바꾸고 재시작 (변경 시 모든 세션 로그아웃)")));
  fillHostStatus();  // after the list exists, so its row can be filled
}
async function trustIp(ip) {
  const label = prompt(`${ip} 을(를) 신뢰 IP로 영구 등록합니다.\n로그인을 몇 번 틀려도 차단되지 않습니다. (모바일 IP는 다른 사람과 공유될 수 있어요)\n\n이 IP의 이름:`, "내 기기");
  if (label === null) return;
  try { await post("/api/trusted/add", { ip, label: label.trim().slice(0, 20) }); toast("신뢰 IP로 등록했습니다."); loadSecurity(); }
  catch (err) { toast(err.message, true); }
}
async function untrustIp(ip) {
  if (!(await confirmDialog("신뢰 IP 해제", `${ip} 를 신뢰 IP에서 뺄까요? 이후 3번 틀리면 차단될 수 있습니다.`, true))) return;
  try { await post("/api/trusted/remove", { ip }); toast("해제했습니다."); loadSecurity(); }
  catch (err) { toast(err.message, true); }
}

$("revokeOthers").addEventListener("click", async () => {
  if (!(await confirmDialog("다른 세션 로그아웃", "현재 세션을 제외한 모든 로그인을 끊을까요?", true))) return;
  await post("/api/sessions/revoke", { others: true });
  toast("다른 세션을 모두 로그아웃했습니다.");
  loadSecurity();
});

$("logoutBtn").addEventListener("click", async () => {
  try { await post("/api/logout"); } finally { location.replace("/login"); }
});

// ---------------------------------------------------------------- risk display

const RISK_META = {
  low: { label: "낮음", text: "특이사항 없음", cls: "risk-low" },
  medium: { label: "주의", text: "확인이 필요한 일이 있었습니다", cls: "risk-medium" },
  high: { label: "위험", text: "즉시 확인하세요", cls: "risk-high" },
};

function riskIcon(level) {
  const svg = s("svg", { viewBox: "0 0 24 24", width: 28, height: 28, "aria-hidden": "true", class: "risk-icon" });
  if (level === "low") {
    svg.append(s("circle", { cx: 12, cy: 12, r: 10 }), s("path", { d: "M7 12.5l3.2 3.2L17 9", class: "glyph" }));
  } else if (level === "medium") {
    svg.append(s("path", { d: "M12 2.5L22.5 21h-21z", "stroke-linejoin": "round" }), s("path", { d: "M12 9v5.5M12 17.6v.4", class: "glyph" }));
  } else {
    svg.append(s("path", { d: "M8 2h8l6 6v8l-6 6H8l-6-6V8z" }), s("path", { d: "M8.5 8.5l7 7M15.5 8.5l-7 7", class: "glyph" }));
  }
  return svg;
}

function riskBanner(level, sub) {
  const m = RISK_META[level] || { label: level, text: "", cls: "" };
  return h("div", { class: `risk-banner ${m.cls}`, role: "status" }, riskIcon(level),
    h("div", {}, h("div", { class: "risk-title" }, `위험도 ${m.label}`), h("div", { class: "risk-sub" }, sub || m.text)));
}

function riskPill(level) {
  const m = RISK_META[level] || { label: level, cls: "" };
  return h("span", { class: `risk-pill ${m.cls}` }, m.label);
}

// ---------------------------------------------------------------- AI analyst

const RISK = { low: ["낮음", "good"], medium: ["주의", "warn"], high: ["위험", "crit"] };
const SEV = { info: ["정보", ""], warn: ["주의", "warn"], critical: ["위험", "crit"] };
let aiHistory = [];
let aiShownReport = null;

/** Safe mini-markdown: **bold** and `code` only, everything else stays plain text. */
function md(text) {
  const out = [];
  for (const part of String(text).split(/(\*\*[^*]+\*\*|`[^`]+`)/g)) {
    if (/^\*\*[^*]+\*\*$/.test(part)) out.push(h("b", {}, part.slice(2, -2)));
    else if (/^`[^`]+`$/.test(part)) out.push(h("code", {}, part.slice(1, -1)));
    else if (part) out.push(part);
  }
  return out;
}

function actionButton(a) {
  if (a.type === "restart_service")  // reports are listed per server, so the viewed server is the target
    return h("button", { class: "btn", onclick: () => { $("reportModal").close(); currentNode != null && nodeCache
      ? nodeServiceAction(nodeCache, a.target, "restart") : serviceAction(a.target, "restart"); } }, `${a.target} 재시작`);
  if (a.type === "view_ip")
    return h("button", { class: "btn", onclick: () => { $("reportModal").close(); if (currentNode == null) { $("fIp").value = a.target; accessPage = 0; } selectTab("access"); } }, `${a.target} 기록 보기`);
  if (a.type === "revoke_other_sessions")
    return h("button", { class: "btn danger", onclick: () => { $("reportModal").close(); selectTab("security"); $("revokeOthers").click(); } }, "다른 세션 로그아웃");
  return null;
}

function riskSub(c) {
  if (c.ai_failed) return "AI 요약 실패 — 규칙 판단만 반영";
  return c.rule_reasons && c.rule_reasons.length ? `근거: ${c.rule_reasons.join(" · ")}` : null;
}

function findingsList(c) {
  return c.findings.length ? h("ul", { class: "findings" }, c.findings.map((f) => {
    const [sl, sc] = SEV[f.severity] || [f.severity, ""];
    return h("li", {}, h("span", { class: `pill ${sc}` }, sl), h("div", {}, h("b", {}, ...md(f.title)), h("div", { class: "ink2" }, ...md(f.detail))));
  })) : null;
}

function actionsList(c) {
  return c.actions.length ? h("div", { class: "brief-actions" }, h("div", { class: "muted" }, "AI 제안 조치 (누르면 확인 후 실행)"),
    c.actions.map((a) => h("div", { class: "brief-action" }, actionButton(a), h("span", { class: "ink2" }, a.reason)))) : null;
}

function statBox(k, v, sub) { return h("div", { class: "stat" }, h("div", { class: "k" }, k), h("div", { class: "v num" }, v ?? "–"), sub ? h("div", { class: "muted" }, sub) : null); }

function statsGrid(st) {
  const peak = (p, unit) => p ? [`${p.값}${unit}`, p.시각] : ["–", null];
  const [cpuV, cpuT] = peak(st.CPU && st.CPU.최고, "%"), [tV, tT] = peak(st.온도 && st.온도.최고, "°C"), [mV, mT] = peak(st.메모리 && st.메모리.최고, "%");
  const a = st.인증 || {};
  const nodesBad = (st.다른서버 || []).filter((n) => n.온라인 === false).map((n) => n.이름);
  return h("div", { class: "stats-grid" },
    statBox("최고 CPU", cpuV, cpuT), statBox("최고 온도", tV, tT), statBox("최고 메모리", mV, mT),
    statBox("고부하 시간", `${st.고부하_분 ?? 0}분`), statBox("로그인 성공 / 실패", `${a.로그인성공 ?? 0} / ${a.로그인실패 ?? 0}`),
    statBox("새 차단 IP", (st.새차단 || []).length), statBox("처음 보는 IP 로그인", a.처음보는IP로그인 ?? 0),
    statBox("다른 서버", `${(st.다른서버 || []).length}대`, nodesBad.length ? `끊김: ${nodesBad.join(", ")}` : null));
}

const CHECK = { ok: ["양호", "good"], warn: ["주의", "warn"], fail: ["취약", "crit"] };
function auditBody(c) {
  const order = { fail: 0, warn: 1, ok: 2 };
  return [h("div", { class: "audit-score" }, h("span", { class: `num pill ${c.score >= 80 ? "good" : c.score >= 50 ? "warn" : "crit"}` }, `${c.score}점`),
      h("span", { class: "brief-summary" }, ...md(c.summary))),
    h("ul", { class: "findings" }, [...c.checks].sort((a, b) => order[a.status] - order[b.status]).map((k) => {
      const [lbl, cls] = CHECK[k.status] || [k.status, ""];
      return h("li", {}, h("span", { class: `pill ${cls}` }, lbl),
        h("div", {}, h("b", {}, `${k.server} · `, ...md(k.item)), h("div", { class: "ink2" }, ...md(k.detail)),
          k.status !== "ok" && k.fix ? h("div", { class: "muted" }, "해결: ", ...md(k.fix)) : null));
    }))];
}

/** Full report (briefing or daily) in a modal; the page itself only shows the banner + summary. */
async function openReport(id) {
  let r;
  try { r = await api(`/api/ai/report/${id}`); } catch (err) { toast(err.message, true); return; }
  const c = r.content;
  if (r.trigger === "보안점검") {
    put($("reportBody"), h("div", { class: "modal-head" }, h("h3", {}, `보안 점검 · ${fmtDateTime(r.ts)}`),
      h("button", { class: "btn", type: "button", onclick: () => $("reportModal").close() }, "닫기")), ...auditBody(c),
      h("p", { class: "muted ai-note" }, "ⓘ AI는 점검만 하고 아무것도 바꾸지 않습니다. 해결 방법은 직접 확인 후 적용하세요."));
    $("reportModal").showModal();
    return;
  }
  put($("reportBody"),
    h("div", { class: "modal-head" }, h("h3", {}, r.day ? `${r.day} 일일 보고서` : `${r.trigger} 브리핑`),
      h("button", { class: "btn", type: "button", onclick: () => $("reportModal").close() }, "닫기")),
    h("div", { class: "muted" }, `작성 ${fmtDateTime(r.ts)} · ${r.duration}초${r.tps ? ` · ${r.tps.toFixed(1)} 토큰/초` : ""}` +
      (c.stats ? ` · 수집률 ${c.stats["수집률%"] ?? "–"}%` : "")),
    riskBanner(c.risk, riskSub(c)),
    c.stats ? statsGrid(c.stats) : null,
    h("p", { class: "brief-summary" }, ...md(c.summary)),
    findingsList(c), actionsList(c),
    h("p", { class: "muted ai-note" }, "ⓘ 수치·위험도·차단은 규칙이 정합니다. AI 설명은 참고용이며 작은 모델이라 세부 내용이 틀릴 수 있어요 — 중요한 건 ‘기록 보기’로 확인하세요."));
  $("reportModal").showModal();
}

function reportCard(r) {
  return [riskBanner(r.risk, r.rule_reasons && r.rule_reasons.length ? `근거: ${r.rule_reasons.join(" · ")}` : null),
    h("p", { class: "brief-summary" }, ...md(r.summary)),
    h("div", { class: "card-foot" }, h("button", { class: "btn", onclick: () => openReport(r.id) }, "보고서 자세히 보기"),
      h("span", { class: "muted" }, "수치·위험도는 규칙 기반, 설명은 AI 참고용"))];
}

let dailyKey = "";
function renderRiskCalendar(daily) {
  const byDay = Object.fromEntries(daily.map((r) => [r.day, r]));
  const cells = [];
  for (let i = 30; i >= 1; i--) {
    const d = new Date(Date.now() - i * 86400000);
    const key = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const r = byDay[key], lvl = r ? r.risk : "none";
    const label = r ? `${key} · 위험도 ${(RISK_META[lvl] || {}).label || lvl}` : `${key} · 보고서 없음`;
    cells.push(h("button", { class: `cal-cell lv-${lvl}`, role: "listitem", title: label, "aria-label": label,
      disabled: !r, onclick: () => r && openReport(r.id) },
      h("span", { class: "d" }, d.getDate()), d.getDate() === 1 || i === 30 ? h("span", { class: "m" }, `${d.getMonth() + 1}월`) : null));
  }
  $("riskCal").replaceChildren(...cells);
}

const fmtTok = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1000 ? `${(n / 1000).toFixed(1)}k` : `${n || 0}`);
const fmtWhen = (ts) => {
  const d = new Date(ts * 1000), today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay ? fmtTime(ts) : `${d.getMonth() + 1}/${d.getDate()} ${fmtTime(ts)}`;
};

// CSP forbids style="" attributes; CSSOM property writes are allowed.
const withStyle = (el, prop, value) => { el.style.setProperty(prop, String(value)); return el; };

let aiBusy = null;  // { label, since (server epoch), offset (server - client seconds) }
function renderAiNow(st) {
  const busy = st.busy;
  aiBusy = busy ? { label: busy, since: st.busy_since, offset: (st.server_now || Date.now() / 1000) - Date.now() / 1000 } : null;
  put($("aiNow"),
    h("span", { class: `ai-dot ${!st.online ? "off" : busy ? "busy" : "idle"}`, "aria-hidden": "true" }),
    h("div", {},
      h("div", { class: "ai-now-title" }, !st.online ? "AI 꺼짐" : busy ? busy : "대기 중"),
      h("div", { class: "muted" }, busy ? h("span", { id: "aiElapsed", class: "num" }, "") : null,
        busy ? " · " : null, st.model)));
  tickAiElapsed();
}
function tickAiElapsed() {
  const el = document.getElementById("aiElapsed");
  if (el && aiBusy && aiBusy.since) {
    const t = Math.max(0, Math.round(Date.now() / 1000 + aiBusy.offset - aiBusy.since));
    el.textContent = `${t >= 60 ? `${Math.floor(t / 60)}분 ` : ""}${t % 60}초째 진행 중`;
  }
}
setInterval(() => { if (activeTab === "ai") tickAiElapsed(); }, 1000);

function gauge(title, pct, sub) {
  const cls = pct == null ? "" : pct >= 90 ? "crit" : pct >= 70 ? "warn" : "";
  return h("div", { class: "gauge" },
    h("div", { class: "gauge-k" }, h("span", {}, title), h("b", { class: "num" }, pct == null ? "–" : `${pct}%`)),
    h("div", { class: "meter" }, withStyle(h("i", { class: cls }), "width", `${Math.min(100, pct || 0)}%`)),
    h("div", { class: "muted gauge-sub" }, sub));
}

const jobName = (t) => t.replace(" 중 · ", " · ").replace(/\s*(생성|작성|판단|답하는)?\s*중$/, "").replace(/질문에$/, "질문 답변");

function renderAiUsage(st) {
  const u = st.usage, now = (st.server_now || Date.now() / 1000);
  if (!u) { put($("aiGauges"), h("p", { class: "muted" }, "사용량은 Claude 백엔드에서만 표시됩니다.")); put($("aiSched")); return; }
  const w = (u.limits && u.limits.unifiedWindows) || {};
  const win = (x) => (x && x.utilization != null ? Math.round(x.utilization * 100) : null);
  const resets = (x) => (x && x.resetsAt ? `${fmtWhen(x.resetsAt)} 초기화 · ${fmtDur(x.resetsAt - now)} 남음` : "AI가 한 번 실행되면 표시");
  const t = u.today;
  put($("aiGauges"),
    gauge("5시간 세션 사용량", win(w.five_hour), resets(w.five_hour)),
    gauge("주간 사용량 (7일)", win(w.seven_day), resets(w.seven_day)),
    h("div", { class: "gauge" },
      h("div", { class: "gauge-k" }, h("span", {}, "오늘 사용"), h("b", { class: "num" }, `${t.calls}회`)),
      h("div", { class: "tok-line num" }, `입력 ${fmtTok(t.tin)} · 출력 ${fmtTok(t.tout)} 토큰`),
      h("div", { class: "muted gauge-sub" }, `최근 7일 ${u.week.calls}회 · ${fmtTok(u.week.tin + u.week.tout)} 토큰` +
        (t.fails ? ` · 오늘 실패 ${t.fails}회` : ""))));
  const n = u.next || {};
  const chip = (label, ts) => ts ? h("span", { class: "sched-chip" }, h("span", { class: "muted" }, label),
    h("b", { class: "num" }, ts <= now ? "곧" : fmtWhen(ts))) : null;
  put($("aiSched"), h("span", { class: "muted" }, "다음 예정"),
    chip(`위험 감지 (${st.briefing_hours}시간마다)`, n.regular), chip("일일 보고서", n.daily), chip("보안 점검 (매주)", n.audit),
    st.budget && st.budget !== "ok" ? h("span", { class: "pill warn" }, BUDGET[st.budget]) : null,
    u.limits && u.limits.checked ? h("span", { class: "muted sched-note" }, `사용량 기준 ${fmtWhen(u.limits.checked)}`) : null);
  fill($("aiJobs"), u.recent.map((r) => h("tr", {},
    h("td", { class: "num" }, fmtWhen(r.ts)),
    h("td", {}, r.ok ? jobName(r.task) : h("span", { class: "pill crit" }, `${jobName(r.task)} · 실패`)),
    h("td", { class: "r num" }, r.ok ? `${fmtTok(r.tin)} / ${fmtTok(r.tout)}` : "–"),
    h("td", { class: "r num" }, `${Math.round(r.secs)}초`))), 4, "아직 작업 기록이 없습니다");
}

function auditCard(a) {
  if (!a) return h("p", { class: "muted" }, "아직 점검 기록이 없습니다. ‘보안 점검’을 누르면 1~2분 뒤 결과가 나옵니다.");
  const cls = a.score >= 80 ? "good" : a.score >= 50 ? "warn" : "crit";
  return [h("div", { class: "score-row" },
      withStyle(h("div", { class: `score-ring ${cls}` }, h("b", { class: "num" }, a.score ?? "–"), h("small", {}, "/100")), "--p", a.score ?? 0),
      h("div", {}, h("div", { class: "muted" }, `${fmtDateTime(a.ts)} 점검`), h("p", { class: "brief-summary" }, ...md(a.summary)))),
    h("button", { class: "btn", onclick: () => openReport(a.id) }, "점검표 자세히 보기")];
}

let aiView = "now";
$("aiSeg").addEventListener("click", (e) => {
  const v = e.target.closest("button[data-v]");
  if (!v) return;
  aiView = v.dataset.v;
  for (const b of $("aiSeg").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b === v));
  for (const el of document.querySelectorAll("[data-aiview]")) el.classList.toggle("hidden", el.dataset.aiview !== aiView);
});

async function loadAi() {
  const st = await api(`/api/ai/status${currentNode != null ? `?node=${currentNode}` : ""}`);
  renderAiNow(st);
  renderAiUsage(st);
  const key = JSON.stringify(st.daily.map((d) => [d.id, d.risk]));
  if (key !== dailyKey) {
    dailyKey = key;
    renderRiskCalendar(st.daily);
    const last = st.daily[0];
    put($("dailyView"), last ? [h("div", { class: "daily-head" }, h("h3", {}, `${last.day} 보고서`)), ...reportCard(last)]
      : h("p", { class: "muted" }, "아직 일일 보고서가 없습니다. 오늘 밤 12시에 첫 보고서가 작성됩니다."));
  }
  const busy = !st.online || !!st.busy;
  $("briefBtn").disabled = busy;
  $("briefBtn").textContent = st.busy === "브리핑 생성 중" ? "분석 중…" : "지금 분석";
  $("auditBtn").disabled = busy;
  $("auditBtn").textContent = st.busy === "보안 점검 중" ? "점검 중…" : "보안 점검";
  const au = st.audits || [];
  put($("auditView"), auditCard(au[0]));
  fill($("auditRows"), au.map((a) => h("tr", { class: "clickable", onclick: () => openReport(a.id) },
    h("td", { class: "num" }, fmtDateTime(a.ts)), h("td", { class: "r num" }, `${a.score ?? "–"}점`),
    h("td", { class: "ellipsis" }, a.summary))), 3, "기록이 없습니다");
  const latest = st.reports[0];
  if (!latest || aiShownReport !== latest.id) {
    aiShownReport = latest ? latest.id : null;
    $("briefMeta").textContent = latest ? `${fmtWhen(latest.ts)} · ${latest.trigger}` : "";
    put($("briefing"), latest ? reportCard(latest) : h("p", { class: "muted" }, "아직 브리핑이 없습니다. ‘지금 분석’을 누르면 1~2분 뒤 결과가 나옵니다."));
  }
  fill($("reports"), st.reports.map((r) => h("tr", { class: "clickable", onclick: () => openReport(r.id) },
    h("td", { class: "num" }, fmtDateTime(r.ts)), h("td", {}, r.trigger), h("td", {}, riskPill(r.risk)),
    h("td", { class: "ellipsis" }, r.summary), h("td", { class: "r num" }, `${r.duration}s`))), 5, "기록이 없습니다");
}

$("auditBtn").addEventListener("click", async () => {
  try { await post("/api/ai/audit", {}); toast("보안 점검을 시작했습니다. 1~2분 걸립니다."); loadAi(); }
  catch (err) { toast(err.message, true); }
});

$("briefBtn").addEventListener("click", async () => {
  try { await post("/api/ai/briefing", { node: currentNode }); toast("분석을 시작했습니다. 2~4분 걸립니다."); loadAi(); }
  catch (err) { toast(err.message, true); }
});

async function remember(text) {
  try { await post("/api/ai/memory", { content: text.slice(0, 300) }); toast("기억에 추가했습니다."); loadMemory(); }
  catch (err) { toast(err.message, true); }
}

function chatBubble(role, text) {
  const body = h("div", { class: "bubble-body" }, ...md(text || ""));
  const el = h("div", { class: `bubble ${role}` }, body,
    role === "user" ? h("button", { class: "bubble-remember", title: "이 말을 AI가 기억하게 하기", onclick: () => remember(text) }, "기억하기") : null);
  $("chatLog").append(el);
  $("chatLog").scrollTop = $("chatLog").scrollHeight;
  return body;
}

async function askAi(question) {
  question = question.trim();
  if (!question) return;
  $("chatSend").disabled = true;
  $("chatSuggest").classList.add("hidden");
  chatBubble("user", question);
  const out = chatBubble("assistant", "");
  const status = h("span", { class: "muted" }, "연결 중…");
  out.append(status);
  let answer = "";
  try {
    const res = await fetch("/api/ai/chat", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify({ question, history: aiHistory, node: currentNode }),
    });
    if (res.status === 401) { location.replace("/login"); return; }
    if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || `오류 ${res.status}`); }
    const reader = res.body.getReader(), dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (!line.startsWith("data: ")) continue;
        const ev = JSON.parse(line.slice(6));
        if (ev.status) status.textContent = ev.status;
        if (ev.error) throw new Error(ev.error);
        if (ev.t) { answer += ev.t; out.replaceChildren(...md(answer)); $("chatLog").scrollTop = $("chatLog").scrollHeight; }
        if (ev.memory) loadMemory().catch(() => {});
        if (ev.done && ev.tps) out.parentElement.append(h("div", { class: "bubble-meta" },
          `${ev.tps.toFixed(1)} 토큰/초${ev.past ? ` · 지난 대화 ${ev.past}개 참고` : ""}`));
      }
    }
    aiHistory.push({ role: "user", content: question }, { role: "assistant", content: answer });
    aiHistory = aiHistory.slice(-12);
    loadChats().catch(() => {});
  } catch (err) {
    out.replaceChildren(h("span", { class: "err-text" }, err.message));
  } finally {
    $("chatSend").disabled = false;
  }
}

async function loadMemory() {
  const { memories, max } = await api("/api/ai/memory");
  $("memMeta").textContent = `모든 답변에 반영 · 최근 ${max}개까지`;
  $("memList").replaceChildren(...(memories.length ? memories.map((m) => h("li", {},
    h("div", {}, h("div", {}, m.content), h("div", { class: "muted" }, `${fmtDateTime(m.ts)} · ${m.source === "chat" ? "대화에서" : "직접 추가"}`)),
    h("button", { class: "btn danger", onclick: async () => {
      if (!(await confirmDialog("기억 삭제", `“${m.content}” 를 잊게 할까요?`, true))) return;
      await post("/api/ai/memory/delete", { id: m.id }); loadMemory();
    } }, "삭제"))) : [h("li", { class: "muted" }, "아직 기억한 내용이 없습니다. 채팅에서 “기억해: …” 라고 말하거나 위에 직접 추가하세요.")]));
}
$("memForm").addEventListener("submit", (e) => { e.preventDefault(); const v = $("memInput").value.trim(); if (v) { $("memInput").value = ""; remember(v); } });

// ---------------------------------------------------------------- AI security investigations + lessons

const CASE_KIND = { config_change: "설정 변경", ssh_login: "SSH 로그인", login_risk: "수상한 로그인", manual: "직접 요청" };
const VERDICT = { benign: ["정상", "good"], suspicious: ["확인 필요", "warn"], malicious: ["공격", "crit"], unknown: ["판단 보류", ""] };
const TOOL_LABEL = { ip_history: "IP 접속 기록", ip_across_servers: "전체 서버에서 IP 확인", server_state: "서버 상태", service_logs: "서비스 로그",
  recent_web_attacks: "최근 웹 공격", past_cases: "지난 조사 검색", block_ip: "IP 차단", restart_service: "서비스 재시작",
  close_port: "포트 내부 전용으로" };
function casePill(c) {
  if (c.status === "queued") return h("span", { class: "pill" }, "대기");
  if (c.status === "running") return h("span", { class: "pill warn" }, "조사 중");
  if (c.status === "failed") return h("span", { class: "pill crit" }, "실패");
  const [l, cls] = VERDICT[c.verdict] || [c.verdict, ""];
  return h("span", { class: `pill ${cls}` }, l);
}
const BUDGET = { save: "토큰 절약 중 — 긴급한 조사만", stop: "사용량 한도 근접 — AI 작업 일시 중지" };

async function loadCases() {
  const r = await api("/api/ai/cases");
  put($("caseMeta"), `오늘 ${r.today}/${r.daily_cap}건 · 배운 것 ${r.lessons}개 · 한 건 최대 ${r.max_steps}단계`,
    r.budget !== "ok" ? h("span", { class: "pill warn" }, BUDGET[r.budget]) : null);
  fill($("caseRows"), r.cases.map((c) => h("tr", { class: "clickable", onclick: () => openCase(c.id) },
    h("td", { class: "num" }, fmtWhen(c.ts)), h("td", {}, CASE_KIND[c.kind] || c.kind), h("td", {}, c.server || "중앙"),
    h("td", { class: "ellipsis" }, c.subject), h("td", {}, casePill(c)),
    h("td", {}, c.actions.length ? c.actions.map((a) => `${TOOL_LABEL[a.type] || a.type}${a.ok ? "" : "(거부)"}`).join(", ") : "–"),
    h("td", { class: "r num" }, c.tokens ? fmtTok(c.tokens) : "–"),
    h("td", {}, c.feedback === "good" ? "👍 맞음" : c.feedback === "bad" ? "👎 오판" : c.status === "done" ? h("span", { class: "muted" }, "평가하기") : ""))),
    8, "아직 조사 기록이 없습니다. 설정 변경·처음 보는 SSH 로그인·수상한 로그인이 생기면 AI가 스스로 조사합니다.");
}

async function openCase(id) {
  let c;
  try { c = await api(`/api/ai/cases/${id}`); } catch (err) { toast(err.message, true); return; }
  const note = h("input", { class: "input", maxlength: "300", placeholder: "오판이면 이유 (예: 내가 설치한 프로그램이야)" });
  const rate = (good) => async () => {
    try { await post(`/api/ai/cases/${id}/feedback`, { good, note: note.value }); toast(good ? "평가했습니다." : "정정을 AI가 배웠습니다. 다음 판단부터 반영돼요."); $("reportModal").close(); loadCases(); loadLessons(); }
    catch (err) { toast(err.message, true); }
  };
  const [vl, vc] = VERDICT[c.verdict] || ["", ""];
  put($("reportBody"),
    h("div", { class: "modal-head" }, h("h3", {}, `AI 보안 조사 #${c.id} · ${CASE_KIND[c.kind] || c.kind}`),
      h("button", { class: "btn", type: "button", onclick: () => $("reportModal").close() }, "닫기")),
    h("div", { class: "muted" }, `${fmtDateTime(c.ts)} · ${c.server || "중앙서버"} · 토큰 ${fmtTok(c.tokens || 0)}`),
    h("div", { class: "case-subject" }, c.detail),
    c.status === "done" ? h("div", { class: "case-verdict" }, h("span", { class: `pill ${vc}` }, vl), h("p", { class: "brief-summary" }, ...md(c.summary || ""))) :
      h("p", { class: "muted" }, c.status === "failed" ? c.summary : "조사 대기·진행 중입니다."),
    h("ol", { class: "case-steps" }, c.steps.map((s) => h("li", {},
      h("div", {}, h("b", {}, TOOL_LABEL[s.tool] || s.tool), " ", h("span", { class: "mono muted" }, Object.values(s.args || {}).join(" · "))),
      h("div", { class: "ink2" }, s.thought),
      h("details", {}, h("summary", { class: "muted" }, "조회 결과"), h("pre", { class: "log-view mono" }, s.result))))),
    c.actions.length ? h("div", { class: "brief-actions" }, h("div", { class: "muted" }, "AI가 한 조치"),
      c.actions.map((a) => h("div", {}, `${TOOL_LABEL[a.type] || a.type} ${a.target} → ${a.ok ? "완료" : "거부"} (${a.detail || ""})`))) : null,
    c.lesson ? h("p", { class: "muted ai-note" }, `배운 것: ${c.lesson.text}${c.lesson.active ? "" : " (취소됨)"}`) : null,
    c.status === "done" ? h("div", { class: "case-feedback" },
      h("span", { class: "muted" }, c.feedback ? `평가: ${c.feedback === "good" ? "맞음" : "오판"} — 다시 평가할 수 있어요` : "이 판단이 맞았나요? 평가하면 AI가 배웁니다"),
      note, h("button", { class: "btn", onclick: rate(true) }, "👍 맞음"), h("button", { class: "btn danger", onclick: rate(false) }, "👎 오판")) : null);
  $("reportModal").showModal();
}

$("caseForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const v = $("caseInput").value.trim();
  if (!v) return;
  try { await post("/api/ai/cases", { subject: v }); $("caseInput").value = ""; toast("조사를 요청했습니다. 순서대로 AI가 조사합니다."); loadCases(); }
  catch (err) { toast(err.message, true); }
});

async function loadLessons() {
  const { lessons, max } = await api("/api/ai/lessons");
  $("lessonMeta").textContent = `${lessons.length}/${max}개 · 조사 결과와 관리자 정정에서 쌓임 · 모든 AI 판단에 반영`;
  $("lessonList").replaceChildren(...(lessons.length ? lessons.map((l) => h("li", {},
    h("div", {}, h("div", {}, l.source === "admin" ? h("span", { class: "pill me" }, "관리자 정정") : null, " ", l.text),
      h("div", { class: "muted" }, `${fmtDateTime(l.ts)}${l.case_id ? ` · 조사 #${l.case_id}` : ""}${l.uses ? ` · 맞음 ${l.uses}회` : ""}`)),
    h("button", { class: "btn danger", onclick: async () => {
      if (!(await confirmDialog("배운 것 지우기", `“${l.text}” 를 잊게 할까요?`, true))) return;
      await api(`/api/ai/lessons/${l.id}`, { method: "DELETE" }); loadLessons();
    } }, "삭제"))) : [h("li", { class: "muted" }, "아직 없습니다. AI가 조사를 마치거나, 조사 결과를 ‘오판’으로 평가하면 여기에 쌓입니다.")]));
}
$("lessonForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const v = $("lessonInput").value.trim();
  if (v.length < 8) { toast("8자 이상 적어 주세요.", true); return; }
  try { await post("/api/ai/lessons", { text: v }); $("lessonInput").value = ""; loadLessons(); } catch (err) { toast(err.message, true); }
});

// ---------------------------------------------------------------- fleet: uptime, disk forecast, upgrades, wake

const verLt = (a, b) => { const x = (a || "0").split(".").map(Number), y = b.split(".").map(Number); return x[0] < y[0] || (x[0] === y[0] && (x[1] || 0) < (y[1] || 0)); };
function diskText(f) {
  if (!f || f.now == null) return h("span", { class: "muted" }, "–");
  if (f.collecting) return h("span", { class: "muted" }, `${f.now}% · 예측은 하루치 기록 후`);
  if (f.days_left == null) return h("span", {}, `${f.now}% · 안정적`);
  return h("span", { class: f.days_left <= 14 ? "pill crit" : f.days_left <= 60 ? "pill warn" : "" },
    `${f.now}% · 약 ${Math.round(f.days_left)}일 뒤 95% (하루 +${f.per_day}%)`);
}
function upgradeText(u, upd) {
  if (u && u.state === "running") return h("span", { class: "pill warn" }, `업그레이드 중 (${fmtWhen(u.started)}~)`);
  const base = upd && upd.pending != null ? `대기 ${upd.pending}개${upd.security ? ` · 보안 ${upd.security}` : ""}${upd.reboot_required ? " · 재부팅 필요" : ""}` : "–";
  if (u && u.finished) return h("span", {}, base, h("div", { class: "muted" }, `${u.state === "done" ? "완료" : "실패"} ${fmtWhen(u.finished)}${u.upgraded ? ` · ${u.upgraded}개 설치` : ""}`));
  return base;
}
function copyBlock(text) {
  const btn = h("button", { class: "btn primary", type: "button", onclick: async () => {
    try { await navigator.clipboard.writeText(text); btn.textContent = "복사됨 ✓"; setTimeout(() => { btn.textContent = "복사"; }, 2000); }
    catch { toast("복사하지 못했습니다 — 직접 선택해서 복사하세요.", true); }
  } }, "복사");
  return h("div", { class: "copy-block" }, h("pre", { class: "log-view mono" }, text), btn);
}
function agentUpdateHelp(n, latest) {
  const dest = `${n.user || "<사용자>"}@${n.address.split(":")[0]}`;
  put($("reportBody"),
    h("div", { class: "modal-head" }, h("h3", {}, `${n.name} 에이전트 업데이트 (${n.version || "?"} → ${latest})`),
      h("button", { class: "btn", type: "button", onclick: () => $("reportModal").close() }, "닫기")),
    h("p", {}, "두 번에 나눠 실행합니다. 토큰·설정은 그대로 유지됩니다."),
    h("p", {}, h("b", {}, "① 중앙서버 터미널에서"), ` (${location.hostname} 이 돌아가는 서버, ~/server-monitor 가 있는 곳) — 파일 보내기`),
    copyBlock(`scp -r ~/server-monitor/node_agent ${dest}:~/`),
    h("p", {}, h("b", {}, `② ${n.name} 터미널에서`), ` (ssh ${dest} 로 들어가서) — 에이전트 재설치 + 방화벽·업그레이드 도구 설치 (sudo 비밀번호 물어봄)`),
    copyBlock(`bash ~/node_agent/install.sh ${DASHBOARD_TS_IP} && sudo bash ~/node_agent/install-blocker.sh`),
    n.user ? null : h("p", { class: "muted" }, "계정 이름을 몰라 <사용자>로 남겼습니다 — 붙여넣기 전에 그 서버의 로그인 계정으로 바꾸세요."),
    h("p", { class: "muted" }, "대시보드가 코드를 원격으로 밀어 넣는 방식은 일부러 만들지 않았습니다 — 토큰이 새면 그 서버에서 아무 코드나 실행되는 통로가 되기 때문입니다."));
  $("reportModal").showModal();
}
async function upgradeServer(r) {
  if (!(await confirmDialog("패키지 업그레이드", `${r.name} 에서 apt-get update && upgrade 를 실행할까요? (설정 파일은 유지, 패키지 삭제 없음 · 몇 분 걸릴 수 있음)`, false))) return;
  try { const x = await post("/api/fleet/upgrade", { node: r.id ?? null }); toast(x.detail || "요청했습니다."); setTimeout(() => loadServers().catch(() => {}), 3000); }
  catch (err) { toast(err.message, true); }
}
async function wakeServer(r) {
  try { const x = await post(`/api/fleet/wake/${r.id}`); toast(`켜기 신호를 보냈습니다 (${x.sent}개). 1~2분 뒤 연결되는지 보세요.`); }
  catch (err) { toast(err.message, true); }
}

async function loadFleet(d) {
  const [f, hs] = await Promise.all([api("/api/fleet"), api("/api/hoststatus").catch(() => null)]);
  const find = (rows, key) => rows.find((x) => x.server === key);
  const fc = Object.fromEntries(f.forecast.map((x) => [x.server, x]));
  const rows = [{ key: "main", name: d.local.name, online: true, updates: hs && hs.updates, upgrade: f.upgrade.main, local: true }]
    .concat(d.nodes.map((n) => ({ key: `node:${n.id}`, id: n.id, name: n.name, address: n.address, online: n.online,
      user: n.data && (n.data.user || ((n.data.host_facts && n.data.host_facts.sessions) || []).map((x) => x.name).find(Boolean)),
      version: n.data && n.data.version, updates: n.data && n.data.updates, upgrade: n.data && n.data.host_facts && n.data.host_facts.upgrade,
      macs: f.macs[`node:${n.id}`] })));
  const pct = (x) => (x ? h("span", { class: x.pct < 99 ? "pill warn" : "" }, `${x.pct}%`) : h("span", { class: "muted" }, "–"));
  fill($("fleetRows"), rows.map((r) => {
    const t = find(f.uptime.this.rows, r.key), l = find(f.uptime.last.rows, r.key);
    const outdated = !r.local && verLt(r.version, f.agent_latest);
    return h("tr", {},
      h("td", {}, h("b", {}, r.name), " ", h("span", { class: `pill ${r.online ? "good" : r.online === false ? "crit" : ""}` }, r.online ? "켜짐" : r.online === false ? "꺼짐" : "확인 중")),
      h("td", {}, r.local ? h("span", { class: "muted" }, "중앙") : outdated ?
        h("button", { class: "btn", title: "업데이트 방법 보기", onclick: () => agentUpdateHelp(r, f.agent_latest) }, `${r.version || "?"} → ${f.agent_latest} 업데이트`) :
        h("span", { class: "num" }, r.version || "–")),
      h("td", { class: "r num" }, pct(t)), h("td", { class: "r num" }, pct(l)),
      h("td", { class: "r num" }, t ? `${t.outages}회${t.longest ? ` · 최장 ${fmtDur(t.longest)}` : ""}` : "–"),
      h("td", {}, diskText(fc[r.key])), h("td", {}, upgradeText(r.upgrade, r.updates)),
      h("td", { class: "actions" },
        r.online ? h("button", { class: "btn", disabled: (r.upgrade && r.upgrade.state === "running") || (!r.local && verLt(r.version, "2.0")),
          title: !r.local && verLt(r.version, "2.0") ? "에이전트 2.0 이상 필요" : "", onclick: () => upgradeServer(r) }, "업그레이드") : null,
        !r.local && r.online === false ? h("button", { class: "btn primary", disabled: !r.macs, title: r.macs ? r.macs.map((m) => m.mac).join(", ") : "MAC 주소를 아직 모름 (에이전트 2.0 연결 후 기록)",
          onclick: () => wakeServer(r) }, "켜기 (WoL)") : null));
  }), 8, "");
  $("fleetMeta").textContent = `가동률은 중앙서버 기준으로 매분 기록 · ${f.uptime.this.month} · 디스크는 최근 14일 추세로 예측 · 최신 에이전트 ${f.agent_latest}`;
  return f;
}

// ---------------------------------------------------------------- port guard (외부 차단 모드) + exposure

function askPassword(title, text) {
  const dlg = $("pwModal");
  $("pwTitle").textContent = title;
  $("pwText").textContent = text;
  $("pwInput").value = "";
  dlg.showModal();
  $("pwInput").focus();
  return new Promise((resolve) => dlg.addEventListener("close", () => {
    const v = dlg.returnValue === "ok" ? $("pwInput").value : "";
    $("pwInput").value = "";
    resolve(v);
  }, { once: true }));
}
const parsePorts = (v) => [...new Set(v.split(/[\s,]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n) && n > 0 && n < 65536))];
async function guardChange(srv, cfg, label) {
  let password = "";
  const g = srv.guard || {};
  const weak = (g.lockdown && cfg.lockdown === false) || (cfg.allow_tcp && cfg.allow_tcp.some((p) => !(g.allow_tcp || []).includes(p)))
    || (cfg.internal_tcp && (g.internal_tcp || []).some((p) => !cfg.internal_tcp.includes(p)));
  if (weak) {
    password = await askPassword(`${srv.name}: ${label}`, "보안을 낮추는 변경이라 비밀번호를 한 번 더 확인합니다. 틀리면 로그인 실패로 셉니다.");
    if (!password) return;
  } else if (!(await confirmDialog("외부 차단 설정", `${srv.name}: ${label}`, false))) return;
  try { await post("/api/guard", { node: srv.node, ...cfg, password }); toast("적용했습니다."); setTimeout(() => loadGuard().catch(() => {}), 1500); }
  catch (err) { toast(err.message, true); }
}
function portEditor(srv, key, title) {
  const cur = (srv.guard && srv.guard[key]) || [];
  return h("button", { class: "btn link", title: "눌러서 바꾸기", onclick: () => {
    const v = prompt(`${srv.name} · ${title} (쉼표로 구분, 비우면 없음)`, cur.join(", "));
    if (v == null) return;
    guardChange(srv, { [key]: parsePorts(v) }, `${title} → ${parsePorts(v).join(", ") || "없음"}`);
  } }, cur.length ? cur.join(", ") : "없음");
}

async function loadGuard() {
  const r = await api("/api/guard");
  fill($("guardRows"), r.servers.map((srv) => {
    const g = srv.guard;
    if (!g) return h("tr", {}, h("td", {}, h("b", {}, srv.name)), h("td", { colspan: "5" }, h("span", { class: "muted" },
      srv.node != null && verLt(srv.version, "2.1") ? `에이전트 2.1 + 최신 sm-block 필요 (지금 ${srv.version || "?"}) — 서버 목록의 업데이트 안내 참고`
        : `최신 sm-block 필요 — 그 서버에서: sudo bash ${srv.node == null ? "~/server-monitor" : "~"}/node_agent/install-blocker.sh`)));
    const st = g.stats || {};
    return h("tr", {},
      h("td", {}, h("b", {}, srv.name), g.error ? h("div", { class: "err-text" }, g.error) : null),
      h("td", {}, h("button", { class: "switch", role: "switch", "aria-checked": String(!!g.lockdown),
        onclick: () => guardChange(srv, { lockdown: !g.lockdown }, g.lockdown ? "외부 차단 모드 끄기" : "외부 차단 모드 켜기 (허용 포트 말고는 인터넷에서 못 들어옴)") },
        h("i"), h("span", {}, g.lockdown ? "켜짐 — 허용 포트만" : "꺼짐"))),
      h("td", {}, h("span", { class: "mono" }, `SSH ${g.ssh.join(",")} · Tailscale udp/${g.tailscale_udp} · `), portEditor(srv, "allow_tcp", "인터넷 허용 TCP 포트")),
      h("td", {}, g.lockdown ? h("span", { class: "muted" }, "모드 켜짐 — 허용 외 전부") : portEditor(srv, "internal_tcp", "내부 전용 TCP 포트 (인터넷 출발만 차단)")),
      h("td", { class: "r num" }, `${st.closed ?? 0} · 과다 ${st.flood ?? 0}`),
      h("td", { class: "muted" }, `분당 새 연결 ${g.rate}회 넘으면 차단`));
  }), 6, "");
  const ok = new Set(r.public_ok);
  fill($("tunnelRows"), r.tunnels.map((t) => h("tr", {},
    h("td", { class: "mono" }, t.host), h("td", {}, `${t.server} → `, h("span", { class: "mono" }, t.service)),
    h("td", {}, t.state === "access" ? h("span", { class: "pill good" }, "Access 로그인 필요") :
      t.state === "public" ? h("span", { class: `pill ${ok.has(t.host) ? "" : "crit"}` }, `로그인 없이 공개 (HTTP ${t.code})${ok.has(t.host) ? " · 허용함" : ""}`) :
      h("span", { class: "pill warn" }, `확인 실패 ${t.error || ""}`)),
    h("td", { class: "actions" }, t.state === "public" ? h("button", { class: "btn", onclick: async () => {
      await post("/api/exposure/allow", { host: t.host, allowed: !ok.has(t.host) }); loadGuard();
    } }, ok.has(t.host) ? "허용 취소" : "공개 허용") : null))), 4, "확인 전입니다 (매시간, 또는 ‘다시 확인’)");
  const entries = Object.entries(r.upnp);
  put($("upnpView"), entries.length ? entries.map(([name, m]) => h("div", {}, h("b", {}, name), " — ",
    m && m.length ? h("ul", { class: "plain" }, m.map((x) => h("li", { class: "mono" }, x)))
      : h("span", { class: "muted" }, "포트포워딩 없음 (또는 공유기 UPnP 꺼짐 — 좋은 상태)")))
    : h("p", { class: "muted" }, "첫 확인 전입니다 (1시간 안)"),
    h("p", { class: "muted ai-note" }, "카메라는 공유기 설정에서 UPnP를 끄고, 가능하면 카메라 자체의 인터넷(P2P 클라우드)도 막아 두세요."));
}
$("guardRefresh").addEventListener("click", async () => {
  try { await post("/api/guard/refresh", { node: null }); toast("다시 확인했습니다."); loadGuard(); } catch (err) { toast(err.message, true); }
});

async function loadIntegrity() {
  const f = await api("/api/fleet");
  const base = Object.keys(f.baselines).length;
  fill($("integrityRows"), f.changes.map((c) => h("tr", {},
    h("td", { class: "num" }, fmtDateTime(c.ts)), h("td", {}, c.name),
    h("td", {}, h("ul", { class: "plain" }, c.changes.map((x) => h("li", {}, x)))))), 3,
    base ? `변경 없음 · 서버 ${base}대의 기준 상태와 비교 중` : "첫 기준 상태를 기록하는 중입니다 (1시간 안)");
}

let chatsPage = 0, chatsTimer;
async function loadChats() {
  const d = await api(`/api/ai/chats?${new URLSearchParams({ q: $("chatsQ").value.trim(), page: chatsPage })}`);
  $("chatsMeta").textContent = `${d.total.toLocaleString()}건 · 1년 보관`;
  $("chatHistory").replaceChildren(...(d.chats.length ? d.chats.map((c) => h("li", {},
    h("div", { class: "muted" }, fmtDateTime(c.ts), " · ", c.ip, c.label ? ` (${c.label})` : ""),
    h("div", {}, h("b", {}, "Q. "), c.question),
    h("details", {}, h("summary", { class: "ink2" }, "답변 보기"), h("div", { class: "answer" }, ...md(c.answer))))) : [h("li", { class: "muted" }, "기록이 없습니다")]));
  $("chatsPrev").disabled = chatsPage === 0;
  $("chatsNext").disabled = (chatsPage + 1) * 20 >= d.total;
}
$("chatsQ").addEventListener("input", () => { clearTimeout(chatsTimer); chatsTimer = setTimeout(() => { chatsPage = 0; loadChats(); }, 300); });
$("chatsPrev").addEventListener("click", () => { chatsPage--; loadChats(); });
$("chatsNext").addEventListener("click", () => { chatsPage++; loadChats(); });

$("chatForm").addEventListener("submit", (e) => { e.preventDefault(); const q = $("chatInput").value; $("chatInput").value = ""; askAi(q); });
$("chatInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); $("chatForm").requestSubmit(); } });
$("chatSuggest").addEventListener("click", (e) => { const b = e.target.closest("button[data-q]"); if (b) askAi(b.dataset.q); });

// ---------------------------------------------------------------- servers (tailnet)

let currentNode = null;
let DASHBOARD_TS_IP = "<대시보드_Tailscale_IP>";  // filled from /api/nodes (tailscale ip -4 on the server)

function miniMeter(label, v, unit, warn, crit) {
  const bar = h("div", { class: "meter" }, h("i", { class: level(v, warn, crit) }));
  bar.firstChild.style.width = `${Math.min(100, Math.max(0, v || 0))}%`;
  return h("div", { class: "mini" }, h("div", { class: "mini-k" }, label, h("span", { class: "num" }, v == null ? "–" : `${Math.round(v)}${unit}`)), bar);
}

function serverCard(n, isLocal) {
  const d = isLocal ? n : n.data;
  const now = isLocal ? n.now : d && d.now;
  const online = isLocal ? true : n.online;
  const status = online ? h("span", { class: "pill good" }, "온라인") : online === false ? h("span", { class: "pill crit" }, "연결 끊김") : h("span", { class: "pill" }, "확인 중");
  return h("button", { class: "card server-card" + (online === false ? " offline" : ""), onclick: () => { if (isLocal) { closeNode(); selectTab("overview"); } else openNode(n.id); } },
    h("div", { class: "sc-head" }, h("b", {}, n.name), status, isLocal ? h("span", { class: "pill me" }, "이 서버") : null),
    h("div", { class: "muted mono" }, isLocal ? `${n.host} · ${DASHBOARD_TS_IP}` : `${(d && d.host) || "?"} · ${n.address}`),
    n.memo ? h("div", { class: "sc-memo" }, n.memo) : null,
    now ? h("div", { class: "minis" }, miniMeter("CPU", now.cpu, "%", 60, 80), miniMeter("메모리", now.mem, "%", 75, 90),
      miniMeter("온도", now.temp, "°", 70, 85), miniMeter("디스크", now.disk, "%", 80, 92))
      : h("div", { class: "err-text" }, n.error || "데이터 없음"),
    h("div", { class: "muted sc-foot" }, isLocal ? `가동 ${fmtDur(n.uptime)}` : online ? `가동 ${fmtDur(d.uptime)}` : n.last_ok ? `마지막 응답 ${fmtAgo(n.last_ok)}` : ""));
}

async function loadServers() {
  if (currentNode == null) loadSites().catch(() => {});
  const d = await api("/api/nodes");
  if (d.local.ts_ip && d.local.ts_ip !== DASHBOARD_TS_IP) {
    DASHBOARD_TS_IP = d.local.ts_ip;
    $("installCmd").textContent = `bash ~/node_agent/install.sh ${DASHBOARD_TS_IP}`;
  }
  if (currentNode == null && !$("serverListView").classList.contains("hidden")) loadFleet(d).catch(() => {});
  const local = h("div", { class: "local-wrap" }, serverCard(d.local, true),
    h("button", { class: "link-btn", onclick: (e) => { e.stopPropagation(); editServer(d.local, true); } }, "정보 수정"));
  $("serverCards").replaceChildren(local, ...d.nodes.map((n) => serverCard(n, false)));
  fillServerSel(d);
  if (currentNode != null) {
    const n = d.nodes.find((x) => x.id === currentNode);
    if (n) renderNode(n); else closeNode();
  }
}

/** One place decides which server the page is about: header, tabs, banner and the switcher follow it. */
function applyView() {
  const remote = currentNode != null;
  if (applyView.last !== currentNode) {  // new server: start a fresh AI conversation about it
    applyView.last = currentNode;
    aiHistory = []; $("chatLog").replaceChildren(); $("chatSuggest").classList.remove("hidden"); aiShownReport = undefined;
  }
  $("viewBanner").classList.toggle("hidden", !remote);
  if (remote) {
    const n = nodeCache && nodeCache.id === currentNode ? nodeCache : null, d = (n && n.data) || {};
    $("host").textContent = n ? n.name : "…";
    $("meta").textContent = n ? (n.online ? `가동 ${fmtDur(d.uptime)} · 부팅 ${fmtDateTime(d.boot_time)} · ${d.os || ""}` : `연결 끊김 · ${n.error || ""}`) : "";
    $("vbName").textContent = n ? n.name : ""; $("vbAddr").textContent = n ? `${d.host || "?"} · ${n.address}` : "";
  } else if (lastStatus) {
    $("host").textContent = lastStatus.name || lastStatus.host;
    $("meta").textContent = `가동 ${fmtDur(lastStatus.uptime)} · 부팅 ${fmtDateTime(lastStatus.boot_time)} · ${lastStatus.os}`;
  }
  document.title = `${$("host").textContent} · 서버 모니터`;
  if ($("serverSel").querySelector(`option[value="${remote ? currentNode : "local"}"]`)) $("serverSel").value = remote ? String(currentNode) : "local";
}

function openNode(id, tab) {
  currentNode = id;
  applyView();
  selectTab(tab || "overview");
}
function closeNode() {
  currentNode = null;
  applyView();
}
$("vbBack").addEventListener("click", () => { closeNode(); selectTab(activeTab === "servers" ? "overview" : activeTab); });
$("nodeBack").addEventListener("click", () => { closeNode(); selectTab("servers"); });

let nodeCache = null;
/** Agent older than 1.2 reports only user services and no ports. */
const agentBelow = (v, minor) => { const [a, b] = String(v || "1.0").split(".").map(Number); return a < 1 || (a === 1 && b < minor); };
const agentOld = (v) => agentBelow(v, 2);
function renderNode(n) {
  nodeCache = n;
  applyView();
  const d = n.data || {}, x = d.now;
  $("ndName").textContent = n.name;
  $("ndMeta").textContent = n.online ? `${d.host} · ${n.address} · ${d.os || ""} · 가동 ${fmtDur(d.uptime)}` : `${n.address} · ${n.error || "연결 끊김"}`;
  $("ndScope").textContent = agentOld(d.version)
    ? `⚠ 에이전트 ${d.version || "구버전"} — 시스템 서비스·포트를 보려면 그 서버에 에이전트를 다시 설치하세요 (토큰 유지)`
    : "사용자 서비스는 제어 가능 · 시스템 서비스는 보기 전용 (root 필요)";
  if (x) {
    $("ndTiles").replaceChildren(
      tile("CPU", x.cpu.toFixed(1), "%", `${d.cpu_count}코어`, x.cpu, level(x.cpu, 60, 80)),
      tile("메모리", x.mem.toFixed(1), "%", `${fmtBytes(x.mem_used)} / ${fmtBytes(x.mem_total)}`, x.mem, level(x.mem, 75, 90)),
      tile("CPU 온도", x.temp != null ? x.temp.toFixed(0) : "–", "°C", "패키지 온도", x.temp, level(x.temp, 70, 85)),
      tile("로드 평균", x.load[0].toFixed(2), "", `5분 ${x.load[1].toFixed(2)} · 15분 ${x.load[2].toFixed(2)}`, (x.load[0] / d.cpu_count) * 100, level(x.load[0] / d.cpu_count, 0.8, 1.2)),
      tile("스왑", (x.swap ?? 0).toFixed(1), "%", `${fmtBytes(x.swap_used)} / ${fmtBytes(x.swap_total)}`, x.swap, level(x.swap, 50, 80)),
      tile("디스크 /", x.disk != null ? x.disk.toFixed(0) : "–", "%", "루트 파티션", x.disk, level(x.disk, 80, 92)),
      tile("네트워크 수신", fmtRate(x.net_rx), "", `송신 ${fmtRate(x.net_tx)}`, null, ""));
    fill($("ndTemps"), (x.temps || []).map((t) => h("tr", {},
      h("td", {}, t.label, h("span", { class: "muted" }, t.label !== t.chip ? ` · ${t.chip}` : "")),
      h("td", { class: "r num" }, `${t.current.toFixed(0)}°C`))), 2, "온도 센서를 찾지 못했습니다");
    fill($("ndDisks"), (x.disks || []).map((dk) => {
      const bar = h("div", { class: "meter" }, h("i", { class: level(dk.percent, 80, 92) }));
      bar.firstChild.style.width = `${dk.percent}%`;
      return h("tr", {}, h("td", { class: "mono" }, dk.mount), h("td", { class: "r num" }, fmtBytes(dk.used)),
        h("td", { class: "r num" }, fmtBytes(dk.total)), h("td", {}, h("span", { class: "num" }, `${dk.percent}%`), bar));
    }), 4, "–");
    fill($("ndProcs"), x.top.map((p) => h("tr", {}, h("td", {}, p.name), h("td", { class: "num" }, p.pid), h("td", { class: "muted" }, p.user),
      h("td", { class: "r num" }, `${p.cpu.toFixed(1)}%`), h("td", { class: "r num" }, `${p.mem.toFixed(1)}%`))), 5, "–");
  } else {
    $("ndTiles").replaceChildren(h("div", { class: "card err-text" }, n.error || "서버에 연결할 수 없습니다"));
  }
  const du = d.home_du;
  $("ndHomeMeta").textContent = du ? `${fmtAgo(du.ts)} 계산 · 홈 전체 ${fmtBytes(du.total)} · 1시간마다 다시 계산` : "";
  const dmax = du && du.dirs.length ? du.dirs[0].size : 1;
  put($("ndHomeDu"), du && du.dirs.length ? du.dirs.map((f) => {
    const bar = h("div", { class: "meter" }, h("i", {}));
    bar.firstChild.style.width = `${(f.size / dmax) * 100}%`;
    return h("li", {}, h("span", { class: "mono" }, f.path), h("span", { class: "num" }, fmtBytes(f.size)), bar);
  }) : h("li", { class: "muted" }, agentBelow(d.version, 5) ? "에이전트 1.5 이상에서 표시됩니다" : "계산 중… (설치 후 몇 분 걸릴 수 있어요)"));
}


async function nodeServiceAction(n, unit, action) {
  const label = { start: "시작", stop: "종료", restart: "재시작", enable: "부팅 시 자동 실행 켜기", disable: "부팅 시 자동 실행 끄기", delete: "삭제" }[action];
  const why = action === "delete" ? " 서비스 파일은 그 서버의 ~/.config/systemd/user/.deleted/ 로 옮겨집니다." : "";
  if (!(await confirmDialog(`${n.name} · ${unit}`, `${n.name} 서버의 ${unit} 을(를) ${label}할까요?${why}`, ["stop", "disable", "delete"].includes(action)))) return;
  try { await post(`/api/nodes/${n.id}/services/${encodeURIComponent(unit)}/${action}`); toast(`${label} 요청을 보냈습니다.`); setTimeout(() => loadServers().catch(() => {}), 1500); }
  catch (err) { toast(err.message, true); }
}

async function loadNodeMetrics() {
  if (currentNode == null) return;
  const m = await api(`/api/nodes/${currentNode}/metrics?hours=24`);
  const P = m.points, b = m.bucket;
  const pct = (v, sh) => `${v.toFixed(sh ? 0 : 1)}%`, deg = (v, sh) => `${v.toFixed(0)}${sh ? "°" : "°C"}`;
  const peak = (key, f) => { const vs = P.filter((p) => p[key] != null); if (!vs.length) return ""; const t = vs.reduce((a, c) => (c[key] > a[key] ? c : a)); return `최고 ${f(t[key])} · ${fmtTime(t.t)}`; };
  lineChart($("ndChartCpu"), P.map((p) => ({ t: p.t, v: p.cpu, max: p.cpu_max })), { yMax: 100, threshold: 80, fmt: pct, bucket: b, hours: 24 });
  lineChart($("ndChartMem"), P.map((p) => ({ t: p.t, v: p.mem })), { yMax: 100, threshold: 90, fmt: pct, bucket: b, hours: 24 });
  lineChart($("ndChartTemp"), P.map((p) => ({ t: p.t, v: p.temp, max: p.temp_max })), { yMax: 100, threshold: 85, fmt: deg, bucket: b, hours: 24 });
  lineChart($("ndChartLoad"), P.map((p) => ({ t: p.t, v: p.load1 })), { fmt: (v) => v.toFixed(2), bucket: b, hours: 24 });
  $("ndLoadPeak").textContent = peak("load1", (v) => v.toFixed(2));
  $("ndCpuPeak").textContent = peak("cpu_max", (v) => pct(v)); $("ndMemPeak").textContent = peak("mem", (v) => pct(v)); $("ndTempPeak").textContent = peak("temp_max", (v) => deg(v));
}

$("ndRename").addEventListener("click", () => nodeCache && editServer(nodeCache, false));

function editServer(n, isLocal) {
  $("editTitle").textContent = `${n.name} 정보 수정`;
  $("edName").value = n.name; $("edMemo").value = n.memo || "";
  $("edAddr").value = isLocal ? "" : n.address; $("edToken").value = "";
  $("edRemote").classList.toggle("hidden", isLocal);
  $("editForm").onsubmit = async (e) => {
    e.preventDefault();
    $("edSave").disabled = true;
    const body = { name: $("edName").value.trim(), memo: $("edMemo").value.trim() };
    if (!isLocal) Object.assign(body, { address: $("edAddr").value.trim(), token: $("edToken").value.trim() });
    try {
      await post(isLocal ? "/api/local/edit" : `/api/nodes/${n.id}/edit`, body);
      $("editModal").close(); toast("저장했습니다."); loadServers(); if (isLocal) loadStatus().catch(() => {});
    } catch (err) { toast(err.message, true); }
    finally { $("edSave").disabled = false; }
  };
  $("editModal").showModal();
}
$("edCancel").addEventListener("click", () => $("editModal").close());

/** Top-bar switcher: pick any server from anywhere in the dashboard. */
function fillServerSel(d) {
  const sel = $("serverSel"), cur = currentNode != null ? String(currentNode) : "local";
  const opts = [h("option", { value: "local" }, `${d.local.name} (이 서버)`),
    ...d.nodes.map((n) => h("option", { value: String(n.id) }, `${n.name}${n.online === false ? " · 끊김" : ""}`))];
  sel.replaceChildren(...opts);
  sel.value = cur;
}
$("serverSel").addEventListener("change", (e) => {
  const keep = activeTab === "servers" ? "overview" : activeTab;  // switching server keeps the tab you're on
  if (e.target.value === "local") { closeNode(); selectTab(keep); }
  else openNode(Number(e.target.value), keep);
});
$("ndDelete").addEventListener("click", async () => {
  if (!nodeCache) return;
  if (!(await confirmDialog("서버 삭제", `${nodeCache.name} 을(를) 목록에서 뺄까요? (그 서버의 에이전트는 계속 실행됩니다)`, true))) return;
  await post(`/api/nodes/${nodeCache.id}/delete`); closeNode(); loadServers();
});

$("scpCmd").textContent = `scp -r ~/server-monitor/node_agent <사용자>@<새서버>:~/`;
$("installCmd").textContent = `bash ~/node_agent/install.sh ${DASHBOARD_TS_IP}`;
$("addServerBtn").addEventListener("click", () => { $("addServer").classList.toggle("hidden"); $("nsName").focus(); });
$("addServerCancel").addEventListener("click", () => $("addServer").classList.add("hidden"));
$("addServerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.submitter; btn.disabled = true; btn.textContent = "연결 확인 중…";
  try {
    const r = await post("/api/nodes", { name: $("nsName").value.trim(), address: $("nsAddr").value.trim(), token: $("nsToken").value.trim() });
    toast(`추가했습니다 (${r.host})`);
    $("addServerForm").reset(); $("addServer").classList.add("hidden"); loadServers();
  } catch (err) { toast(err.message, true); }
  finally { btn.disabled = false; btn.textContent = "연결 확인 후 추가"; }
});


// ---------------------------------------------------------------- shared tabs for a remote server

/** Fresh data for the server being viewed (from /api/nodes, which the dashboard polls anyway). */
async function currentNodeData() {
  const d = await api("/api/nodes");
  fillServerSel(d);
  const n = d.nodes.find((x) => x.id === currentNode);
  if (!n) { closeNode(); throw new Error("서버가 목록에서 사라졌습니다"); }
  nodeCache = n;
  applyView();
  return n;
}
const oldAgentNote = (d) => agentOld(d.version) ? `⚠ 에이전트 ${d.version || "구버전"} — 그 서버에 에이전트를 다시 설치하면 모든 정보가 보입니다 (토큰 유지)` : null;

function renderNodeServices(n) {
  const d = n.data || {};
  $("lingerNote").textContent = oldAgentNote(d) || "사용자 서비스는 제어 가능 · 시스템 서비스는 보기 전용 (root 필요)";
  const svcs = [...(d.services || [])].sort((a, b) => (a.active === "failed" ? -1 : 0) - (b.active === "failed" ? -1 : 0)
    || (b.controllable !== false) - (a.controllable !== false) || a.unit.localeCompare(b.unit));
  fill($("services"), svcs.map((sv) => {
    const ctl = sv.controllable !== false;  // agents < 1.2 only reported controllable user units
    const running = sv.active === "active", enabled = sv.enabled === "enabled";
    const cls = running ? "good" : sv.active === "failed" ? "crit" : "";
    const act = (a) => nodeServiceAction(n, sv.unit, a);
    return h("tr", {},
      h("td", {}, h("b", { class: "mono" }, sv.unit), sv.protected ? h("span", { class: "pill lock" }, "보호") : null,
        h("span", { class: "pill scope" }, sv.scope === "system" ? "시스템" : "사용자"), h("div", { class: "muted" }, sv.description || "")),
      h("td", {}, h("span", { class: `pill ${cls}` }, `${sv.active} (${sv.sub})`)), h("td", { class: "num" }, sv.pid || "–"),
      h("td", { class: "r num muted" }, "–"), h("td", { class: "muted" }, running ? fmtSince(sv.since) : "–"),
      h("td", { class: "r num" }, sv.restarts ?? "–"),
      h("td", {}, ctl && (enabled || sv.enabled === "disabled")
        ? h("button", { class: "switch", role: "switch", "aria-checked": String(enabled), disabled: enabled && sv.protected, onclick: () => act(enabled ? "disable" : "enable") }, h("i", {}), h("span", {}, enabled ? "켜짐" : "꺼짐"))
        : h("span", { class: "muted" }, enabled ? "켜짐" : sv.enabled || "–")),
      h("td", { class: "actions" }, ctl ? [
        running ? null : h("button", { class: "btn", onclick: () => act("start") }, "켜기"),
        h("button", { class: "btn", onclick: () => act("restart") }, "다시 켜기"),
        running && !sv.protected ? h("button", { class: "btn danger", onclick: () => act("stop") }, "종료") : null,
        !running && !sv.protected && !agentBelow(d.version, 6) ? h("button", { class: "btn danger", onclick: () => act("delete") }, "삭제") : null]
        : h("span", { class: "muted", title: `그 서버에서: sudo systemctl restart ${sv.unit}` }, "보기 전용"),
        agentBelow(d.version, 7) ? null : h("button", { class: "btn", onclick: () => openLogs(sv.unit, n) }, "로그")));
  }), 8, n.online ? "등록된 서비스가 없습니다" : "서버에 연결할 수 없습니다");
}

async function nodeKill(n, pid, name) {
  if (!(await confirmDialog("프로세스 종료", `${n.name} 서버의 PID ${pid} (${name || "?"}) 에 종료 신호(SIGTERM)를 보낼까요?`, true))) return;
  try { await post(`/api/nodes/${n.id}/process/${pid}/terminate`); toast(`PID ${pid} 종료 신호를 보냈습니다.`); setTimeout(() => loadNetwork().catch(() => {}), 12000); }
  catch (err) { toast(err.message, true); }
}

function renderNodeNetwork(n) {
  const d = n.data || {}, x = d.now || {}, hf = d.host_facts || {};
  const note = oldAgentNote(d);
  fill($("listening"), (x.ports || []).map((l) => h("tr", {},
    h("td", { class: "num" }, h("b", {}, l.port)), h("td", { class: "mono" }, l.ip),
    h("td", {}, h("span", { class: `pill ${l.public ? "warn" : "good"}` }, l.public ? "외부 노출" : "로컬 전용")),
    h("td", {}, l.process || h("span", { class: "muted" }, "(다른 사용자)"),
      l.cwd ? h("div", { class: "muted mono", title: l.cwd }, `📁 ${l.cwd.replace(/^\/home\/[^/]+/, "~")}`) : null),
    h("td", { class: "num" }, l.pid || "–"),
    h("td", { class: "actions" }, l.pid && l.process ? h("button", { class: "btn danger", onclick: () => nodeKill(n, l.pid, l.process) }, "종료") : null))),
    6, note || "열린 포트가 없습니다");
  const connRow = (c) => h("tr", {}, h("td", { class: "mono" }, `${c.remote}:${c.rport}`), h("td", { class: "num" }, c.lport),
    h("td", {}, c.process || h("span", { class: "muted" }, "–")));
  fill($("inbound"), (x.inbound || []).map(connRow), 3, note || "외부에서 직접 접속한 클라이언트가 없습니다");
  fill($("outbound"), (x.outbound || []).map(connRow), 3, note || "–");
  fill($("users"), (hf.sessions || []).map((u) => h("tr", {}, h("td", {}, u.name || "–"), h("td", { class: "mono" }, u.terminal || "–"),
    h("td", { class: "mono" }, u.host || "로컬"), h("td", { class: "muted" }, u.started ? fmtDateTime(u.started) : "–"))),
    4, note || "로그인한 사용자가 없습니다");
}

const SSH_EVENT = { login_ok: ["로그인 성공", "good"], login_fail: ["비밀번호 실패", "crit"], invalid_user: ["없는 계정 시도", "crit"] };
function renderNodeAccess(n) {
  const d = n.data || {}, ssh = (d.host_facts || {}).ssh;
  const empty = oldAgentNote(d) || (ssh === null ? "이 서버의 시스템 로그를 읽을 권한이 없습니다 (그 계정을 adm 그룹에 추가하세요)" : "기록이 없습니다");
  const by = {};
  for (const e of ssh || []) {
    const k = by[e.ip] || (by[e.ip] = { ip: e.ip, ok: 0, fail: 0, first: e.ts, last: e.ts, users: new Set() });
    e.event === "login_ok" ? k.ok++ : k.fail++;
    k.first = Math.min(k.first, e.ts); k.last = Math.max(k.last, e.ts); k.users.add(e.user);
  }
  fill($("rIpSummary"), Object.values(by).sort((a, b) => b.last - a.last).map((r) => h("tr", {},
    ipCell({ ip: r.ip }), h("td", { class: "r num" }, r.ok), h("td", { class: "r num" }, r.fail ? h("b", {}, r.fail) : 0),
    h("td", { class: "muted" }, fmtDateTime(r.first)), h("td", {}, fmtDateTime(r.last)), h("td", { class: "mono" }, [...r.users].join(", ")))),
    6, empty);
  fill($("rAccess"), [...(ssh || [])].reverse().map((e) => {
    const [lbl, cls] = SSH_EVENT[e.event] || [e.event, ""];
    return h("tr", {}, h("td", { class: "num" }, fmtDateTime(e.ts)), ipCell({ ip: e.ip }),
      h("td", {}, h("span", { class: `pill ${cls}` }, lbl)), h("td", { class: "mono" }, e.user), h("td", { class: "muted" }, e.method || "–"));
  }), 5, empty);
}

async function renderNodeSecurity(n) {
  const d = n.data || {}, hf = d.host_facts || {}, sec = hf.security, x = d.now || {};
  const exposed = (x.ports || []).filter((p) => p.public);
  const fails = (hf.ssh || []).filter((e) => e.event !== "login_ok" && e.ts > Date.now() / 1000 - 86400);
  const fact = (ok, k, v) => h("li", {}, h("span", { class: `pill ${ok ? "good" : "crit"}` }, ok ? "양호" : "주의"), h("b", {}, k), " — ", v);
  $("rSecMeta").textContent = sec ? `${n.name} · 1분마다 갱신` : "";
  put($("rSecFacts"), sec ? [
    h("li", {}, h("span", { class: "pill" }, "정보"), h("b", {}, "SSH 로그인 방식"), " — ",
      sec.ssh_password_auth === "no" ? "키 전용" : `비밀번호 (관리자 선택) · 등록된 키 ${sec.authorized_keys}개`),
    fact(sec.ssh_root_login !== "yes", "root SSH 로그인", sec.ssh_root_login),
    fact(sec.firewall === "on", "방화벽(ufw)", sec.firewall === "on" ? "켜짐" : "꺼짐"),
    fact(fails.length < 5, "SSH 로그인 실패 (24시간)", hf.ssh === null ? "로그 읽기 권한 없음" : `${fails.length}회`),
    fact(exposed.every((p) => p.port === 22 || /^(100\.|fd7a:115c:a1e0:)/.test(p.ip)), "외부 노출 포트",
      exposed.length ? exposed.map((p) => `${p.port}${p.process ? `(${p.process})` : ""}`).join(", ") : "없음"),
    fact(!sec.reboot_required, "재부팅 필요", sec.reboot_required ? "예 — 업데이트 적용을 위해 재부팅 필요" : "아니오"),
    d.updates ? fact(!d.updates.security && d.updates.auto_security, "업데이트", updatesText(d.updates))
      : h("li", {}, h("span", { class: "pill" }, "정보"), h("b", {}, "업데이트"), " — ", agentBelow(d.version, 7) ? "에이전트 1.7 이상에서 표시" : "확인 중…"),
    d.backups ? h("li", {}, h("span", { class: "pill" }, "정보"), h("b", {}, "보관 중인 대시보드 백업"), " — ",
      d.backups.length ? `${d.backups.length}개 (최신 ${d.backups[d.backups.length - 1].name})` : "아직 없음 (매시 확인 후 복사)") : null,
  ] : h("li", { class: "muted" }, oldAgentNote(d) || "아직 수집 전입니다 (최대 1분)"));
  renderHostBlocks("r", agentBelow(d.version, 5) ? null : (hf.blocker === undefined ? null : hf.blocker), n);
  if (agentBelow(d.version, 5)) $("rHbMeta").textContent = `에이전트 ${d.version || "구버전"} — 1.5 로 다시 설치한 뒤 그 서버에서: sudo bash ~/node_agent/install-blocker.sh`;
  const [{ actions }, { alerts: al }] = await Promise.all([api(`/api/ai/actions?server=${encodeURIComponent(n.name)}`), api("/api/alerts")]);
  fill($("rAiActions"), actions.map((a) => {
    const [sl, sc] = FIX_STATUS[a.status] || [a.status, ""];
    return h("tr", {}, h("td", { class: "num" }, fmtDateTime(a.ts)), h("td", {}, a.server || "–"), h("td", { class: "mono" }, a.target),
      h("td", {}, FIX_KIND[a.kind] || a.kind), h("td", {}, h("span", { class: `pill ${sc}` }, sl)), h("td", {}, a.reason));
  }), 6, "이 서버에 대한 자동 조치 기록이 없습니다");
  fill($("rAlerts"), al.filter((a) => (a.message || "").includes(`'${n.name}'`) || (a.message || "").includes(n.name)).map((a) => {
    const [lbl, cls] = ALERT_KIND[a.kind] || [a.kind, ""];
    return h("tr", {}, h("td", { class: "num" }, fmtDateTime(a.ts)), h("td", {}, h("span", { class: `pill ${cls}` }, lbl)), h("td", {}, a.message));
  }), 3, "이 서버 알림이 없습니다");
}

function toggleRemote(prefix, remote) {
  $(`${prefix}Remote`).classList.toggle("hidden", !remote);
  $(`${prefix}Local`).classList.toggle("hidden", remote);
}


// ---------------------------------------------------------------- service logs

let logTarget = null;
async function openLogs(unit, node) {
  logTarget = { unit, node };
  $("logTitle").textContent = `${node ? node.name : "이 서버"} · ${unit} 최근 로그`;
  $("logBody").textContent = "불러오는 중…";
  $("logAiOut").replaceChildren();
  if (!$("logModal").open) $("logModal").showModal();
  try {
    const r = await api(node ? `/api/nodes/${node.id}/services/${encodeURIComponent(unit)}/logs?lines=300`
                             : `/api/services/${encodeURIComponent(unit)}/logs?lines=300`);
    $("logBody").textContent = r.log;
    $("logBody").scrollTop = $("logBody").scrollHeight;  // newest at the bottom
  } catch (err) { $("logBody").textContent = err.message; }
}
$("logRefresh").addEventListener("click", () => logTarget && openLogs(logTarget.unit, logTarget.node));
$("logClose").addEventListener("click", () => $("logModal").close());
$("logAi").addEventListener("click", async () => {
  if (!logTarget) return;
  const btn = $("logAi");
  btn.disabled = true; btn.textContent = "분석 중…";
  put($("logAiOut"), h("p", { class: "muted" }, "비밀번호·토큰은 가린 뒤 AI에게 보냅니다. 30초~1분 걸려요."));
  try {
    const r = await post("/api/ai/analyze-log", { unit: logTarget.unit, node: logTarget.node ? logTarget.node.id : null });
    put($("logAiOut"), h("div", { class: "card log-ai" }, h("p", { class: "brief-summary" }, ...md(r.summary)),
      findingsList({ findings: r.problems }),
      r.fixes.length ? h("div", {}, h("div", { class: "muted" }, "해결 방법"), h("ol", {}, r.fixes.map((f) => h("li", {}, ...md(f))))) : null));
  } catch (err) { put($("logAiOut"), h("p", { class: "muted" }, `⚠ ${err.message}`)); }
  finally { btn.disabled = false; btn.textContent = "AI로 분석"; }
});

// ---------------------------------------------------------------- website checks

async function loadSites() {
  const { sites } = await api("/api/sites");
  fill($("siteRows"), sites.map((x) => h("tr", {},
    h("td", {}, h("b", {}, x.name)), h("td", { class: "mono ellipsis", title: x.url }, x.url),
    h("td", {}, x.ok == null ? h("span", { class: "pill" }, "확인 중")
      : h("span", { class: `pill ${x.ok ? "good" : "crit"}` }, x.ok ? `정상 ${x.code}` : (x.code ? `오류 ${x.code}` : "응답 없음"))),
    h("td", { class: "r num" }, x.ms != null ? `${x.ms}ms` : "–"),
    h("td", { class: "muted" }, x.ts ? fmtAgo(x.ts) : "–"), h("td", { class: "muted" }, x.since ? fmtDur(Date.now() / 1000 - x.since) : "–"),
    h("td", { class: "actions" }, h("button", { class: "btn danger", onclick: async () => {
      if (!(await confirmDialog("감시 해제", `${x.name} (${x.url}) 감시를 그만할까요?`, true))) return;
      await post("/api/sites/delete", { url: x.url }); loadSites();
    } }, "삭제")))), 7, "등록된 웹사이트가 없습니다");
}
$("siteForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await post("/api/sites", { name: $("siteName").value.trim(), url: $("siteUrl").value.trim() });
    $("siteForm").reset(); toast("추가했습니다."); loadSites();
  } catch (err) { toast(err.message, true); }
});

// ---------------------------------------------------------------- machine power

const POWER_TEXT = { reboot: "재부팅", poweroff: "종료" };

/** target: { node } for a remote server, or {} for this server. State comes from logind ("yes" once allow-power.sh ran). */
async function openPower(action, target) {
  const remote = !!target.node;
  let name, state, cmd;
  if (remote) {
    const n = target.node, d = n.data || {};
    name = n.name; state = ((d.host_facts || {}).power || {})[action] || (agentBelow(d.version, 4) ? "old" : "unknown");
    cmd = state === "old" ? "에이전트를 1.4 이상으로 다시 설치한 뒤:\nsudo bash ~/node_agent/allow-power.sh" : "sudo bash ~/node_agent/allow-power.sh";
  } else {
    const p = await api("/api/power");
    name = p.name; state = p[action]; cmd = "sudo bash ~/server-monitor/node_agent/allow-power.sh";
  }
  const verb = POWER_TEXT[action];
  $("powerTitle").textContent = `${name} ${verb}`;
  $("powerWarn").textContent = action === "poweroff"
    ? (remote ? `${name} 서버가 꺼집니다. 다시 켜려면 그 기기의 전원 버튼을 직접 눌러야 합니다.`
              : "⚠ 이 서버(대시보드 본체)가 꺼집니다. 대시보드·AI·터널이 모두 멈추고, 다시 켜려면 전원 버튼을 직접 눌러야 합니다.")
    : (remote ? `${name} 서버가 재부팅됩니다. 1~2분 뒤 다시 연결됩니다.`
              : "이 서버(대시보드 본체)가 재부팅됩니다. 1~2분 동안 대시보드에 접속할 수 없습니다.");
  const ready = state === "yes";
  $("powerSetup").classList.toggle("hidden", ready);
  $("powerFields").classList.toggle("hidden", !ready);
  $("powerGo").classList.toggle("hidden", !ready);
  $("powerCmd").textContent = cmd;
  $("powerNameHint").textContent = name;
  $("powerConfirm").value = ""; $("powerPw").value = "";
  $("powerGo").textContent = verb;
  $("powerForm").onsubmit = async (e) => {
    e.preventDefault();
    if ($("powerConfirm").value.trim() !== name) { toast("서버 이름이 일치하지 않습니다.", true); return; }
    $("powerGo").disabled = true;
    try {
      const body = { action, password: $("powerPw").value, confirm: $("powerConfirm").value.trim() };
      await post(remote ? `/api/nodes/${target.node.id}/power` : "/api/power", body);
      $("powerModal").close();
      toast(`${name} ${verb} 명령을 보냈습니다. 몇 초 뒤 실행됩니다.`);
    } catch (err) { toast(err.message, true); }
    finally { $("powerGo").disabled = false; $("powerPw").value = ""; }
  };
  $("powerModal").showModal();
  (ready ? $("powerConfirm") : $("powerCancel")).focus();
}
$("powerCancel").addEventListener("click", () => $("powerModal").close());
$("btnReboot").addEventListener("click", () => openPower("reboot", {}).catch((e) => toast(e.message, true)));
$("btnPoweroff").addEventListener("click", () => openPower("poweroff", {}).catch((e) => toast(e.message, true)));
$("ndReboot").addEventListener("click", () => nodeCache && openPower("reboot", { node: nodeCache }));
$("ndPoweroff").addEventListener("click", () => nodeCache && openPower("poweroff", { node: nodeCache }));

// ---------------------------------------------------------------- tabs & polling

let activeTab = "overview";
const TAB_LOADERS = { overview: () => Promise.all([loadStatus(), loadMetrics(), loadEvents(), loadHomeDu()]), servers: loadServers, services: loadServices,
  network: loadNetwork, ai: () => Promise.all([loadAi(), loadMemory(), loadChats(), loadCases(), loadLessons()]), access: loadAccess, security: loadSecurity };

function selectTab(name) {
  activeTab = name;
  const remoteOverview = currentNode != null && name === "overview";  // a remote server's 개요 is its detail view
  const panel = remoteOverview ? "servers" : name;
  for (const t of document.querySelectorAll(".tab")) t.setAttribute("aria-selected", String(t.dataset.tab === name));
  for (const p of document.querySelectorAll("[data-panel]")) p.classList.toggle("hidden", p.dataset.panel !== panel);
  $("serverDetail").classList.toggle("hidden", !remoteOverview);
  $("serverListView").classList.toggle("hidden", remoteOverview);
  try { sessionStorage.setItem("sm-tab", name); } catch {}
  (remoteOverview ? Promise.all([loadServers(), loadNodeMetrics()]) : TAB_LOADERS[name]()).catch((e) => toast(e.message, true));
}
document.querySelector(".tabs").addEventListener("click", (e) => {
  const t = e.target.closest(".tab");
  if (t) selectTab(t.dataset.tab);
});

let tick = 0;
setInterval(() => {
  if (document.hidden) return;
  tick++;
  const quiet = () => {};
  if (activeTab === "overview" && currentNode != null) {
    if (tick % 2 === 0) loadServers().catch(quiet);
    if (tick % 6 === 0) loadNodeMetrics().catch(quiet);
  } else if (activeTab === "overview") {
    loadStatus().catch(quiet);
    if (tick % 6 === 0) loadMetrics().catch(quiet);
    if (tick % 12 === 0) loadEvents().catch(quiet);
  } else if (activeTab === "services" && tick % 2 === 0) loadServices().catch(quiet);
  else if (activeTab === "network" && tick % 2 === 0) loadNetwork().catch(quiet);
  else if (activeTab === "ai" && tick % 2 === 0) { loadAi().catch(quiet); if (aiView === "now") loadCases().catch(quiet); }
  else if ((activeTab === "access" || activeTab === "security") && currentNode != null && tick % 12 === 0)
    TAB_LOADERS[activeTab]().catch(quiet);
  else if (activeTab === "servers") { if (tick % 2 === 0) loadServers().catch(quiet); if (tick % 6 === 0) loadNodeMetrics().catch(quiet); }
  if (tick % 12 === 0) loadAlertBadge().catch(quiet);
  $("liveDot").classList.toggle("stale", Date.now() - lastStatusAt > 30000 && activeTab === "overview");
}, 5000);

let resizeTimer;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(renderCharts, 150); });

(async () => {
  const me = await api("/api/me");
  CSRF = me.csrf;
  let start = "overview";
  try { start = sessionStorage.getItem("sm-tab") || "overview"; } catch {}
  if (!TAB_LOADERS[start]) start = "overview";
  if (start !== "overview") loadEvents().catch(() => {});
  loadAlertBadge().catch(() => {});
  api("/api/nodes").then(fillServerSel).catch(() => {});
  selectTab(start);
})();
