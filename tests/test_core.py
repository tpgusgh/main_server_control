"""Self-checks for the security-critical logic. Run:  venv/bin/python -m unittest discover -s tests
Uses only in-memory databases — never touches data/monitor.db or data/config.json."""
import base64
import hashlib
import hmac
import sqlite3
import struct
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent  # noqa: E402
import nodes  # noqa: E402
import security  # noqa: E402


def totp_now(secret: str, offset: int = 0) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", int(time.time()) // 30 + offset), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


class PasswordAndTotp(unittest.TestCase):
    def test_password_roundtrip(self):
        h = security.hash_password("correct horse battery")
        self.assertTrue(security.verify_password("correct horse battery", h))
        self.assertFalse(security.verify_password("wrong", h))
        self.assertFalse(security.verify_password("x", "garbage"))

    def test_totp_accepts_current_and_blocks_replay(self):
        secret = security.new_totp_secret()
        code = totp_now(secret)
        counter = security.totp_match(secret, code, 0)
        self.assertIsNotNone(counter)
        self.assertIsNone(security.totp_match(secret, code, counter), "same code must not work twice")
        self.assertIsNone(security.totp_match(secret, "000000" if code != "000000" else "111111", 0))
        self.assertIsNone(security.totp_match(secret, "12ab56", 0))


class TailnetAddressGuard(unittest.TestCase):
    def test_allows_tailscale_only(self):
        self.assertEqual(nodes.parse_address("100.64.1.2"), "http://100.64.1.2:8101")
        self.assertEqual(nodes.parse_address("100.127.255.1:9000"), "http://100.127.255.1:9000")
        self.assertEqual(nodes.parse_address("[fd7a:115c:a1e0::1]:8101"), "http://[fd7a:115c:a1e0::1]:8101")
        self.assertEqual(nodes.parse_address("nas.tail1234.ts.net:8101"), "http://nas.tail1234.ts.net:8101")

    def test_rejects_ssrf_targets(self):
        for bad in ("192.168.0.1:80", "127.0.0.1:8100", "169.254.169.254", "10.0.0.1", "100.128.0.1",
                    "evil.com", "ts.net.evil.com", "localhost:8100", "100.64.1.2:0", "100.64.1.2:99999",
                    "100.64.1.2:80x"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                nodes.parse_address(bad)


def make_analyst(trusted=()):
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript("""
        CREATE TABLE bans(key TEXT, ip TEXT, country TEXT, ts INTEGER, fails INTEGER, ua TEXT, reason TEXT);
        CREATE TABLE access_log(id INTEGER PRIMARY KEY, ts INTEGER, ip TEXT, country TEXT, method TEXT, path TEXT,
                                status INTEGER, ua TEXT, event TEXT, detail TEXT, email TEXT);
        CREATE TABLE metrics(ts INTEGER, cpu REAL, mem REAL, swap REAL, temp REAL, load1 REAL, disk REAL,
                             net_rx REAL, net_tx REAL);
        CREATE TABLE alerts(id INTEGER PRIMARY KEY, ts INTEGER, kind TEXT, ip TEXT, country TEXT, message TEXT);
    """)

    def db(sql, params=(), one=False):
        rows = con.execute(sql, params).fetchall()
        return (rows[0] if rows else None) if one else rows

    a = agent.Analyst(db, services_fn=lambda: [], units_fn=lambda: ["todont-backend.service"],
                      status_fn=None, events_fn=None, ip_labels={}, is_trusted=lambda ip: ip in trusted,
                      config_fn=None)
    return a, db


class RiskRules(unittest.TestCase):
    def test_ai_can_raise_only_one_step(self):
        a, _ = make_analyst()
        now = int(time.time())
        r = a.apply_floor({"risk": "high"}, now - 86400, now)
        self.assertEqual(r["risk"], "medium", "AI alone must not jump low → high")

    def test_rules_set_the_floor(self):
        a, db = make_analyst()
        now = int(time.time())
        db("INSERT INTO bans VALUES('1.2.3.4','1.2.3.4','CN',?,3,'','x')", (now - 10,))
        self.assertEqual(a.apply_floor({"risk": "low"}, now - 86400, now)["risk"], "medium")
        for ip in ("5.5.5.5", "6.6.6.6"):
            db("INSERT INTO bans VALUES(?,?,'CN',?,3,'','x')", (ip, ip, now - 10))
        self.assertEqual(a.apply_floor({"risk": "low"}, now - 86400, now)["risk"], "high")

    def test_trusted_failures_do_not_raise_risk(self):
        a, db = make_analyst(trusted={"9.9.9.9"})
        now = int(time.time())
        db("INSERT INTO access_log(ts, ip, event) VALUES(?, '9.9.9.9', 'login_fail')", (now - 10,))
        self.assertEqual(a.apply_floor({"risk": "low"}, now - 86400, now)["risk"], "low")


class AiOutputValidation(unittest.TestCase):
    def test_only_whitelisted_actions_survive(self):
        a, _ = make_analyst()
        out = a.validate_actions([
            {"type": "restart_service", "target": "todont-backend.service", "reason": "ok"},
            {"type": "restart_service", "target": "todont-backend.service", "reason": "dup"},
            {"type": "restart_service", "target": "ssh.service", "reason": "not managed"},
            {"type": "view_ip", "target": "not-an-ip", "reason": "x"},
            {"type": "unban", "target": "1.2.3.4", "reason": "never"},
            {"type": "view_ip", "target": "8.8.8.8", "reason": "ok"},
        ])
        self.assertEqual([(x["type"], x["target"]) for x in out],
                         [("restart_service", "todont-backend.service"), ("view_ip", "8.8.8.8")])

    def test_paths_lose_instruction_text(self):
        self.assertEqual(agent.safe_path("/a b<script>; rm -rf"), "/abscriptrm-rf")
        self.assertLessEqual(len(agent.safe_path("/x" * 100)), 60)

    def test_remember_command(self):
        self.assertEqual(agent.REMEMBER.match("기억해: todont 는 꺼도 됨").group(1), "todont 는 꺼도 됨")
        self.assertTrue(agent.REMEMBER.match("기억해줘 밤엔 조용히"))
        self.assertIsNone(agent.REMEMBER.match("이거 기억해야 하나?"))


if __name__ == "__main__":
    unittest.main()


def load_sm_block():
    import importlib.machinery
    import importlib.util
    path = str(Path(__file__).resolve().parent.parent / "node_agent" / "sm-block")
    loader = importlib.machinery.SourceFileLoader("sm_block", path)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("sm_block", loader))
    loader.exec_module(mod)
    mod.ssh_peers = lambda: {"8.8.4.4"}  # pretend this IP has a live SSH session
    return mod


class SmBlockGuards(unittest.TestCase):
    def test_never_blocks_internal_or_live_ssh(self):
        m = load_sm_block()
        for ip in ("192.168.219.10", "10.0.0.1", "127.0.0.1", "100.64.101.17", "fd7a:115c:a1e0::1", "::1",
                   "169.254.1.1", "0.0.0.0", "8.8.4.4", "not-an-ip"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                m.key_for(ip)

    def test_public_keys(self):
        m = load_sm_block()
        self.assertEqual(m.key_for("45.155.205.99"), "45.155.205.99")
        self.assertEqual(m.key_for("2a01:4f8:1:2:3:4:5:6"), "2a01:4f8:1:2::/64")

    def test_queue_processing_validates_each_request(self):
        import json as _json
        import tempfile
        import uxrules
        m = load_sm_block()
        with tempfile.TemporaryDirectory() as tmp:
            m.QUEUE, m.PUBLIC, m.STATE = f"{tmp}/q", f"{tmp}/public.json", f"{tmp}/blocked.json"
            m.apply = lambda d: None  # no nft in tests
            Path(m.QUEUE).mkdir()
            for rid, req in {"a": {"op": "add", "ip": "45.155.205.99", "reason": "ssh"},
                             "b": {"op": "add", "ip": "192.168.0.5"},
                             "c": {"op": "nuke"}}.items():
                Path(f"{m.QUEUE}/{rid}.json").write_text(_json.dumps(req))
            d = {}
            m.process(d)
            pub = _json.loads(Path(m.PUBLIC).read_text())
            self.assertEqual([b["key"] for b in pub["blocked"]], ["45.155.205.99"])
            self.assertEqual({k: v["ok"] for k, v in pub["results"].items()}, {"a": True, "b": False, "c": False})
            self.assertEqual(list(Path(m.QUEUE).iterdir()), [], "requests are consumed")


class NightlySchedule(unittest.TestCase):
    def test_servers_are_staggered_15_minutes(self):
        from datetime import datetime as real_dt
        a, db = make_analyst()
        db("CREATE TABLE IF NOT EXISTS node_metrics(node_id INTEGER, ts INTEGER)")
        a.node_ids_fn = lambda: [7, 3]
        day = real_dt(2026, 10, 10, tzinfo=agent.TZ)
        for i in range(0, 4 * 3600, 10):  # 4h of samples for the previous day
            db("INSERT INTO metrics(ts) VALUES(?)", (int(day.timestamp()) - 86400 + i,))

        def due_at(h, m):
            class Fixed(real_dt):
                @classmethod
                def now(cls, tz=None):
                    return real_dt(2026, 10, 10, h, m, tzinfo=agent.TZ)
            agent.datetime = Fixed
            try:
                job = a.daily_due()
            finally:
                agent.datetime = real_dt
            return "nothing" if job is None else job[1]

        self.assertIsNone(due_at(0, 0))       # this server (node None) is due first
        db("INSERT INTO ai_reports(ts, trigger, day) VALUES(1, '일일', '2026-10-09')")
        self.assertEqual(due_at(0, 14), "nothing")  # node 3's slot (00:15) not reached yet
        self.assertEqual(due_at(0, 15), 3)    # lowest id first
        db("INSERT INTO ai_reports(ts, trigger, day, node_id) VALUES(1, '일일', '2026-10-09', 3)")
        self.assertEqual(due_at(0, 20), "nothing")  # node 7's slot is 00:30
        self.assertEqual(due_at(9, 0), 7)     # missed slot is caught up later



class DeleteUnit(unittest.TestCase):
    def test_only_stopped_units_are_moved_to_trash(self):
        import tempfile
        import uxrules
        import types
        from node_agent import hostsec
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.service").write_text("[Service]\n")
            (Path(d) / "b.service").write_text("[Service]\n")
            calls = []

            def systemctl(*args):
                calls.append(args)
                state = "active" if args[:2] == ("show", "b.service") else "inactive"
                return types.SimpleNamespace(stdout=state + "\n", returncode=0)

            ok, _ = hostsec.delete_user_unit("b.service", d, systemctl)
            self.assertFalse(ok, "a running unit must not be deleted")
            self.assertTrue((Path(d) / "b.service").exists())
            ok, msg = hostsec.delete_user_unit("a.service", d, systemctl)
            self.assertTrue(ok, msg)
            self.assertFalse((Path(d) / "a.service").exists())
            self.assertEqual(len(list((Path(d) / ".deleted").iterdir())), 1, "moved, not destroyed")
            self.assertIn(("disable", "a.service"), calls)


class SiteChecks(unittest.TestCase):
    def test_up_down_and_alert_once(self):
        import asyncio
        import threading
        import types
        if "sites" not in sys.modules:  # stub core: importing the real one would open data/monitor.db
            sys.modules.setdefault("core", types.SimpleNamespace(_cfg_lock=threading.Lock(), raise_alert=None,
                                                                 require_auth=None))
        import sites
        sent = []
        sites.raise_alert = lambda kind, ip, country, msg, *a: sent.append(kind)
        codes = iter([200, 502, 502, 502, 301])

        async def fake_get(url):
            return types.SimpleNamespace(status_code=next(codes))
        sites._client = types.SimpleNamespace(get=fake_get)
        site = {"name": "t", "url": "https://t.example/"}
        sites.state.clear()
        for _ in range(5):
            asyncio.run(sites.check(site))
        self.assertEqual(sent, ["site_down", "site_up"], "alert after 2 failures, once; recovery on redirect (Access)")
        self.assertTrue(sites.state[site["url"]]["ok"])


class AutoBanSparesYou(unittest.TestCase):
    def test_rotating_ipv6_and_manual_unban_are_never_auto_banned(self):
        a, db = make_analyst()
        a.fixers = {}
        a.services_fn = lambda: []
        a.status_fn = lambda: {"now": {}, "top": []}
        now = int(time.time())
        rows = [("2001:db8:5:6::aaaa", "login_ok"),                        # you, earlier, one address
                ("2001:db8:5:6::bbbb", "login_fail"), ("2001:db8:5:6::bbbb", "login_fail"),  # you, new address
                ("45.155.205.10", "login_fail"), ("45.155.205.10", "login_fail"),          # unbanned by admin
                ("45.155.205.10", "unban"),
                ("45.155.205.20", "login_fail"), ("45.155.205.20", "login_fail")]          # a stranger
        for ip, ev in rows:
            db("INSERT INTO access_log(ts, ip, event) VALUES(?,?,?)", (now - 60, ip, ev))
        db("CREATE TABLE IF NOT EXISTS ai_actions(item TEXT)")
        cands, _ = a.red_state()
        self.assertEqual([c["target"] for c in cands if c["type"] == "ban_ip"], ["45.155.205.20"])



class RetryBackoff(unittest.TestCase):
    def test_failed_daily_job_is_not_retried_for_an_hour(self):
        from datetime import datetime as real_dt
        a, db = make_analyst()
        db("CREATE TABLE IF NOT EXISTS node_metrics(node_id INTEGER, ts INTEGER)")
        a.node_ids_fn = lambda: [3]
        db("INSERT INTO ai_reports(ts, trigger, day) VALUES(1, '일일', '2026-10-09')")  # this server done

        class Fixed(real_dt):
            @classmethod
            def now(cls, tz=None):
                return real_dt(2026, 10, 10, 1, 0, tzinfo=agent.TZ)
        agent.datetime = Fixed
        try:
            self.assertEqual(a.daily_due()[1], 3)
            a._backoff[("daily", 3, "2026-10-09")] = time.time() + 3600   # what the loop sets after a failure
            self.assertIsNone(a.daily_due(), "a failed slot must wait instead of re-running every minute")
        finally:
            agent.datetime = real_dt

    def test_temperature_alone_does_not_start_a_briefing(self):
        a, db = make_analyst()
        agent.BRIEFING_HOURS = 0  # as in production .env: only event-driven briefings during the day
        a.events_fn = lambda: {"events": [{"end": time.time(), "reasons": ["온도"]}]}
        self.assertIsNone(a.due_trigger())
        a.events_fn = lambda: {"events": [{"end": time.time(), "reasons": ["CPU", "온도"]}]}
        self.assertEqual(a.due_trigger(), "고부하 발생")


class ClaudeBackend(unittest.TestCase):
    def test_runs_without_tools_or_api_key_and_reads_structured_output(self):
        import asyncio
        import json as _json
        import os as _os
        captured = {}

        class FakeProc:
            returncode = 0

            async def communicate(self, data):
                captured["stdin"] = data.decode()
                lines = [{"type": "system", "subtype": "init"},
                         {"type": "rate_limit_event", "rate_limit_info": {"unifiedWindows": {"five_hour": {"utilization": 0.25}}}},
                         {"type": "result", "is_error": False, "result": "", "structured_output": {"risk": "low"},
                          "usage": {"input_tokens": 3, "cache_read_input_tokens": 7, "output_tokens": 5}}]
                return ("\n".join(map(_json.dumps, lines)) + "\n").encode(), b""

        async def fake_exec(*args, **kw):
            captured["args"], captured["env"] = args, kw["env"]
            return FakeProc()

        real = asyncio.create_subprocess_exec
        asyncio.create_subprocess_exec = fake_exec
        _os.environ["ANTHROPIC_API_KEY"] = "sk-should-not-leak"
        try:
            out = asyncio.run(agent.claude_complete({
                "messages": [{"role": "system", "content": "rules"}, {"role": "user", "content": "q"}],
                "response_format": {"json_schema": {"schema": {"type": "object"}}}}))
        finally:
            asyncio.create_subprocess_exec = real
            _os.environ.pop("ANTHROPIC_API_KEY", None)
        args = captured["args"]
        self.assertEqual(args[args.index("--tools") + 1], "", "every built-in tool off")
        self.assertIn("--safe-mode", args)
        self.assertIn("mcp__*", args)
        self.assertNotIn("ANTHROPIC_API_KEY", captured["env"], "never bill an API key by accident")
        self.assertEqual(_json.loads(out["choices"][0]["message"]["content"]), {"risk": "low"})
        self.assertEqual(captured["stdin"], "q")
        self.assertEqual(out["usage"]["in"], 10)
        self.assertEqual(agent.CLAUDE_LIMITS["unifiedWindows"]["five_hour"]["utilization"], 0.25)


class SecurityAgent(unittest.TestCase):
    def test_redact_masks_secrets_keeps_context(self):
        log = ("Oct 10 app[1]: login password=hunter2hunter ok\n"
               "Authorization: Bearer abcdefghijklmnop.qrstu\n"
               "token: sk-ant-oat01-AAAAbbbbCCCC gho_" + "x" * 30 + "\n"
               "jwt eyJ" + "a" * 60 + "\nERROR port 8080 in use")
        out = agent.redact(log)
        for secret in ("hunter2hunter", "abcdefghijklmnop", "sk-ant-oat01", "gho_xxx", "eyJaaa"):
            self.assertNotIn(secret, out)
        self.assertIn("password=[가림]", out)
        self.assertIn("ERROR port 8080 in use", out)

    def test_audit_runs_weekly_and_skips_event_briefing_clock(self):
        a, _ = make_analyst()
        self.assertTrue(a.audit_due())
        a.db("INSERT INTO ai_reports(ts,trigger,risk,content,duration,tps) VALUES(?,?,?,?,?,?)",
             (int(time.time()), "보안점검", "low", '{"score":90,"summary":"","checks":[]}', 1, None))
        self.assertFalse(a.audit_due())
        a._backoff[("audit",)] = 0
        a.db("UPDATE ai_reports SET ts=?", (int(time.time()) - agent.AUDIT_EVERY - 1,))
        self.assertTrue(a.audit_due())


class FleetLogic(unittest.TestCase):
    def test_integrity_diff_names_added_and_removed(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "node_agent"))
        import hostsec
        old = {"ssh_keys": ["aa me@laptop"], "ports": ["tcp/22"], "sshd_config": "x1", "users": ["a(uid 1000)"]}
        new = {"ssh_keys": ["aa me@laptop", "bb evil@x"], "ports": [], "sshd_config": "x2", "users": ["a(uid 1000)"]}
        out = hostsec.integrity_diff(old, new)
        self.assertIn("SSH 공개키 추가: bb evil@x", out)
        self.assertIn("외부에서 열린 포트 제거: tcp/22", out)
        self.assertIn("SSH 서버 설정 변경됨", out)
        self.assertEqual(len(out), 3)
        self.assertEqual(hostsec.integrity_diff(old, {}), [], "missing fields (old agent) are not changes")
        with self.assertRaises(ValueError):
            hostsec.wake("not-a-mac")

    def test_budget_level_saves_tokens_near_the_limit(self):
        future = time.time() + 3600
        for five, week, want in ((0.5, 0.1, "ok"), (0.92, 0.1, "save"), (0.5, 0.96, "save"), (0.98, 0.1, "stop")):
            agent.CLAUDE_LIMITS.clear()
            agent.CLAUDE_LIMITS["unifiedWindows"] = {"five_hour": {"utilization": five, "resetsAt": future},
                                                     "seven_day": {"utilization": week}}
            self.assertEqual(agent.budget_level(), want, (five, week))
        agent.CLAUDE_LIMITS["unifiedWindows"]["five_hour"]["resetsAt"] = time.time() - 1
        self.assertEqual(agent.budget_level(), "ok", "window already reset")
        agent.CLAUDE_LIMITS.clear()


class PortGuard(unittest.TestCase):
    def load_smblock(self):
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("smblock", str(Path(__file__).resolve().parent.parent / "node_agent" / "sm-block"))
        spec = importlib.util.spec_from_loader("smblock", loader)
        m = importlib.util.module_from_spec(spec)
        loader.exec_module(m)
        m.ssh_ports = lambda: [22, 2222]
        return m

    def test_ssh_and_tailscale_can_never_be_closed(self):
        m = self.load_smblock()
        g = m.clean_guard({"lockdown": True, "internal_tcp": [22, 2222, 554, "x", 70000], "internal_udp": [41641, 5353],
                           "allow_tcp": [443]}, dict(m.GUARD_DEFAULT))
        self.assertEqual(g["internal_tcp"], [554])
        self.assertEqual(g["internal_udp"], [5353])
        rules = m.guard_ruleset(g)
        self.assertIn("elements = { 22, 443, 2222 }", rules, "SSH ports always allowed from the internet")
        self.assertIn("elements = { 41641 }", rules)
        for safe in ("ct state established,related accept", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", 'iif "lo" accept'):
            self.assertIn(safe, rules)
        self.assertLess(rules.index("192.168.0.0/16"), rules.index("counter name closed drop"), "LAN accepted before any drop")
        off = m.guard_ruleset(m.clean_guard({"lockdown": False}, g))
        self.assertNotIn("    counter name closed drop", off.replace("tcp dport @internal_tcp counter name closed drop", ""))
        with self.assertRaises(ValueError):
            m.clean_guard({"allow_tcp": list(range(200))}, dict(m.GUARD_DEFAULT))

    def test_service_control_never_touches_access_or_network_units(self):
        m = self.load_smblock()
        denied = ["ssh.service", "sshd.service", "ssh@x.service", "systemd-logind.service", "dbus-broker.service",
                  "tailscaled.service", "cloudflared.service", "getty@tty1.service", "sm-block-queue.service",
                  "wpa_supplicant.service", "wpa_supplicant@wlp2s0.service", "networking.service", "network-manager.service",
                  "NetworkManager.service", "ifup@wlp2s0.service", "netplan-wpa-wlp2s0.service", "cron.service",
                  "unattended-upgrades.service"]
        for u in denied:
            self.assertTrue(m.SVC_DENY.match(u), f"{u} must be refused")
        for u in ["worldrium.service", "worldrium-auth.service", "nginx.service", "docker.service", "postgresql@16-main.service",
                  "mosquitto.service", "frigate.service"]:
            self.assertFalse(m.SVC_DENY.match(u), f"{u} must stay controllable")
        for bad in ("rm", "start; reboot", ""):
            with self.assertRaises(ValueError):
                m.do_svc(bad, "worldrium.service")
        with self.assertRaises(ValueError):
            m.do_svc("stop", "../../etc/passwd")

    def test_slow_service_does_not_crash_the_queue_or_lose_earlier_requests(self):
        import json
        import os
        import shutil
        import subprocess
        import tempfile
        import uxrules
        from unittest import mock
        m = self.load_smblock()
        tmp = tempfile.mkdtemp(prefix="sm-queue-")
        self.addCleanup(shutil.rmtree, tmp, True)
        m.QUEUE, m.PUBLIC = os.path.join(tmp, "requests"), os.path.join(tmp, "public.json")
        os.mkdir(m.QUEUE)
        applied = []
        m.apply, m.save, m.ssh_peers, m.guard_stats = (lambda d: applied.append(sorted(d)), lambda d: None, lambda: set(), lambda: {})
        real = subprocess.run

        def slow_systemctl(cmd, *a, **kw):  # `stop` outlasts the 60 s limit, like a container that is slow to exit
            if cmd[:2] == ["systemctl", "cat"]:
                return subprocess.CompletedProcess(cmd, 0, b"", b"")
            if cmd[0] == "systemctl":
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            return real(cmd, *a, **kw)
        for name, req in (("a.json", {"op": "add", "ip": "8.8.8.8", "reason": "x"}),
                          ("b.json", {"op": "svc", "action": "stop", "unit": "docker.service"}),
                          ("c.json", {"op": "add", "ip": "1.1.1.1", "reason": "y"})):
            Path(m.QUEUE, name).write_text(json.dumps(req))
        with mock.patch.object(subprocess, "run", slow_systemctl):
            m.process({})
        self.assertEqual(applied, [["1.1.1.1", "8.8.8.8"]], "both blocks must reach the firewall despite the slow stop")
        res = json.loads(Path(m.PUBLIC).read_text())["results"]
        self.assertTrue(res["a"]["ok"] and res["c"]["ok"])
        self.assertFalse(res["b"]["ok"])
        self.assertIn("제한 시간", res["b"]["msg"])
        self.assertEqual(os.listdir(m.QUEUE), [], "every request is answered and removed")


class Exposure(unittest.TestCase):
    def test_tailscale_and_lan_binds_are_not_exposed(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "node_agent"))
        import hostsec
        for ip, want in (("0.0.0.0", True), ("::", True), ("8.8.8.8", True), ("100.94.77.73", False),
                         ("fd7a:115c:a1e0::1", False), ("192.168.0.5", False), ("127.0.0.1", False), ("::1", False),
                         ("fe80::1%eth0", False)):
            self.assertEqual(hostsec.exposed(ip), want, ip)


class AptPhasing(unittest.TestCase):
    def test_phased_packages_are_parsed(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "node_agent"))
        import hostsec
        sim = ("Calculating upgrade...\nThe following upgrades have been deferred due to phasing:\n"
               "  libopeniscsiusr open-iscsi\n0 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.\n")
        self.assertEqual(hostsec.phased_packages(sim), ["libopeniscsiusr", "open-iscsi"])
        self.assertEqual(hostsec.phased_packages("0 upgraded"), [])


class UpgradeRefresh(unittest.TestCase):
    def test_counts_refresh_after_an_upgrade_finishes(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "node_agent"))
        import hostsec
        real = hostsec.upgrade_status
        self.addCleanup(setattr, hostsec, "upgrade_status", real)
        hostsec.upgrade_status = lambda: {"state": "done", "finished": 1000}
        self.assertTrue(hostsec.upgraded_since(900), "read before the upgrade ended → stale")
        self.assertFalse(hostsec.upgraded_since(1001), "read after → fresh")
        hostsec.upgrade_status = lambda: None
        self.assertFalse(hostsec.upgraded_since(0), "no sm-block → never stale")



class ChatActions(unittest.TestCase):
    def test_only_real_controllable_targets_become_buttons(self):
        a, _ = make_analyst()
        a.services_fn = lambda: [
            {"unit": "app.service", "controllable": True},
            {"unit": "server-monitor.service", "controllable": True, "protected": True},
            {"unit": "worldrium.service", "controllable": False, "root": True},
            {"unit": "ssh.service", "controllable": False}]
        a.status_fn = lambda: {"top": [{"pid": 1736, "name": "Unity"}]}
        out = a.validate_chat_actions([
            {"type": "stop_service", "target": "worldrium.service", "label": "끄기", "reason": "r"},
            {"type": "disable_service", "target": "worldrium.service", "label": "자동시작 끄기", "reason": "r"},
            {"type": "stop_service", "target": "server-monitor.service", "label": "x", "reason": "protected"},
            {"type": "restart_service", "target": "ssh.service", "label": "x", "reason": "view-only"},
            {"type": "terminate_process", "target": "999", "label": "x", "reason": "not in the list"},
            {"type": "terminate_process", "target": "1736", "label": "Unity 종료", "reason": "r"},
            {"type": "rm_rf", "target": "/", "label": "x", "reason": "x"},
        ])
        self.assertEqual([(x["action"], x["target"]) for x in out],
                         [("stop", "worldrium.service"), ("disable", "worldrium.service"), ("terminate", "1736")])


class NetworkFeatures(unittest.TestCase):
    def test_wireless_line_is_parsed(self):
        from node_agent import hostsec
        text = ("Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n"
                " face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n"
                "wlp2s0: 0000   63.  -47.  -256        0      0      0      2  20625        0\n")
        self.assertEqual(hostsec.parse_wireless(text), {"iface": "wlp2s0", "dbm": -47})
        self.assertIsNone(hostsec.parse_wireless(""), "no Wi-Fi interface")

    def test_upload_surge_needs_history_a_big_jump_and_a_real_volume(self):
        import netwatch
        usual = [100_000.0] * 20
        self.assertEqual(netwatch.surge(4_000_000, usual), (True, 100_000.0))
        self.assertFalse(netwatch.surge(900_000, usual)[0], "5x the usual but under 1 MB/s is just noise")
        self.assertFalse(netwatch.surge(2_000_000, [1_000_000.0] * 20)[0], "a busy server doubling is not a surge")
        self.assertFalse(netwatch.surge(9_000_000, usual[:11])[0], "needs an hour of history first")
        self.assertFalse(netwatch.surge(None, usual)[0])

    def test_central_outage_is_reported_once_after_recovery(self):
        import netwatch
        w = netwatch.CentralWatch()
        self.assertIsNone(w.observe(True, 0))
        self.assertIsNone(w.observe(False, 60))
        self.assertIsNone(w.observe(False, 120))
        self.assertEqual(w.observe(True, 420), 6, "down since the first failed check, ~6 minutes")
        self.assertIsNone(w.observe(True, 480), "reported once")
        w.observe(False, 600)
        self.assertIsNone(w.observe(True, 660), "a single blip is not an outage")

    def test_node_is_not_called_down_while_our_own_internet_is_down(self):
        import asyncio
        from unittest import mock
        con = sqlite3.connect(":memory:", check_same_thread=False)
        con.row_factory = sqlite3.Row

        def db(sql, params=(), one=False):
            rows = con.execute(sql, params).fetchall()
            return (rows[0] if rows else None) if one else rows
        alerts = []
        hub = nodes.NodeHub(db, lambda kind, *a, **k: alerts.append(kind))

        async def unreachable(node):
            raise ConnectionError("no route")
        hub.fetch = unreachable
        node = {"id": 1, "name": "sub", "address": "http://100.64.0.1:8101"}
        hub.state[1] = {"online": True, "fails": 0}
        with mock.patch.object(nodes, "central_online", lambda: False):
            for _ in range(nodes.OFFLINE_AFTER):
                asyncio.run(hub.poll(node))
        self.assertEqual(alerts, [], "our own outage must not be reported as the server's")
        self.assertTrue(hub.state[1]["unknown"])
        self.assertTrue(hub.state[1]["online"], "kept as is, but marked unknown")
        hub._central = (0.0, True)  # drop the cached "internet down" answer
        with mock.patch.object(nodes, "central_online", lambda: True):
            asyncio.run(hub.poll(node))
        self.assertEqual(alerts, ["node_down"])
        self.assertIs(hub.state[1]["online"], False)
        self.assertFalse(hub.state[1]["unknown"])
        self.assertEqual(db("SELECT COUNT(*) c FROM net_quality WHERE ok=0", one=True)["c"], nodes.OFFLINE_AFTER + 1)

    def test_a_system_service_job_that_outlasts_the_wait_says_it_is_still_running(self):
        from unittest import mock
        from node_agent import hostsec
        with mock.patch.object(hostsec, "caps", lambda: ["svc"]):
            with mock.patch.object(hostsec, "_request", lambda *a, **k: (True, "요청함 (처리 대기 중)")):
                ok, msg = hostsec.system_service("stop", "docker.service")
            self.assertTrue(ok)
            self.assertIn("80초", msg)
            with mock.patch.object(hostsec, "_request", lambda *a, **k: (True, "docker.service stop 완료")):
                self.assertEqual(hostsec.system_service("stop", "docker.service"), (True, "docker.service stop 완료"))
            with mock.patch.object(hostsec, "_request", lambda *a, **k: (False, "거부")):
                self.assertEqual(hostsec.system_service("stop", "docker.service"), (False, "거부"))


def _load_smblock():
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("smblock_h", str(Path(__file__).resolve().parent.parent / "node_agent" / "sm-block"))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("smblock_h", loader))
    loader.exec_module(m)
    return m


class HealthFeatures(unittest.TestCase):
    ANALYZE = ("Startup finished in 4.194s (firmware) + 4.893s (loader) + 1.158s (kernel) + 2.197s (initrd) + "
               "2min 3.670s (userspace) = 2min 16.114s \ngraphical.target reached after 2min 3.630s in userspace.\n")
    CHAIN = ("graphical.target @2min 3.630s\n└─multi-user.target @2min 3.630s\n  └─apport.service @2min 3.425s +205ms\n"
             "    └─foo.service @10.000s +4.500s\n")

    def test_boot_output_from_a_real_server_is_parsed(self):
        from node_agent import hostsec
        info = hostsec.parse_boot(self.ANALYZE, self.CHAIN, [("systemd-networkd-wait-online.service", 120.2)])
        self.assertEqual(info["total_s"], 136.1)
        self.assertEqual(info["parts"]["kernel"], 1.2)
        self.assertEqual(info["parts"]["userspace"], 123.7)
        self.assertEqual(info["failed"], [{"unit": "systemd-networkd-wait-online.service", "secs": 120.2}])
        self.assertEqual(info["slow"], [("foo.service", 4.5)], "units under 3 s are not slow")
        self.assertEqual(hostsec.parse_boot("Bootup is not yet finished", "", [])["parts"], {}, "no 'Startup finished' line yet")

    def test_boot_summary_names_the_unit_that_really_delayed_boot(self):
        import healthrules
        from node_agent import hostsec
        info = hostsec.parse_boot(self.ANALYZE, self.CHAIN, [("systemd-networkd-wait-online.service", 120.2)])
        lines = healthrules.boot_lines(info, ignore=("systemd-networkd-wait-online.service",))
        self.assertIn("부팅 2분 16초", lines[0])
        self.assertIn("systemd-networkd-wait-online.service 2분 0초 (실패)", lines[1])
        self.assertTrue(any("fix-wait-online.sh" in l for l in lines))
        self.assertEqual(lines[-1], "실패한 서비스 없음 ✅", "an ignored failure is shown as slow but not as a failure")
        self.assertEqual(healthrules.boot_lines(None), [])

    def test_kernel_log_keeps_only_real_trouble(self):
        from node_agent import hostsec
        lines = [
            "1795180366.361155 hyunho kernel: [UFW BLOCK] IN=wlp2s0 OUT= MAC=c0:e3:50:66:06:ea SRC=192.168.219.102 DST=192.168.219.106 LEN=56",
            "1795187229.701242 hyunho kernel: kauditd_printk_skb: 9 callbacks suppressed",
            "1795190000.100000 hyunho kernel: Out of memory: Killed process 4242 (java) total-vm:1234kB",
            "1795190010.100000 hyunho kernel: blk_update_request: I/O error, dev nvme0n1, sector 123 op 0x0:(READ)",
            "1795190020.100000 hyunho kernel: mce: [Hardware Error]: Machine check events logged",
            "1795190030.100000 hyunho kernel: CPU0: Package temperature above threshold, cpu clock throttled (total events = 3)",
            "1795190040.100000 hyunho systemd-oomd[1]: Killed /user.slice/user-1000.slice/session-3.scope due to memory pressure",
            "not-a-timestamp hyunho kernel: I/O error"]
        self.assertEqual([(e["kind"], e["ts"]) for e in hostsec.classify_kernel(lines)],
                         [("oom", 1795190000), ("disk", 1795190010), ("hardware", 1795190020), ("thermal", 1795190030), ("oom", 1795190040)])

    def test_smart_rules(self):
        import healthrules
        nv = lambda **k: {"passed": True, "temp": 40, "nvme": {"critical_warning": 0, "percentage_used": 3, "available_spare": 100,
                                                              "available_spare_threshold": 10, "media_errors": 0, **k}}
        ata = lambda attrs, **k: {"passed": True, "temp": 35, "ata": {i: {"value": v, "raw": r} for i, (v, r) in attrs.items()}, **k}
        a = healthrules.smart_assess(nv())
        self.assertEqual((a["level"], a["wear"], a["notes"]), ("ok", 3, []))
        self.assertEqual(healthrules.smart_assess(nv(percentage_used=85))["level"], "warn")
        self.assertEqual(healthrules.smart_assess(nv(percentage_used=95))["level"], "crit")
        self.assertEqual(healthrules.smart_assess(nv(available_spare=5))["level"], "crit")
        self.assertEqual(healthrules.smart_assess(nv(media_errors=2))["level"], "warn")
        self.assertEqual(healthrules.smart_assess(nv(critical_warning=4))["level"], "crit")
        self.assertEqual(healthrules.smart_assess({**nv(), "passed": False})["level"], "crit")
        self.assertEqual(healthrules.smart_assess(ata({"5": (100, 8)}))["level"], "warn")
        self.assertEqual(healthrules.smart_assess(ata({"5": (100, 60)}))["level"], "crit")
        self.assertEqual(healthrules.smart_assess(ata({"197": (100, 1)}))["level"], "warn")
        w = healthrules.smart_assess(ata({"231": (15, 0)}))
        self.assertEqual((w["level"], w["wear"]), ("warn", 85))
        self.assertEqual(healthrules.smart_assess(ata({"231": (8, 0)}))["level"], "crit")
        self.assertEqual(healthrules.smart_assess({"passed": True, "temp": 70})["level"], "warn")
        self.assertEqual(healthrules.smart_assess({"passed": True, "temp": 80})["level"], "crit")
        self.assertEqual(healthrules.smart_assess({"dev": "/dev/sda", "error": "읽지 못함"})["level"], "warn")

    def test_root_helper_passes_on_only_whitelisted_smart_facts(self):
        import json
        m = _load_smblock()
        raw = {"model_name": "Test SSD", "serial_number": "SECRET-123", "smart_status": {"passed": True},
               "temperature": {"current": 41}, "power_on_time": {"hours": 1234}, "user_capacity": {"bytes": 512_000_000_000},
               "nvme_smart_health_information_log": {"percentage_used": 4, "temperature": 41, "available_spare": 100,
                                                     "host_reads": 99999, "critical_warning": 0},
               "ata_smart_attributes": {"table": [{"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 0}},
                                                  {"id": 12, "name": "Power_Cycle_Count", "value": 99, "raw": {"value": 7}}]}}
        out = m.smart_pick("/dev/nvme0n1", raw)
        self.assertEqual(out["nvme"], {"percentage_used": 4, "temperature": 41, "available_spare": 100, "critical_warning": 0})
        self.assertEqual(list(out["ata"]), ["5"], "only the attributes we judge")
        self.assertNotIn("SECRET-123", json.dumps(out))
        for ok in ("/dev/nvme0n1", "/dev/sda", "/dev/mmcblk0", "/dev/vdb"):
            self.assertTrue(m.SMART_DEV.match(ok), ok)
        for bad in ("/dev/sda1", "/dev/../etc/passwd", "sda", "/dev/nvme0n1; reboot", "/dev/loop0"):
            self.assertFalse(m.SMART_DEV.match(bad), bad)


class UxRules(unittest.TestCase):
    def test_quiet_window_can_wrap_past_midnight(self):
        import uxrules
        for now, want in (("23:30", True), ("00:00", True), ("06:59", True), ("07:00", False), ("12:00", False), ("22:59", False)):
            self.assertEqual(uxrules.in_quiet(now, "23:00", "07:00"), want, now)
        self.assertTrue(uxrules.in_quiet("13:00", "12:00", "14:00"))
        self.assertFalse(uxrules.in_quiet("14:00", "12:00", "14:00"), "end is exclusive")
        self.assertFalse(uxrules.in_quiet("03:00", "05:00", "05:00"), "start == end means never")

    def test_only_critical_alerts_get_through_quiet_hours(self):
        import uxrules
        cfg = {"enabled": True, "start": "23:00", "end": "07:00"}
        self.assertFalse(uxrules.should_hold("critical", cfg, "03:00"), "critical always goes out")
        self.assertTrue(uxrules.should_hold("warning", cfg, "03:00"))
        self.assertTrue(uxrules.should_hold("info", cfg, "03:00"))
        self.assertFalse(uxrules.should_hold("warning", cfg, "12:00"), "outside the window")
        self.assertFalse(uxrules.should_hold("warning", {**cfg, "enabled": False}, "03:00"))
        self.assertFalse(uxrules.should_hold("warning", None, "03:00"))

    def test_digest_groups_by_title(self):
        import uxrules
        head, lines = uxrules.digest([("🔄 재부팅", "서버 A 재부팅 완료\n자세히"), ("📦 업그레이드", "x"), ("🔄 재부팅", "서버 B 재부팅 완료")])
        self.assertEqual(head, "조용한 시간 동안 알림 3건")
        self.assertEqual(lines[0], "🔄 재부팅 ×2 — 서버 B 재부팅 완료")
        self.assertEqual(lines[1], "📦 업그레이드 — x")

    def test_terse_action_log_is_said_in_korean(self):
        import uxrules
        h = uxrules.humanize_action
        self.assertEqual(h("action", "restart hi-tunnel.service"), "서비스 다시 켜기: hi-tunnel.service")
        self.assertEqual(h("action", "stop docker.service (system)"), "서비스 끄기: docker.service (시스템 서비스)")
        self.assertEqual(h("action", "restart foo.service @ 서브서버 1"), "서비스 다시 켜기: foo.service (서버 서브서버 1)")
        self.assertEqual(h("action", "power reboot (this server)"), "서버 재부팅 (this server)")
        self.assertEqual(h("action", "terminate pid 1736 (Unity)"), "프로세스 종료: Unity (PID 1736)")
        self.assertEqual(h("upgrade", "중앙서버"), "패키지 업그레이드: 중앙서버")
        self.assertEqual(h("unban", "해제: 1.2.3.4"), "차단 해제: 1.2.3.4")
        self.assertEqual(h("action", "quiet hours on 23:00-07:00"), "알림 조용한 시간 켜기 (23:00~07:00)")
        self.assertEqual(h("action", "something new"), "something new", "unknown wording is kept as is")

    def test_discord_commands(self):
        import uxrules
        self.assertEqual(uxrules.parse_command("  상태 "), ("status", []))
        self.assertEqual(uxrules.parse_command("재시작 worldrium  서브서버 1"), ("restart", ["worldrium", "서브서버", "1"]))
        self.assertEqual(uxrules.parse_command("STATUS"), ("status", []))
        self.assertIsNone(uxrules.parse_command("안녕"))
        self.assertIsNone(uxrules.parse_command(""))
        self.assertEqual(uxrules.restart_target(["worldrium", "서브서버", "1"]), ("worldrium.service", "서브서버 1"))
        self.assertEqual(uxrules.restart_target(["a.service"]), ("a.service", ""))
        for bad in (["x;reboot"], ["a b"], [], ["../etc"]):
            self.assertIsNone(uxrules.restart_target(bad), bad)
        self.assertEqual(uxrules.parse_restart_id(uxrules.restart_id(None, "a.service")), (None, "a.service"))
        self.assertEqual(uxrules.parse_restart_id(uxrules.restart_id(3, "a.service")), (3, "a.service"))
        for bad in ("rs:main:a b", "rs:x:a.service", "confirm:1.2.3.4", "rs:main:"):
            self.assertIsNone(uxrules.parse_restart_id(bad), bad)


class StoppedUnits(unittest.TestCase):
    def test_admin_unit_files_survive_stop(self):
        import tempfile
        import uxrules
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "worldrium.service").write_text("[Service]\n")
            (Path(d) / "bad name.service").write_text("")
            (Path(d) / "enabled.service").symlink_to(Path(d) / "worldrium.service")  # enable-link, not admin-made
            (Path(d) / "note.txt").write_text("")
            self.assertEqual(uxrules.admin_unit_files(d), {"worldrium.service"})
        self.assertEqual(uxrules.admin_unit_files("/nonexistent-dir"), set())
