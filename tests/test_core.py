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

    a = agent.Analyst(db, services_fn=lambda: [], units_fn=lambda: ["todont-backend.service", "llm.service"],
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
            {"type": "restart_service", "target": "llm.service", "reason": "self"},
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

