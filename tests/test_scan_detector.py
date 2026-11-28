"""Scan detector (ADR-067): pure detector, EVE classification, nft contract, follower.

No kernel, network or sensor access: nft is replaced by a recording fake.
"""
import base64
import collections
import copy
import gzip
import hashlib
import json
import os
import pathlib
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "runtime"))
import scan_detector as s  # noqa: E402

NOW = 1795836000.0  # 2026-11-28T03:20:00Z
BASE = {
    "schema": "cs-public0-scan-v1", "mode": "observe", "bridge": "public0", "sensor_id": "sdd",
    "protected_networks": ["83.168.93.0/24"], "own_networks": ["91.0.0.0/16"],
    "eve_file": "/var/log/wd-public0-inline/eve.json",
    "ioc_file": "/var/lib/cs-public0-ip-intelligence/ioc.json",
    "state_directory": "/var/lib/cs-public0-scan",
    "metrics_file": "/var/lib/node_exporter/cs_public0_scan.prom",
    "decision_log": "/var/lib/cs-public0-scan/events.jsonl",
    "window_seconds": 600, "min_pairs": 100, "min_ports": 30,
    "ttl_seconds": [900, 3600, 21600], "repeat_window_seconds": 86400,
    "set_size": 4096, "max_decisions_per_minute": 60,
    "whitelist": [
        {"network": "79.76.59.29/32", "kind": "own_probe", "reporter": "ppisz",
         "reason": "watchdog OCI status", "added": "2026-11-28", "expires": None},
        {"network": "198.199.0.0/24", "kind": "reported", "reporter": "klient X",
         "reason": "audyt bezpieczeństwa", "added": "2026-11-01", "expires": "2026-11-20"},
    ],
}
SCANNER = "150.251.225.29"


def config(**changes):
    out = copy.deepcopy(BASE)
    out.update(changes)
    return s.load_config(out)


def stamp(t):
    return s.iso(t).replace("Z", "+0000")


def flow(src, dst, port, start, ts="02", tc="14", **extra):
    row = {"timestamp": stamp(start + 31), "event_type": "flow", "src_ip": src, "src_port": 40000,
           "dest_ip": dst, "dest_port": port, "proto": "TCP",
           "flow": {"start": stamp(start), "end": stamp(start + 1), "state": "closed"},
           "tcp": {"tcp_flags": ts, "tcp_flags_ts": ts, "tcp_flags_tc": tc, "state": "closed"}}
    row.update(extra)
    return (json.dumps(row, separators=(",", ":")) + "\n").encode()


def ioc_snapshot(ranges_by_source, now=NOW):
    sources = []
    for name, ranges in sorted(ranges_by_source.items()):
        packed = b"".join(struct.pack("!II", a, b) for a, b in ranges)
        sources.append({"name": name, "mode": "detect", "ranges_zlib_b64": base64.b64encode(zlib.compress(packed)).decode(),
                        "range_count": len(ranges), "sha256": hashlib.sha256(packed).hexdigest(),
                        "fetched_unix": int(now) - 60, "expires_unix": int(now) + 3600})
    content = {"sources": sources}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema": "cs-public0-egress-ioc-v3", "source": "test", "version": digest, "content_sha256": digest,
            "published_unix": int(now) - 10, "fetched_unix": int(now) - 10, "expires_unix": int(now) + 3600, **content}


def addr(text):
    return int.from_bytes(bytes(int(x) for x in text.split(".")), "big")


def scan(det, src=SCANNER, start=NOW, count=150, ports=None, targets=8, now=None, step=0.5):
    """Feed a port scan: `count` distinct failed (target, port) pairs. Returns decisions."""
    out = []
    for i in range(count):
        dst = "83.168.93.%d" % (130 + i % targets)
        port = (ports[i % len(ports)] if ports else 1000 + i)
        t = start + i * step
        d = det.observe("failed", src, dst, port, t, now if now is not None else t)
        if d:
            out.append(d)
    return out


class Config(unittest.TestCase):
    def test_valid_and_enforce_refused(self):
        self.assertEqual(config()["mode"], "observe")
        with self.assertRaisesRegex(ValueError, "enforce is not implemented"):
            config(mode="enforce")

    def test_contract_rejects_unknown_fields_and_wide_or_undated_exceptions(self):
        bad = copy.deepcopy(BASE)
        bad["extra"] = 1
        with self.assertRaises(ValueError):
            s.load_config(bad)
        for entry, message in (
                ({"network": "198.199.0.0/23", "kind": "reported", "reporter": "a", "reason": "b",
                  "added": "2026-11-28", "expires": "2026-12-28"}, "canonical IPv4 network"),
                ({"network": "198.199.0.1/32", "kind": "reported", "reporter": "a", "reason": "b",
                  "added": "2026-11-28", "expires": None}, "requires an expiry"),
                ({"network": "198.199.0.1/32", "kind": "reported", "reporter": "a", "reason": "b",
                  "added": "2026-11-28"}, "fields")):
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, message):
                config(whitelist=[entry])

    def test_ttl_bounded_to_six_hours_and_increasing(self):
        with self.assertRaises(ValueError):
            config(ttl_seconds=[900, 30000])
        with self.assertRaises(ValueError):
            config(ttl_seconds=[3600, 900])
        with self.assertRaises(ValueError):
            config(min_ports=200)


class Classify(unittest.TestCase):
    def setUp(self):
        self.scope = s.Scope(config())

    def test_failed_variants(self):
        # SYN unanswered, closed port (RST), open port answered by a stateless scanner's RST.
        for ts, tc in (("02", "00"), ("02", "14"), ("06", "12")):
            with self.subTest(ts=ts, tc=tc):
                self.assertEqual(s.classify(flow(SCANNER, "83.168.93.140", 22, NOW, ts, tc), self.scope)[0], "failed")

    def test_handshake_and_scope(self):
        self.assertEqual(s.classify(flow("5.5.5.5", "83.168.93.140", 443, NOW, "1b", "1b"), self.scope)[0], "handshake")
        self.assertEqual(s.classify(flow("91.0.3.4", "83.168.93.140", 22, NOW), self.scope)[0], "excluded")
        self.assertEqual(s.classify(flow("10.1.1.1", "83.168.93.140", 22, NOW), self.scope)[0], "excluded")
        self.assertEqual(s.classify(flow("83.168.93.141", "83.168.93.140", 22, NOW), self.scope)[0], "excluded")
        self.assertEqual(s.classify(flow(SCANNER, "8.8.8.8", 53, NOW), self.scope)[0], "unprotected")
        self.assertEqual(s.classify(flow("2001:db8::1", "2001:db8::2", 22, NOW), self.scope)[0], "unprotected")
        self.assertEqual(s.classify(flow(SCANNER, "83.168.93.140", 22, NOW, "10", "10"), self.scope)[0], "no_syn")
        mid = flow(SCANNER, "83.168.93.140", 22, NOW)
        mid = mid.replace(b'"state":"closed"}}', b'"state":"closed","midstream":true}}')
        self.assertEqual(s.classify(mid, self.scope)[0], "no_syn")

    def test_non_flow_and_invalid(self):
        self.assertIsNone(s.classify(b'{"event_type":"alert","proto":"TCP"}', self.scope))
        self.assertIsNone(s.classify(b'{"event_type":"flow","proto":"UDP"}', self.scope))
        self.assertEqual(s.classify(b'{"event_type":"flow","proto":"TCP","src_ip":1}', self.scope)[0], "invalid")
        self.assertEqual(s.classify(b'{"event_type":"flow","proto":"TCP",', self.scope)[0], "invalid")


class Detect(unittest.TestCase):
    def setUp(self):
        self.det = s.Detector(config())

    def test_scan_crosses_threshold_once(self):
        decisions = scan(self.det, count=400)
        self.assertEqual(len(decisions), 1)
        d = decisions[0]
        self.assertEqual((d["failed_pairs"], d["ttl_seconds"], d["repeat"]), (100, 900, 0))
        self.assertEqual(d["verdict"], "behavior_only")
        self.assertEqual(d["reputation"]["status"], "unavailable")
        self.assertEqual(d["sets"], ["scan_behavior"])
        self.assertAlmostEqual(d["detection_seconds"], 49.5)
        # Later flows of an active source are not re-evaluated.
        self.assertEqual(self.det.flows["from_active"], 300)

    def test_busy_legitimate_client_never_decides(self):
        for i in range(2000):
            self.det.observe("handshake", "5.5.5.5", "83.168.93.140", 443, NOW + i * 0.1, NOW + i * 0.1)
        # A few failures (timeouts) on the same service: one pair, one port.
        for i in range(50):
            self.det.observe("failed", "5.5.5.5", "83.168.93.140", 443, NOW + i, NOW + i)
        self.assertFalse(self.det.active)
        self.assertEqual(self.det.flows["handshake"], 2000)

    def test_horizontal_sweep_of_few_ports_is_not_a_port_scan(self):
        self.assertEqual(scan(self.det, count=600, ports=[22, 23, 3389], targets=200), [])

    def test_pairs_outside_window_do_not_count(self):
        # 99 pairs, then 700 s pause, then 99 more: never 100 inside 600 s.
        self.assertEqual(scan(self.det, count=99, step=1), [])
        self.assertEqual(scan(self.det, start=NOW + 800, count=99, step=1), [])

    def test_whitelist_hit_is_counted_and_held(self):
        scan(self.det, src="79.76.59.29", count=300)
        self.assertFalse(self.det.active)
        self.assertEqual(self.det.counts["whitelist_hits"], 1)
        self.assertGreater(self.det.flows["held"], 0)

    def test_expired_whitelist_entry_stops_protecting(self):
        decisions = scan(self.det, src="198.199.0.7", count=150)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(self.det.whitelist_state(NOW), (1, 1))

    def test_rate_fuse_stops_decisions(self):
        det = s.Detector(config(max_decisions_per_minute=2))
        made = []
        for n in range(5):
            made += scan(det, src="45.1.1.%d" % (n + 1), count=120, step=0.01, now=NOW)
        self.assertEqual(len(made), 2)
        self.assertEqual(det.counts["rate_limited"], 3)

    def test_ttl_ladder_on_repeat(self):
        ttls = []
        when = NOW
        for _ in range(4):
            d = scan(self.det, start=when, count=120, step=0.1)
            ttls.append(d[0]["ttl_seconds"])
            when = d[0]["expires_unix"] + 1
        self.assertEqual(ttls, [900, 3600, 21600, 21600])
        # After the repeat window the ladder starts again.
        d = scan(self.det, start=when + 86400 + 10, count=120, step=0.1)
        self.assertEqual(d[0]["ttl_seconds"], 900)

    def test_reputation_is_necessary_for_block_verdict(self):
        self.det.ioc = s.IOC(ioc_snapshot({"ipinsights": [(addr(SCANNER), addr(SCANNER))]}))
        d = scan(self.det, count=120, now=NOW)[0]
        self.assertEqual(d["verdict"], "behavior_reputation")
        self.assertEqual(d["reputation"], {"status": "match", "sources": ["ipinsights"]})
        self.assertEqual(d["sets"], ["scan_behavior", "scan_block"])
        other = scan(self.det, src="45.9.9.9", count=120, now=NOW)[0]
        self.assertEqual(other["verdict"], "behavior_only")
        self.assertEqual(other["reputation"]["status"], "none")

    def test_memory_bounds_evict_least_recent(self):
        det = s.Detector(config(), max_sources=50, max_pairs=500)
        for n in range(200):
            det.observe("failed", "45.2.%d.%d" % (n // 250, n % 250 + 1), "83.168.93.140", 22, NOW + n, NOW + n)
        self.assertLessEqual(len(det.tracks), 50)
        self.assertEqual(det.counts["source_evictions"], 150)
        scan(det, src="45.3.3.3", start=NOW + 300, count=60, step=0.1)
        self.assertLessEqual(det.total_pairs, 500)
        self.assertEqual(det.total_pairs, sum(len(t.pairs) for t in det.tracks.values()))

    def test_late_evidence_ignored_and_sweep_releases_state(self):
        self.det.observe("failed", SCANNER, "83.168.93.140", 22, NOW + 2000, NOW + 2000)
        self.det.observe("failed", "45.4.4.4", "83.168.93.140", 22, NOW, NOW + 2000)
        self.assertEqual(self.det.flows["late"], 1)
        self.det.sweep(NOW + 4000)
        self.det.clock = NOW + 4000
        self.det.sweep(NOW + 4000)
        self.assertEqual(len(self.det.tracks), 0)
        self.assertEqual(self.det.total_pairs, 0)


class FakeNft:
    """Records nft invocations; table readback from a JSON document."""

    def __init__(self, rows=None, elements=None):
        self.calls = []
        self.rows = rows
        self.elements = elements or {}
        self.fail_add = False

    def __call__(self, args, payload=None):
        self.calls.append((args, payload))
        out, code = b"", 0
        if args[:3] == ["-j", "list", "table"]:
            if self.rows is None:
                code = 1
            else:
                out = json.dumps({"nftables": self.rows}).encode()
        elif args[:2] == ["-j", "list"] and args[2] == "tables":
            out = json.dumps({"nftables": [{"metainfo": {}}]}).encode()
        elif args[:3] == ["-j", "list", "set"]:
            name = args[-1]
            elem = [{"elem": {"val": a, "timeout": 900, "expires": r}} for a, r in self.elements.get(name, {}).items()]
            out = json.dumps({"nftables": [{"set": {"name": name, "elem": elem}}]}).encode()
        elif args[:3] == ["-j", "list", "counters"]:
            out = json.dumps({"nftables": [{"counter": {"name": c, "packets": 7}} for c in s.SETS.values()]}).encode()
        elif args[:2] == ["add", "element"]:
            code = 1 if self.fail_add else 0
        return type("R", (), {"returncode": code, "stdout": out, "stderr": b"err"})()


def owned_rows(protected=("83.168.93.0/24",), size=4096, bridge="public0"):
    common = [{"match": {"op": "==", "left": {"meta": {"key": k}}, "right": bridge}} for k in ("ibrname", "obrname")]
    rows = [{"table": {"family": "bridge", "name": s.TABLE, "comment": s.OWNER}},
            {"set": {"name": "protected", "type": "ipv4_addr", "flags": ["interval"],
                     "elem": [{"prefix": {"addr": p.split("/")[0], "len": int(p.split("/")[1])}} for p in protected]}}]
    for name in s.SETS:
        rows.append({"set": {"name": name, "type": "ipv4_addr", "flags": ["timeout"], "size": size}})
    rows += [{"counter": {"name": c}} for c in s.SETS.values()]
    rows.append({"chain": {"name": s.CHAIN, "hook": "forward", "prio": s.PRIORITY, "policy": "accept"}})
    for name, counter in s.SETS.items():
        rows.append({"rule": {"comment": f"{s.OWNER}:{name}", "expr": common + [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@protected"}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@" + name}},
            {"match": {"op": "==", "left": {"&": [{"payload": {"protocol": "tcp", "field": "flags"}},
                                                ["fin", "syn", "rst", "ack"]]}, "right": "syn"}},
            {"counter": counter}]}})
    return rows


class KernelContract(unittest.TestCase):
    PROTECTED = (s.ipaddress.ip_network("83.168.93.0/24"),)

    def test_batch_has_no_verdict(self):
        batch = s.Kernel("public0").create_batch(self.PROTECTED, 4096).decode()
        for word in ("drop", "reject", "queue", "accept;", "jump", "goto", "redirect", "nat"):
            if word == "accept;":
                # Only the chain policy accepts; no rule carries a verdict.
                self.assertEqual(batch.count("accept"), 1)
                continue
            self.assertNotIn(word, batch.replace("ether type", ""))
        self.assertIn("priority -245", batch)
        self.assertIn("size 4096", batch)
        self.assertEqual(batch.count("counter name"), 2)

    def test_conforms_exact_and_foreign(self):
        k = s.Kernel("public0")
        self.assertEqual(k.conforms(owned_rows(), self.PROTECTED, 4096), [])
        foreign = owned_rows()
        foreign[0]["table"]["comment"] = "someone-else"
        self.assertEqual(k.conforms(foreign, self.PROTECTED, 4096), ["foreign"])
        dropping = owned_rows()
        dropping[-1]["rule"]["expr"].append({"drop": None})
        self.assertIn("rules", k.conforms(dropping, self.PROTECTED, 4096))
        self.assertIn("protected members", k.conforms(owned_rows(("83.168.94.0/24",)), self.PROTECTED, 4096))

    def test_ensure_creates_keeps_replaces_and_refuses(self):
        fake = FakeNft()
        self.assertEqual(s.Kernel("public0", runner=fake).ensure(self.PROTECTED, 4096), "created")
        self.assertEqual([c[0][:2] for c in fake.calls[-2:]], [["--check", "-f"], ["-f", "-"]])
        fake = FakeNft(owned_rows())
        self.assertEqual(s.Kernel("public0", runner=fake).ensure(self.PROTECTED, 4096), "kept")
        fake = FakeNft(owned_rows(size=1024))
        result = s.Kernel("public0", runner=fake).ensure(self.PROTECTED, 4096)
        self.assertTrue(result.startswith("replaced:"))
        self.assertTrue(fake.calls[-1][1].startswith(b"delete table bridge cs_public0_scan\n"))
        rows = owned_rows()
        rows[0]["table"]["comment"] = "foreign"
        with self.assertRaisesRegex(ValueError, "foreign owner"):
            s.Kernel("public0", runner=FakeNft(rows)).ensure(self.PROTECTED, 4096)
        with self.assertRaisesRegex(ValueError, "foreign"):
            s.Kernel("public0", runner=FakeNft(rows)).withdraw()
        self.assertEqual(s.Kernel("public0", runner=FakeNft(owned_rows())).withdraw(), "deleted")
        self.assertEqual(s.Kernel("public0", runner=FakeNft()).withdraw(), "absent")


@unittest.skipIf(os.name == "nt", "rename of an open file and O_NOFOLLOW are POSIX runtime contract")
class FollowerAndService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.eve = self.root / "eve.json"
        self.eve.write_bytes(flow(SCANNER, "83.168.93.140", 1, NOW - 50))

    def tearDown(self):
        self.tmp.cleanup()

    def append(self, raw, path=None):
        with open(path or self.eve, "ab") as f:
            f.write(raw)

    def test_follower_starts_at_end_and_survives_rotation(self):
        gaps = collections.Counter()
        f = s.Follower(str(self.eve), gaps)
        self.assertEqual(f.read(), [])
        self.append(b"one\ntw")
        self.assertEqual(f.read(), [b"one"])
        self.append(b"o\n")
        self.assertEqual(f.read(), [b"two"])
        # Rename rotation: lines appended to the old file before the switch are still read.
        os.replace(self.eve, str(self.eve) + ".1")
        self.append(b"late\n", str(self.eve) + ".1")
        self.eve.write_bytes(b"new\n")
        self.assertEqual(f.read(), [b"late"])
        self.assertEqual(f.read(), [])
        self.assertEqual(f.read(), [b"new"])
        self.assertEqual(gaps["rotated"], 1)
        # copytruncate: the size drops below the offset.
        os.truncate(self.eve, 0)
        self.assertEqual(f.read(), [])
        self.append(b"after\n")
        self.assertEqual(f.read(), [b"after"])
        self.assertEqual(gaps["truncated"], 1)
        # Oversize lines are skipped, the following line is kept.
        self.append(b"x" * (s.MAX_RECORD + 10) + b"\nok\n")
        self.assertEqual(f.read(), [b"ok"])
        self.assertEqual(gaps["oversize"], 1)
        f.close()

    def service(self, fake, **changes):
        cfg = config(eve_file=str(self.eve), ioc_file=str(self.root / "ioc.json"),
                     state_directory=str(self.root), metrics_file=str(self.root / "cs_public0_scan.prom"),
                     decision_log=str(self.root / "events.jsonl"), **changes)
        clock = iter(NOW + i * 0.001 for i in range(10**7))
        return s.Service(cfg, kernel=s.Kernel("public0", runner=fake), clock=lambda: next(clock))

    def test_end_to_end_observe(self):
        (self.root / "ioc.json").write_text(json.dumps(ioc_snapshot({"ipinsights": [(addr(SCANNER), addr(SCANNER))]})))
        fake = FakeNft()
        svc = self.service(fake)
        self.assertEqual(svc.prepare(), "created")
        svc.run(iterations=1)
        rows = b"".join(flow(SCANNER, "83.168.93.%d" % (130 + i % 9), 2000 + i, NOW + i * 0.2) for i in range(300))
        rows += b"".join(flow("5.5.5.5", "83.168.93.140", 443, NOW + i, "1b", "1b") for i in range(100))
        self.append(rows)
        svc.run(iterations=2)
        svc.follower.close()
        events = [json.loads(x) for x in (self.root / "events.jsonl").read_text().splitlines()]
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual((e["schema"], e["sensor_id"], e["action"], e["enforcement"]),
                         ("cs-public0-scan-decision-v1", "sdd", "observe", "none"))
        self.assertEqual((e["remote_ip"], e["verdict"], e["kernel"]), (SCANNER, "behavior_reputation", "added"))
        self.assertEqual(e["ioc"]["matched_sources"], [{"name": "ipinsights"}])
        self.assertIsInstance(e["observed_unix"], float)
        self.assertEqual(len(e["event_id"]), 64)
        adds = [c[0] for c in fake.calls if c[0][:2] == ["add", "element"]]
        self.assertEqual([a[4] for a in adds], ["scan_behavior", "scan_block"])
        self.assertEqual(adds[0][5], "{ %s timeout 900s }" % SCANNER)
        metrics = (self.root / "cs_public0_scan.prom").read_text()
        self.assertIn('cs_public0_scan_decisions_total{verdict="behavior_reputation"} 1', metrics)
        self.assertIn('cs_public0_scan_observed_syn_packets_total{set="scan_block"} 7', metrics)
        self.assertIn("cs_public0_scan_reputation_fresh 1", metrics)
        self.assertNotIn(SCANNER, metrics)
        history = json.loads((self.root / "history.json").read_text())
        self.assertEqual(list(history["history"]), [SCANNER])

    def test_restart_restores_active_and_kernel_errors_are_reported(self):
        fake = FakeNft(owned_rows(), elements={"scan_behavior": {SCANNER: 600}})
        svc = self.service(fake)
        self.assertEqual(svc.prepare(), "kept")
        self.assertIn(SCANNER, svc.det.active)
        svc.run(iterations=1)
        self.append(b"".join(flow(SCANNER, "83.168.93.140", 2000 + i, NOW + i) for i in range(150)))
        fake.fail_add = True
        self.append(b"".join(flow("45.6.6.6", "83.168.93.141", 3000 + i, NOW + i) for i in range(150)))
        svc.run(iterations=2)
        svc.follower.close()
        events = [json.loads(x) for x in (self.root / "events.jsonl").read_text().splitlines()]
        self.assertEqual([(e["remote_ip"], e["kernel"]) for e in events], [("45.6.6.6", "error")])
        self.assertEqual(svc.kernel_errors, 1)

    def test_replay_gzip(self):
        path = self.root / "eve.json.2.gz"
        with gzip.open(path, "wb") as f:
            f.write(b"".join(flow(SCANNER, "83.168.93.%d" % (130 + i % 9), 2000 + i, NOW + i * 0.2) for i in range(300)))
            f.write(b'{"event_type":"stats"}\n')
        result = s.replay(config(), [str(path)])
        self.assertEqual([d["src_ip"] for d in result["decisions"]], [SCANNER])
        self.assertEqual(result["flows"]["failed"], 100)


if __name__ == "__main__":
    unittest.main()
