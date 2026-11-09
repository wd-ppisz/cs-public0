"""Real local files/SQLite, synthetic EVE, no sensor or network operations."""
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "runtime"))
import egress_collector as c
from test_egress_model import NOW, alert, catalog, config, flow


def wire(row):
    return (json.dumps(row, separators=(",", ":")) + "\n").encode()


def stats(uptime=1, when="2026-11-07T08:00:01Z"):
    return {"timestamp": when, "event_type": "stats", "stats": {"uptime": uptime}}


@unittest.skipIf(os.name == "nt", "Linux flock/permissions are part of the runtime contract")
class EgressCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "state").mkdir()
        self.eve = self.root / "eve.json"
        self.eve.write_bytes(b"")
        self.rules = self.root / "rules"
        self.rules.write_bytes(b"owned synthetic rules\n")
        pin = hashlib.sha256(self.rules.read_bytes()).hexdigest()
        self.cat = {"schema": "cs-public0-egress-catalog-v1", "version": "lab-1",
                    "rules_sha256": pin, "entries": [{"gid": 1, "sid": 9900001, "rev": 2,
                    "category": "c2", "severity": "high", "metadata": {"malware_family": ["TEST_ONLY"]},
                    "source": "owned-lab"}]}
        self.catalog_file = self.root / "catalog.json"
        self.catalog_file.write_text(json.dumps(self.cat))
        s = self.rules.stat()
        self.cfg = config() | {"initial_position": "begin", "flow_join_enabled": True, "join_wait_seconds": 3600,
            "eve_file": str(self.eve),
            "rules_file": str(self.rules), "catalog_file": str(self.catalog_file),
            "state_directory": str(self.root / "state"), "details_file": str(self.root / "events.jsonl"),
            "metrics_file": str(self.root / "egress.prom"), "rules_identity": {
                "device": s.st_dev, "inode": s.st_ino, "size": s.st_size,
                "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns, "sha256": pin}}

    def append(self, *rows):
        with self.eve.open("ab") as f:
            f.write(b"".join(wire(r) for r in rows))

    def run_once(self, now=NOW):
        return c.run(self.cfg, now=now)

    def scalar(self, name):
        for line in pathlib.Path(self.cfg["metrics_file"]).read_text().splitlines():
            if line.startswith("cs_public0_egress_" + name + " "):
                return float(line.split()[-1])
        self.fail("missing scalar " + name)

    def count(self, key):
        with sqlite3.connect(self.root / "state/state.sqlite3") as db:
            row = db.execute("SELECT value FROM counts WHERE key=?", (key,)).fetchone()
            return row[0] if row else 0

    def details(self):
        p = pathlib.Path(self.cfg["details_file"])
        return [json.loads(s) for s in p.read_text().splitlines()] if p.exists() else []

    def test_independent_file_join_and_fixed_metric_budget(self):
        self.append(stats(), alert(), flow())
        self.assertTrue(self.run_once()["success"])
        items = self.details()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["direction"], "egress")
        self.assertEqual(self.count("observation:c2:high:egress"), 1)
        self.assertEqual(self.scalar("source_fresh"), 1)
        text = pathlib.Path(self.cfg["metrics_file"]).read_text()
        self.assertEqual(len(text.splitlines()), 148)
        self.assertIn('cs_public0_egress_observations_v2_total{category="c2",severity="high",direction="egress"} 1', text)
        self.assertEqual(self.scalar("classification_v2_ready"), 1)
        for sensitive in ("192.0.2.4", "198.51.100.7", "9900001", "flow_id", "secret"):
            self.assertNotIn(sensitive, text)
        state = (self.root / "state/state.sqlite3").read_bytes()
        for forbidden in (b"password", b"private", b"DO NOT CLASSIFY", b'"payload"'):
            self.assertNotIn(forbidden, state)

    def test_restart_and_duplicate_raw_do_not_increment_observations(self):
        self.append(stats(), alert(), flow())
        self.assertTrue(self.run_once()["success"])
        self.assertTrue(self.run_once(NOW + 1)["success"])
        self.append(alert(), flow())
        self.assertTrue(self.run_once(NOW + 2)["success"])
        self.assertEqual(self.count("record:accepted"), 1)
        self.assertEqual(len(self.details()), 1)
        self.assertGreaterEqual(self.count("record:duplicate"), 1)

    def test_v2_does_not_import_legacy_scan_noise(self):
        self.append(stats())
        self.assertTrue(self.run_once()["success"])
        with sqlite3.connect(self.root / "state/state.sqlite3") as db:
            db.execute("INSERT INTO counts VALUES (?,?)", ("observation:scan:low:egress", 50000))
        self.append(alert(), flow())
        self.assertTrue(self.run_once(NOW + 1)["success"])
        self.assertEqual(self.count("observation:scan:low:egress"), 50000)
        self.assertEqual(self.count("observation_v2:scan:low:egress"), 0)
        self.assertEqual(self.count("observation_v2:c2:high:egress"), 1)
        self.assertTrue(self.run_once(NOW + 2)["success"])
        self.assertEqual(self.count("observation_v2:c2:high:egress"), 1)

    def test_pending_ipinsights_egress_is_filtered_but_signature_scan_is_preserved(self):
        source = {"name": "ipinsights", "expires_unix": NOW + 600}
        store = c.Store(self.root / "isolated.sqlite3")
        try:
            consumer = c.Consumer(store, self.cfg, c.Catalog(self.cat))
            for index, kind in enumerate(("ioc_contact_observation", "signature_match")):
                candidate = {"event_id": str(index), "category": "scan", "severity": "low",
                             "direction": "egress", "observed_unix": NOW,
                             "limitations": [], "evidence_kind": kind,
                             "ioc": {"matched_sources": [source], "expires_unix": NOW + 600}}
                consumer.publish(candidate, alert(), flow(), NOW)
            rows = [json.loads(row[0]) for row in store.db.execute("SELECT body FROM outbox ORDER BY rowid")]
            self.assertEqual([row["category"] for row in rows], ["scan"])
            self.assertTrue(all(row["classification_revision"] == 2 for row in rows))
            self.assertIsNone(rows[0]['ioc'])
            self.assertEqual(store.db.execute("SELECT value FROM counts WHERE key='record:ipinsights_non_ingress_filtered'").fetchone()[0], 1)
        finally:
            store.db.close()

    def test_initial_end_does_not_replay_old_history_or_claim_fresh_stats(self):
        self.cfg["initial_position"] = "end"
        self.append(stats(), alert(), flow())
        self.assertTrue(self.run_once()["success"])
        self.assertEqual(self.details(), [])
        self.assertEqual(self.scalar("source_fresh"), 0)
        self.assertEqual(self.count("gap:initial_boundary"), 1)
        self.append(stats(2))
        self.assertTrue(self.run_once(NOW + 1)["success"])
        self.assertEqual(self.scalar("source_fresh"), 1)

    def test_no_alert_is_healthy_only_with_advancing_stats(self):
        self.append(stats())
        self.run_once()
        self.assertEqual(self.scalar("source_fresh"), 1)
        self.run_once(NOW + 40)
        self.assertEqual(self.scalar("source_fresh"), 0)
        self.assertEqual(self.scalar("collector_up"), 1)
        self.eve.unlink()
        self.assertFalse(self.run_once(NOW + 41)["success"])
        self.assertEqual(self.scalar("collector_up"), 0)
        self.assertEqual(self.scalar("source_available"), 0)

    def test_live_stats_arriving_during_read_are_fresh_at_publication(self):
        self.run_once(NOW - 65)
        self.append(stats(when="2026-11-07T08:00:03Z"))
        with mock.patch.object(c.time, "time", side_effect=[NOW, NOW + 2]):
            result = c.run(self.cfg)
        self.assertTrue(result["success"])
        self.assertEqual(self.scalar("last_publish_unix_seconds"), NOW + 2)
        self.assertEqual(self.scalar("source_fresh"), 1)
        self.assertEqual(self.scalar("collection_continuity_known"), 1)

    def test_live_publication_does_not_qualify_still_future_stats(self):
        self.run_once(NOW - 65)
        self.append(stats(when="2026-11-07T08:00:05Z"))
        with mock.patch.object(c.time, "time", side_effect=[NOW, NOW + 2]):
            self.assertTrue(c.run(self.cfg)["success"])
        self.assertEqual(self.scalar("source_fresh"), 0)
        self.assertEqual(self.scalar("collection_continuity_known"), 0)

    def test_explicit_clock_remains_fixed_for_publication(self):
        self.append(stats())
        with mock.patch.object(c.time, "time", side_effect=AssertionError("explicit clock")):
            self.assertTrue(self.run_once()["success"])
        self.assertEqual(self.scalar("last_publish_unix_seconds"), NOW)

    def test_partial_line_resumes_and_invalid_does_not_commit_partial_work(self):
        raw = wire(alert())
        self.eve.write_bytes(wire(stats()) + raw[:40])
        self.run_once()
        self.assertEqual(self.scalar("backlog_bytes"), 40)
        self.assertEqual(self.scalar("source_fresh"), 0)
        with self.eve.open("ab") as f:
            f.write(raw[40:] + b'{"timestamp":"bad","event_type":"flow"}\n' + wire(flow()))
        self.assertTrue(self.run_once(NOW + 1)["success"])
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.count("record:invalid"), 1)
        self.assertEqual(self.scalar("backlog_bytes"), 0)

    def test_oversized_line_is_skipped_to_boundary_then_valid_input_survives(self):
        self.eve.write_bytes(b"x" * 80000 + b"\n" + wire(stats()) + wire(alert()) + wire(flow()))
        self.assertTrue(self.run_once()["success"])
        self.assertEqual(self.count("record:oversize"), 1)
        self.assertEqual(len(self.details()), 1)

    def test_rotation_and_regrown_copytruncate_mark_gaps_without_double_count(self):
        self.append(stats(), alert(), flow())
        self.run_once()
        self.eve.rename(self.root / "eve.old")
        self.eve.write_bytes(wire(stats(2)) + wire(alert()) + wire(flow()))
        self.run_once(NOW + 1)
        self.assertEqual(self.count("gap:inode_change"), 1)
        self.assertEqual(self.count("record:accepted"), 1)
        self.eve.write_bytes(wire(stats(3)) + b" " * 2000 + b"\n")
        self.run_once(NOW + 2)
        self.assertEqual(self.count("gap:fingerprint_changed"), 1)
        self.assertEqual(self.scalar("collection_continuity_known"), 0)

    def test_size_decrease_is_a_separate_detected_gap(self):
        self.append(stats(), flow())
        self.run_once()
        self.eve.write_bytes(wire(stats(2)))
        self.run_once(NOW + 1)
        self.assertEqual(self.count("gap:truncated"), 1)

    def test_missing_flow_expires_as_unknown_not_as_egress(self):
        self.append(stats(), alert())
        self.run_once()
        self.assertEqual(self.scalar("pending_records"), 1)
        self.run_once(NOW + 3601)
        self.assertEqual(self.details()[0]["direction"], "unknown")
        self.assertEqual(self.scalar("pending_records"), 0)

    def test_sensor_uptime_reset_does_not_join_old_pending_with_new_flow(self):
        self.append(stats(100), alert())
        self.run_once()
        self.append(stats(1), flow())
        self.run_once(NOW + 1)
        self.assertEqual(self.details()[0]["direction"], "unknown")
        self.assertEqual(self.count("gap:sensor_epoch"), 1)

    def test_rule_identity_change_invalidates_signature_catalog(self):
        self.rules.write_bytes(b"different rules\n")
        self.append(stats(), alert(), flow())
        self.assertFalse(self.run_once()["success"])
        self.assertEqual(self.scalar("catalog_ready"), 0)
        self.assertEqual(self.scalar("source_fresh"), 0)
        self.assertEqual(self.scalar("collector_up"), 0)
        self.assertEqual(self.count("gap:catalog"), 1)
        self.assertEqual(self.details(), [])

    def test_batch_bound_leaves_visible_backlog_and_can_resume(self):
        self.append(stats(), *[flow() for _ in range(5)])
        with mock.patch.object(c, "MAX_ROWS", 2):
            self.assertTrue(self.run_once()["success"])
        self.assertGreater(self.scalar("backlog_bytes"), 0)
        self.assertEqual(self.scalar("source_fresh"), 0)
        self.assertTrue(self.run_once(NOW + 1)["success"])
        self.assertEqual(self.scalar("backlog_bytes"), 0)

    def test_backpressure_keeps_cursor_on_unaccepted_record_and_prior_progress(self):
        self.cfg["flow_join_enabled"] = False
        a2 = alert()
        a2["flow_id"] -= 1
        self.append(stats(), alert(), a2)
        with mock.patch.object(c, "MAX_JOIN", 1):
            result = self.run_once()
        self.assertEqual(result["error"], "Backpressure")
        self.assertEqual(self.scalar("collector_up"), 0)
        self.assertEqual(self.scalar("pending_records"), 0)
        self.assertEqual(self.count("record:alert"), 1)
        self.assertEqual(self.scalar("backlog_bytes"), len(wire(a2)))
        self.assertTrue(self.run_once(NOW + 1)["success"])
        self.assertEqual(self.count("record:accepted"), 2)
        self.assertEqual(self.scalar("backlog_bytes"), 0)

    def test_full_pending_publishes_oldest_unknown_without_stopping_input(self):
        rows = []
        for i in range(3):
            a = alert(); a["flow_id"] -= i; rows.append(a)
        self.append(stats(), *rows)
        with mock.patch.object(c, "MAX_JOIN", 2):
            self.assertTrue(self.run_once()["success"])
        self.assertEqual(self.scalar("pending_records"), 2)
        self.assertEqual(self.scalar("backlog_bytes"), 0)
        self.assertEqual(self.count("record:join_evicted"), 1)
        self.assertEqual(self.details()[0]["direction"], "unknown")
        self.assertIn("JOIN_EVICTED_EARLY", self.details()[0]["limitations"])

    def test_finite_dedup_horizon_evicts_instead_of_stopping_ingestion(self):
        self.cfg["flow_join_enabled"] = False
        for i in range(3):
            a = alert(); a["flow_id"] -= i; self.append(a)
        with mock.patch.object(c, "MAX_SEEN", 1):
            self.assertTrue(self.run_once()["success"])
        self.assertEqual(len(self.details()), 3)
        self.assertEqual(self.count("record:dedup_evicted"), 2)
        self.assertEqual(self.scalar("backlog_bytes"), 0)

    def test_default_no_join_mode_publishes_alert_without_waiting_for_flow(self):
        del self.cfg["flow_join_enabled"]
        self.append(stats(), alert())
        self.assertTrue(self.run_once()["success"])
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.details()[0]["direction"], "unknown")
        self.assertEqual(self.scalar("pending_records"), 0)

    def test_clock_reversal_marks_one_gap_and_continues_from_new_clock(self):
        self.append(stats())
        self.run_once()
        self.assertTrue(self.run_once(NOW - 1)["success"])
        self.assertEqual(self.count("gap:clock"), 1)
        self.assertEqual(self.scalar("collection_continuity_known"), 0)
        self.run_once(NOW)
        self.assertEqual(self.count("gap:clock"), 1)

    def test_detail_delivery_retries_stable_ids_without_recounting(self):
        self.append(stats(), alert(), flow())
        real = c.deliver
        calls = []
        def fail_after_commit(store, path, deadline=None):
            calls.append(1)
            if len(calls) == 2:
                raise OSError("delivery failed with a secret that must not escape")
            return real(store, path, deadline)
        with mock.patch.object(c, "deliver", side_effect=fail_after_commit):
            self.assertFalse(self.run_once()["success"])
        self.assertEqual(self.count("record:accepted"), 1)
        self.assertTrue(self.run_once(NOW + 1)["success"])
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.count("record:accepted"), 1)

    def test_symlink_source_is_rejected_without_reading_it(self):
        self.eve.unlink()
        self.eve.symlink_to(self.rules)
        self.assertFalse(self.run_once()["success"])
        self.assertEqual(self.scalar("source_available"), 0)

    def test_partial_detail_line_cannot_swallow_retried_complete_event(self):
        target = pathlib.Path(self.cfg["details_file"])
        fragment = b'{"event_id":"interrupted'
        target.write_bytes(fragment)
        self.append(stats(), alert(), flow())
        self.assertTrue(self.run_once()["success"])
        lines = target.read_bytes().splitlines()
        self.assertEqual(lines[0], fragment)
        self.assertEqual(len(lines), 2)
        event = json.loads(lines[1])
        self.assertEqual(event["category"], "c2")
        self.assertEqual(self.count("record:accepted"), 1)
        with sqlite3.connect(self.root / "state/state.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM outbox").fetchone()[0], 0)

    def test_real_sqlite_full_commits_cache_recovery_and_next_run_advances(self):
        self.append(stats())
        self.run_once()
        state = self.root / "state/state.sqlite3"
        s = c.Store(state)
        with s.db:
            for i in range(80):
                f = flow(); f["flow_id"] = i+1000
                f["flow"]["exception_policy"] = {"owned_pressure_fixture": "x"*20000}
                s.db.execute("INSERT INTO flows VALUES (?,?,?)", (c.canonical(c.flow_key(f)), NOW, c.canonical(f)))
            before = s.get("cursor")
        s.db.close()
        f = flow(); f["flow_id"] = 100000
        f["flow"]["exception_policy"] = {"owned_pressure_fixture": "x"*60000}
        self.assertLessEqual(len(wire(f)), c.MAX_RECORD)
        self.append(f)
        original_store = c.Store
        def physical_page_limit(path):
            store = original_store(path)
            pages = store.db.execute("PRAGMA page_count").fetchone()[0]
            store.db.execute("PRAGMA max_page_count="+str(pages))
            return store
        with mock.patch.object(c, "Store", side_effect=physical_page_limit):
            result = self.run_once(NOW+1)
        self.assertEqual(result["error"], "Backpressure")
        self.assertEqual(self.scalar("collector_up"), 0)
        with sqlite3.connect(state) as db:
            self.assertEqual(json.loads(db.execute("SELECT value FROM kv WHERE key='cursor'").fetchone()[0]), before)
            self.assertEqual(db.execute("SELECT count(*) FROM flows").fetchone()[0], 0)
        self.assertEqual(self.count("record:cache_evicted"), 80)
        self.assertTrue(self.run_once(NOW+2)["success"])
        self.assertEqual(self.scalar("backlog_bytes"), 0)

    def test_interrupted_input_batch_rolls_back_records_epoch_and_cursor_together(self):
        self.append(stats()); self.run_once()
        self.append(stats(2), alert(), flow(), stats(3))
        original_accept = c.Consumer.accept
        def fail_late(consumer, row, ref, now):
            if row.get("stats", {}).get("uptime") == 3:
                raise TimeoutError("owned interruption after earlier rows")
            return original_accept(consumer, row, ref, now)
        with mock.patch.object(c.Consumer, "accept", fail_late):
            self.assertEqual(self.run_once(NOW+1)["error"], "TimeoutError")
        self.assertEqual(self.count("record:stats"), 1)
        self.assertEqual(self.count("record:accepted"), 0)
        self.assertEqual(self.details(), [])
        with sqlite3.connect(self.root / "state/state.sqlite3") as db:
            self.assertEqual(json.loads(db.execute("SELECT value FROM kv WHERE key='uptime'").fetchone()[0]), 1)
        self.assertTrue(self.run_once(NOW+2)["success"])
        self.assertEqual(self.count("record:stats"), 3)
        self.assertEqual(self.count("record:accepted"), 1)
        self.assertEqual(self.count("gap:sensor_epoch"), 0)
        self.assertEqual(len(self.details()), 1)
        self.run_once(NOW+3)
        self.assertEqual(self.count("record:stats"), 3)
        self.assertEqual(self.count("record:accepted"), 1)

    def test_sqlite_full_recovery_without_python_311_error_constant(self):
        self.append(stats()); self.run_once()
        self.append(stats(2), alert(), flow(), stats(3))
        original_accept = c.Consumer.accept
        def full_late(consumer, row, ref, now):
            if row.get("stats", {}).get("uptime") == 3:
                raise sqlite3.OperationalError("database or disk is full")
            return original_accept(consumer, row, ref, now)
        with mock.patch.object(c.sqlite3, "SQLITE_FULL", 13):
            del c.sqlite3.SQLITE_FULL  # Model the absent Python 3.10 API, not a new SQLite code.
            with mock.patch.object(c.Consumer, "accept", full_late):
                self.assertEqual(self.run_once(NOW+1)["error"], "Backpressure")
        self.assertEqual(self.count("record:stats"), 1)
        self.assertEqual(self.count("record:accepted"), 0)
        self.assertTrue(self.run_once(NOW+2)["success"])
        self.assertEqual(self.count("record:accepted"), 1)
        self.assertEqual(self.count("gap:sensor_epoch"), 0)

    def test_all_cache_byte_budgets_fit_with_full_dedup_and_real_rows(self):
        s = c.Store(self.root / "state/pressure.sqlite3")
        consumer = c.Consumer(s, self.cfg | {"active_rules_sha256": self.cfg["rules_identity"]["sha256"]}, c.Catalog(self.cat))
        ref = lambda row: {"device": 1, "inode": 2, "offset": 0, "length": len(wire(row)),
                           "record_sha256": hashlib.sha256(wire(row)).hexdigest()}
        with s.db:
            s.db.executemany("INSERT INTO seen VALUES (?,?)", ((hashlib.sha256(str(i).encode()).hexdigest(), NOW)
                                                              for i in range(c.MAX_SEEN)))
            for i in range(350):
                f = flow(); f["flow_id"] = 10000+i
                f["flow"]["exception_policy"] = {"owned_pressure_fixture": "x"*8192}
                consumer.accept(f, ref(f), NOW)
            stopped = False
            for i in range(4000):
                a = alert(); a["flow_id"] = 100000+i
                s.db.execute("SAVEPOINT pressure_row")
                try:
                    consumer.accept(a, ref(a), NOW)
                except OverflowError:
                    s.db.execute("ROLLBACK TO pressure_row")
                    stopped = True
                finally:
                    s.db.execute("RELEASE pressure_row")
                if stopped: break
            self.assertTrue(stopped, {"tables": {t: (s.size(t), s.storage(t)) for t in ("flows", "pending", "outbox")},
                                      "counts": list(s.db.execute("SELECT key,value FROM counts"))})
            for table in ("flows", "pending", "outbox"):
                self.assertLessEqual(s.storage(table), c.MAX_TABLE_BYTES)
                self.assertGreater(s.storage(table), c.MAX_TABLE_BYTES * .9)
            self.assertEqual(s.size("seen"), c.MAX_SEEN)
        physical = s.db.execute("PRAGMA page_count").fetchone()[0] * s.db.execute("PRAGMA page_size").fetchone()[0]
        self.assertLess(physical, 24*1024*1024)  # At least 8 MiB headroom under the unchanged cap.
        s.db.close()

    def test_state_and_detail_retention_have_explicit_bounds(self):
        self.append(stats(), alert(), flow())
        self.run_once()
        with sqlite3.connect(self.root / "state/state.sqlite3") as db:
            self.assertLessEqual(db.execute("PRAGMA page_count").fetchone()[0] *
                                 db.execute("PRAGMA page_size").fetchone()[0], 32 * 1024 * 1024)
        self.assertEqual((self.root / "state/state.sqlite3").stat().st_mode & 0o777, 0o600)
        self.assertLessEqual(pathlib.Path(self.cfg["details_file"]).stat().st_size, c.MAX_LOG)

    def test_late_flow_inside_declared_join_retention_resolves_direction(self):
        self.append(stats(), alert())
        self.run_once()
        self.append(flow())
        self.run_once(NOW + 601)
        self.assertEqual(self.details()[0]["direction"], "egress")

    def test_continuity_window_recovers_but_historical_gap_stays_counted(self):
        self.append(stats())
        self.run_once()
        self.eve.rename(self.root / "old")
        self.eve.write_bytes(wire(stats(2)))
        self.run_once(NOW + 1)
        self.assertEqual(self.scalar("collection_continuity_known"), 0)
        self.append(stats(70, "2026-11-07T08:01:10Z"))
        self.run_once(NOW + 70)
        self.assertEqual(self.scalar("collection_continuity_known"), 1)
        self.assertEqual(self.count("gap:inode_change"), 1)

    def test_unsupported_ipv6_and_portless_protocols_are_not_bad_json(self):
        a = alert()
        a["ip_v"] = 6
        f = flow()
        f["proto"] = "ICMP"
        f.pop("src_port"); f.pop("dest_port")
        self.append(stats(), a, f)
        self.run_once()
        self.assertEqual(self.count("record:invalid"), 0)
        self.assertEqual(self.count("record:ignored"), 2)

    def test_batch_delivery_uses_one_fsync_for_multiple_observations(self):
        a2 = alert()
        a2["flow_id"] -= 1
        f2 = flow()
        f2["flow_id"] = a2["flow_id"]
        self.append(stats(), alert(), a2, flow(), f2)
        # The metric publication has another fsync; SQL's own fsync is not os.fsync.
        with mock.patch.object(c.os, "fsync", wraps=c.os.fsync) as fsync:
            self.run_once()
        self.assertEqual(len(self.details()), 2)
        self.assertEqual(fsync.call_count, 2)

    def test_changed_catalog_freezes_cursor_and_keeps_original_pending_qualification(self):
        self.append(stats(), alert())
        self.run_once()
        self.rules.write_bytes(b"new owned rules")
        self.append(flow())
        self.assertFalse(self.run_once(NOW + 1)["success"])
        self.assertEqual(self.scalar("pending_records"), 1)
        self.assertEqual(self.scalar("backlog_bytes"), len(wire(flow())))
        s = self.rules.stat()
        pin = hashlib.sha256(self.rules.read_bytes()).hexdigest()
        self.cfg["rules_identity"] = {"device": s.st_dev, "inode": s.st_ino, "size": s.st_size,
                                      "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns, "sha256": pin}
        self.cat["rules_sha256"] = pin
        self.cat["entries"] = []  # The newly installed catalog no longer maps the old SID.
        self.catalog_file.write_text(json.dumps(self.cat))
        self.assertTrue(self.run_once(NOW + 2)["success"])
        self.assertEqual(self.details()[0]["signature"]["sid"], 9900001)
        self.assertEqual(self.details()[0]["direction"], "egress")
        self.assertNotEqual(self.details()[0]["signature"]["catalog_rules_sha256"], pin)

    def test_flow_cache_eviction_is_not_a_collection_gap(self):
        rows = []
        for i in range(3):
            f = flow(); f["flow_id"] -= i; rows.append(f)
        self.append(stats(), *rows)
        with mock.patch.object(c, "MAX_JOIN", 1): self.run_once()
        self.assertEqual(self.count("record:cache_evicted"), 2)
        self.assertEqual(self.count("gap:join_eviction"), 0)

    def test_unread_old_revision_is_retained_as_unqualified_after_rules_change(self):
        self.append(stats()); self.run_once()
        self.append(alert(), flow())
        self.rules.write_bytes(b"new rules without the former SID")
        self.assertEqual(self.run_once(NOW+1)["error"], "CatalogUnavailable")
        st = self.rules.stat(); pin = hashlib.sha256(self.rules.read_bytes()).hexdigest()
        self.cfg["rules_identity"] = {"device": st.st_dev, "inode": st.st_ino, "size": st.st_size,
            "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns, "sha256": pin}
        self.cat.update(rules_sha256=pin, entries=[])
        self.catalog_file.write_text(json.dumps(self.cat))
        self.assertTrue(self.run_once(NOW+2)["success"])
        event, = self.details()
        self.assertEqual(event["signature"]["sid"], 9900001)
        self.assertIsNone(event["signature"]["catalog_rules_sha256"])
        self.assertEqual(event["category"], "other")
        self.assertEqual(event["severity"], "unknown")
        self.assertEqual(event["evidence_kind"], "signature_observation_unqualified")
        self.assertIn("RULESET_TRANSITION_UNQUALIFIED", event["limitations"])

    def test_unobserved_catalog_swap_marks_only_its_unread_prefix_unqualified(self):
        self.append(stats()); self.run_once()
        self.append(alert(), flow())
        self.cat["version"] = "new-qualified-catalog"
        self.catalog_file.write_text(json.dumps(self.cat))
        self.run_once(NOW+1)
        self.assertEqual(self.details()[0]["category"], "other")
        a, f = alert(), flow(); a["flow_id"] += 1; f["flow_id"] = a["flow_id"]
        self.append(a, f); self.run_once(NOW+2)
        event = self.details()[1]
        self.assertEqual(event["category"], "c2")
        self.assertNotIn("RULESET_TRANSITION_UNQUALIFIED", event["limitations"])
        self.assertIn("CATALOG_RULESET_SHA_IS_NOT_PRODUCER_RULESET_ATTESTATION", event["limitations"])
        self.assertNotIn("rules_sha256", event["signature"])

    def test_catalog_transition_does_not_admit_unmapped_alerts(self):
        self.cfg["flow_join_enabled"] = False
        self.append(stats()); self.run_once()
        noise = alert(); noise["alert"]["signature_id"] = 9900999
        self.append(noise, alert())
        self.cat["version"] = "new-qualified-catalog"
        self.catalog_file.write_text(json.dumps(self.cat))
        self.assertTrue(self.run_once(NOW+1)["success"])
        self.assertEqual(self.count("record:unmapped"), 1)
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.details()[0]["signature"]["sid"], 9900001)
        self.assertEqual(self.details()[0]["category"], "other")

    def test_repeated_catalog_changes_hold_input_at_transition_key_capacity(self):
        self.append(stats()); self.run_once()
        self.append(alert(), flow())
        self.cat["entries"][0]["sid"] = 9900002
        self.catalog_file.write_text(json.dumps(self.cat))
        with mock.patch.object(c, "MAX_ROWS", 0):
            self.run_once(NOW+1)
        self.cat["entries"][0]["sid"] = 9900003
        self.catalog_file.write_text(json.dumps(self.cat))
        with mock.patch.object(c, "MAX_TRANSITION_KEYS", 2):
            self.assertEqual(self.run_once(NOW+2)["error"], "CatalogTransitionCapacity")
        self.assertEqual(self.scalar("catalog_ready"), 0)
        self.assertEqual(self.details(), [])
        self.assertTrue(self.run_once(NOW+3)["success"])
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.details()[0]["signature"]["sid"], 9900001)

    def test_cache_usage_changes_and_rolls_back_with_real_sql_transactions(self):
        s = c.Store(self.root / "state/usage.sqlite3")
        with s.db:
            s.db.execute("INSERT INTO flows VALUES (?,?,?)", ("one", NOW, "a"))
            baseline = (s.size("flows"), s.storage("flows"))
            s.db.execute("SAVEPOINT own_usage")
            s.db.execute("UPDATE flows SET body=? WHERE id='one'", ("x"*10000,))
            s.db.execute("INSERT INTO flows VALUES (?,?,?)", ("two", NOW, "y"*20000))
            self.assertEqual(s.size("flows"), 2)
            self.assertGreater(s.storage("flows"), 30000)
            s.db.execute("ROLLBACK TO own_usage"); s.db.execute("RELEASE own_usage")
            self.assertEqual((s.size("flows"), s.storage("flows")), baseline)
        s.db.close()
        s = c.Store(self.root / "state/usage.sqlite3")
        self.assertEqual((s.size("flows"), s.storage("flows")), baseline)
        s.db.close()

    def test_continuity_becomes_unknown_on_stale_stats_or_backlog(self):
        self.append(stats())
        self.run_once()
        self.append(stats(70, "2026-11-07T08:01:10Z"))
        self.run_once(NOW + 70)
        self.assertEqual(self.scalar("collection_continuity_known"), 1)
        self.run_once(NOW + 101)
        self.assertEqual(self.scalar("collection_continuity_known"), 0)
        self.append(stats(110, "2026-11-07T08:01:50Z"), flow())
        with mock.patch.object(c, "MAX_ROWS", 1): self.run_once(NOW + 110)
        self.assertEqual(self.scalar("collection_continuity_known"), 0)

    def test_large_clock_reversal_retains_and_expires_previously_qualified_event(self):
        self.append(stats(100), alert())
        self.run_once()
        self.assertTrue(self.run_once(NOW - 7200)["success"])
        self.assertTrue(self.run_once(NOW - 7200 + 3601)["success"])
        item = self.details()[0]
        self.assertEqual(item["direction"], "unknown")
        self.assertIn("SOURCE_CLOCK_SKEW_AFTER_COLLECTOR_REVERSAL", item["limitations"])
        self.assertEqual(item["observed_unix"], NOW - 1)
        self.assertEqual(self.scalar("pending_records"), 0)

    def test_clock_reversal_does_not_discard_unread_old_clock_records(self):
        self.append(stats(100))
        self.run_once()
        self.append(alert(), flow())
        self.assertTrue(self.run_once(NOW - 7200)["success"])
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.count("record:invalid"), 0)
        self.assertIn("SOURCE_CLOCK_SKEW_AFTER_COLLECTOR_REVERSAL", self.details()[0]["limitations"])

    def test_invalid_input_marks_source_quality_unknown_for_its_window(self):
        self.append(stats())
        with self.eve.open("ab") as f: f.write(b"not-json\n")
        self.run_once()
        self.assertEqual(self.scalar("source_fresh"), 0)
        self.assertEqual(self.scalar("collection_continuity_known"), 0)

    def test_malformed_or_missing_catalog_publishes_unhealthy_and_preserves_cursor(self):
        self.append(stats())
        self.run_once()
        self.append(alert(), flow())
        for raw in (b'[]', b'{', b'[' * 1100, None):
            if raw is None: self.catalog_file.unlink()
            else: self.catalog_file.write_bytes(raw)
            self.assertFalse(self.run_once(NOW + 1)["success"])
            self.assertEqual(self.scalar("collector_up"), 0)
            self.assertEqual(self.scalar("catalog_ready"), 0)
            self.assertEqual(self.scalar("source_fresh"), 0)
            self.assertGreater(self.scalar("backlog_bytes"), 0)
            self.assertEqual(self.details(), [])
        self.catalog_file.write_text(json.dumps(self.cat))
        self.assertTrue(self.run_once(NOW + 2)["success"])
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.count("gap:catalog"), 1)

    def test_malformed_optional_ioc_does_not_disable_signatures(self):
        p = self.root / "ioc.json"
        self.cfg["ioc_file"] = str(p)
        for index, raw in enumerate((b'[]', b'{', b'[' * 1100)):
            p.write_bytes(raw)
            a, f = alert(), flow()
            a["flow_id"] -= index; f["flow_id"] -= index
            self.append(stats(index + 1), a, f)
            self.assertTrue(self.run_once(NOW + index)["success"])
        self.assertEqual(len(self.details()), 3)
        self.assertEqual(self.scalar("ioc_fresh"), 0)

    def test_rule_rewrite_preserving_size_and_mtime_invalidates_catalog(self):
        import time
        before = self.rules.stat()
        time.sleep(.025)  # Cross the real filesystem timestamp granularity.
        self.rules.write_bytes(self.rules.read_bytes().replace(b'owned', b'other'))
        os.utime(self.rules, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.rules.stat().st_size, before.st_size)
        self.assertEqual(self.rules.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertNotEqual(self.rules.stat().st_ctime_ns, before.st_ctime_ns)
        self.append(stats(), alert(), flow())
        self.assertEqual(self.run_once()["error"], "CatalogUnavailable")
        self.assertEqual(self.scalar("catalog_ready"), 0)
        self.assertEqual(self.details(), [])

    def test_config_errors_hold_input_instead_of_losing_qualified_alerts(self):
        self.append(stats()); self.run_once()
        self.append(alert(), flow())
        bad = [dict(self.cfg, owned_ipv4_networks=["192.0.2.1/24"]),
               dict(self.cfg, attribution={"192.0.2.4": {"vm_ref": "missing-exclusive"}}),
               dict(self.cfg, sensor_id=""), dict(self.cfg, sensor_epoch="x"*128)]
        good = self.cfg
        for cfg in bad:
            self.cfg = cfg
            self.assertEqual(self.run_once(NOW+1)["error"], "ConfigInvalid")
            self.assertEqual(self.scalar("collector_up"), 0)
            self.assertEqual(self.scalar("source_fresh"), 0)
            self.assertEqual(self.count("record:invalid"), 0)
            self.assertEqual(self.details(), [])
            self.assertGreater(self.scalar("backlog_bytes"), 0)
        self.cfg = good
        self.assertTrue(self.run_once(NOW+2)["success"])
        self.assertEqual(len(self.details()), 1)

    def test_valid_multicast_and_unspecified_addresses_are_unsupported_not_invalid(self):
        rows = []
        for address in ("224.0.0.2", "224.0.0.251", "0.0.0.0"):
            f = flow(); f["proto"] = "UDP"; f["dest_ip"] = address; rows.append(f)
        self.append(stats(), *rows)
        self.assertTrue(self.run_once()["success"])
        self.assertEqual(self.count("record:invalid"), 0)
        self.assertEqual(self.count("record:ignored"), 3)
        self.assertEqual(self.scalar("source_fresh"), 1)

    def test_failed_rule_binding_never_reuses_old_ready_metric(self):
        self.append(stats()); self.run_once()
        self.assertEqual(self.scalar("catalog_ready"), 1)
        self.rules.unlink()
        self.assertFalse(self.run_once(NOW+1)["success"])
        self.assertEqual(self.scalar("catalog_ready"), 0)
        self.assertEqual(self.scalar("source_fresh"), 0)

    def test_regrown_copytruncate_resets_and_counts_once_while_catalog_holds(self):
        self.append(stats(), alert(), flow()); self.run_once()
        self.rules.write_bytes(b"changed binding\n")
        self.eve.write_bytes(wire(stats(2))*100)
        for i in range(3): self.assertFalse(self.run_once(NOW+i+1)["success"])
        self.assertEqual(self.count("gap:fingerprint_changed"), 1)
        with sqlite3.connect(self.root / "state/state.sqlite3") as db:
            cursor = json.loads(db.execute("SELECT value FROM kv WHERE key='cursor'").fetchone()[0])
        self.assertEqual(cursor["offset"], 0)
        self.assertEqual(cursor["fingerprint"], hashlib.sha256(b"").hexdigest())
        self.assertFalse(cursor["discarding"])

    def test_ipv6_without_ip_v_and_no_flow_alert_are_not_malformed(self):
        v6 = alert(); v6["src_ip"], v6["dest_ip"] = "2001:db8::1", "2001:db8::2"
        noflow = alert(); del noflow["flow_id"]; del noflow["flow"]
        unmapped = dict(noflow); unmapped["alert"] = {**noflow["alert"], "signature_id": 123}
        self.append(stats(), v6, noflow, unmapped)
        self.assertTrue(self.run_once()["success"])
        self.assertEqual(self.count("record:invalid"), 0)
        self.assertEqual(self.scalar("source_fresh"), 1)
        self.assertEqual(len(self.details()), 1)
        self.assertEqual(self.details()[0]["direction_basis"], "NO_MATCHING_FLOW")
        self.assertIsNone(self.details()[0]["flow_id"])
        self.assertEqual(self.scalar("pending_records"), 0)

    def test_invalid_window_ages_after_clock_reversal(self):
        self.append(stats())
        with self.eve.open("ab") as f: f.write(b'not-json\n')
        self.run_once()
        self.run_once(NOW - 7200)
        self.append(stats(70, "2026-11-07T06:01:12Z"))
        self.assertTrue(self.run_once(NOW - 7200 + 70)["success"])
        self.assertEqual(self.scalar("source_fresh"), 1)
        self.assertEqual(self.scalar("collection_continuity_known"), 1)


class EgressInstallerTransport(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ansible-playbook"), "actual Ansible required for preflight transport")
    def test_preflight_stdin_reaches_the_unsafe_ancestor_guard_without_json_coercion(self):
        import yaml
        source = pathlib.Path(__file__).resolve().parents[1]
        tasks = yaml.safe_load((source / "ansible/egress.yml").read_text())[0]["tasks"]
        task = next(t for t in tasks if t["name"] == "Refuse active installation, unsafe paths or replacement of installed policy")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); (root / "ansible").mkdir(); (root / "config").mkdir()
            for name in ("cs-public0-egress.service.j2", "cs-public0-egress.timer"):
                shutil.copyfile(source / "config" / name, root / "config" / name)
            cfg = {"catalog_file": str(root / "catalog.json"), "state_directory": str(root / "state"),
                   "details_file": str(root / "events.jsonl"), "metrics_file": str(root / "metrics.prom")}
            variables = {"ansible_python_interpreter": sys.executable,
                "cs_public0_egress_configuration": cfg, "cs_public0_egress_config_bytes": json.dumps(cfg),
                "cs_public0_egress_catalog_bytes": json.dumps({"entries": [], "schema": "owned-test"}),
                "cs_public0_egress_bundle": str(root / "bundle"), "cs_public0_egress_pins": {},
                "cs_public0_egress_config_path": str(root / "config.json"),
                "cs_public0_egress_log_group": "root", "cs_public0_egress_input_group": "root"}
            var_path, play_path = root / "vars.json", root / "ansible/play.yml"
            var_path.write_text(json.dumps(variables))
            play_path.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local",
                                                 "gather_facts": False, "tasks": [task]}]))
            result = subprocess.run(["ansible-playbook", "-i", "localhost,", str(play_path),
                                     "-e", "@"+str(var_path)], capture_output=True, timeout=30)
            output = (result.stdout+result.stderr).decode(errors="replace")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe installation ancestor", output)
            self.assertNotIn("JSONDecodeError", output)
            self.assertFalse((root / "config.json").exists())

    @unittest.skipUnless(os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0 and
                         shutil.which("ansible-playbook") and shutil.which("setpriv"), "Linux root/Ansible/setpriv required")
    def test_actual_nocap_eve_probe_requires_the_declared_read_group(self):
        import yaml
        import grp
        installer = pathlib.Path(__file__).resolve().parents[1] / "ansible" / "egress.yml"
        task = next(t for t in yaml.safe_load(installer.read_text())[0]["tasks"]
                    if t["name"] == "Require readable EVE without DAC override capabilities")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); directory = root / "sensor"; directory.mkdir()
            eve = directory / "eve.json"; eve.write_bytes(b"{}\n")
            os.chown(directory, 65534, 65534); directory.chmod(0o750)
            os.chown(eve, 65534, 65534); eve.chmod(0o640)
            variables = {"cs_public0_egress_log_group": "root", "cs_public0_egress_input_group": "root",
                         "cs_public0_egress_configuration": {"eve_file": str(eve)}}
            var_path, play_path = root / "vars.json", root / "play.yml"
            play_path.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local",
                                                 "gather_facts": False, "tasks": [task]}]))
            args = ["ansible-playbook", "-i", "localhost,", str(play_path), "-e", "@"+str(var_path)]
            var_path.write_text(json.dumps(variables))
            denied = subprocess.run(args, capture_output=True, timeout=30)
            self.assertNotEqual(denied.returncode, 0)
            variables["cs_public0_egress_input_group"] = grp.getgrgid(65534).gr_name
            var_path.write_text(json.dumps(variables))
            allowed = subprocess.run(args, capture_output=True, timeout=30)
            self.assertEqual(allowed.returncode, 0, (allowed.stdout+allowed.stderr).decode(errors="replace")[:3000])

    @unittest.skipUnless(shutil.which("ansible-playbook"), "actual Ansible required for artifact transport")
    def test_large_json_artifacts_preserve_exact_bytes_through_ansible(self):
        import yaml
        installer = pathlib.Path(__file__).resolve().parents[1] / "ansible" / "egress.yml"
        tasks = yaml.safe_load(installer.read_text())[0]["tasks"]
        task = next(t for t in tasks if t["name"] == "Write exact configuration and catalog bytes atomically")
        # Exercise the real task with older Ansible's JSON-to-dict coercion and
        # a catalog far larger than Linux's single-execve-argument allowance.
        task = {**task, "no_log": True}
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cfg = {"catalog_file": str(root / "catalog.json"), "enabled": False}
            cat = {"entries": [{"sid": i+1, "source": "OWNED_TRANSPORT_FIXTURE_"+"x"*220}
                               for i in range(4096)]}
            cfg_raw, cat_raw = (json.dumps(x, sort_keys=True, separators=(",", ":"))+"\n" for x in (cfg, cat))
            self.assertGreater(len(cat_raw), 131072)
            variables = {"ansible_python_interpreter": sys.executable,
                "cs_public0_egress_config_path": str(root / "config.json"),
                "cs_public0_egress_configuration": cfg,
                "cs_public0_egress_config_bytes": cfg_raw,
                "cs_public0_egress_catalog_bytes": cat_raw,
                "cs_public0_egress_config_sha256": hashlib.sha256(cfg_raw.encode()).hexdigest(),
                "cs_public0_egress_catalog_sha256": hashlib.sha256(cat_raw.encode()).hexdigest()}
            var_path, play_path = root / "vars.json", root / "play.yml"
            var_path.write_text(json.dumps(variables))
            play_path.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local",
                                                 "gather_facts": False, "tasks": [task]}]))
            args = ["ansible-playbook", "-i", "localhost,", str(play_path), "-e", "@"+str(var_path)]
            result = subprocess.run(args, capture_output=True, timeout=45)
            self.assertEqual(result.returncode, 0, (result.stdout+result.stderr).decode(errors="replace")[:3000])
            self.assertEqual((root / "config.json").read_bytes(), cfg_raw.encode())
            self.assertEqual((root / "catalog.json").read_bytes(), cat_raw.encode())
            if os.name != "nt":
                self.assertEqual((root / "catalog.json").stat().st_mode & 0o777, 0o600)
            # The same real task must reject wrong bytes without replacing an
            # already committed artifact.
            variables["cs_public0_egress_catalog_bytes"] = cat_raw + " "
            var_path.write_text(json.dumps(variables))
            failed = subprocess.run(args, capture_output=True, timeout=45)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual((root / "catalog.json").read_bytes(), cat_raw.encode())


def isolated_lab(engine, expected_sha256, parent_netns, runtime_directory):
    """Explicit Linux LAB entry point; must already be in a private network unit.

    Uses only owned documentation addresses on that unit's loopback. It never
    installs a firewall, NFQUEUE selector, production rule or guest resource.
    """
    import resource
    import re
    import shutil
    import signal
    import socket
    import subprocess
    import threading
    import time
    if (os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == parent_netns or
            os.readlink("/proc/1/ns/net") != parent_netns):
        raise ValueError("LAB requires root inside a distinct pre-created network namespace")
    if sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
        raise ValueError("LAB must have only private loopback")
    runtime = pathlib.Path(runtime_directory)
    if (runtime.parent != pathlib.Path("/run") or not re.fullmatch(r"cs-public0-egress-lab-[a-z0-9-]{1,64}", runtime.name) or
            runtime.is_symlink() or not runtime.is_dir() or runtime.stat().st_uid != 0):
        raise ValueError("dedicated systemd RuntimeDirectory required")
    binary = pathlib.Path(engine)
    if not binary.is_absolute() or hashlib.sha256(binary.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError("explicit LAB engine pin required")
    ip = shutil.which("ip")
    if not ip: raise ValueError("iproute2 required")
    for address in ("192.0.2.4", "198.51.100.7"):
        subprocess.run([ip, "address", "add", address+"/32", "dev", "lo"], check=True, timeout=5)
    subprocess.run([ip, "link", "set", "lo", "up"], check=True, timeout=5)
    with tempfile.TemporaryDirectory(prefix="owned-", dir=runtime) as tmp:
        root = pathlib.Path(tmp)
        (root / "state").mkdir()
        rules = root / "lab.rules"
        rules.write_text('alert tcp any any -> any any (msg:"OWNED EGRESS LAB"; flow:established; content:"WD_EGRESS_LAB"; sid:9900001; rev:2; metadata:malware_family TEST_ONLY;)\n')
        pin = hashlib.sha256(rules.read_bytes()).hexdigest()
        yaml = root / "suricata.yaml"
        for name in ("classification.config", "reference.config", "threshold.config"):
            (root / name).write_text("")
        yaml.write_text('%YAML 1.1\n---\nclassification-file: '+str(root / 'classification.config')+
            '\nreference-config-file: '+str(root / 'reference.config')+
            '\nthreshold-file: '+str(root / 'threshold.config')+
            '\nvars:\n  address-groups:\n    HOME_NET: "[192.0.2.4]"\n    EXTERNAL_NET: "!$HOME_NET"\noutputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      types:\n        - alert:\n            metadata: yes\n        - flow\n        - stats:\n            totals: yes\n            threads: no\nstats:\n  enabled: yes\n  interval: 1\nunix-command:\n  enabled: no\nlogging:\n  default-log-level: notice\n  outputs:\n    - console:\n        enabled: yes\n')
        argv = [str(binary), "-c", str(yaml), "-S", str(rules), "-l", str(root),
                "-i", "lo", "-k", "none", "--runmode=single", "--init-errors-fatal"]
        log = root / "engine.log"
        with log.open("wb") as engine_log:
            process = subprocess.Popen(argv, stdout=engine_log, stderr=subprocess.STDOUT, cwd=root)
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if log.stat().st_size > 65536: raise ValueError("LAB engine log bound")
                    if process.poll() is not None: raise ValueError("LAB engine startup failed: "+log.read_text()[-4096:])
                    if b"engine started" in log.read_bytes().lower(): break
                    time.sleep(.1)
                else: raise TimeoutError("LAB engine not ready")
                backend = []
                def exchange(client, server, request, response):
                    listener = socket.socket()
                    listener.settimeout(5)
                    listener.bind((server, 0)); listener.listen(1)
                    port = listener.getsockname()[1]
                    errors = []
                    def serve():
                        try:
                            with listener:
                                conn, peer = listener.accept()
                                with conn:
                                    conn.settimeout(5); body = b""
                                    while len(body) < len(request):
                                        chunk = conn.recv(1024)
                                        if not chunk: break
                                        body += chunk
                                    if body != request: raise ValueError("LAB backend body mismatch")
                                    backend.append({"client": peer[0], "server": server,
                                        "body_sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})
                                    conn.sendall(response)
                        except BaseException as exc: errors.append(type(exc).__name__)
                    t = threading.Thread(target=serve, daemon=True); t.start()
                    with socket.socket() as sock:
                        sock.settimeout(5); sock.bind((client, 0)); sock.connect((server, port))
                        sock.sendall(request); actual = b""
                        while len(actual) < len(response):
                            chunk = sock.recv(1024)
                            if not chunk: break
                            actual += chunk
                        if actual != response: raise ValueError("LAB response mismatch")
                    t.join(6)
                    if t.is_alive() or errors: raise ValueError("LAB backend unfinished: "+str(errors))
                exchange("192.0.2.4", "198.51.100.7", b"WD_EGRESS_LAB outgoing", b"OWNED_ACK")
                exchange("198.51.100.7", "192.0.2.4", b"OWNED_REQUEST", b"WD_EGRESS_LAB incoming reply")
                time.sleep(2)
                process.send_signal(signal.SIGINT)
                process.wait(timeout=10)
                if process.returncode != 0: raise ValueError("LAB engine stop failed")
                if any(line.startswith("E:") for line in log.read_text().splitlines()):
                    raise ValueError("LAB engine reported a configuration/runtime error")
                now = time.time()
                cat = {"schema": "cs-public0-egress-catalog-v1", "version": "owned-lab-1", "rules_sha256": pin,
                       "entries": [{"gid": 1, "sid": 9900001, "rev": 2, "category": "c2", "severity": "high",
                                    "metadata": {"malware_family": ["TEST_ONLY"]}, "source": "owned-lab-alert-only"}]}
                (root / "catalog.json").write_text(json.dumps(cat))
                ioc = {"schema": "cs-public0-egress-ioc-v1", "source": "OWNED_LAB_NOT_A_REAL_IOC", "version": "1",
                       "content_sha256": hashlib.sha256(b"198.51.100.7\n").hexdigest(), "addresses": ["198.51.100.7"],
                       "published_unix": int(now)-5, "fetched_unix": int(now)-1, "expires_unix": int(now)+60}
                (root / "ioc.json").write_text(json.dumps(ioc))
                s = rules.stat()
                cfg = config() | {"initial_position": "begin", "eve_file": str(root / "eve.json"),
                    "flow_join_enabled": True, "join_wait_seconds": 15,
                    "observation_point": "isolated_lab_ipv4_without_nat",
                    "rules_file": str(rules), "catalog_file": str(root / "catalog.json"), "ioc_file": str(root / "ioc.json"),
                    "state_directory": str(root / "state"), "details_file": str(root / "events.jsonl"),
                    "metrics_file": str(root / "egress.prom"), "attribution": {"192.0.2.4": {"vr_ref": "owned-lab-vr"}},
                    "rules_identity": {"device": s.st_dev, "inode": s.st_ino, "size": s.st_size,
                                       "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns, "sha256": pin}}
                usage = resource.getrusage(resource.RUSAGE_SELF); started = time.monotonic()
                result = c.run(cfg, now)
                after = resource.getrusage(resource.RUSAGE_SELF)
                eve = (root / "eve.json").read_bytes()
                if len(eve) > 1048576: raise ValueError("owned LAB EVE retention bound")
                events = [json.loads(x) for x in (root / "events.jsonl").read_text().splitlines()]
                if not result["success"]: raise ValueError("LAB collector failed")
                if not any(x["direction"] == "egress" and x["category"] == "c2" for x in events):
                    raise ValueError("real outbound alert was not joined")
                if not any(x["direction"] == "ingress" and x["category"] == "c2" and
                           x["packet_tuple"]["src_ip"] == "192.0.2.4" for x in events):
                    raise ValueError("real owned reply was not distinguished from egress")
                if not any(x["category"] == "ioc" for x in events): raise ValueError("owned IOC flow missing")
                if any("vm_ref" in x["attribution"] for x in events): raise ValueError("guessed VM attribution")
                return {"result": "PASS_ISOLATED_LOOPBACK_EVE_COLLECTOR_ONLY", "engine_sha256": expected_sha256,
                    "network_namespace": os.readlink("/proc/self/ns/net"), "parent_netns": parent_netns,
                    "backend": backend, "events": events, "metrics": (root / "egress.prom").read_text(),
                    "original_owned_eve": eve.decode(), "eve_sha256": hashlib.sha256(eve).hexdigest(),
                    "engine_log": log.read_text(), "collector_wall_seconds": time.monotonic()-started,
                    "collector_cpu_seconds": after.ru_utime+after.ru_stime-usage.ru_utime-usage.ru_stime,
                    "whole_test_process_peak_rss_kib": after.ru_maxrss,
                    "limitations": ["NO_PHYSICAL_PUBLIC0_OR_NFQUEUE_TEST", "NAT_NOT_EXERCISED", "NOT_A_PRODUCTION_IOC",
                                    "NOT_REAL_NODE_EXPORTER_OR_PROMETHEUS_ACCEPTANCE", "SMALL_TWO_CONNECTION_CORPUS"],
                    "production_ready": False, "measurement_eligible": False, "G6": "OPEN"}
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=5)


if __name__ == "__main__":
    if "--lab" in sys.argv:
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--lab", action="store_true")
        p.add_argument("--engine", required=True)
        p.add_argument("--engine-sha256", required=True)
        p.add_argument("--parent-netns", required=True)
        p.add_argument("--runtime-directory", required=True)
        args = p.parse_args()
        print(json.dumps(isolated_lab(args.engine, args.engine_sha256, args.parent_netns, args.runtime_directory)))
    else:
        unittest.main()
