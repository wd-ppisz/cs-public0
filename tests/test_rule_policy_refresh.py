import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "runtime"))
import rule_policy_refresh as r


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "root-owned Linux fixture")
class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/root")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = self.root / "transaction"; self.store.mkdir(mode=0o700)
        self.history = self.root / "monitor-state.json"
        self.history.write_bytes(b'{"latched":true,"gap":123,"ack":["preserved"]}')
        self.targets = {}
        for i, name in enumerate(("verifier", "monitor", "release.json")):
            target = self.root / name; target.write_bytes(b"old-" + str(i).encode()); target.chmod(0o600)
            image = self.store / ("new-" + str(i)); image.write_bytes(b"new-" + str(i).encode())
            self.targets[str(target)] = {"before_sha256": r.io.digest(target.read_bytes()),
                "after_sha256": r.io.digest(image.read_bytes()), "image": image.name, "mode": 0o600, "gid": 0}
        self.p = {"schema": "cs-public0-policy-refresh-v1", "host": "fixture.example", "unit": "sensor.service",
            "binding": {"InvocationID": "owned"}, "timer": "monitor.timer", "store": str(self.store),
            "state": str(self.history), "targets": self.targets, "verifier": str(self.root / "verifier"),
            "gso_argv": ["guard"], "preserve": {str(self.history): r.io.digest(self.history.read_bytes())}}
        self.calls = []

    def command(self, argv):
        self.calls.append(argv)
        return json.dumps({"known": True, "enabled": True, "invocation": "owned"}) if argv == ["guard"] else ""

    def test_complete_refresh_preserves_history_and_sensor_and_recovery_is_idempotent(self):
        before = self.history.read_bytes()
        with patch.object(r.io, "binding", return_value=self.p["binding"]), patch.object(r.io, "command", self.command):
            r.apply(self.p); r.restore(self.p)
            with self.assertRaisesRegex(RuntimeError, "one-shot"):
                r.apply(self.p)
        self.assertEqual(self.history.read_bytes(), before)
        for target, spec in self.targets.items():
            self.assertEqual(r.io.digest(Path(target).read_bytes()), spec["after_sha256"])
        self.assertTrue((self.store / "committed.json").exists())
        self.assertFalse(any("restart" in c or "sensor.service" in c for c in self.calls))

    def test_mid_write_failure_restores_all_originals_and_resumes_monitor(self):
        replace = r.io.replace; calls = 0
        def fail_once(*args):
            nonlocal calls
            calls += 1
            if calls == 2: raise RuntimeError("injected interruption")
            return replace(*args)
        with patch.object(r.io, "binding", return_value=self.p["binding"]), \
                patch.object(r.io, "command", self.command), patch.object(r.io, "replace", fail_once):
            with self.assertRaisesRegex(RuntimeError, "injected interruption"):
                r.apply(self.p)
        for target, spec in self.targets.items():
            self.assertEqual(r.io.digest(Path(target).read_bytes()), spec["before_sha256"])
        self.assertIn(["systemctl", "start", "monitor.timer"], self.calls)
        self.assertFalse((self.store / "committed.json").exists())

    def test_recovery_after_process_loss_uses_saved_originals_and_rejects_foreign_bytes(self):
        for i, (target, spec) in enumerate(self.targets.items()):
            r.io.create(self.store / ("before-" + str(i)), Path(target).read_bytes())
            Path(target).write_bytes((self.store / spec["image"]).read_bytes())
        r.io.create(self.store / "started.json", b"{}")
        with patch.object(r.io, "command", self.command): r.restore(self.p)
        target = next(iter(self.targets)); Path(target).write_bytes(b"foreign")
        with patch.object(r.io, "command", self.command), self.assertRaisesRegex(RuntimeError, "foreign target"):
            r.restore(self.p)

    def test_candidate_pin_host_and_scope_are_checked_before_apply(self):
        plan = self.store / "plan.json"; raw = r.io.encoded(self.p); plan.write_bytes(raw)
        with patch.object(r.socket, "getfqdn", return_value="fixture.example"):
            self.assertEqual(r.load(plan, r.io.digest(raw)), self.p)
            (self.store / "new-0").write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "candidate image changed"):
                r.load(plan, r.io.digest(raw))
