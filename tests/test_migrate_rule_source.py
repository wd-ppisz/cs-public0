import contextlib
import copy
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "runtime"))
import activate_rules as activation
import migrate_rule_source as migration
import rule_release as release
import run_rule_activation as launcher

RULE = b'alert tcp any any -> any any (msg:"migration fixture"; sid:9100041; rev:1;)\n'


@unittest.skipUnless(sys.platform == "linux", "Linux fd and filesystem contracts")
class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target, self.stage, self.state_dir = [self.root / n for n in ("target", "stage", "state")]
        for p in (self.target, self.stage, self.state_dir): p.mkdir(mode=0o700)
        self.state = self.state_dir / "monitor.json"
        self.old_state = release.json_bytes({"latched": False, "current_sample_valid": True,
            "kernel_accounting": {"unexplained_gap": 0, "gap_history_latched": False}})
        self.state.write_bytes(self.old_state)
        self.binary = self.root / "engine"
        self.binary.write_bytes(b"bounded engine fixture")
        self.verifier = self.root / "verify"
        self.unit = self.root / "sensor.service"
        config = self.target / "suricata.yaml"
        rules = self.target / "production.rules"
        rules.write_bytes(RULE)
        (self.target / "production.rules.gz").write_bytes(gzip.compress(RULE, mtime=0))
        old_unit = ("[Service]\nExecStart=" + str(self.binary) + " -c " + str(config) + " -S " + str(rules)
                    + " -q 100\nRestart=no\n").encode()
        new_unit = old_unit.replace((" -S " + str(rules)).encode(), b"")
        proto = release.make_release(RULE, gzip.compress(RULE, mtime=0),
            {"rules": "production.rules", "gzip": "production.rules.gz", "manifest": "manifest.json"},
            {str(self.binary): release.sha(self.binary.read_bytes())})
        manifest = release.manifest_for({"config_sha256": release.sha(b"old config"),
            "artifacts": {"config_sha256": release.sha(b"old config")}}, proto)
        new_manifest = copy.deepcopy(manifest)
        new_manifest["config_sha256"] = new_manifest["artifacts"]["config_sha256"] = release.sha(b"new config")
        self.old = {"config": b"old config", "manifest": release.json_bytes(manifest),
            "unit": old_unit, "verifier": b"old verifier"}
        self.new = {"config": b"new config", "manifest": release.json_bytes(new_manifest),
            "unit": new_unit, "verifier": b"new verifier"}
        targets = {"config": config, "manifest": self.target / "manifest.json", "unit": self.unit,
                   "verifier": self.verifier}
        files = {}
        for role, path in targets.items():
            path.write_bytes(self.old[role]); path.chmod(0o755 if role == "verifier" else 0o644)
            (self.stage / (role + ".new")).write_bytes(self.new[role])
            files[role] = {"target": str(path), "source": role + ".new", "old_sha256": release.sha(self.old[role]),
                "new_sha256": release.sha(self.new[role]), "mode": 0o755 if role == "verifier" else 0o644}
        self.binding = {"pid": 123, "start_ticks": 456, "uid": 0, "boot_id": "0"*36,
            "exe": [1, 2], "netns": [3, 4], "command_sha256": "a"*64, "cgroup_sha256": "b"*64,
            "cli_rule_file": True}
        self.plan = {"schema": migration.SCHEMA, "nonce": "c"*64,
            "controller_unit": "cs-public0-activate-" + "c"*16 + ".service", "target": str(self.target),
            "stage": str(self.stage), "files": files, "startup_check": str(self.verifier),
            "immutable": {str(self.binary): release.sha(self.binary.read_bytes()),
                **{str(targets[k]): release.sha(self.new[k]) for k in ("config", "unit", "verifier")}},
            "monitor_timer": "monitor.timer", "monitor_service": "monitor.service", "passive_service": "passive.service",
            "rules_sha256": release.sha(RULE), "rules_count": 1,
            "before": {"cfg": {"service": "sensor.service", "queue": 100, "table": "owned", "bridge": "public0",
                "chain": "forward_ipv4", "priority": -240, "socket": str(self.root / "command.socket"),
                "binary": str(self.binary), "suricata_config": str(config), "rules_file": str(rules),
                "monitor_state": str(self.state)}, "binding": self.binding,
                "unit": {"MainPID": "123", "InvocationID": "d"*32, "ControlGroup": "/system.slice/sensor.service",
                    "ActiveState": "active", "SubState": "running"}, "selector_sha256": "e"*64,
                "qualification_settings": ["stream.inline=yes"]}}
        self.raw = release.json_bytes(self.plan)
        self.calls = []

    def validated_plan(self):
        p = copy.deepcopy(self.plan)
        item = p["files"]["unit"]
        del p["immutable"][item["target"]]
        item["target"] = "/etc/systemd/system/sensor.service"
        p["immutable"][item["target"]] = item["new_sha256"]
        return p

    def fixtures(self, failure=None, qualification=None):
        owner = self
        def manager(argv, **kwargs):
            owner.calls.append(argv)
            if failure is not None: failure(argv)
            return SimpleNamespace(returncode=0)
        def units(name, keys):
            if name == "passive.service": return {"ActiveState": "inactive", "UnitFileState": "disabled"}
            if keys == ("MainPID", "ActiveState"): return {"MainPID": "0", "ActiveState": "inactive"}
            return {**owner.plan["before"]["unit"], "MainPID": "124", "InvocationID": "f"*32}
        class Commands:
            def __init__(self, *a): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def require_reloadable(self): pass
            def query(self, name): return "NFQ" if name == "capture-mode" else []
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(migration.subprocess, "run", side_effect=manager))
        stack.enter_context(patch.object(migration, "systemd", side_effect=units))
        stack.enter_context(patch.object(migration, "probe", return_value={"packets": 2}))
        stack.enter_context(patch.object(migration, "qualify_yaml", side_effect=qualification,
            return_value={"fixture_only": True}))
        stack.enter_context(patch.object(migration, "process_binding", return_value={**self.binding, "pid": 124, "cli_rule_file": False}))
        stack.enter_context(patch.object(migration, "SuricataCommands", Commands))
        stack.enter_context(patch.object(migration, "ruleset"))
        stack.enter_context(patch.object(activation, "exact_selector", return_value=True))
        stack.enter_context(patch.object(activation, "selector_hash", return_value="0"*64))
        stack.enter_context(patch.object(activation.runtime, "table", return_value={}))
        return stack

    def test_plan_refuses_foreign_context_unknown_fields_and_unpinned_startup_assets(self):
        good = self.validated_plan()
        self.assertEqual(migration.parse(release.json_bytes(good)), good)
        for change in (lambda p: p.update(rules_count=True), lambda p: p["before"]["binding"].update(cli_rule_file=False),
                       lambda p: p["before"]["cfg"].update(queue=True), lambda p: p["before"]["unit"].update(MainPID="999"),
                       lambda p: p["immutable"].pop(p["startup_check"]),
                       lambda p: p["files"]["config"].update(source="migration-status.json")):
            bad = copy.deepcopy(good); change(bad)
            with self.assertRaises(Exception): migration.parse(release.json_bytes(bad))

    def test_unit_only_removes_the_exact_S_pair_and_manifest_only_changes_config_pin(self):
        migration.verify_transition(self.plan, self.old, self.new)
        for bad in ({**self.new, "unit": self.new["unit"].replace(b"Restart=no", b"Restart=always")},
                    {**self.new, "unit": self.old["unit"]},
                    {**self.new, "manifest": self.new["manifest"].replace(b'"rules_alert": 1', b'"rules_alert": 2')}):
            with self.assertRaises(RuntimeError): migration.verify_transition(self.plan, self.old, bad)

    def test_migration_archives_old_state_and_all_four_assets_without_changing_rules(self):
        with self.fixtures(): result = migration.migrate(self.plan, self.raw)
        self.assertEqual(result["phase"], "MIGRATED")
        self.assertEqual((self.stage / "monitor-state.before.json").read_bytes(), self.old_state)
        for role, item in self.plan["files"].items():
            self.assertEqual(Path(item["target"]).read_bytes(), self.new[role])
            self.assertEqual((self.stage / (role + ".before")).read_bytes(), self.old[role])
        self.assertEqual((self.target / "production.rules").read_bytes(), RULE)
        self.assertEqual(release.verify_release(self.target / "release.json")["rules_alert"], 1)
        self.assertIn(["/usr/bin/systemctl", "start", "monitor.timer"], self.calls)
        self.assertFalse(any("passive.service" in call for call in self.calls))

    def test_lost_timer_stop_reply_still_attempts_timer_restore_without_sensor_stop(self):
        def fail(argv):
            if argv[-2:] == ["stop", "monitor.timer"]: raise subprocess.TimeoutExpired(argv, 15)
        with self.fixtures(failure=fail), self.assertRaises(subprocess.TimeoutExpired):
            migration.migrate(self.plan, self.raw)
        self.assertEqual(self.state.read_bytes(), self.old_state)
        self.assertIn(["/usr/bin/systemctl", "start", "monitor.timer"], self.calls)
        self.assertFalse(any(call[-2:] == ["stop", "sensor.service"] for call in self.calls))

    def test_start_failure_retains_original_epoch_and_new_files_without_automatic_passive_rollback(self):
        def fail(argv):
            if argv[-2:] == ["start", "sensor.service"]: raise subprocess.CalledProcessError(1, argv)
        with self.fixtures(failure=fail), self.assertRaises(subprocess.CalledProcessError):
            migration.migrate(self.plan, self.raw)
        self.assertEqual((self.stage / "monitor-state.before.json").read_bytes(), self.old_state)
        self.assertEqual((self.stage / "migration-status.json").read_bytes().count(b'START_REQUEST'), 1)
        self.assertEqual(self.unit.read_bytes(), self.new["unit"])
        self.assertIn(["/usr/bin/systemctl", "start", "monitor.timer"], self.calls)
        self.assertFalse(any("passive.service" in call for call in self.calls))

    def test_bad_or_changed_qualification_never_stops_sensor_or_clears_epoch(self):
        def change(*args):
            (self.stage / "config.new").write_bytes(b"changed after compile")
        with self.fixtures(qualification=change), self.assertRaisesRegex(RuntimeError, "source changed"):
            migration.migrate(self.plan, self.raw)
        self.assertEqual(self.state.read_bytes(), self.old_state)
        self.assertFalse(self.calls)

    def test_latched_epoch_blocks_stop_and_timer_is_restored(self):
        bad = json.loads(self.old_state); bad["latched"] = True
        self.state.write_bytes(release.json_bytes(bad))
        with self.fixtures(), self.assertRaisesRegex(RuntimeError, "unresolved old epoch"):
            migration.migrate(self.plan, self.raw)
        self.assertTrue(json.loads(self.state.read_bytes())["latched"])
        self.assertFalse((self.stage / "monitor-state.before.json").exists())
        self.assertFalse(any(call[-2:] == ["stop", "sensor.service"] for call in self.calls))

    def test_slow_qualification_reserves_recovery_time_and_never_stops_sensor(self):
        clock = [1_000_000_000]
        def slow(*args):
            clock[0] += 166_000_000_000
        with self.fixtures(qualification=slow), \
             patch.object(migration.time, "monotonic_ns", side_effect=lambda: clock[0]), \
             self.assertRaisesRegex(RuntimeError, "insufficient controller lifetime"):
            migration.migrate(self.plan, self.raw)
        self.assertEqual(self.state.read_bytes(), self.old_state)
        self.assertFalse((self.stage / "monitor-state.before.json").exists())
        self.assertIn(["/usr/bin/systemctl", "start", "monitor.timer"], self.calls)
        self.assertFalse(any(call[-2:] == ["stop", "sensor.service"] for call in self.calls))
        self.assertEqual(json.loads((self.stage / "migration-status.json").read_bytes())["phase"], "QUALIFIED")

    def test_changed_immutable_support_after_qualification_blocks_sensor_stop(self):
        def change(*args):
            self.binary.write_bytes(b"foreign binary after qualification")
        with self.fixtures(qualification=change), \
             self.assertRaisesRegex(RuntimeError, "migration immutable source changed"):
            migration.migrate(self.plan, self.raw)
        self.assertEqual(self.state.read_bytes(), self.old_state)
        self.assertFalse((self.stage / "monitor-state.before.json").exists())
        self.assertEqual(self.unit.read_bytes(), self.old["unit"])
        self.assertIn(["/usr/bin/systemctl", "start", "monitor.timer"], self.calls)
        self.assertFalse(any(call[-2:] == ["stop", "sensor.service"] for call in self.calls))

    def test_stop_budget_boundary_and_clock_reversal(self):
        start = 1_000_000_000
        with patch.object(migration.time, "monotonic_ns", return_value=start + 165_000_000_000):
            migration.require_stop_budget(start)
        for now in (start - 1, start + 165_000_000_001):
            with patch.object(migration.time, "monotonic_ns", return_value=now), \
                 self.assertRaisesRegex(RuntimeError, "insufficient controller lifetime"):
                migration.require_stop_budget(start)

    def test_migration_launcher_claim_and_ExecStopPost_precede_manager_allocation(self):
        p = self.validated_plan()
        raw = release.json_bytes(p); path = self.stage / "plan.json"; path.write_bytes(raw)
        # Use an accepted persistent plan path while substituting its secure read.
        with patch.object(launcher, "os", SimpleNamespace(geteuid=lambda: 0)), \
             patch.object(launcher, "read_path", return_value=raw), \
             patch.object(launcher.subprocess, "run", side_effect=subprocess.TimeoutExpired("systemd-run", 380)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                launcher.launch(Path("/var/lib/owned-migration/plan.json"), release.sha(raw), migration=True)
        self.assertTrue((self.stage / ("launch-" + release.sha(raw) + ".json")).exists())
        argv = run.call_args.args[0]
        self.assertIn("--property=ExecStopPost=+/usr/bin/systemctl --no-block start monitor.timer", argv)
        self.assertIn("--property=RuntimeMaxSec=360", argv)
        self.assertEqual(run.call_args.kwargs["timeout"], 380)
        self.assertIn("migrate_rule_source.py", " ".join(argv))
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__": unittest.main()
