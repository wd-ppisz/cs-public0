import contextlib
import gzip
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "runtime"))
import activate_rules as activation
import rule_release as release
import rule_update_journal as journal
import run_rule_activation as launcher

RULE = b'alert tcp any any -> any any (msg:"fixture"; sid:9100011; rev:1;)\n'
NEW = RULE + b'alert udp any any -> any any (msg:"fixture2"; sid:9100012; rev:1;)\n'


@unittest.skipUnless(sys.platform == "linux", "Linux fd/filesystem checks")
class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target, self.store, self.candidate = [self.root / n for n in ("target", "store", "candidate")]
        for d in (self.target, self.store, self.candidate):
            d.mkdir(mode=0o700)
        self.binary, self.config = self.root / "engine", self.root / "engine.yaml"
        self.binary.write_bytes(b"engine fixture")
        self.config.write_bytes(b"configuration fixture")
        self.file_names = {"rules": "production.rules", "gzip": "production.rules.gz", "manifest": "manifest.json"}
        (self.target / self.file_names["rules"]).write_bytes(RULE)
        (self.target / self.file_names["gzip"]).write_bytes(gzip.compress(RULE, mtime=0))
        pins = {str(p): release.sha(p.read_bytes()) for p in (self.binary, self.config)}
        initial = release.make_release(RULE, gzip.compress(RULE, mtime=0), self.file_names, pins)
        self.manifest = release.manifest_for({"provider": "preserved", "artifacts": {"binary": "preserved"}}, initial)
        (self.target / "manifest.json").write_bytes(release.json_bytes(self.manifest))
        release.initialize(str(self.target), self.file_names, list(pins))
        (self.candidate / "candidate.rules").write_bytes(NEW)
        (self.candidate / "candidate.rules.gz").write_bytes(gzip.compress(NEW, mtime=0))
        _, self.next, self.images, before = release.prepare_images(self.target, NEW, gzip.compress(NEW, mtime=0))
        self.binding = {"pid": 123, "start_ticks": 456, "uid": 0, "boot_id": "0"*36,
            "exe": [1, 2], "netns": [3, 4], "command_sha256": "a"*64,
            "cgroup_sha256": "b"*64, "cli_rule_file": False}
        self.plan = {"schema": activation.SCHEMA, "nonce": "a"*64,
            "controller_unit": "cs-public0-activate-" + "a"*16 + ".service",
            "target": str(self.target), "store": str(self.store), "candidate": str(self.candidate),
            "candidate_rules": "candidate.rules", "candidate_gzip": "candidate.rules.gz",
            "candidate_rules_sha256": release.sha(NEW),
            "candidate_gzip_sha256": release.sha(gzip.compress(NEW, mtime=0)),
            "expected_old": before, "cfg": {"service": "sensor.service", "queue": 100,
                "table": "owned", "bridge": "public0", "chain": "forward_ipv4", "priority": -240,
                "socket": str(self.root / "sensor.socket"), "binary": str(self.binary),
                "suricata_config": str(self.config), "rules_file": str(self.target / "production.rules"),
                "monitor_state": str(self.root / "monitor.json")},
            "binding": self.binding, "unit": {"MainPID": "123", "InvocationID": "d"*32,
                "ControlGroup": "/system.slice/sensor.service", "ActiveState": "active", "SubState": "running"},
            "selector_sha256": "c"*64, "qualification_settings": ["stream.inline=yes"], "startup_check": None}
        self.raw = release.json_bytes(self.plan)
        self.tx = release.sha(self.raw)

    def files(self):
        return {name: (self.target / name).read_bytes() for name in self.images}

    def test_initialize_and_verify_exact_real_files(self):
        value = release.verify_release(self.target / "release.json")
        self.assertEqual(value["rules_alert"], 1)
        with self.assertRaisesRegex(RuntimeError, "already initialized"):
            release.initialize(str(self.target), self.file_names, [str(self.binary)])
        self.assertEqual(release.manifest_for(self.manifest, self.next)["provider"], "preserved")

    def test_complete_startup_contract_and_immutable_count_bound(self):
        for count in (24, 32):
            with self.subTest(count=count):
                target = self.root / ('complete-' + str(count))
                target.mkdir(mode=0o700)
                paths = []
                for number in range(count):
                    path = self.root / ('immutable-' + str(count) + '-' + str(number))
                    path.write_bytes(str(number).encode())
                    paths.append(str(path))
                (target / self.file_names['rules']).write_bytes(RULE)
                (target / self.file_names['gzip']).write_bytes(gzip.compress(RULE, mtime=0))
                (target / 'manifest.json').write_bytes(release.json_bytes(self.manifest))
                release.initialize(str(target), self.file_names, paths)
                value = release.verify_release(target / 'release.json')
                self.assertEqual(len(value['immutable']), count)
                Path(paths[-1]).write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError, 'immutable source changed'):
                    release.verify_release(target / 'release.json')
        value = json.loads((self.target / 'release.json').read_bytes())
        value['immutable'] = {'/fixture/file-' + str(n): 'a' * 64 for n in range(33)}
        with self.assertRaisesRegex(RuntimeError, 'explicit immutable pins required'):
            release.validate_release(value)
        self.assertEqual(release.MAX_METADATA, 16384)

    def test_four_asset_journal_updates_startup_guard_coherently(self):
        j = journal.RuleFileJournal(self.target, self.store)
        j.prepare(self.tx, self.images, self.plan["expected_old"], {n: release.sha(b) for n, b in self.images.items()})
        j.install(self.tx)
        self.assertEqual(release.verify_release(self.target / "release.json")["rules_alert"], 2)
        j.restore(self.tx)
        self.assertEqual(release.verify_release(self.target / "release.json")["rules_alert"], 1)

    def test_changed_manifest_gzip_static_and_modes_fail_closed(self):
        paths = [self.target / "manifest.json", self.target / "production.rules.gz", self.config]
        for p in paths:
            original = p.read_bytes()
            p.write_bytes(original + b"changed")
            with self.assertRaises(Exception):
                release.verify_release(self.target / "release.json")
            p.write_bytes(original)
        self.config.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "mode"):
            release.verify_release(self.target / "release.json")

    def test_duplicate_json_bool_counts_and_path_escape_rejected(self):
        for field, value in [("rules_alert", True), ("rules_drop", False)]:
            bad = json.loads((self.target / "release.json").read_bytes())
            bad[field] = value
            with self.assertRaises(RuntimeError):
                release.validate_release(bad)
        with self.assertRaisesRegex(RuntimeError, "filename"):
            release.initialize(self.target, {**self.file_names, "rules": "../engine"}, [str(self.binary)])
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            activation.parse_plan(self.raw[:-2] + b', "nonce":"a"}')

    def test_symlink_candidate_and_changed_old_asset_are_rejected(self):
        p = self.candidate / "candidate.rules"
        p.unlink()
        p.symlink_to(self.target / "production.rules")
        with self.assertRaises(OSError):
            activation.activate(self.plan, self.raw)
        self.assertFalse((self.store / "active.json").exists())

    def test_lock_contention_has_no_request_or_target_side_effect(self):
        original = self.files()
        with activation.activation_lock(self.target):
            with self.assertRaises(BlockingIOError):
                activation.activate(self.plan, self.raw)
        self.assertEqual(self.files(), original)
        self.assertFalse(list(self.store.iterdir()))

    def patches(self, reload_error=None, post_error=False, qualification_error=None):
        owner = self
        class Session:
            def __init__(self, *args): self.binding = owner.binding; self.events = []
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def guard(self): pass
            def require_reloadable(self): pass
            def query(self, name):
                if name == "capture-mode": return "NFQ"
                if name == "ruleset-stats":
                    n = 2 if getattr(owner, "reloaded", False) else 1
                    return [{"id": 0, "rules_loaded": n, "rules_failed": 0, "rules_skipped": 0}]
                if name == "ruleset-reload-time":
                    date = "2026-10-25T00:00:02+00:00" if getattr(owner, "reloaded", False) else "2026-10-25T00:00:01+00:00"
                    return [{"id": 0, "last_reload": date}]
            def reload_rules(self):
                owner.reload_calls = getattr(owner, "reload_calls", 0) + 1
                if reload_error:
                    raise reload_error
                owner.reloaded = True
                self.events.append({"command": "ruleset-reload-rules", "finished_ns": time.monotonic_ns()})
        def probe(p):
            if post_error and getattr(owner, "reloaded", False):
                raise RuntimeError("post-reload observation unavailable")
            return {"health": {"finished_ns": time.monotonic_ns()},
                    "queue": {"portid": 123, "inode": 1, "id_sequence": 20 if getattr(owner, "reloaded", False) else 10},
                    "packets": 20 if getattr(owner, "reloaded", False) else 10}
        def qualify(*args):
            owner.assertTrue((owner.store / ("request-" + owner.tx + ".json")).is_file())
            if qualification_error:
                raise qualification_error
            return {"fixture": True}, b"fixture"
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(activation, "SuricataCommands", Session))
        stack.enter_context(patch.object(activation, "probe", probe))
        stack.enter_context(patch.object(activation, "monitor_ready_after", return_value=True))
        stack.enter_context(patch.object(activation, "qualify", qualify))
        stack.enter_context(patch.object(activation.runtime, "selected_rules", return_value=None))
        return stack

    def test_post_reload_readiness_waits_for_engine_and_kernel_without_clearing_latches(self):
        path = self.target / "monitor-readiness.json"
        plan = {"cfg": {"monitor_state": str(path)}, "binding": self.binding}
        state = {"latched": False, "current_sample_valid": False,
                 "sensor": {"pid": self.binding["pid"], "start_ticks": self.binding["start_ticks"]},
                 "kernel_accounting": {"gap_history_latched": False,
                     "observation_gap_history_latched": False,
                     "sample": {"finished_ns": 20, "boot_id": self.binding["boot_id"]}}}
        path.write_text(json.dumps(state))
        self.assertFalse(activation.monitor_ready_after(plan, 10))
        state["current_sample_valid"] = True
        path.write_text(json.dumps(state))
        self.assertFalse(activation.monitor_ready_after(plan, 20))
        self.assertTrue(activation.monitor_ready_after(plan, 10))
        for key in ("gap_history_latched", "observation_gap_history_latched"):
            state["kernel_accounting"][key] = True
            path.write_text(json.dumps(state))
            with self.assertRaisesRegex(RuntimeError, "unresolved degradation"):
                activation.monitor_ready_after(plan, 10)
            state["kernel_accounting"][key] = False
        state["sensor"]["start_ticks"] += 1
        state["current_sample_valid"] = False
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "sensor epoch changed"):
            activation.monitor_ready_after(plan, 10)

    def test_real_four_file_activation_with_separate_command_and_health_receipts(self):
        with self.patches():
            result = activation.activate(self.plan, self.raw)
        self.assertEqual(result["phase"], "ACTIVATED")
        self.assertEqual(self.reload_calls, 1)
        self.assertEqual(release.verify_release(self.target / "release.json"), self.next)
        state = json.loads((self.store / self.tx / "state.json").read_bytes())
        self.assertEqual(state["phase"], "COMMITTED")
        self.assertFalse((self.store / "active.json").exists())
        with self.patches():
            with self.assertRaises(FileExistsError):
                activation.activate(self.plan, self.raw)
        self.assertEqual(self.reload_calls, 1)

    def test_check_only_compiles_without_replacing_assets_or_reload(self):
        original = self.files()
        with self.patches():
            result = activation.activate(self.plan, self.raw, check_only=True)
        self.assertEqual(result["phase"], "QUALIFIED_ONLY")
        self.assertEqual(self.files(), original)
        self.assertFalse(hasattr(self, "reload_calls"))
        self.assertFalse((self.store / "active.json").exists())

    def test_timeout_keeps_pending_and_never_retries_or_restores(self):
        with self.patches(reload_error=TimeoutError("unknown response")):
            with self.assertRaises(TimeoutError):
                activation.activate(self.plan, self.raw)
        self.assertEqual(self.reload_calls, 1)
        j = journal.RuleFileJournal(self.target, self.store)
        self.assertEqual(j.status(self.tx)["state"]["phase"], "RELOAD_PENDING")
        self.assertEqual(self.files(), self.images)
        with self.assertRaisesRegex(RuntimeError, "restore blocked"):
            j.restore(self.tx)
        with self.patches():
            with self.assertRaises(FileExistsError):
                activation.activate(self.plan, self.raw)
        self.assertEqual(self.reload_calls, 1)

    def test_failed_post_monitor_never_claims_activated_or_undoes_committed_engine(self):
        with self.patches(post_error=True):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                activation.activate(self.plan, self.raw)
        state = json.loads((self.store / self.tx / "state.json").read_bytes())
        self.assertEqual(state["phase"], "COMMITTED")
        self.assertFalse((self.store / ("result-" + self.tx + ".json")).exists())
        self.assertEqual(self.files(), self.images)

    def test_abort_qualification_retains_claim_before_callback_and_all_old_files(self):
        original = self.files()
        with self.patches(qualification_error=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                activation.activate(self.plan, self.raw)
        self.assertEqual(self.files(), original)
        self.assertFalse((self.store / "active.json").exists())
        self.assertTrue((self.store / ("request-" + self.tx + ".json")).is_file())

    def test_new_startup_failure_leaves_installed_and_does_not_reload(self):
        original = activation.startup_check
        calls = []
        def startup(plan):
            calls.append(True)
            if len(calls) > 1:
                raise RuntimeError("startup pins incorrect")
            return original(plan)
        with self.patches(), patch.object(activation, "startup_check", startup):
            with self.assertRaisesRegex(RuntimeError, "startup pins"):
                activation.activate(self.plan, self.raw)
        self.assertFalse(hasattr(self, "reload_calls"))
        self.assertEqual(journal.RuleFileJournal(self.target, self.store).status(self.tx)["state"]["phase"], "INSTALLED")

    def test_monitor_rejects_stale_latched_foreign_and_gap_observations(self):
        path = self.root / "health.json"
        now = time.monotonic_ns()
        valid = {"latched": False, "current_sample_valid": True, "sensor": {"pid": 123, "start_ticks": 456},
            "kernel_accounting": {"unexplained_gap": 0, "gap_history_latched": False,
                "sample": {"boot_id": self.binding["boot_id"], "finished_ns": now,
                           "after": {"portid": 123, "inode": 1}}}}
        path.write_bytes(release.json_bytes(valid))
        self.assertEqual(activation.monitor_health(path, self.binding)["gap"], 0)
        changes = [("latched", True), ("current_sample_valid", False)]
        for key, value in changes:
            path.write_bytes(release.json_bytes({**valid, key: value}))
            with self.assertRaises(RuntimeError):
                activation.monitor_health(path, self.binding)
        valid["kernel_accounting"]["sample"]["finished_ns"] -= activation.HEALTH_AGE_NS + 1
        path.write_bytes(release.json_bytes(valid))
        with self.assertRaisesRegex(RuntimeError, "stale"):
            activation.monitor_health(path, self.binding)

    def test_actual_qualifier_child_retains_stdout_on_success_and_failure(self):
        for exit_code in (0, 2):
            d = self.root / ("qualifier-" + str(exit_code))
            d.mkdir(mode=0o700)
            engine = d / "engine"
            engine.write_text("#!/usr/bin/python3\nimport sys\nprint('2 rules successfully loaded, 0 rules failed, 0 rules skipped')\nsys.exit(" + str(exit_code) + ")\n")
            engine.chmod(0o700)
            plan = {**self.plan, "_new_count": 2, "cfg": {**self.plan["cfg"], "binary": str(engine)}}
            if exit_code == 0:
                receipt, raw = activation.qualify(plan, d / "candidate.rules", d)
                self.assertEqual(receipt["exit_code"], 0)
                self.assertEqual((d / "stdout.log").read_bytes(), raw)
            else:
                with self.assertRaisesRegex(RuntimeError, "qualification failed"):
                    activation.qualify(plan, d / "candidate.rules", d)
                self.assertIn(b"2 rules", (d / "stdout.log").read_bytes())

    def test_selector_pin_excludes_only_counter_values_not_rule_or_handles(self):
        doc = {"nftables": [{"metainfo": {"version": "fixture"}},
            {"counter": {"name": "queued", "handle": 2, "packets": 10, "bytes": 100}},
            {"rule": {"handle": 3, "expr": [{"queue": {"num": 100, "flags": ["bypass"]}}]}}]}
        pin = activation.selector_hash(doc)
        doc["nftables"][1]["counter"]["packets"] += 1
        self.assertEqual(activation.selector_hash(doc), pin)
        doc["nftables"][2]["rule"]["expr"][0]["queue"]["num"] += 1
        self.assertNotEqual(activation.selector_hash(doc), pin)

    def test_parse_rejects_cli_rule_selection_bool_queue_and_arbitrary_override(self):
        self.assertEqual(activation.parse_plan(self.raw), self.plan)
        for value in ({**self.plan, "binding": {**self.binding, "cli_rule_file": True}},
                      {**self.plan, "cfg": {**self.plan["cfg"], "queue": True}},
                      {**self.plan, "qualification_settings": ["stream.inline=yes", "unix-command.enabled=yes"]}):
            with self.assertRaises(RuntimeError):
                activation.parse_plan(release.json_bytes(value))

    def test_qualification_settings_must_match_the_running_process(self):
        prefix = (str(self.binary) + "\0-c\0" + str(self.config) + "\0-q\0" + str(self.plan["cfg"]["queue"]) + "\0").encode()
        raw = prefix + b"--set\0stream.inline=yes\0"
        with patch.object(activation, "bounded_read", return_value=raw):
            activation.effective_settings(self.plan)
        for raw in (prefix + b"--set\0stream.inline=no\0", prefix,
                    prefix + b"--set\0stream.inline=yes\0--set\0stream.inline=yes\0"):
            with patch.object(activation, "bounded_read", return_value=raw):
                with self.assertRaises(RuntimeError):
                    activation.effective_settings(self.plan)

    def test_running_cli_cannot_override_the_yaml_rule_source_or_compile_environment(self):
        base = [str(self.binary), "-c", str(self.config), "-q", "100", "--set", "stream.inline=yes"]
        for suffix in (["--set", "rule-files.0=foreign.rules"], ["--set", "vars.address-groups.HOME_NET=any"],
                       ["--include", "/etc/foreign.yaml"], ["-c", "/etc/foreign.yaml"],
                       ["--set=rule-files.0=foreign.rules"], ["-q", "101"]):
            raw = ("\0".join(base + suffix) + "\0").encode()
            with patch.object(activation, "bounded_read", return_value=raw), self.assertRaises(RuntimeError):
                activation.effective_settings(self.plan)
        old = {**self.plan, "binding": {**self.binding, "cli_rule_file": True}}
        with patch.object(activation, "bounded_read", return_value=("\0".join(base + ["-S", self.plan["cfg"]["rules_file"]]) + "\0").encode()):
            activation.effective_settings(old)

    def test_bootstrap_creates_only_missing_metadata_and_never_rewrites_existing_release(self):
        target = self.root / "bootstrap"
        target.mkdir(mode=0o700)
        (target / "production.rules").write_bytes(RULE)
        result = release.bootstrap(target, self.file_names, [str(self.binary)])
        self.assertEqual(result["rules_alert"], 1)
        original = {p.name: p.read_bytes() for p in target.iterdir()}
        self.assertEqual(release.bootstrap(target, self.file_names, [str(self.binary)]), result)
        self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, original)
        self.binary.write_bytes(b"changed source")
        with self.assertRaisesRegex(RuntimeError, "immutable source changed"):
            release.bootstrap(target, self.file_names, [str(self.binary)])
        self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, original)

    def test_launcher_claim_precedes_manager_allocation_and_unknown_reply_is_not_retried(self):
        path = self.root / "plan.json"
        path.write_bytes(self.raw)
        calls = []
        def run(argv, **kwargs):
            self.assertTrue((self.store / ("launch-" + self.tx + ".json")).is_file())
            self.assertIn("--property=MemoryMax=2G", argv)
            self.assertIn("--property=RuntimeMaxSec=240", argv)
            calls.append(argv)
            raise TimeoutError("manager reply unknown")
        # PrivateTmp paths are excluded by the real CLI; this fixture supplies
        # only the already validated object and exercises the real claim file.
        with patch.object(launcher, "os", SimpleNamespace(geteuid=lambda: 0)), \
             patch.object(launcher, "absolute", return_value=Path("/var/lib/plan.json")), \
             patch.object(launcher, "read_path", return_value=self.raw), \
             patch.object(launcher.subprocess, "run", side_effect=run):
            with self.assertRaises(TimeoutError):
                launcher.launch(path, self.tx)
            with self.assertRaises(FileExistsError):
                launcher.launch(path, self.tx)
        self.assertEqual(len(calls), 1)

    def test_effective_controller_limits_and_manager_identity_are_required(self):
        rows = {"MainPID": str(os.getpid()), "InvocationID": "owned", "ControlGroup": "/system.slice/owned",
            "KillMode": "control-group", "Restart": "no", "RuntimeMaxUSec": "4min", "TimeoutStopUSec": "10s"}
        def read(path, limit):
            path = str(path)
            if path == "/proc/self/cgroup": return b"0::/system.slice/owned\n"
            return {"memory.max": b"2147483648", "pids.max": b"32", "cpu.max": b"100000 100000",
                    "memory.swap.max": b"0"}[Path(path).name]
        with patch.object(activation, "systemd", return_value=rows), \
             patch.dict(os.environ, {"INVOCATION_ID": "owned"}), \
             patch.object(activation, "bounded_read", side_effect=read):
            self.assertEqual(activation.own_resources(self.plan["controller_unit"])["tasks_max"], 32)
            rows["RuntimeMaxUSec"] = "6min"
            self.assertEqual(activation.own_resources(self.plan["controller_unit"], lifetime_seconds=360)["tasks_max"], 32)
            with self.assertRaisesRegex(RuntimeError, "lifetime"):
                activation.own_resources(self.plan["controller_unit"])
            with self.assertRaisesRegex(RuntimeError, "unsupported controller lifetime"):
                activation.own_resources(self.plan["controller_unit"], lifetime_seconds=600)
            rows["RuntimeMaxUSec"] = "4min"
            rows["Restart"] = "on-failure"
            with self.assertRaisesRegex(RuntimeError, "lifetime"):
                activation.own_resources(self.plan["controller_unit"])


if __name__ == "__main__":
    unittest.main()
