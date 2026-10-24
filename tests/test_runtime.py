import importlib.util
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("cs_public0", Path(__file__).parents[1] / "runtime/cs_public0.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def nft_document(cfg):
    common = {"family": "bridge", "table": cfg["table"]}
    return {"nftables": [
        {"metainfo": {"version": "test"}},
        {"table": {"family": "bridge", "name": cfg["table"], "handle": 1}},
        {"counter": {"handle": 2, **common, "name": "queued", "packets": 5, "bytes": 100}},
        {"chain": {"handle": 3, **common, "name": "forward_ipv4", "type": "filter", "hook": "forward",
                   "prio": cfg["priority"], "policy": "accept"}},
        {"rule": {"handle": 4, **common, "chain": "forward_ipv4", "expr": runtime.expected_expressions(cfg)}},
    ]}


def queue_fixture(**changes):
    return {"pending": 0, "kernel_dropped": 0, "user_dropped": 0,
            "id_sequence": 5, "portid": 200, "inode": 300, "netlink_dropped": 0, **changes}


def sample_fixture(packets, sequence, started=10000000000, **changes):
    q = queue_fixture(id_sequence=sequence)
    return {"before": dict(q), "after": dict(q), "nft": {"packets": packets, "handles": [1, 2, 3, 4]},
            "started_ns": started, "finished_ns": started + 1000000, "boot_id": "test", **changes}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = runtime.validate_config({})

    def test_static_preflight_does_not_start_a_second_engine(self):
        result = SimpleNamespace(stdout="Suricata version 8.0.3\nNFQueue support: yes", returncode=0)
        with patch.object(runtime.Path, "is_dir", return_value=True), \
             patch.object(runtime.Path, "resolve", return_value=Path("/usr/bin/suricata")), \
             patch.object(runtime, "secure_path"), patch.object(runtime, "validate_rules"), \
             patch.object(runtime, "table", return_value=None), \
             patch.object(runtime, "run", return_value=result) as execute, \
             patch.object(runtime, "selected_rules") as selected:
            runtime.preflight(self.cfg, test_engine=False)
            self.assertFalse(any("-T" in call.args[0] for call in execute.call_args_list))
            execute.reset_mock()
            runtime.preflight(self.cfg)
            self.assertTrue(any("-T" in call.args[0] for call in execute.call_args_list))
            self.assertEqual(selected.call_count, 2)

    def test_effective_yaml_must_select_exactly_the_validated_alert_file(self):
        good = ("default-rule-path = /etc/cs-public0/rules\n"
                "rule-files = (null)\nrule-files.0 = local.rules\n")
        cases = [good.replace("local.rules", "other.rules"),
                 good.replace("/etc/cs-public0/rules", "/var/lib/suricata/rules"),
                 good + "rule-files.1 = foreign.rules\n",
                 good + "rule-files.0 = local.rules\n",
                 good.replace("rule-files.0 = local.rules\n", ""),
                 good.replace("local.rules", "*.rules"),
                 good.replace("local.rules", "../rules/local.rules"),
                 good.replace("rule-files = (null)", "rule-files = unexpected"),
                 good + "firewall.enabled = yes\n",
                 good + "firewall.rule-files.0 = foreign.rules\n",
                 good + "firewall-rule-files.0 = foreign.rules\n",
                 good + "multi-detect.enabled = yes\n",
                 good + "multi-detect.tenants.0.filename = foreign.yaml\n",
                 good + "extra.rule-files.0 = foreign.rules\n",
                 "", "x" * (runtime.MAX_MESSAGE + 1)]
        with patch.object(runtime, "run", return_value=SimpleNamespace(stdout=good)) as execute:
            runtime.selected_rules(self.cfg, Path("/usr/bin/suricata"))
            self.assertEqual(execute.call_args.args[0],
                ["/usr/bin/suricata", "--dump-config", "-c", self.cfg["suricata_config"]])
        with patch.object(runtime, "run", return_value=SimpleNamespace(
                stdout=good + "firewall.enabled = no\nmulti-detect.enabled = false\n"
                    "engine-analysis.rules = yes\nprofiling.rules.enabled = yes\n"
                    "profiling.rules.filename = rule_perf.log\nsecurity.lua.allow-rules = false\n")):
            runtime.selected_rules(self.cfg, Path("/usr/bin/suricata"))
        for raw in cases:
            with self.subTest(raw=raw[:120]), \
                 patch.object(runtime, "run", return_value=SimpleNamespace(stdout=raw)), \
                 self.assertRaises(RuntimeError):
                runtime.selected_rules(self.cfg, Path("/usr/bin/suricata"))

    def test_arm_retries_transient_readiness_timeouts(self):
        for error in (subprocess.TimeoutExpired("systemctl", 15), IndexError("proc stat")):
            with patch.object(runtime, "preflight") as preflight, \
                 patch.object(runtime, "sensor", side_effect=[error, {"pid": 101}]) as sensor, \
                 patch.object(runtime, "queue"), patch.object(runtime, "counters"), \
                 patch.object(runtime, "owned"), \
                 patch.object(runtime, "table", return_value=nft_document(self.cfg)), \
                 patch.object(runtime.time, "sleep"):
                runtime.arm(self.cfg)
            self.assertEqual(sensor.call_count, 2)
            preflight.assert_called_once_with(self.cfg, test_engine=False)

    def test_arm_rechecks_table_ownership_after_sensor_readiness(self):
        for ownership_error in (None, RuntimeError("foreign owner")):
            with patch.object(runtime, "preflight"), \
                 patch.object(runtime, "sensor", return_value={"pid": 101}), \
                 patch.object(runtime, "queue"), patch.object(runtime, "counters"), \
                 patch.object(runtime, "table", return_value={"nftables": []}), \
                 patch.object(runtime, "owned", side_effect=ownership_error) as owner, \
                 patch.object(runtime, "run") as execute:
                with self.assertRaisesRegex(RuntimeError, "foreign"):
                    runtime.arm(self.cfg)
                owner.assert_called_once_with(self.cfg)
                execute.assert_not_called()

    def test_arm_creates_table_exclusively_in_one_transaction(self):
        with patch.object(runtime, "preflight"), \
             patch.object(runtime, "sensor", return_value={"pid": 101}), \
             patch.object(runtime, "queue"), patch.object(runtime, "counters"), \
             patch.object(runtime, "table", side_effect=[None, nft_document(self.cfg)]), \
             patch.object(runtime, "atomic"), patch.object(runtime, "run", return_value=SimpleNamespace(returncode=0, stderr="")) as execute:
            runtime.arm(self.cfg)
        transaction = execute.call_args.args[1]
        self.assertTrue(transaction.startswith("create table bridge cs_public0\n"))
        self.assertIn(runtime.ruleset(self.cfg), transaction)

    def test_command_timeout_publishes_unknown_and_preserves_latch(self):
        with patch.object(runtime, "sensor", side_effect=subprocess.TimeoutExpired("systemctl", 15)):
            result = runtime.observe(self.cfg, {"latched": True, "sensor": None})
        self.assertEqual(result["metrics"]["telemetry_known"], 0)
        self.assertEqual(result["metrics"]["degraded_latched"], 1)
        self.assertNotIn("decoder_packets_total", result["metrics"])

    def test_validation_rejects_injection_unknown_and_root_replacement(self):
        for change in ({"queue": True}, {"queue": 65536}, {"bridge": 'br0" accept'},
                       {"table": "x;flush"}, {"runtime_dir": "/run"},
                       {"state_dir": "/var/lib"}, {"socket": "/run/other.socket"},
                       {"rules_file": "/etc/../etc/passwd.rules"}, {"unknown": 1}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                runtime.validate_config(change)

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(RuntimeError):
            json.loads('{"queue":100,"queue":101}', object_pairs_hook=runtime.unique)

    def test_exact_table_rejects_broader_scope_and_extra_objects(self):
        document = nft_document(self.cfg)
        self.assertTrue(runtime.exact_table(document, self.cfg))
        document["nftables"][-1]["rule"]["expr"][-1]["queue"]["flags"] = "bypass"
        self.assertTrue(runtime.exact_table(document, self.cfg))
        document["nftables"][-1]["rule"]["expr"].pop(0)
        self.assertFalse(runtime.exact_table(document, self.cfg))
        document = nft_document(self.cfg)
        document["nftables"].append(document["nftables"][-1])
        self.assertFalse(runtime.exact_table(document, self.cfg))
        document = nft_document(self.cfg)
        document["nftables"][3]["chain"]["policy"] = "drop"
        self.assertFalse(runtime.exact_table(document, self.cfg))

    def test_disarm_refuses_foreign_or_modified_table(self):
        with patch.object(runtime, "table", return_value=nft_document(self.cfg)), \
             patch.object(runtime, "owned", side_effect=RuntimeError("foreign")), \
             patch.object(runtime, "run") as execute:
            with self.assertRaisesRegex(RuntimeError, "foreign"):
                runtime.disarm(self.cfg)
            execute.assert_not_called()
        with patch.object(runtime, "table", return_value={"nftables": []}), \
             patch.object(runtime, "owned"), patch.object(runtime, "run") as execute:
            with self.assertRaisesRegex(RuntimeError, "foreign or modified"):
                runtime.disarm(self.cfg)
            execute.assert_not_called()

    def test_rules_allow_alert_only_and_reject_empty(self):
        content = b""
        path = SimpleNamespace(stat=lambda: SimpleNamespace(st_size=len(content)), open=lambda mode: io.BytesIO(content))
        with patch.object(runtime, "secure_path", return_value=path):
            for action in ("drop", "reject", "pass", "", "# no active rules"):
                content = (action + (' tcp any any -> any any (sid:1;)' if action and not action.startswith("#") else "")).encode()
                with self.subTest(action=action), self.assertRaises(RuntimeError):
                    runtime.validate_rules(self.cfg)
            content = '# Example\nalert http any any -> any any (msg:"example"; sid:1000001; rev:1;)\n'.encode()
            self.assertEqual(runtime.validate_rules(self.cfg), 1)
            for options in ('bypass; sid:1;', 'msg:"x"; bypass ; sid:1;', 'BYPASS; sid:1;',
                            'bYpAsS; sid:1;', 'metadata:k "v; bypass; metadata:k v"; sid:1;',
                            'msg:"literal ; bypass;"; sid:1;'):
                content = ('alert tcp any any -> any any (' + options + ')').encode()
                with self.subTest(options=options), self.assertRaisesRegex(RuntimeError, "bypass"):
                    runtime.validate_rules(self.cfg)
            for options in (r'msg:"literal \; bypass\;"; sid:1;', r'msg:"escaped \"\; bypass\;"; sid:1;'):
                content = ('alert tcp any any -> any any (' + options + ')').encode()
                with self.subTest(options=options):
                    self.assertEqual(runtime.validate_rules(self.cfg), 1)
            for control in ("\v", "\x85", "\u2028", "\r", "\x7f", "\u200b"):
                content = ('alert tcp any any -> any any (msg:"a)' + control + '#"; bypass; sid:1;)').encode()
                with self.subTest(control=repr(control)), self.assertRaisesRegex(RuntimeError, "control or non-printable"):
                    runtime.validate_rules(self.cfg)
            content = b'alert tcp any any -> any any (sid:1;) \\\n'
            with self.assertRaisesRegex(RuntimeError, "continuations"):
                runtime.validate_rules(self.cfg)
            content = b'alert tcp any any -> any any (msg:"\xff"; sid:1;)'
            with self.assertRaisesRegex(RuntimeError, "valid UTF-8"):
                runtime.validate_rules(self.cfg)
            content = b'\talert tcp any any -> any any (sid:1;)'
            with self.assertRaisesRegex(RuntimeError, "column one"):
                runtime.validate_rules(self.cfg)
            for content in (b"#" + b"x" * runtime.MAX_RULE_LINE_BYTES,
                            b" " * (runtime.MAX_RULE_LINE_BYTES + 1),
                            b'alert tcp any any -> any any (msg:"' + b"x" * runtime.MAX_RULE_LINE_BYTES + b'"; sid:1;)',
                            ("#" + "\u0119" * (runtime.MAX_RULE_LINE_BYTES // 2)).encode("utf-8")):
                with self.subTest(length=len(content)), self.assertRaisesRegex(RuntimeError, "physical rule-file line too long"):
                    runtime.validate_rules(self.cfg)
            content = b'# Actual read must match the size limit'
            with patch.object(runtime, "MAX_RULES_BYTES", 8), \
                 patch.object(path, "stat", return_value=SimpleNamespace(st_size=1)):
                with self.assertRaisesRegex(RuntimeError, "too large"):
                    runtime.validate_rules(self.cfg)

    def test_alert_rules_reject_packet_replacement_without_rejecting_literal_text(self):
        content = b""
        path = SimpleNamespace(stat=lambda: SimpleNamespace(st_size=len(content)), open=lambda mode: io.BytesIO(content))
        with patch.object(runtime, "secure_path", return_value=path):
            for options in ('content:"abc"; replace:"xyz"; sid:1;',
                            'content:"abc"; RePlAcE : "xyz"; sid:1;',
                            'replace:"xyz"; content:"abc"; sid:1;'):
                content = ('alert tcp any any -> any any (' + options + ')').encode()
                with self.subTest(options=options), self.assertRaisesRegex(RuntimeError, "replace"):
                    runtime.validate_rules(self.cfg)
            for options in ('msg:"literal replace:xyz"; sid:1;',
                            r'msg:"literal \; replace:xyz\;"; sid:1;',
                            'content:"replace"; sid:1;'):
                content = ('alert tcp any any -> any any (' + options + ')').encode()
                with self.subTest(options=options):
                    self.assertEqual(runtime.validate_rules(self.cfg), 1)

    def test_flatten_nested_counters_ignores_threads_boolean_and_invalid_values(self):
        data = runtime.flatten({"decoder": {"pkts": 7}, "uptime": 9,
                                "threads": {"W#1": {"decoder": {"pkts": 7}}},
                                "invalid": -1, "boolean": True})
        self.assertEqual(data, {"decoder.pkts": 7, "uptime": 9})

    def test_unavailable_does_not_publish_healthy_zero_or_erase_latch(self):
        with patch.object(runtime, "sensor", side_effect=RuntimeError("offline")):
            result = runtime.observe(self.cfg, {"latched": True, "sensor": None})
        self.assertEqual(result["metrics"]["telemetry_known"], 0)
        self.assertEqual(result["metrics"]["degraded_latched"], 1)
        self.assertNotIn("decoder_packets_total", result["metrics"])

    def test_complete_zero_loss_sample_is_known_and_latches_later_loss(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        epoch = {"pid": 101, "start_ticks": 50, "boot_id": "test"}
        with patch.object(runtime, "sensor", return_value=epoch), \
             patch.object(runtime, "queue", return_value=queue_fixture()), \
             patch.object(runtime, "table", return_value=nft_document(self.cfg)), \
             patch.object(runtime, "owned"), patch.object(runtime, "counters", return_value=data):
            result = runtime.observe(self.cfg)
            self.assertEqual(result["metrics"]["telemetry_known"], 1)
            self.assertEqual(result["metrics"]["degraded_latched"], 0)
            data["flow.memcap"] = 1
            result = runtime.observe(self.cfg, result["state"])
            self.assertEqual(result["metrics"]["degraded_latched"], 1)
            data["flow.memcap"] = 0
            self.assertEqual(runtime.observe(self.cfg, result["state"])["metrics"]["degraded_latched"], 1)

    def test_missing_decoder_or_loss_counter_is_unknown(self):
        with patch.object(runtime, "sensor", return_value={"pid": 101}), \
             patch.object(runtime, "queue", return_value={"pending": 0}), \
             patch.object(runtime, "table", return_value=nft_document(self.cfg)), \
             patch.object(runtime, "owned"), patch.object(runtime, "counters", return_value={"uptime": 10}):
            self.assertEqual(runtime.observe(self.cfg)["metrics"]["telemetry_known"], 0)



    def test_startup_timeouts_leave_a_systemd_margin(self):
        unit = (Path(__file__).parents[1] / "config/cs-public0.service.j2").read_text()
        timeout = int(next(line.split("=", 1)[1].rstrip("s")
                           for line in unit.splitlines() if line.startswith("TimeoutStartSec=")))
        self.assertGreaterEqual(runtime.SENSOR_READY_TIMEOUT_SECONDS, runtime.ENGINE_TEST_TIMEOUT_SECONDS)
        self.assertLess(runtime.ENGINE_TEST_TIMEOUT_SECONDS + runtime.SENSOR_READY_TIMEOUT_SECONDS, timeout)

    def test_arm_allows_engine_initialization_longer_than_configuration_validation(self):
        with patch.object(runtime, "preflight"), \
             patch.object(runtime, "sensor", side_effect=[RuntimeError("loading"), {"pid": 101}]), \
             patch.object(runtime, "queue"), patch.object(runtime, "counters"), \
             patch.object(runtime, "table", return_value=nft_document(self.cfg)), \
             patch.object(runtime, "owned"), patch.object(runtime.time, "sleep"), \
             patch.object(runtime.time, "monotonic", side_effect=[0, runtime.ENGINE_TEST_TIMEOUT_SECONDS + 1]):
            runtime.arm(self.cfg)

    def test_arm_readiness_timeout_is_finite(self):
        with patch.object(runtime, "preflight"), \
             patch.object(runtime, "sensor", side_effect=RuntimeError("loading")), \
             patch.object(runtime.time, "monotonic", side_effect=[0, runtime.SENSOR_READY_TIMEOUT_SECONDS + 1]), \
             patch.object(runtime.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                runtime.arm(self.cfg)
            sleep.assert_not_called()

    def observe_counter(self, name=None, value=1):
        data = {"decoder.pkts": 1000, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        if name:
            data[name] = value
        with patch.object(runtime, "sensor", return_value={"pid": 101, "start_ticks": 50, "boot_id": "test"}), \
             patch.object(runtime, "queue", return_value=queue_fixture()), \
             patch.object(runtime, "table", return_value=nft_document(self.cfg)), \
             patch.object(runtime, "owned"), patch.object(runtime, "counters", return_value=data):
            return runtime.observe(self.cfg)

    def test_flow_exception_policy_latches(self):
        result = self.observe_counter("flow.memcap_exception_policy.pass_flow")
        self.assertEqual(result["metrics"]["degraded_latched"], 1)

    def test_reassembly_exception_policy_latches(self):
        result = self.observe_counter("tcp.reassembly_exception_policy.pass_flow")
        self.assertEqual(result["metrics"]["degraded_latched"], 1)

    def test_midstream_exception_policies_are_observations_not_degradation(self):
        for name in ("tcp.midstream_exception_policy.pass_flow", "exception_policy.tcp.midstream.pass_flow"):
            result = self.observe_counter(name)
            self.assertEqual(result["metrics"]["degraded_latched"], 0)
            self.assertEqual(result["metrics"]["midstream_policy_events_total"], 1)

    def test_app_layer_nested_exception_policy_latches(self):
        result = self.observe_counter("app_layer.error.http.exception_policy.pass_flow")
        self.assertEqual(result["metrics"]["degraded_latched"], 1)

    def test_legacy_exception_policy_and_zero_counters(self):
        self.assertEqual(self.observe_counter("exception_policy.tcp.reassembly.pass_flow")["metrics"]["degraded_latched"], 1)
        self.assertEqual(self.observe_counter("tcp.reassembly_exception_policy.pass_flow", 0)["metrics"]["degraded_latched"], 0)

    def test_asynchronous_nft_and_decoder_samples_do_not_latch(self):
        data = {"decoder.pkts": 1000, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        document = nft_document(self.cfg)
        previous = None
        q = queue_fixture()
        with patch.object(runtime, "sensor", return_value={"pid": 101, "start_ticks": 50, "boot_id": "test"}), \
             patch.object(runtime, "queue", return_value=q), \
             patch.object(runtime, "table", return_value=document), \
             patch.object(runtime, "owned"), patch.object(runtime, "counters", return_value=data):
            for sample in range(5):
                document["nftables"][2]["counter"]["packets"] = 1000 + sample * 1200
                q["id_sequence"] = 1000 + sample * 1200
                data["decoder.pkts"] = 1000 + sample * 1000
                result = runtime.observe(self.cfg, previous)
                self.assertEqual(result["metrics"]["telemetry_known"], 1)
                self.assertEqual(result["metrics"]["degraded_latched"], 0)
                self.assertEqual(result["metrics"]["nft_packets_total"], 1000 + sample * 1200)
                previous = result["state"]


    def observation_patches(self, data, queue_data=None, epoch=None):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(runtime, "sensor", return_value=epoch or {"pid": 101, "start_ticks": 50, "boot_id": "test"}))
        stack.enter_context(patch.object(runtime, "queue", return_value=queue_data or
                                        queue_fixture()))
        stack.enter_context(patch.object(runtime, "table", return_value=nft_document(self.cfg)))
        stack.enter_context(patch.object(runtime, "owned"))
        stack.enter_context(patch.object(runtime, "counters", return_value=data))
        return stack

    def test_acknowledge_baselines_nonzero_counters_and_only_new_events_relatch(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        data["flow.memcap"] = 3
        with self.observation_patches(data), patch.object(runtime, "previous_state", return_value=None), \
             patch.object(runtime, "atomic") as publish:
            acknowledged = runtime.monitor(self.cfg, acknowledge=True)
            self.assertEqual(acknowledged["metrics"]["degraded_latched"], 0)
            self.assertEqual(acknowledged["state"]["counters"]["flow.memcap"], 3)
            self.assertEqual(acknowledged["state"]["reasons"], [])
            self.assertEqual(publish.call_count, 2)
            stable = runtime.observe(self.cfg, acknowledged["state"])
            self.assertEqual(stable["metrics"]["degraded_latched"], 0)
            data["flow.memcap"] = 4
            self.assertEqual(runtime.observe(self.cfg, stable["state"])["metrics"]["degraded_latched"], 1)

    def test_acknowledge_unknown_refuses_state_and_metric_writes(self):
        with patch.object(runtime, "sensor", side_effect=RuntimeError("offline")), \
             patch.object(runtime, "previous_state", return_value={"latched": True, "sensor": None}), \
             patch.object(runtime, "atomic") as publish:
            with self.assertRaisesRegex(RuntimeError, "cannot acknowledge unknown"):
                runtime.monitor(self.cfg, acknowledge=True)
            publish.assert_not_called()

    def test_queue_drop_acknowledgement_preserves_baseline(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        queue_data = queue_fixture(kernel_dropped=2, user_dropped=1)
        with self.observation_patches(data, queue_data), patch.object(runtime, "previous_state", return_value=None), \
             patch.object(runtime, "atomic"):
            self.assertEqual(runtime.observe(self.cfg)["metrics"]["degraded_latched"], 1)
            acknowledged = runtime.monitor(self.cfg, acknowledge=True)
            stable = runtime.observe(self.cfg, acknowledged["state"])
            self.assertEqual(stable["metrics"]["degraded_latched"], 0)
            queue_data["user_dropped"] = 2
            self.assertEqual(runtime.observe(self.cfg, stable["state"])["metrics"]["degraded_latched"], 1)

    def test_counter_reset_in_same_sensor_epoch_latches(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        data["flow.memcap"] = 3
        with self.observation_patches(data):
            previous = runtime.observe(self.cfg)["state"]
            previous["latched"] = False
            data["flow.memcap"] = 1
            result = runtime.observe(self.cfg, previous)
            self.assertEqual(result["metrics"]["degraded_latched"], 1)
            self.assertIn("counter_reset", result["state"]["reasons"])

    def test_sensor_restart_latches_with_a_new_counter_epoch(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        with self.observation_patches(data):
            previous = runtime.observe(self.cfg)["state"]
        with self.observation_patches(data, epoch={"pid": 102, "start_ticks": 55, "boot_id": "test"}):
            result = runtime.observe(self.cfg, previous)
            self.assertEqual(result["metrics"]["degraded_latched"], 1)
            self.assertIn("sensor_restarted", result["state"]["reasons"])

    def test_missing_previously_seen_optional_counter_is_unknown(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        data["tcp.reassembly_exception_policy.pass_flow"] = 0
        with self.observation_patches(data):
            previous = runtime.observe(self.cfg)["state"]
            del data["tcp.reassembly_exception_policy.pass_flow"]
            self.assertEqual(runtime.observe(self.cfg, previous)["metrics"]["telemetry_known"], 0)


    def test_malformed_saved_counter_schema_preserves_a_latch(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            cfg = {**self.cfg, "state_dir": directory}
            file = Path(directory) / "monitor.json"
            with patch.object(runtime, "secure_path"):
                valid = {"latched": False, "sensor": None, "counters": {"flow.memcap": 3}}
                file.write_text(json.dumps(valid))
                self.assertEqual(runtime.previous_state(cfg), valid)
                for payload in ({"latched": False, "counters": []},
                                {"latched": False, "counters": {"flow.memcap": "3"}},
                                {"latched": False, "counters": {"flow.memcap": True}},
                                ["invalid state"]):
                    file.write_text(json.dumps(payload))
                    previous = runtime.previous_state(cfg)
                    self.assertEqual(previous, {"latched": True, "sensor": None})

    def test_oversized_observations_are_unknown_and_cannot_be_acknowledged(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        data.update({"exception_policy." + "x" * 100 + str(i): 0 for i in range(1000)})
        with self.observation_patches(data), patch.object(runtime, "previous_state", return_value=None), \
             patch.object(runtime, "atomic") as publish:
            result = runtime.observe(self.cfg)
            self.assertEqual(result["metrics"]["telemetry_known"], 0)
            with self.assertRaisesRegex(RuntimeError, "cannot acknowledge unknown"):
                runtime.monitor(self.cfg, acknowledge=True)
            publish.assert_not_called()


    def account(self, previous, sample):
        current = {"pid": 101, "start_ticks": 50, "boot_id": "test"}
        accounting, gap, reason = runtime.account_kernel(previous or {}, sample, current)
        return {"sensor": current, "kernel_accounting": accounting}, gap, reason

    def test_single_burst_gap_stays_unknown_without_fabricating_a_bypass(self):
        previous, _, _ = self.account(None, sample_fixture(100, 100))
        for n in range(1, 5):
            previous, gap, reason = self.account(previous, sample_fixture(1100, 100, (10+n)*1000000000))
            self.assertEqual(gap, 1000)
            self.assertIsNone(reason)

    def test_inflight_interval_can_converge_and_gso_surplus_is_not_a_loss(self):
        previous, _, _ = self.account(None, sample_fixture(100, 100))
        previous, gap, _ = self.account(previous, sample_fixture(1100, 100, 11000000000))
        self.assertEqual(gap, 1000)
        previous, gap, _ = self.account(previous, sample_fixture(1100, 1100, 12000000000))
        self.assertEqual(gap, 0)
        previous, gap, _ = self.account(previous, sample_fixture(1200, 1300, 13000000000))
        self.assertEqual(gap, 0)
        self.assertEqual(previous["kernel_accounting"]["gap_history_peak"], 1000)

    def test_gso_surplus_and_restart_cannot_erase_an_observed_unknown_period(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        prior = None
        for sample in (sample_fixture(100, 100), sample_fixture(5100, 100, 11000000000),
                       sample_fixture(5200, 10300, 12000000000)):
            with self.observation_patches(data), patch.object(runtime, "kernel_sample", return_value=sample):
                result = runtime.observe(self.cfg, prior)
                prior = result["state"]
        self.assertEqual(result["metrics"]["accounting_unexplained_gap"], 0)
        self.assertEqual(result["metrics"]["accounting_gap_history_peak"], 5000)
        self.assertEqual(result["metrics"]["telemetry_known"], 1)
        self.assertEqual(result["metrics"]["degraded_latched"], 1)
        self.assertEqual(result["metrics"]["accounting_gap_history_latched"], 1)
        self.assertEqual(prior["accounting_status"], "OBSERVED_NO_GAP")
        # Zapis/ponowny odczyt stanu nie jest operatorem rozwiązującym lukę.
        prior = json.loads(json.dumps(prior))
        changed = sample_fixture(10, 10, 13000000000)
        changed["boot_id"] = "another-boot"
        accounting, _, _ = runtime.account_kernel(prior, changed, prior["sensor"])
        self.assertEqual(accounting["gap_history_peak"], 5000)

    def test_unsigned_wrap_and_observation_discontinuities(self):
        previous, _, _ = self.account(None, sample_fixture(100, (1<<32)-5))
        _, gap, reason = self.account(previous, sample_fixture(110, 5, 11000000000))
        self.assertEqual((gap, reason), (0, None))
        for change in ("boot", "socket", "nft", "time_gap", "clock_reversal", "reset"):
            sample = sample_fixture(110, 5, 11000000000)
            if change == "boot": sample["boot_id"] = "changed"
            if change == "socket": sample["after"]["inode"] += 1
            if change == "nft": sample["nft"]["handles"][0] += 1
            if change == "time_gap": sample["started_ns"] += runtime.MAX_OBSERVATION_GAP_NS
            if change == "clock_reversal": sample["started_ns"] = 0
            if change == "reset": sample["nft"]["packets"] = 0
            with self.subTest(change=change):
                self.assertEqual(self.account(previous, sample)[2],
                                 "nfqueue.observation_gap" if change == "time_gap" else "nfqueue.observation_discontinuity")

    def test_long_observation_pause_has_audited_exit_without_clearing_loss_latches(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        prior = None
        for index, sample in enumerate((sample_fixture(100, 100),
                sample_fixture((1 << 31) + 200, 200, 130000000000),
                sample_fixture((1 << 31) + 300, 300, 140000000000))):
            with self.observation_patches(data), patch.object(runtime, "kernel_sample", return_value=sample):
                result = runtime.observe(self.cfg, prior)
                prior = result["state"]
            self.assertFalse(prior["latched"])
            if index == 1:
                self.assertEqual(result["metrics"]["telemetry_known"], 0)
                self.assertEqual(result["metrics"]["accounting_observation_gap_history_latched"], 1)
        self.assertEqual(result["metrics"]["telemetry_known"], 1)
        self.assertEqual(result["metrics"]["degraded_latched"], 1)
        self.assertEqual(prior["kernel_accounting"]["gap_history_peak"], 0)
        runtime.acknowledge_accounting_gap(prior, result["metrics"], "c" * 64, runtime.accounting_claim(prior))
        self.assertEqual(result["metrics"]["degraded_latched"], 0)
        self.assertFalse(prior["kernel_accounting"]["observation_gap_history_latched"])
        self.assertTrue(prior["gap_acknowledgements"][0]["before"]["observation_gap_history_latched"])

    def test_monitor_lock_failure_never_publishes_without_the_state_lock(self):
        for error in (BlockingIOError("busy"), RuntimeError("unsafe lock"), PermissionError("denied")):
            with self.subTest(error=type(error).__name__), \
                 patch.object(runtime, "locked", side_effect=error), \
                 patch.object(runtime, "publish_metrics") as publish, \
                 patch.object(runtime, "previous_state") as read:
                with self.assertRaises(type(error)):
                    with runtime.monitored_lock(self.cfg, True):
                        self.fail("lock failure admitted monitor")
                read.assert_not_called()
                publish.assert_not_called()

    def test_monitor_body_failure_publishes_unknown_under_lock_without_false_degraded(self):
        from contextlib import nullcontext
        with patch.object(runtime, "locked", return_value=nullcontext()), \
             patch.object(runtime, "previous_state", return_value={"latched": False}), \
             patch.object(runtime, "publish_metrics") as publish:
            with self.assertRaises(RuntimeError):
                with runtime.monitored_lock(self.cfg, True):
                    raise RuntimeError("state write failed")
            self.assertEqual(publish.call_args.args[1]["telemetry_known"], 0)
            self.assertEqual(publish.call_args.args[1]["degraded_latched"], 0)
            publish.reset_mock()
            with self.assertRaises(RuntimeError):
                with runtime.monitored_lock(self.cfg, False):
                    raise RuntimeError("operator request refused")
            publish.assert_not_called()

    def test_listener_observation_survives_nft_read_failure(self):
        with self.observation_patches({}), patch.object(runtime, "table", side_effect=RuntimeError("nft")):
            result = runtime.observe(self.cfg)
        self.assertEqual(result["metrics"]["queue_listener"], 1)
        self.assertEqual(result["metrics"]["nft_rule"], 0)
        self.assertEqual(result["metrics"]["telemetry_known"], 0)
        self.assertFalse(result["state"]["current_sample_valid"])

    def test_gap_is_unknown_and_acknowledge_is_refused(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        first = sample_fixture(100, 100)
        later = sample_fixture(1100, 100, 11000000000)
        with self.observation_patches(data), patch.object(runtime, "kernel_sample", return_value=first):
            prior = runtime.observe(self.cfg)["state"]
        with self.observation_patches(data), patch.object(runtime, "kernel_sample", return_value=later), \
             patch.object(runtime, "previous_state", return_value=prior), patch.object(runtime, "atomic") as write:
            result = runtime.observe(self.cfg, prior)
            self.assertEqual(result["metrics"]["telemetry_known"], 0)
            self.assertEqual(result["metrics"]["degraded_latched"], 1)
            self.assertEqual(result["metrics"]["full_inspection_verified"], 0)
            with self.assertRaisesRegex(RuntimeError, "cannot acknowledge unknown"):
                runtime.monitor(self.cfg, acknowledge=True)
            write.assert_not_called()

    def gap_ack_fixture(self):
        previous, _, _ = self.account(None, sample_fixture(100, 100))
        previous, _, _ = self.account(previous, sample_fixture(5100, 100, 11000000000))
        previous, _, _ = self.account(previous, sample_fixture(5200, 10300, 12000000000))
        previous.update(latched=True, reasons=["nfqueue.netlink_dropped"],
                        accounting_status="OBSERVED_NO_GAP", current_sample_valid=True)
        return previous, {"telemetry_known": 1, "degraded_latched": 1, "accounting_gap_history_latched": 1}

    def test_gap_ack_is_audited_without_erasing_peak_or_other_latches(self):
        state, metrics = self.gap_ack_fixture()
        before = json.loads(json.dumps(state["kernel_accounting"]))
        runtime.acknowledge_accounting_gap(state, metrics, "a" * 64, runtime.accounting_claim(state))
        self.assertTrue(state["latched"])
        self.assertEqual(state["reasons"], ["nfqueue.netlink_dropped"])
        self.assertFalse(state["kernel_accounting"]["gap_history_latched"])
        self.assertEqual(state["kernel_accounting"]["gap_history_peak"], 5000)
        self.assertEqual(metrics["degraded_latched"], 1)
        self.assertEqual(state["gap_acknowledgements"][0]["before"], before)
        self.assertEqual(state["gap_acknowledgements"][0]["evidence_sha256"], "a" * 64)
        self.assertIs(type(state["gap_acknowledgements"][0]["monotonic_ns"]), int)
        self.assertIs(type(state["gap_acknowledgements"][0]["unix_ns"]), int)
        state, metrics = self.gap_ack_fixture()
        with patch.object(runtime, "observe", return_value={"state": state, "metrics": metrics}), \
             patch.object(runtime, "previous_state", return_value=state), patch.object(runtime, "atomic") as write:
            result = runtime.monitor(self.cfg, accounting_gap_evidence="b" * 64,
                                     accounting_gap_expected=runtime.accounting_claim(state))
        saved = json.loads(write.call_args_list[0].args[1])
        self.assertEqual(saved["gap_acknowledgements"][0]["evidence_sha256"], "b" * 64)
        self.assertFalse(saved["kernel_accounting"]["gap_history_latched"])
        self.assertTrue(saved["latched"])
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        with self.observation_patches(data):
            following = runtime.observe(self.cfg, saved)
        self.assertEqual(following["state"]["gap_acknowledgements"], saved["gap_acknowledgements"])

    def test_gap_ack_rejects_incomplete_sample_missing_evidence_and_audit_overflow(self):
        for case in ("unknown", "no_history", "invalid_evidence", "audit_full"):
            state, metrics = self.gap_ack_fixture()
            evidence = "a" * 64
            if case == "unknown": state["current_sample_valid"] = False
            if case == "no_history": state["kernel_accounting"]["gap_history_latched"] = False
            if case == "invalid_evidence": evidence = "not-a-reference"
            if case == "audit_full": state["gap_acknowledgements"] = [{}] * 32
            before = json.dumps([state, metrics], sort_keys=True)
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                runtime.acknowledge_accounting_gap(state, metrics, evidence, runtime.accounting_claim(state))
            self.assertEqual(before, json.dumps([state, metrics], sort_keys=True))

    def test_persistent_gap_can_be_audited_without_restart_or_rewriting_past_quality(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        prior = None
        for sample in (sample_fixture(100, 100), sample_fixture(5100, 100, 11000000000),
                       sample_fixture(5200, 200, 12000000000)):
            with self.observation_patches(data), patch.object(runtime, "kernel_sample", return_value=sample):
                result = runtime.observe(self.cfg, prior)
                prior = result["state"]
        self.assertEqual(result["metrics"]["telemetry_known"], 0)
        self.assertEqual(prior["kernel_accounting"]["unexplained_gap"], 5000)
        runtime.acknowledge_accounting_gap(prior, result["metrics"], "d" * 64, runtime.accounting_claim(prior))
        self.assertEqual(result["metrics"]["telemetry_known"], 0)
        self.assertEqual(prior["gap_acknowledgements"][0]["before"]["unexplained_gap"], 5000)
        with self.observation_patches(data), patch.object(runtime, "kernel_sample",
                return_value=sample_fixture(5300, 300, 13000000000)):
            following = runtime.observe(self.cfg, prior)
        self.assertEqual(following["metrics"]["telemetry_known"], 1)
        self.assertEqual(following["metrics"]["degraded_latched"], 0)
        self.assertEqual(following["state"]["kernel_accounting"]["gap_history_peak"], 5000)

    def test_gap_ack_compares_reviewed_history_and_rejects_unreviewed_growth(self):
        state, metrics = self.gap_ack_fixture()
        reviewed = runtime.accounting_claim(state)
        state["kernel_accounting"].update(unexplained_gap=50000, gap_history_peak=50000)
        before = json.dumps(state, sort_keys=True)
        with self.assertRaisesRegex(RuntimeError, "history changed"):
            runtime.acknowledge_accounting_gap(state, metrics, "e" * 64, reviewed)
        self.assertEqual(json.dumps(state, sort_keys=True), before)

    def test_unknown_publication_survives_invalid_state_and_preserves_original_error(self):
        from contextlib import nullcontext
        for prior in (OSError("unreadable"), {"latched": False, "kernel_accounting": "invalid"}):
            with patch.object(runtime, "locked", return_value=nullcontext()), \
                 patch.object(runtime, "previous_state", side_effect=prior if isinstance(prior, Exception) else None,
                              return_value=prior), patch.object(runtime, "publish_metrics") as publish:
                with self.assertRaisesRegex(RuntimeError, "original failure"):
                    with runtime.monitored_lock(self.cfg, True):
                        raise RuntimeError("original failure")
                self.assertEqual(publish.call_args.args[1]["telemetry_known"], 0)
                self.assertEqual(publish.call_args.args[1]["degraded_latched"], 1)

    def test_normal_ack_cannot_clear_accounting_gap_history(self):
        state, metrics = self.gap_ack_fixture()
        with patch.object(runtime, "observe", return_value={"state": state, "metrics": metrics}), \
             patch.object(runtime, "previous_state", return_value=state), patch.object(runtime, "atomic"):
            result = runtime.monitor(self.cfg, acknowledge=True)
        self.assertFalse(result["state"]["latched"])
        self.assertTrue(result["state"]["kernel_accounting"]["gap_history_latched"])
        self.assertEqual(result["metrics"]["degraded_latched"], 1)

    def test_closed_unrelated_fd_is_skipped_but_permission_failure_is_unknown(self):
        def read(path, *args, **kwargs):
            if str(path).endswith("nfnetlink_queue"):
                return "100 200 0 2 65531 0 0 42 1\n"
            return "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0 12 200 0 0 0 0 0 7 300\n"
        for error in (FileNotFoundError(), PermissionError()):
            with patch.object(runtime.Path, "read_text", read), \
                 patch.object(runtime.Path, "iterdir", return_value=iter([Path('/proc/101/fd/8'), Path('/proc/101/fd/9')])), \
                 patch.object(runtime.os, "readlink", side_effect=[error, 'socket:[300]']):
                if isinstance(error, PermissionError):
                    with self.assertRaises(PermissionError): runtime.queue(self.cfg, 101)
                else:
                    self.assertEqual(runtime.queue(self.cfg, 101)["inode"], 300)

    def test_netlink_loss_latches_with_equal_nft_and_sequence_counts(self):
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        q = queue_fixture()
        with self.observation_patches(data, q):
            prior = runtime.observe(self.cfg)["state"]
            q["netlink_dropped"] = 1
            result = runtime.observe(self.cfg, prior)
            self.assertEqual(result["metrics"]["degraded_latched"], 1)
            self.assertIn("nfqueue.netlink_dropped", result["state"]["reasons"])

    def test_kernel_sample_rejects_sensor_socket_and_clock_changes(self):
        current = {"pid": 101, "start_ticks": 50, "boot_id": "test"}
        for change in ("sensor", "socket", "slow"):
            after = queue_fixture()
            if change == "socket": after["inode"] += 1
            with self.subTest(change=change), \
                 patch.object(runtime, "queue", side_effect=[queue_fixture(), after]), \
                 patch.object(runtime, "table", return_value=nft_document(self.cfg)), \
                 patch.object(runtime, "owned"), \
                 patch.object(runtime, "sensor", return_value={**current, "start_ticks": 51}
                              if change == "sensor" else current), \
                 patch.object(runtime.time, "monotonic_ns", side_effect=[0, 1000000001 if change == "slow" else 1]):
                with self.assertRaises(RuntimeError):
                    runtime.kernel_sample(self.cfg, current)

    def test_queue_authenticates_netlink_inode_instead_of_assuming_portid_is_pid(self):
        def read(path, *args, **kwargs):
            if str(path).endswith("nfnetlink_queue"):
                return "100 200 0 2 65531 0 0 42 1\n"
            return "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0 12 200 0 0 0 0 0 7 300\n"
        with patch.object(runtime.Path, "read_text", read), \
             patch.object(runtime.Path, "iterdir", return_value=iter([Path("/proc/101/fd/3")])), \
             patch.object(runtime.os, "readlink", return_value="socket:[300]"):
            q = runtime.queue(self.cfg, 101)
            self.assertEqual((q["portid"], q["netlink_dropped"], q["id_sequence"]), (200, 7, 42))

    @unittest.skipUnless(hasattr(runtime.os, "fchmod"), "POSIX atomic file permissions required")
    def test_monitor_unknown_writes_actual_state_and_string_metric_path(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            state_dir, metrics_dir = Path(directory) / "state", Path(directory) / "metrics"
            state_dir.mkdir()
            metrics_dir.mkdir()
            metrics = metrics_dir / "sensor.prom"
            cfg = {**self.cfg, "state_dir": str(state_dir), "metrics_file": str(metrics)}
            with patch.object(runtime, "secure_path", side_effect=lambda p, **kw: Path(p)), \
                 patch.object(runtime, "sensor", side_effect=RuntimeError("offline")):
                runtime.monitor(cfg)
            self.assertEqual(json.loads((state_dir / "monitor.json").read_text())["error"], "offline")
            self.assertIn('cs_public0_telemetry_known{bridge="public0",queue="100"} 0', metrics.read_text())
            self.assertEqual(metrics.stat().st_mode & 0o777, 0o644)
            self.assertFalse(list(Path(directory).rglob("*.tmp-*")))

    @unittest.skipUnless(hasattr(runtime.os, "fchmod"), "POSIX atomic file permissions required")
    def test_monitor_healthy_and_acknowledge_write_actual_json_and_metrics(self):
        import tempfile
        data = {"decoder.pkts": 2, "uptime": 10, **dict.fromkeys(runtime.LOSS_COUNTERS, 0)}
        with tempfile.TemporaryDirectory() as directory:
            state_dir, metrics_dir = Path(directory) / "state", Path(directory) / "metrics"
            state_dir.mkdir()
            metrics_dir.mkdir()
            metrics = metrics_dir / "sensor.prom"
            cfg = {**self.cfg, "state_dir": str(state_dir), "metrics_file": str(metrics)}
            with self.observation_patches(data), \
                 patch.object(runtime, "secure_path", side_effect=lambda p, **kw: Path(p)):
                runtime.monitor(cfg)
                self.assertIn('cs_public0_telemetry_known{bridge="public0",queue="100"} 1', metrics.read_text())
                data["flow.memcap"] = 2
                runtime.monitor(cfg)
                self.assertTrue(json.loads((state_dir / "monitor.json").read_text())["latched"])
                runtime.monitor(cfg, acknowledge=True)
                saved = json.loads((state_dir / "monitor.json").read_text())
                self.assertFalse(saved["latched"])
                self.assertEqual(saved["counters"]["flow.memcap"], 2)
                self.assertIn('cs_public0_degraded_latched{bridge="public0",queue="100"} 0', metrics.read_text())
                runtime.monitor(cfg)
                self.assertFalse(json.loads((state_dir / "monitor.json").read_text())["latched"])
            self.assertFalse(list(Path(directory).rglob("*.tmp-*")))

    @unittest.skipUnless(hasattr(runtime.os, "fchmod"), "POSIX atomic file permissions required")
    def test_rejected_atomic_create_removes_marker_and_disarm_refuses_racing_table(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            cfg = {**self.cfg, "runtime_dir": directory}
            with patch.object(runtime, "preflight"), patch.object(runtime, "sensor", return_value={"pid": 101}), \
                 patch.object(runtime, "queue"), patch.object(runtime, "counters"), \
                 patch.object(runtime, "table", side_effect=[None, nft_document(cfg)]), \
                 patch.object(runtime, "secure_path", side_effect=lambda p, **kw: Path(p)), \
                 patch.object(runtime, "run", return_value=SimpleNamespace(returncode=1, stderr="File exists")) as execute:
                with self.assertRaisesRegex(RuntimeError, "File exists"):
                    runtime.arm(cfg)
                self.assertFalse((Path(directory) / "owner.json").exists())
                with self.assertRaises(FileNotFoundError):
                    runtime.disarm(cfg)
                execute.assert_called_once()
                self.assertEqual(execute.call_args.kwargs, {"check": False})

    @unittest.skipUnless(hasattr(runtime.os, "fchmod"), "POSIX atomic file permissions required")
    def test_ambiguous_nft_outcomes_retain_the_owner_marker(self):
        import tempfile
        for outcome in (SimpleNamespace(returncode=-9, stderr="killed"),
                        subprocess.TimeoutExpired("nft", 15), OSError("transport failed")):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                cfg = {**self.cfg, "runtime_dir": directory}
                exception = outcome if isinstance(outcome, Exception) else None
                with patch.object(runtime, "preflight"), patch.object(runtime, "sensor", return_value={"pid": 101}), \
                     patch.object(runtime, "queue"), patch.object(runtime, "counters"), \
                     patch.object(runtime, "table", return_value=None), \
                     patch.object(runtime, "secure_path", side_effect=lambda p, **kw: Path(p)), \
                     patch.object(runtime, "run", return_value=outcome, side_effect=exception):
                    with self.assertRaises(type(exception) if exception else RuntimeError):
                        runtime.arm(cfg)
                self.assertEqual(json.loads((Path(directory) / "owner.json").read_text()), runtime.identity(cfg))

if __name__ == "__main__":
    unittest.main()
