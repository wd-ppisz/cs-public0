import gzip
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import tempfile
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from cs_public0 import validate_rules_bytes
from prepare_blocking_rules import convert
from rule_release import make_release, manifest_for, validate_release, verify_metadata
import cs_public0 as runtime
import activate_rules as activation

RULES = b'alert tcp any any -> any any (msg:"one"; sid:1; rev:1;)\nalert tcp any any -> any any (msg:"two"; sid:2; rev:1;)\n'


class BlockingPolicyTests(unittest.TestCase):
    def test_only_selected_action_changes(self):
        out = convert(RULES, [2])
        self.assertEqual(out, RULES.replace(b'alert tcp any any -> any any (msg:"two"', b'drop tcp any any -> any any (msg:"two"'))
        self.assertEqual(validate_rules_bytes(out, [2]), 2)
        with self.assertRaises(RuntimeError):
            validate_rules_bytes(out)

    def test_missing_duplicate_and_unapproved_sid_reject(self):
        for raw, sids in [(RULES, [3]), (RULES + RULES, [2]), (RULES, [True]), (RULES, [2, 1]),
                          (RULES, [2, 2]), (RULES, [])]:
            with self.subTest(sids=sids), self.assertRaises(RuntimeError):
                convert(raw, sids)

    def test_fake_sid_in_message_cannot_authorize_drop(self):
        raw = b'drop tcp any any -> any any (msg:"sid:2;"; sid:1; rev:1;)\n'
        with self.assertRaises(RuntimeError):
            validate_rules_bytes(raw, [2])

    def test_reject_pass_bypass_replace(self):
        for raw in [RULES.replace(b"alert", b"pass", 1),
                    RULES.replace(b"rev:1;", b"rev:1; bypass;", 1),
                    RULES.replace(b"rev:1;", b"rev:1; replace:xx;", 1)]:
            with self.assertRaises(RuntimeError):
                convert(raw, [2])

    def test_v1_compatible_and_v2_exact_counts(self):
        names = dict(rules="local.rules", gzip="local.rules.gz", manifest="manifest.json")
        pins = {"/etc/example/config": "a" * 64}
        v1 = make_release(RULES, gzip.compress(RULES), names, pins)
        self.assertEqual(v1["schema"], "cs-public0-rule-release-v1")
        self.assertNotIn("drop_sids", v1)
        raw = convert(RULES, [2])
        v2 = make_release(raw, gzip.compress(raw), names, pins, [2])
        self.assertEqual((v2["rules_alert"], v2["rules_drop"]), (1, 1))
        m = manifest_for({"provider": "kept"}, v2)
        self.assertEqual(m["actions"], {"alert": 1, "drop": 1})
        verify_metadata(m, v2)
        for field in ('rules_alert', 'rules_drop'):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                verify_metadata({**m, field: True}, v2)
        m["drop_sids"] = [1]
        with self.assertRaises(RuntimeError):
            verify_metadata(m, v2)
        v2["rules_drop"] = True
        with self.assertRaises(RuntimeError):
            validate_release(v2)

    def test_policy_cannot_hide_selected_alert_or_duplicate(self):
        for raw in [RULES, convert(RULES, [2]) + RULES.splitlines(keepends=True)[1]]:
            with self.assertRaises(RuntimeError):
                validate_rules_bytes(raw, [2])

    def test_runtime_uses_verified_release_policy_and_rejects_changed_rule_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selected.rules"
            path.write_bytes(convert(RULES, [2]))
            (path.parent / "release.json").write_text("{}")
            release = {"names": {"rules": path.name}, "drop_sids": [2]}
            with patch.object(runtime, "secure_path", return_value=path), \
                    patch("rule_release.verify_release", return_value=release) as verify:
                self.assertEqual(runtime.validate_rules({"rules_file": str(path)}), 2)
                verify.assert_called_once_with(path.parent / "release.json")
                release["names"]["rules"] = "foreign.rules"
                with self.assertRaises(RuntimeError):
                    runtime.validate_rules({"rules_file": str(path)})
            (path.parent / "release.json").unlink()
            with patch.object(runtime, "secure_path", return_value=path), self.assertRaises(RuntimeError):
                runtime.validate_rules({"rules_file": str(path)})

    def test_activation_accepts_only_enabled_unambiguous_gso_override(self):
        plan = {"binding": {"pid": 123, "cli_rule_file": False},
                "cfg": {"binary": "/engine", "suricata_config": "/config.yaml", "queue": 32201},
                "qualification_settings": ["stream.inline=yes"]}
        args = ["/engine", "-c", "/config.yaml", "-q", "32201", "--set", "stream.inline=yes"]
        for extra, accepted in [(["--set", "nfq.gso=yes"], True),
                                (["--set", "nfq.gso=no"], False),
                                (["--set", "nfq.gso=yes", "--set", "nfq.gso=yes"], False)]:
            with self.subTest(extra=extra), patch.object(activation, "bounded_read",
                    return_value=("\0".join(args + extra) + "\0").encode()):
                if accepted:
                    activation.effective_settings(plan)
                else:
                    with self.assertRaises(RuntimeError):
                        activation.effective_settings(plan)

if __name__ == "__main__":
    unittest.main()
