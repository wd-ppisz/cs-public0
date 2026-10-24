import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNTIME = Path(__file__).parents[1] / "runtime"
spec = importlib.util.spec_from_file_location("cs_public0", RUNTIME / "cs_public0.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
with patch.dict(sys.modules, {"cs_public0": runtime}):
    spec = importlib.util.spec_from_file_location("prepare_alert_rules", RUNTIME / "prepare_alert_rules.py")
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)


def rule(action="alert", options='msg:"example"; sid:1000001; rev:1;'):
    return (action + " tcp any any -> any any (" + options + ")\n").encode()


def prepare(raw):
    return candidate.prepare(raw, hashlib.sha256(raw).hexdigest())


class CandidateTests(unittest.TestCase):
    def test_converts_only_supported_enforcement_actions_and_preserves_bytes(self):
        for action in sorted(candidate.CONVERTIBLE):
            raw = b"# drop comment\n\n" + rule(action)
            built, zipped, report = prepare(raw)
            self.assertEqual(built, b"# drop comment\n\n" + rule())
            self.assertEqual(gzip.decompress(zipped), built)
            self.assertEqual(report["source"]["actions"], {action: 1})
            self.assertEqual(report["converted_actions"], 1)
            self.assertEqual(report["candidate"]["alert_rules"], 1)
            self.assertEqual(report["engine_test"], "NOT_PERFORMED")
            self.assertEqual(report["activation"], "NOT_PERFORMED")

    def test_alert_bytes_and_gzip_are_deterministic(self):
        raw = rule(options='msg:"drop replace bypass"; content:"drop"; sid:1;')
        first = prepare(raw)
        self.assertEqual(first, prepare(raw))
        self.assertEqual(first[0], raw)
        self.assertEqual(first[2]["converted_actions"], 0)
        self.assertFalse(first[2]["production_ready"])

    def test_rejects_bypass_replace_also_in_converted_rules(self):
        for action in ("alert", "drop"):
            for forbidden in ('bypass;', 'replace:"x";', 'RePlAcE : "x";'):
                with self.subTest(action=action, forbidden=forbidden), self.assertRaises(RuntimeError):
                    prepare(rule(action, options="sid:1; " + forbidden))

    def test_rejects_unknown_actions_pass_controls_continuations_and_encoding(self):
        for raw in (rule("pass"), rule("log"), rule("Alert"), b" " + rule("drop"),
                    rule().replace(b"\n", b"\r\n"), rule() + b"\\\n", rule() + b"\xff", b"# only comment\n"):
            with self.subTest(raw=raw[:40]), self.assertRaises(RuntimeError):
                prepare(raw)

    def test_same_line_and_file_limits_as_runtime(self):
        with self.assertRaisesRegex(RuntimeError, "line too long"):
            prepare(rule(options='msg:"' + "x" * 4096 + '"; sid:1;'))
        with patch.object(candidate, "MAX_RULES_BYTES", 10), self.assertRaisesRegex(RuntimeError, "too large"):
            prepare(rule())

    def test_requires_exact_canonical_source_pin(self):
        raw = rule()
        for pin in ("0" * 64, hashlib.sha256(raw).hexdigest().upper(), "", "sha256:abc"):
            with self.assertRaises(RuntimeError):
                candidate.prepare(raw, pin)


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "Linux filesystem API required")
class CandidateFilesystemTests(unittest.TestCase):
    def test_pinned_snapshot_rejects_changed_and_symlink_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.rules"
            raw = rule("drop")
            path.write_bytes(raw)
            pin = hashlib.sha256(raw).hexdigest()
            self.assertEqual(candidate.pinned_snapshot(path, pin), raw)
            path.write_bytes(rule())
            with self.assertRaises(RuntimeError):
                candidate.pinned_snapshot(path, pin)
            link = Path(tmp) / "link.rules"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                candidate.pinned_snapshot(link, pin)

    def test_source_mutation_during_read_rejected(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.rules"
            raw = rule()
            path.write_bytes(raw)
            before = path.stat()
            fields = ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            after = SimpleNamespace(**{key: getattr(before, key) for key in fields})
            after.st_mtime_ns += 1
            with patch.object(candidate.os, "fstat", side_effect=[before, after]), self.assertRaises(RuntimeError):
                candidate.pinned_snapshot(path, hashlib.sha256(raw).hexdigest())

    def test_new_private_directory_exact_artifacts_and_existing_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "candidate"
            values = prepare(rule("reject"))
            candidate.write_candidate(directory, *values)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            for path in directory.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((directory / "candidate.rules").read_bytes(), values[0])
            self.assertEqual(json.loads((directory / "manifest.json").read_text()), values[2])
            with self.assertRaises(FileExistsError):
                candidate.write_candidate(directory, *prepare(rule()))
            self.assertEqual((directory / "candidate.rules").read_bytes(), values[0])

    def test_partial_write_retained_without_completion_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "candidate"
            with patch.object(candidate.os, "fsync", side_effect=OSError("fixture disk error")), \
                    self.assertRaises(OSError):
                candidate.write_candidate(directory, *prepare(rule()))
            self.assertTrue(directory.is_dir())
            self.assertFalse((directory / "manifest.json").exists())
            with self.assertRaises(FileExistsError):
                candidate.write_candidate(directory, *prepare(rule()))

    def test_cli_without_output_directory_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.rules"
            raw = rule("drop")
            path.write_bytes(raw)
            result = subprocess.run([sys.executable, str(RUNTIME / "prepare_alert_rules.py"), str(path),
                                     "--source-sha256", hashlib.sha256(raw).hexdigest()],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)["converted_actions"], 1)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["feed.rules"])
            self.assertEqual(path.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
