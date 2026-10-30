import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "runtime"))
import suricata_commands as control
from rule_update_journal import RuleFileJournal, digest

TX = "c" * 64
SERVER = r'''
import json,socket,sys,time
path,mode,log=sys.argv[1:4]
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
server.bind(path)
server.listen(1)
connection,_=server.accept()
reader=connection.makefile('rb')
changed=False
with open(log,'w') as events:
 for line in reader:
  request=json.loads(line)
  command=request.get('command','handshake')
  events.write(json.dumps(command)+'\n');events.flush()
  if command=='ruleset-reload-rules':
   changed=True
   if mode=='slow':time.sleep(3)
   if mode=='eof':break
   if mode=='refuse':
    connection.sendall(b'{"return":"NOK","message":"busy"}\n');continue
  message={'handshake':None,'version':'8.0.7 fixture', 'capture-mode':'NFQ',
   'ruleset-stats':[{'id':0,'rules_loaded':(3 if mode=='bad_count' else 2) if changed else 1,
                    'rules_failed':0,'rules_skipped':0}],
   'ruleset-reload-time':[{'id':0,'last_reload':
     '2026-10-24T12:00:01.000001+0000' if changed and mode!='stale' else '2026-10-24T12:00:00.000001+0000'}],
   'ruleset-reload-rules':'done'}.get(command)
  response={'return':'OK'} if command=='handshake' else {'return':'OK','message':message}
  raw=(json.dumps(response)+'\n').encode()
  if command=='version':
   if mode=='duplicate':raw=b'{"return":"OK","return":"NOK"}\n'
   if mode=='invalid':raw=b'{broken}\n'
   if mode=='utf8':raw=b'{"return":"OK","message":"\xff"}\n'
   if mode=='large':raw=b'x'*65537+b'\n'
   if mode=='extra':raw+=raw
  try:
   if mode=='fragment':
    for byte in raw:connection.sendall(bytes([byte]))
   else:connection.sendall(raw)
  except (BrokenPipeError,ConnectionResetError):break
'''


@unittest.skipUnless(sys.platform == "linux", "Linux pidfd/AF_UNIX tests")
class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "command.socket"
        self.log = self.root / "commands.jsonl"
        self.process = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)

    def server(self, mode="ok", extra=()):
        self.process = subprocess.Popen([sys.executable, "-c", SERVER, str(self.path),
            mode, str(self.log), *extra], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while not self.path.exists():
            self.assertIsNone(self.process.poll(), "fixture server exited")
            self.assertLess(time.monotonic(), deadline, "fixture server did not bind")
            time.sleep(0.005)
        return control.process_binding(self.process.pid)

    def commands(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def installed(self):
        target, store = self.root / "assets", self.root / "journal"
        target.mkdir(mode=0o700)
        store.mkdir(mode=0o700)
        (target / "rules").write_bytes(b"old")
        (target / "rules").chmod(0o600)
        journal = RuleFileJournal(target, store)
        journal.prepare(TX, {"rules": b"new"}, {"rules": digest(b"old")}, {"rules": digest(b"new")})
        journal.install(TX)
        return journal, target, store

    def test_construction_has_no_io(self):
        binding = control.process_binding(os.getpid())
        with patch.object(control.os, "pidfd_open", side_effect=AssertionError("IO")), \
             patch.object(control.socket, "socket", side_effect=AssertionError("IO")):
            control.SuricataCommands(self.path, binding)

    def test_actual_peer_process_and_fragmented_protocol(self):
        binding = self.server("fragment")
        with control.SuricataCommands(self.path, binding) as session:
            self.assertEqual(session.query("version"), "8.0.7 fixture")
            self.assertEqual(session.binding, binding)
            self.assertTrue(all(e["finished_ns"] >= e["started_ns"] for e in session.events))
        self.assertEqual(self.commands(), ["handshake", "version"])

    def test_wrong_epoch_is_rejected_before_handshake(self):
        binding = self.server()
        binding["start_ticks"] += 1
        with self.assertRaisesRegex(RuntimeError, "binding changed"):
            with control.SuricataCommands(self.path, binding): pass
        self.assertEqual(self.commands(), [])

    def test_foreign_socket_peer_is_rejected(self):
        self.server()
        binding = control.process_binding(os.getpid())
        with self.assertRaisesRegex(RuntimeError, "foreign command socket peer"):
            with control.SuricataCommands(self.path, binding): pass
        self.assertEqual(self.commands(), [])

    def test_symlink_socket_is_rejected(self):
        binding = self.server()
        alias = self.root / "alias.socket"
        alias.symlink_to(self.path)
        with self.assertRaisesRegex(RuntimeError, "unsafe command socket"):
            with control.SuricataCommands(alias, binding): pass

    def test_replaced_socket_stops_commands_to_the_existing_peer(self):
        binding = self.server()
        with control.SuricataCommands(self.path, binding) as session:
            self.path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
                replacement.bind(str(self.path))
                with self.assertRaisesRegex(RuntimeError, "socket replaced"):
                    session.query("version")
        self.assertEqual(self.commands(), ["handshake"])

    def test_dead_process_cannot_be_replaced_by_pid_reuse(self):
        binding = self.server()
        with control.SuricataCommands(self.path, binding) as session:
            self.process.kill()
            self.process.wait(timeout=5)
            with self.assertRaisesRegex(RuntimeError, "process exited"):
                session.query("version")

    def test_cli_rule_switch_blocks_reload_before_any_mutating_command(self):
        binding = self.server(extra=("-Sfixture.rules",))
        journal, target, _ = self.installed()
        with control.SuricataCommands(self.path, binding) as session:
            with self.assertRaisesRegex(RuntimeError, "reload unavailable with -S/-s"):
                control.reload_installed(journal, TX, session, 1, 2)
        self.assertEqual(journal.status(TX)["state"]["phase"], "INSTALLED")
        self.assertEqual(self.commands(), ["handshake"])
        journal.restore(TX)
        self.assertEqual((target / "rules").read_bytes(), b"old")

    def test_join_to_real_file_journal_commits_only_after_readback(self):
        binding = self.server()
        journal, target, store = self.installed()
        with control.SuricataCommands(self.path, binding) as session:
            result = control.reload_installed(journal, TX, session, 1, 2)
            self.assertTrue(session.reload_attempted)
            with self.assertRaisesRegex(RuntimeError, "already attempted"):
                session.reload_rules()
        self.assertEqual(result["phase"], "COMMITTED")
        self.assertEqual((target / "rules").read_bytes(), b"new")
        self.assertFalse((store / "active.json").exists())
        receipt = json.loads((store / TX / "receipt").read_bytes())
        self.assertEqual(receipt["binding"], binding)
        self.assertEqual(receipt["ruleset"]["rules_loaded"], 2)
        self.assertEqual(self.commands().count("ruleset-reload-rules"), 1)

    def test_invalid_new_count_is_rejected_before_intent_or_commands(self):
        binding = self.server()
        journal, _, _ = self.installed()
        with control.SuricataCommands(self.path, binding) as session:
            for count in (True, 0, -1, "2"):
                with self.assertRaisesRegex(RuntimeError, "positive old/new rule counts"):
                    control.reload_installed(journal, TX, session, 1, count)
        self.assertEqual(journal.status(TX)["state"]["phase"], "INSTALLED")
        self.assertEqual(self.commands(), ["handshake"])

    def test_unknown_reload_never_restores_files_or_retries_command(self):
        for mode in ("eof", "slow", "refuse", "stale", "bad_count"):
            with self.subTest(mode=mode):
                # Each case uses distinct real process/socket/journal ownership.
                with tempfile.TemporaryDirectory(dir=self.root) as case:
                    saved = self.root, self.path, self.log
                    self.root = Path(case)
                    self.path, self.log = self.root / "command.socket", self.root / "commands.jsonl"
                    try:
                        binding = self.server(mode)
                        journal, target, store = self.installed()
                        with control.SuricataCommands(self.path, binding, timeout_ns=1_000_000_000) as session:
                            with self.assertRaises((RuntimeError, TimeoutError)):
                                control.reload_installed(journal, TX, session, 1, 2)
                        self.assertEqual(journal.status(TX)["state"]["phase"], "RELOAD_PENDING")
                        with self.assertRaises(RuntimeError): journal.restore(TX)
                        self.assertEqual((target / "rules").read_bytes(), b"new")
                        self.assertTrue((store / "active.json").exists())
                        self.assertEqual(self.commands().count("ruleset-reload-rules"), 1)
                    finally:
                        self.cleanup()
                        self.process = None
                        self.root, self.path, self.log = saved

    def test_bad_protocol_poisoned_session_cannot_send_reload(self):
        for mode in ("duplicate", "invalid", "utf8", "large", "extra"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory(dir=self.root) as case:
                    saved = self.path, self.log
                    self.path, self.log = Path(case) / "command.socket", Path(case) / "commands.jsonl"
                    try:
                        binding = self.server(mode)
                        with control.SuricataCommands(self.path, binding) as session:
                            with self.assertRaises((RuntimeError, ValueError)):
                                session.query("version")
                            with self.assertRaises(RuntimeError): session.reload_rules()
                        self.assertNotIn("ruleset-reload-rules", self.commands())
                    finally:
                        self.cleanup()
                        self.process = None
                        self.path, self.log = saved

    def test_exact_ruleset_schema_and_unknown_timestamp_are_rejected(self):
        for value in ([{"id": False, "rules_loaded": 2, "rules_failed": 0, "rules_skipped": 0}],
                      [{"id": 0, "rules_loaded": 2, "rules_failed": 0, "rules_skipped": 1}]):
            with self.assertRaises(RuntimeError): control.ruleset(value, 2)
        with self.assertRaises(RuntimeError):
            control.reload_time([{"id": 0, "last_reload": "2026-10-24T12:00:00"}])


class ReloadTimeCompatibilityTests(unittest.TestCase):
    def test_basic_offsets_are_normalized_before_the_python310_parser(self):
        actual_datetime = control.datetime.datetime
        observed = []
        class Python310Datetime(actual_datetime):
            @classmethod
            def fromisoformat(cls, value):
                observed.append(value)
                if value.endswith(('Z', '+0000', '+0530', '-0230')):
                    raise ValueError('basic offsets unsupported before Python 3.11')
                return actual_datetime.fromisoformat(value)
        with patch.object(control.datetime, 'datetime', Python310Datetime):
            for suffix, seconds in [('+0000', 0), ('+0530', 19800), ('-0230', -9000), ('Z', 0)]:
                value = control.reload_time([{'id': 0, 'last_reload': '2026-10-30T12:00:00.000001' + suffix}])
                self.assertEqual(value.utcoffset().total_seconds(), seconds)
                self.assertEqual(value.microsecond, 1)
        self.assertEqual([s[-6:] for s in observed], ['+00:00', '+05:30', '-02:30', '+00:00'])


if __name__ == "__main__":
    unittest.main()
