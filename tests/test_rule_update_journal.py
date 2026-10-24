import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("rule_update_journal",
    Path(__file__).parents[1] / "runtime/rule_update_journal.py")
journal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journal)
TX = "a" * 64
NEXT = "b" * 64


@unittest.skipUnless(sys.platform == "linux", "Linux directory-fd/filesystem tests")
class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = self.root / "installation"
        self.store = self.root / "journal"
        self.target.mkdir(mode=0o750)
        self.store.mkdir(mode=0o700)
        self.old = {"a.rules": b"old rules\n", "b.manifest": b'{"old":true}\n'}
        self.new = {"a.rules": b"new rules\n", "b.manifest": b'{"new":true}\n'}
        for name, raw in self.old.items():
            (self.target / name).write_bytes(raw)
            (self.target / name).chmod(0o644)
        self.j = journal.RuleFileJournal(self.target, self.store)

    def prepare(self, transaction=TX, old=None, new=None):
        old, new = self.old if old is None else old, self.new if new is None else new
        return self.j.prepare(transaction, new, {n: journal.digest(v) for n, v in old.items()},
                              {n: journal.digest(v) for n, v in new.items()})

    def files(self):
        return {n: (self.target / n).read_bytes() for n in self.old}

    def phase(self):
        return self.j.status(TX)["state"]["phase"]

    def crash(self, function, signal_number=None):
        pid = os.fork()
        if pid == 0:
            try:
                function()
            except BaseException:
                os._exit(92)
            os._exit(93)
        _, status = os.waitpid(pid, 0)
        if signal_number is None:
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 91)
        else:
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status), signal_number)

    def test_construction_does_not_open_files(self):
        with patch.object(journal.os, "open", side_effect=AssertionError("unexpected IO")):
            journal.RuleFileJournal(self.target, self.store)

    def test_prepare_is_durable_private_and_leaves_targets_old(self):
        self.assertEqual(self.prepare()["phase"], "PREPARED")
        self.assertEqual(self.files(), self.old)
        self.assertEqual(self.phase(), "PREPARED")
        for path in (self.store / TX).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.store / TX).stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(RuntimeError, "active transaction"):
            self.prepare(NEXT)

    def test_install_and_restore_complete_real_files(self):
        self.prepare()
        self.j.install(TX)
        self.assertEqual(self.files(), self.new)
        self.assertEqual(self.phase(), "INSTALLED")
        self.j.install(TX)
        self.j.restore(TX)
        self.assertEqual(self.files(), self.old)
        self.assertFalse((self.store / "active.json").exists())
        state = json.loads((self.store / TX / "state.json").read_bytes())
        self.assertEqual(state["phase"], "RESTORED")
        with self.assertRaisesRegex(RuntimeError, "already used"):
            self.prepare()

    def test_crash_after_first_rename_restores_mixed_file_set(self):
        self.prepare()
        original = self.j._replace
        def interrupted():
            def replace(*args):
                original(*args)
                os.kill(os.getpid(), signal.SIGKILL)
            self.j._replace = replace
            self.j.install(TX)
        self.crash(interrupted, signal.SIGKILL)
        self.assertEqual(self.phase(), "INSTALLING")
        self.assertEqual(self.files(), {"a.rules": self.new["a.rules"], "b.manifest": self.old["b.manifest"]})
        journal.RuleFileJournal(self.target, self.store).restore(TX)
        self.assertEqual(self.files(), self.old)

    def test_interrupted_install_can_resume_before_reload_intent(self):
        self.prepare()
        original = self.j._replace
        def interrupted():
            def replace(*args):
                original(*args)
                os._exit(91)
            self.j._replace = replace
            self.j.install(TX)
        self.crash(interrupted)
        self.j.install(TX)
        self.assertEqual((self.phase(), self.files()), ("INSTALLED", self.new))

    def test_interrupted_restore_blocks_install_and_can_resume_restore(self):
        self.prepare()
        self.j.install(TX)
        original = self.j._replace
        def interrupted():
            def replace(*args):
                original(*args)
                os._exit(91)
            self.j._replace = replace
            self.j.restore(TX)
        self.crash(interrupted)
        self.assertEqual(self.phase(), "RESTORING")
        with self.assertRaisesRegex(RuntimeError, "installation is blocked"):
            self.j.install(TX)
        self.j.restore(TX)
        self.assertEqual(self.files(), self.old)

    def test_crash_during_prepare_leaves_claim_and_can_be_abandoned(self):
        write = journal.write_file
        def interrupted():
            def write_then_exit(fd, name, *args, **kwargs):
                write(fd, name, *args, **kwargs)
                if name == "0-new": os._exit(91)
            with patch.object(journal, "write_file", side_effect=write_then_exit):
                self.prepare()
        self.crash(interrupted)
        self.assertEqual(self.files(), self.old)
        self.assertFalse((self.store / TX / "state.json").exists())
        with self.assertRaisesRegex(RuntimeError, "active transaction"):
            self.prepare(NEXT)
        self.j.abandon_preparation(TX)
        self.assertFalse((self.store / "active.json").exists())
        self.assertTrue((self.store / TX / "0-new").exists())

    def test_crash_before_transaction_directory_does_not_touch_targets(self):
        mkdir = journal.os.mkdir
        def interrupted():
            def mkdir_then_exit(name, *args, **kwargs):
                if name == TX: os._exit(91)
                return mkdir(name, *args, **kwargs)
            with patch.object(journal.os, "mkdir", side_effect=mkdir_then_exit): self.prepare()
        self.crash(interrupted)
        self.assertFalse((self.store / TX).exists())
        self.j.abandon_preparation(TX)
        self.assertEqual(self.files(), self.old)

    def test_abandon_refuses_prepared_state_and_changed_target(self):
        self.prepare()
        with self.assertRaisesRegex(RuntimeError, "already has a state"):
            self.j.abandon_preparation(TX)
        (self.store / TX / "state.json").unlink()
        (self.target / "a.rules").write_bytes(b"foreign")
        with self.assertRaisesRegex(RuntimeError, "foreign/changed"):
            self.j.abandon_preparation(TX)
        self.assertTrue((self.store / "active.json").exists())

    def test_all_files_preflight_before_first_target_mutation(self):
        self.prepare()
        (self.target / "b.manifest").write_bytes(b"foreign")
        for method in (self.j.install, self.j.restore):
            with self.assertRaisesRegex(RuntimeError, "foreign/changed"):
                method(TX)
        self.assertEqual((self.target / "a.rules").read_bytes(), self.old["a.rules"])
        self.assertEqual((self.target / "b.manifest").read_bytes(), b"foreign")

    def test_corrupt_backup_or_new_image_blocks_before_mutation(self):
        self.prepare()
        for name in ("1-old", "1-new"):
            path = self.store / TX / name
            before = path.read_bytes()
            path.write_bytes(b"corrupt")
            with self.assertRaisesRegex(RuntimeError, "changed transaction image"):
                self.j.install(TX)
            self.assertEqual(self.files(), self.old)
            path.write_bytes(before)

    def test_reload_pending_is_persistent_and_never_automatically_rolled_back(self):
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        self.assertEqual(self.phase(), "RELOAD_PENDING")
        for method in (self.j.install, self.j.restore, self.j.mark_reload_pending):
            with self.assertRaises(RuntimeError): method(TX)
        with self.assertRaisesRegex(RuntimeError, "active transaction"):
            self.prepare(NEXT)
        self.assertEqual(self.files(), self.new)
        self.assertTrue((self.store / "active.json").exists())

    def test_commit_records_caller_receipt_without_claiming_service_attestation(self):
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        receipt = b'{"fixture":"caller decision only, not a runtime attestation"}\n'
        state = self.j.record_reload_receipt(TX, receipt)
        self.assertEqual(state["phase"], "COMMITTED")
        self.assertEqual(state["receipt"], {"sha256": journal.digest(receipt), "bytes": len(receipt)})
        self.assertEqual((self.store / TX / "receipt").read_bytes(), receipt)
        self.assertFalse((self.store / "active.json").exists())
        self.prepare(NEXT, old=self.new, new=self.old)
        with self.assertRaisesRegex(RuntimeError, "wrong transaction"):
            self.j.retire_terminal(TX)
        self.assertTrue((self.store / "active.json").exists())

    def test_crash_after_commit_marker_can_retire_without_reloading(self):
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        def interrupted():
            self.j._clear = lambda *args: os._exit(91)
            self.j.record_reload_receipt(TX, b"caller fixture")
        self.crash(interrupted)
        self.assertEqual(self.phase(), "COMMITTED")
        self.j.retire_terminal(TX)
        self.assertEqual(self.files(), self.new)
        self.assertFalse((self.store / "active.json").exists())

    def test_receipt_retry_after_state_write_failure_never_reexecutes_reload(self):
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        with patch.object(self.j, "_save", side_effect=OSError("disk error")), self.assertRaises(OSError):
            self.j.record_reload_receipt(TX, b"same receipt")
        with self.assertRaisesRegex(RuntimeError, "different caller receipt"):
            self.j.record_reload_receipt(TX, b"different")
        self.j.record_reload_receipt(TX, b"same receipt")
        self.assertFalse((self.store / "active.json").exists())

    def test_terminal_target_or_receipt_tamper_never_releases_claim(self):
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        with patch.object(self.j, "_clear", side_effect=OSError("crash")), self.assertRaises(OSError):
            self.j.record_reload_receipt(TX, b"receipt")
        (self.store / TX / "receipt").write_bytes(b"wrong")
        with self.assertRaisesRegex(RuntimeError, "caller receipt"):
            self.j.retire_terminal(TX)
        self.assertTrue((self.store / "active.json").exists())

    def test_identity_change_and_wrong_transaction_are_rejected(self):
        self.prepare()
        with self.assertRaisesRegex(RuntimeError, "wrong transaction"):
            self.j.restore(NEXT)
        self.target.rename(self.root / "original-installation")
        self.target.mkdir(mode=0o750)
        for name, raw in self.old.items(): (self.target / name).write_bytes(raw)
        with self.assertRaisesRegex(RuntimeError, "directory identity changed"):
            self.j.restore(TX)
        self.assertEqual(self.files(), self.old)

    def test_symlinks_hardlinks_and_writable_directories_are_refused(self):
        path = self.target / "a.rules"
        path.unlink()
        path.symlink_to(self.target / "b.manifest")
        with self.assertRaises(OSError): self.prepare()
        path.unlink()
        os.link(self.target / "b.manifest", path)
        with self.assertRaisesRegex(RuntimeError, "ownership/type/links"): self.prepare()
        path.unlink()
        path.write_bytes(self.old["a.rules"])
        self.target.chmod(0o770)
        with self.assertRaisesRegex(RuntimeError, "writable directory"): self.prepare()
        self.target.chmod(0o750)
        self.store.chmod(0o750)
        with self.assertRaisesRegex(RuntimeError, "must be private"): self.prepare()
        self.assertFalse((self.store / "active.json").exists())

    def test_corrupt_json_and_typed_metadata_do_not_authorize_mutations(self):
        self.prepare()
        active = self.store / "active.json"
        original = active.read_bytes()
        active.write_bytes(b'{"schema":1,"schema":2}')
        with self.assertRaisesRegex(RuntimeError, "duplicate journal key"): self.j.install(TX)
        plan = json.loads(original)
        plan["assets"][0]["mode"] = True
        active.write_text(json.dumps(plan))
        with self.assertRaisesRegex(RuntimeError, "asset metadata"): self.j.restore(TX)
        self.assertEqual(self.files(), self.old)

    def test_explicit_pins_names_file_and_receipt_bounds(self):
        with self.assertRaises(RuntimeError):
            self.j.prepare(TX, {"../escape": b"x"}, {"../escape":"0"*64}, {"../escape":journal.digest(b"x")})
        with self.assertRaisesRegex(RuntimeError, "old image SHA256"):
            self.j.prepare(TX, self.new, dict.fromkeys(self.old, "0"*64),
                           {n: journal.digest(v) for n,v in self.new.items()})
        with patch.object(journal, "MAX_FILE", 2), self.assertRaisesRegex(RuntimeError, "new image"):
            self.prepare()
        with self.assertRaisesRegex(RuntimeError, "update set is unchanged"):
            self.prepare(new=self.old)
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        for receipt in (b"", "string", b"x" * (journal.MAX_RECEIPT+1)):
            with self.assertRaisesRegex(RuntimeError, "caller receipt"):
                self.j.record_reload_receipt(TX, receipt)

    def test_abandoned_preparation_can_retire_after_clear_crash(self):
        self.prepare()
        (self.store / TX / "state.json").unlink()
        def interrupted():
            self.j._clear = lambda *args: os._exit(91)
            self.j.abandon_preparation(TX)
        self.crash(interrupted)
        self.assertEqual(self.phase(), "ABANDONED_PREPARATION")
        self.j.retire_terminal(TX)
        self.assertEqual(self.files(), self.old)
        self.assertFalse((self.store / "active.json").exists())

    def test_backup_integrity_is_checked_before_reload_intent(self):
        self.prepare()
        self.j.install(TX)
        (self.store / TX / "0-old").write_bytes(b"corrupt")
        with self.assertRaisesRegex(RuntimeError, "changed transaction image"):
            self.j.mark_reload_pending(TX)
        self.assertEqual(self.phase(), "INSTALLED")

    def test_target_readback_is_required_before_installed_state(self):
        self.prepare()
        replace = self.j._replace
        def change_after_replace(*args):
            replace(*args)
            (self.target / "a.rules").write_bytes(b"foreign")
        with patch.object(self.j, "_replace", side_effect=change_after_replace), \
             self.assertRaisesRegex(RuntimeError, "foreign/changed"):
            self.j.install(TX)
        self.assertEqual(self.phase_without_target_read(), "INSTALLING")

    def phase_without_target_read(self):
        return json.loads((self.store / TX / "state.json").read_bytes())["phase"]

    def test_boolean_receipt_size_is_not_a_valid_terminal_record(self):
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        with patch.object(self.j, "_clear", side_effect=OSError("crash")), self.assertRaises(OSError):
            self.j.record_reload_receipt(TX, b"x")
        path = self.store / TX / "state.json"
        state = json.loads(path.read_bytes())
        state["receipt"]["bytes"] = True
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(RuntimeError, "caller receipt"):
            self.j.retire_terminal(TX)
        self.assertTrue((self.store / "active.json").exists())

    def test_existing_mode_is_preserved_in_install_and_restore(self):
        (self.target / "a.rules").chmod(0o755)
        self.prepare()
        self.j.install(TX)
        self.assertEqual((self.target / "a.rules").stat().st_mode & 0o777, 0o755)
        self.j.restore(TX)
        self.assertEqual((self.target / "a.rules").stat().st_mode & 0o777, 0o755)

    def alternate_gid(self):
        if os.geteuid() == 0:
            return 65534 if os.getegid() != 65534 else 0
        choices = set(os.getgroups()) - {os.getegid()}
        if not choices:
            self.skipTest("requires a second permitted group")
        return min(choices)

    def test_nondefault_group_and_group_read_mode_survive_install_and_restore(self):
        gid = self.alternate_gid()
        path = self.target / "a.rules"
        os.chown(path, -1, gid)
        path.chmod(0o640)
        state = self.prepare()
        self.assertEqual(state["plan"]["assets"][0]["gid"], gid)
        for method in (self.j.install, self.j.restore):
            method(TX)
            self.assertEqual((path.stat().st_gid, path.stat().st_mode & 0o777), (gid, 0o640))

    def test_changed_group_is_foreign_and_chown_failure_does_not_replace_target(self):
        gid = self.alternate_gid()
        path = self.target / "a.rules"
        self.prepare()
        os.chown(path, -1, gid)
        with self.assertRaisesRegex(RuntimeError, "foreign/changed"):
            self.j.install(TX)
        self.assertEqual(self.files(), self.old)
        os.chown(path, -1, os.getegid())
        self.j.restore(TX)
        os.chown(path, -1, gid)
        self.prepare(NEXT)
        with patch.object(journal.os, "fchown", side_effect=PermissionError("group change denied")), \
             self.assertRaises(PermissionError):
            self.j.install(NEXT)
        self.assertEqual(self.files(), self.old)
        self.assertEqual(path.stat().st_gid, gid)

    def test_second_asset_unrestorable_group_is_refused_before_claim(self):
        gid = self.alternate_gid()
        os.chown(self.target / "b.manifest", -1, gid)
        # Real target metadata, with a restricted non-root group policy fixture.
        with patch.object(journal, "permitted_gids", return_value={os.getegid()}), \
             patch.object(journal.os, "fchown", side_effect=AssertionError("must reject before writes")), \
             self.assertRaisesRegex(RuntimeError, "asset group is not restorable"):
            self.prepare()
        self.assertEqual(self.files(), self.old)
        self.assertFalse((self.store / "active.json").exists())
        self.assertFalse((self.store / TX).exists())
        self.assertFalse(any(p.name.startswith(".journal-") for p in self.target.iterdir()))

    def test_nonroot_group_policy_uses_effective_and_supplementary_groups(self):
        with patch.object(journal.os, "geteuid", return_value=1001), \
             patch.object(journal.os, "getegid", return_value=1002), \
             patch.object(journal.os, "getgroups", return_value=[1003, 1004]):
            self.assertEqual(journal.permitted_gids(), {1002, 1003, 1004})

    def kill_before_file_sync(self, filename, action):
        write = journal.write_file
        def interrupted():
            def kill_during_write(fd, name, *args, **kwargs):
                if name == filename:
                    with patch.object(journal.os, "fsync", side_effect=lambda _: os.kill(os.getpid(), signal.SIGKILL)):
                        return write(fd, name, *args, **kwargs)
                return write(fd, name, *args, **kwargs)
            with patch.object(journal, "write_file", side_effect=kill_during_write):
                action()
        self.crash(interrupted, signal.SIGKILL)

    def test_sigkill_inside_initial_state_write_allows_abandon(self):
        self.kill_before_file_sync("state.json", self.prepare)
        self.assertFalse((self.store / TX / "state.json").exists())
        self.assertEqual(self.files(), self.old)
        self.j.abandon_preparation(TX)
        self.assertFalse((self.store / "active.json").exists())

    def test_sigkill_inside_abandon_state_write_can_retry_abandon(self):
        self.prepare()
        (self.store / TX / "state.json").unlink()
        self.kill_before_file_sync("state.json", lambda: self.j.abandon_preparation(TX))
        self.assertFalse((self.store / TX / "state.json").exists())
        self.assertEqual(self.files(), self.old)
        self.j.abandon_preparation(TX)
        self.assertFalse((self.store / "active.json").exists())

    def test_sigkill_inside_receipt_write_can_record_same_verified_caller_decision(self):
        self.prepare()
        self.j.install(TX)
        self.j.mark_reload_pending(TX)
        self.kill_before_file_sync("receipt", lambda: self.j.record_reload_receipt(TX, b"same decision"))
        self.assertEqual(self.phase(), "RELOAD_PENDING")
        self.assertFalse((self.store / TX / "receipt").exists())
        self.j.record_reload_receipt(TX, b"same decision")
        self.assertEqual(self.files(), self.new)
        self.assertFalse((self.store / "active.json").exists())

    def test_competing_process_cannot_take_store_lock(self):
        import fcntl
        fd = os.open(self.store / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def competing():
                try: self.prepare()
                except BlockingIOError: os._exit(91)
            self.crash(competing)
            self.assertFalse((self.store / "active.json").exists())
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
