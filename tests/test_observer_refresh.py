"""Local root filesystem and injected-manager transaction regressions."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("refresh", Path(__file__).parents[1] / "runtime/observer_refresh.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "root-only real safe-file tests")
class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="observer-refresh-", dir="/root")
        self.root = Path(self.tmp.name)
        helper = self.root / "observer_refresh.py"
        helper.write_bytes(Path(m.__file__).read_bytes())
        helper.chmod(0o700)
        self.helper_patch = patch.object(m, "__file__", str(helper))
        self.helper_patch.start()
        self.observer = self.root / "observer"
        self.candidate = self.root / "candidate"
        self.verifier = self.root / "verifier"
        self.release = self.root / "release.json"
        self.profile = self.root / "profile.json"
        self.old = b"old observer\n"
        self.new = b"print('candidate')\n"
        for p, raw in [(self.observer,self.old),(self.candidate,self.new),(self.verifier,b"verify\n")]:
            p.write_bytes(raw)
            p.chmod(0o700)
        self.metadata = {"schema":"cs-public0-rule-release-v2","immutable":{str(self.observer):m.digest(self.old)},
                         "drop_sids":[2034125],"rules_sha256":"a"*64,"rules_alert":10,"rules_drop":1}
        self.release.write_bytes(m.encoded(self.metadata))
        self.release.chmod(0o600)
        self.config = {"host":"fixture.invalid","unit":"fixture.service","state_dir":str(self.root),
                       "release":str(self.release),"release_sha256":m.digest(self.release.read_bytes()),
                       "observer_paths":{str(self.observer):m.digest(self.old)},
                       "candidate":str(self.candidate),"candidate_sha256":m.digest(self.new),
                       "verifier":str(self.verifier),"verifier_sha256":m.digest(self.verifier.read_bytes()),
                       "binary_sha256":"b"*64,"queue":32201,"rcvbuf_size":16777216,
                       "timer_units":["fixture-monitor.timer","fixture-gso.timer"]}
        self.identity={"MainPID":"123","InvocationID":"c"*32,"ActiveState":"active","SubState":"running","start_ticks":"99"}
        self.calls=[]

    def tearDown(self):
        self.helper_patch.stop()
        self.tmp.cleanup()

    def execute(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["systemctl","is-active"]:
            return "active\n"
        if argv[0] == str(self.observer):
            return json.dumps({"known":True,"enabled":True,"rcvbuf_known":True,"rcvbuf_effective_bytes":33554432})
        return ""

    def prepared(self):
        self.profile.write_bytes(m.encoded(self.config))
        self.profile.chmod(0o600)
        with patch.object(m.socket,"getfqdn",return_value="fixture.invalid"), \
             patch.object(m,"command",side_effect=self.execute), \
             patch.object(m,"binding",return_value=self.identity):
            result=m.prepare(str(self.profile),m.digest(self.profile.read_bytes()))
            path=Path(result["plan"])
            plan=m.load_plan(path,result["sha256"])
            return path,plan

    def run_apply(self,path,plan,command=None,clock=None,binding=None):
        with patch.object(m,"execution_guard"), \
             patch.object(m,"command",side_effect=command or self.execute), \
             patch.object(m,"binding",side_effect=binding or [self.identity,self.identity]), \
             patch.object(m.time,"monotonic",side_effect=clock or [0,1]):
            return m.apply(path,plan)

    def test_success_preserves_process_rules_and_every_other_release_field(self):
        path,plan=self.prepared()
        result=self.run_apply(path,plan)
        self.assertEqual(result["phase"],"COMMITTED")
        self.assertEqual(self.observer.read_bytes(),self.new)
        new=json.loads(self.release.read_bytes())
        original=copy.deepcopy(self.metadata)
        original["immutable"][str(self.observer)]=m.digest(self.new)
        self.assertEqual(new,original)
        self.assertEqual(m.rollback(path,plan),{"phase":"COMMITTED","action":"NONE"})
        self.assertFalse(any("fixture.service" in c and c[:2] in
                             (["systemctl","start"],["systemctl","stop"]) for c in self.calls))

    def test_foreign_observer_is_untouched_and_no_services_are_stopped(self):
        path,plan=self.prepared();self.calls=[]
        self.observer.write_bytes(b"foreign")
        with self.assertRaisesRegex(RuntimeError,"foreign"):
            self.run_apply(path,plan)
        self.assertEqual(self.observer.read_bytes(),b"foreign")
        self.assertEqual(self.calls,[])

    def test_changed_verifier_is_not_executed_and_targets_are_untouched(self):
        path,plan=self.prepared();self.calls=[]
        self.verifier.write_bytes(b"foreign verifier")
        with self.assertRaisesRegex(RuntimeError,"verifier differs"):
            self.run_apply(path,plan)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.observer.read_bytes(),self.old)
        self.assertEqual(json.loads(path.with_name("state.json").read_bytes())["phase"],"PREPARED")

    def test_failed_verifier_restores_exact_old_files(self):
        path,plan=self.prepared()
        old_release=self.release.read_bytes()
        failure=[False]
        def execute(argv):
            if argv[0]==str(self.verifier) and self.observer.read_bytes()==self.new and not failure[0]:
                failure[0]=True
                raise RuntimeError("verify failed")
            return self.execute(argv)
        with self.assertRaisesRegex(RuntimeError,"verify failed"):
            self.run_apply(path,plan,command=execute)
        self.assertEqual(self.observer.read_bytes(),self.old)
        self.assertEqual(self.release.read_bytes(),old_release)
        self.assertEqual(json.loads(path.with_name("state.json").read_bytes())["phase"],"ROLLED_BACK")

    def test_keyboard_interrupt_after_partial_installation_is_rolled_back(self):
        path,plan=self.prepared()
        original=m.replace;seen=[False]
        def interrupted(target,*args):
            if str(target)==str(self.release) and not seen[0]:
                seen[0]=True
                raise KeyboardInterrupt()
            return original(target,*args)
        with patch.object(m,"replace",side_effect=interrupted),self.assertRaises(KeyboardInterrupt):
            self.run_apply(path,plan)
        self.assertEqual(self.observer.read_bytes(),self.old)
        self.assertEqual(json.loads(self.release.read_bytes()),self.metadata)

    def test_exec_stop_post_recovers_an_interrupted_applying_transaction(self):
        path,plan=self.prepared()
        m.state(path,"APPLYING")
        row=plan["images"][str(self.observer)]
        m.replace(self.observer,bytes.fromhex(row["new"]),{m.digest(self.old)},0o700)
        with patch.object(m,"command",side_effect=self.execute):
            result=m.rollback(path,plan)
        self.assertEqual(result["phase"],"ROLLED_BACK")
        self.assertEqual(self.observer.read_bytes(),self.old)
        self.assertEqual(m.rollback(path,plan),{"phase":"ROLLED_BACK","action":"NONE"})

    def test_changed_process_or_late_callback_cannot_commit(self):
        for kind in ("epoch","late"):
            path,plan=self.prepared()
            identities=[self.identity,dict(self.identity,InvocationID="d"*32)] if kind=="epoch" else None
            with self.subTest(kind=kind),self.assertRaisesRegex(RuntimeError,"changed|deadline"):
                self.run_apply(path,plan,binding=identities,clock=[0,80] if kind=="late" else None)
            self.assertEqual(self.observer.read_bytes(),self.old)

    def test_unpinned_existing_observer_does_not_expand_immutable_scope(self):
        self.metadata["immutable"]={}
        self.release.write_bytes(m.encoded(self.metadata))
        self.config["release_sha256"]=m.digest(self.release.read_bytes())
        path,plan=self.prepared();before=self.release.read_bytes()
        self.run_apply(path,plan)
        self.assertEqual(self.release.read_bytes(),before)

    def test_nondefault_group_and_exact_mode_survive_umask_and_rollback(self):
        os.chown(self.observer,0,65534);self.observer.chmod(0o750)
        os.chown(self.release,0,65534);self.release.chmod(0o640)
        path,plan=self.prepared()
        previous=os.umask(0o077)
        try:
            self.run_apply(path,plan)
            for target,mode in [(self.observer,0o750),(self.release,0o640)]:
                self.assertEqual(target.stat().st_gid,65534)
                self.assertEqual(target.stat().st_mode&0o777,mode)
            m.state(path,"APPLYING")
            with patch.object(m,"command",side_effect=self.execute):m.rollback(path,plan)
            self.assertEqual(self.observer.read_bytes(),self.old)
            for target,mode in [(self.observer,0o750),(self.release,0o640)]:
                self.assertEqual(target.stat().st_gid,65534)
                self.assertEqual(target.stat().st_mode&0o777,mode)
        finally:os.umask(previous)

    def test_recovery_accepts_changed_boot_but_apply_refuses_it(self):
        path,plan=self.prepared()
        plan["boot"]="different-boot"
        path.write_bytes(m.encoded(plan))
        pin=m.digest(path.read_bytes())
        with patch.object(m.socket,"getfqdn",return_value="fixture.invalid"):
            with self.assertRaisesRegex(RuntimeError,"boot differs"):m.load_plan(path,pin)
            recovery=m.load_plan(path,pin,recovery=True)
        m.state(path,"APPLYING")
        m.install(recovery,"new")
        with patch.object(m,"command",side_effect=self.execute):m.rollback(path,recovery)
        self.assertEqual(self.observer.read_bytes(),self.old)
        self.assertEqual(json.loads(path.with_name("state.json").read_bytes())["phase"],"ROLLED_BACK")

    def test_timer_stopped_after_prepare_prevents_mutation(self):
        path,plan=self.prepared();self.calls=[]
        def stopped(argv):
            if argv[:2]==["systemctl","is-active"]:return "inactive"
            return self.execute(argv)
        with self.assertRaisesRegex(RuntimeError,"timer inactive"):self.run_apply(path,plan,command=stopped)
        self.assertEqual(self.observer.read_bytes(),self.old)
        self.assertEqual(json.loads(path.with_name("state.json").read_bytes())["phase"],"PREPARED")
        self.assertFalse(any(c[:2] in (["systemctl","stop"],["systemctl","start"]) for c in self.calls))

    def test_recovery_waits_for_real_shared_lock_then_restores_images(self):
        path,plan=self.prepared();m.state(path,"APPLYING");m.install(plan,"new")
        lock=self.root/"lock";lock.write_bytes(b"")
        first=os.open(lock,os.O_RDWR);second=os.open(lock,os.O_RDWR)
        m.fcntl.flock(first,m.fcntl.LOCK_EX|m.fcntl.LOCK_NB)
        def release():
            time.sleep(0.1)
            m.fcntl.flock(first,m.fcntl.LOCK_UN)
        thread=threading.Thread(target=release);thread.start()
        try:
            started=time.monotonic();m.activation_lock(second,recovery=True)
            self.assertGreaterEqual(time.monotonic()-started,0.05)
            with patch.object(m,"command",side_effect=self.execute):
                self.assertEqual(m.rollback(path,plan)["phase"],"ROLLED_BACK")
            self.assertEqual(self.observer.read_bytes(),self.old)
        finally:thread.join();os.close(second);os.close(first)

    def test_apply_lock_is_immediate_and_recovery_has_bounded_wait(self):
        lock=self.root/"lock";lock.write_bytes(b"")
        first=os.open(lock,os.O_RDWR);second=os.open(lock,os.O_RDWR)
        m.fcntl.flock(first,m.fcntl.LOCK_EX|m.fcntl.LOCK_NB)
        try:
            with self.assertRaises(BlockingIOError):m.activation_lock(second,recovery=False)
            with patch.object(m.time,"monotonic",side_effect=[0,11]),self.assertRaisesRegex(RuntimeError,"remained busy"):
                m.activation_lock(second,recovery=True)
        finally:os.close(second);os.close(first)

    def test_restored_monitors_resume_even_when_verifier_pin_changed(self):
        path,plan=self.prepared();m.state(path,"APPLYING");m.install(plan,"new")
        self.verifier.write_bytes(b"foreign verifier");self.calls=[]
        with patch.object(m,"command",side_effect=self.execute),self.assertRaisesRegex(RuntimeError,"verifier differs"):
            m.rollback(path,plan)
        self.assertEqual(self.observer.read_bytes(),self.old)
        self.assertTrue(any(c[:2]==["systemctl","start"] for c in self.calls))
        self.assertFalse(any(c[0]==str(self.verifier) for c in self.calls))
        self.assertEqual(json.loads(path.with_name("state.json").read_bytes())["phase"],"APPLYING")

    def test_recovery_sigterm_during_verification_still_resumes_monitors(self):
        path,plan=self.prepared();m.state(path,"APPLYING");m.install(plan,"new")
        self.calls=[]
        def interrupted(argv):
            if argv[0]==str(self.verifier):m.signal.raise_signal(m.signal.SIGTERM)
            return self.execute(argv)
        previous=m.signal.signal(m.signal.SIGTERM,m.recovery_sigterm)
        try:
            with patch.object(m,"command",side_effect=interrupted),self.assertRaises(SystemExit) as caught:
                m.rollback(path,plan)
            self.assertEqual(caught.exception.code,143)
            self.assertEqual(self.observer.read_bytes(),self.old)
            self.assertTrue(any(c[:2]==["systemctl","start"] for c in self.calls))
            self.assertEqual(json.loads(path.with_name("state.json").read_bytes())["phase"],"APPLYING")
        finally:m.signal.signal(m.signal.SIGTERM,previous)

    def test_profile_pins_and_stopped_monitor_refuse_before_prepare_writes(self):
        for fault in ("pin","timer"):
            self.profile.write_bytes(m.encoded(self.config));self.profile.chmod(0o600)
            with patch.object(m.socket,"getfqdn",return_value="fixture.invalid"), \
                 patch.object(m,"command",return_value="inactive"), \
                 patch.object(m,"binding",return_value=self.identity), \
                 self.assertRaisesRegex(RuntimeError,"pin|timer"):
                m.prepare(self.profile,"0"*64 if fault=="pin" else m.digest(self.profile.read_bytes()))

    def test_symlink_hardlink_and_writable_file_are_rejected(self):
        link=self.root/"link";link.symlink_to(self.observer)
        with self.assertRaises(OSError):m.read(link)
        link.unlink();os.link(self.observer,link)
        with self.assertRaisesRegex(RuntimeError,"unsafe file"):m.read(self.observer)
        link.unlink();self.observer.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,"unsafe file"):m.read(self.observer)

    def test_tampered_plan_and_foreign_host_are_rejected(self):
        path,plan=self.prepared()
        with self.assertRaisesRegex(RuntimeError,"plan pin"):
            m.load_plan(path,"0"*64)
        with patch.object(m.socket,"getfqdn",return_value="other.invalid"),self.assertRaisesRegex(RuntimeError,"host"):
            m.load_plan(path,m.digest(path.read_bytes()))

    def test_boolean_queue_and_sensor_in_monitor_scope_are_rejected(self):
        for field,value in [("queue",True),("timer_units",["fixture.timer","fixture-gso.timer"]),
                            ("unit","fixture!service"),("state_dir","/root/../tmp")]:
            bad=copy.deepcopy(self.config);bad[field]=value
            with patch.object(m.socket,"getfqdn",return_value="fixture.invalid"),self.assertRaises(RuntimeError):
                m.check_profile(bad)

    def test_manager_guard_requires_exact_pid_invocation_expiry_and_rollback(self):
        path,plan=self.prepared()
        argv="argv[]=/usr/bin/python3 -B "+plan["helper"]+" rollback --file "+str(path)+" --sha256 "+m.digest(path.read_bytes())+" ;"
        good={"InvocationID":"e"*32,"MainPID":str(os.getpid()),"Type":"exec","RuntimeMaxUSec":"1min 30s",
              "TimeoutStopUSec":"2min",
              "KillMode":"control-group","ExecStopPost":"{ path=/usr/bin/python3 ; "+argv+" ignore_errors=no ; }"}
        for field,value in [(None,None),("MainPID","1"),("Type","oneshot"),("RuntimeMaxUSec","infinity"),
                            ("TimeoutStopUSec","1min"),
                            ("KillMode","process"),("ExecStopPost","/bin/true"),
                            ("ExecStopPost","{ path=/bin/true ; "+argv+" ignore_errors=no ; }"),
                            ("ExecStopPost","{ path=/usr/bin/python3 ; "+argv+" ignore_errors=yes ; }"),
                            ("ExecStopPost","{ "+argv+" } { argv[]=/bin/true ; }"),("InvocationID","f"*32)]:
            props=copy.deepcopy(good)
            if field:props[field]=value
            with patch.dict(os.environ,{"INVOCATION_ID":"e"*32}), \
                 patch.object(m,"command",return_value="\n".join(k+"="+v for k,v in props.items())):
                if field:
                    with self.assertRaisesRegex(RuntimeError,"bounded"):m.execution_guard(path,plan)
                else:m.execution_guard(path,plan)


if __name__=="__main__":
    unittest.main()
