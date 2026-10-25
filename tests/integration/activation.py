#!/usr/bin/env python3
"""Real four-file activation and process-death tests on a disposable CI VM.

This executable is not a production deployment tool. It creates alert-only
rules, private network namespaces and transient systemd units. No physical
interface or root-namespace firewall is modified. The CI VM is the hard outer
cleanup boundary; ordinary failures also stop every registered unit and child.
"""
import gzip
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time

from netns import Lab, Unavailable, prerequisites, require, run

RUNTIME = Path(__file__).resolve().parents[2] / "runtime"
sys.path.insert(0, str(RUNTIME))
import activate_rules as activation
import cs_public0 as runtime
import rule_release as release
import rule_update_journal as journal
from suricata_commands import process_binding

RULE = b'alert http any any -> any 8080 (msg:"activation old"; http.uri; content:"/old-"; sid:9100101; rev:1;)\n'
NEW = RULE + b'alert http any any -> any 8080 (msg:"activation new"; http.uri; content:"/new-"; sid:9100102; rev:1;)\n'
FILES = {"rules": "local.rules", "gzip": "local.rules.gz", "manifest": "manifest.json"}


def file_set(target):
    return {n: (target / n).read_bytes() for n in (*FILES.values(), "release.json")}


def initialize(target, binary, config):
    target.mkdir(mode=0o700)
    compressed = gzip.compress(RULE, mtime=0)
    (target / "local.rules").write_bytes(RULE)
    (target / "local.rules.gz").write_bytes(compressed)
    pins = {str(p): release.sha(p.read_bytes()) for p in (binary, config)}
    policy = release.make_release(RULE, compressed, FILES, pins)
    (target / "manifest.json").write_bytes(release.json_bytes(release.manifest_for({}, policy)))
    release.initialize(target, FILES, list(pins))


def crash_child(target, store, transaction, images, old, point):
    """The actual filesystem operation finishes before SIGSTOP fault injection."""
    j = journal.RuleFileJournal(target, store)
    j.prepare(transaction, images, old, {n: release.sha(b) for n, b in images.items()})
    if point == "PREPARED":
        os.kill(os.getpid(), signal.SIGSTOP)
    if point == "FIRST_REPLACE":
        original = os.replace

        def replace(source, destination, **kwargs):
            original(source, destination, **kwargs)
            if destination in images:
                os.kill(os.getpid(), signal.SIGSTOP)
        os.replace = replace
    j.install(transaction)
    if point == "INSTALLED":
        os.kill(os.getpid(), signal.SIGSTOP)
    j.mark_reload_pending(transaction)
    os.kill(os.getpid(), signal.SIGSTOP)


def crash_cases(root, binary, config):
    results = []
    for point in ("PREPARED", "FIRST_REPLACE", "INSTALLED", "RELOAD_PENDING"):
        base = root / point.lower()
        base.mkdir(mode=0o700)
        target, store = base / "target", base / "journal"
        store.mkdir(mode=0o700)
        initialize(target, binary, config)
        before = file_set(target)
        _, _, images, old = release.prepare_images(target, NEW, gzip.compress(NEW, mtime=0))
        transaction = secrets.token_hex(32)
        child = multiprocessing.get_context("fork").Process(target=crash_child,
            args=(target, store, transaction, images, old, point))
        child.start()
        try:
            deadline = time.monotonic() + 10
            while True:
                event = os.waitid(os.P_PID, child.pid,
                                  os.WSTOPPED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if event is not None:
                    require(event.si_code == os.CLD_STOPPED and event.si_status == signal.SIGSTOP,
                            "fault child exited before durable boundary")
                    break
                require(time.monotonic() < deadline, "fault child did not reach durable boundary")
                time.sleep(0.01)
            # This is our stopped, unreaped child; its PID cannot be reused.
            os.kill(child.pid, signal.SIGKILL)
            child.join(timeout=5)
            require(child.exitcode == -signal.SIGKILL, "fault child was not actually killed")
        finally:
            if child.is_alive():
                child.kill()
                child.join(timeout=5)
        j = journal.RuleFileJournal(target, store)
        interrupted = j.status(transaction)["state"]
        current = file_set(target)
        changed = [n for n in before if before[n] != current[n]]
        if point == "FIRST_REPLACE":
            require(len(changed) == 1 and interrupted["phase"] == "INSTALLING",
                    "partial install was not observed")
        if point == "RELOAD_PENDING":
            for operation in (j.restore, j.install):
                try:
                    operation(transaction)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("unknown reload allowed automatic restore or reinstall")
            require(j.status(transaction)["state"]["phase"] == "RELOAD_PENDING", "unknown intent was cleared")
            recovery = "REFUSED_UNKNOWN_RELOAD_PRESERVED"
        else:
            restored = j.restore(transaction)
            require(file_set(target) == before, "explicit file recovery differs from all four originals")
            require(release.verify_release(target / "release.json")["rules_alert"] == 1,
                    "recovered startup policy does not verify")
            recovery = restored["phase"]
        results.append({"point": point, "signal": "SIGKILL", "phase": interrupted["phase"],
                        "changed_files_at_crash": changed, "recovery": recovery,
                        "engine_command_sent": False})
    return results


class ActivationLab(Lab):
    def __init__(self, target, state, runtime_dir, token):
        super().__init__(target)
        self.state, self.runtime_dir, self.token = state, runtime_dir, token
        self.units, self.stop_traffic, self.traffic_errors = [], threading.Event(), []
        self.traffic_count = 0
        self.owner = "cs-public0-disposable-qualification-" + token

    def unit(self, unit, argv, *, wait=False, memory="256M", netns=True, lifetime=600):
        state = run(["systemctl", "show", unit, "-p", "LoadState", "-p", "MainPID"]).stdout
        require(set(state.splitlines()) == {"LoadState=not-found", "MainPID=0"}, "occupied unit")
        # Register ownership before a manager call can allocate and lose its reply.
        self.units.append(unit)
        command = ["systemd-run", "--unit=" + unit, "--service-type=exec", "--collect",
                   "--property=Description=" + self.owner, "--property=Restart=no",
                   "--property=RuntimeMaxSec=" + str(lifetime), "--property=TimeoutStopSec=10",
                   "--property=KillMode=control-group", "--property=CPUQuota=100%",
                   "--property=MemoryMax=" + memory, "--property=MemorySwapMax=0",
                   "--property=TasksMax=32"]
        if netns:
            command += ["--property=NetworkNamespacePath=/run/netns/" + self.names["bridge"]]
        if wait:
            command += ["--wait", "--pipe"]
        return run(command + ["--", *argv], check=False, timeout=260 if wait else 15)

    def traffic(self):
        end = time.monotonic() + 300
        while not self.stop_traffic.is_set() and time.monotonic() < end:
            try:
                if not self.http("/progress-" + str(self.traffic_count)):
                    self.traffic_errors.append({"attempt": self.traffic_count, "error": "HTTP_FAILED"})
                    return
            except BaseException as error:
                self.traffic_errors.append({"attempt": self.traffic_count, "error": repr(error)})
                return
            finally:
                self.traffic_count += 1
            self.stop_traffic.wait(0.2)

    def exercise(self):
        config = self.configure()
        config_text = config.read_text().replace(str(self.directory / "suricata.socket"),
                                                 str(self.runtime_dir / "suricata.socket"))
        config.write_text(config_text)
        (self.directory / "local.rules").write_bytes(RULE)
        binary = Path(shutil.which("suricata")).resolve()
        # The runner checkout belongs to its unprivileged user. The provider's
        # immutable files must instead be exact root-owned copies.
        modules = self.state / "runtime"
        modules.mkdir(mode=0o700)
        for source in RUNTIME.glob("*.py"):
            (modules / source.name).write_bytes(source.read_bytes())
        sensor_unit = "cs-public0-sensor-" + self.token + ".service"
        cfg = runtime.validate_config({"bridge": "br-test", "table": "csp0_qual", "queue": 100,
            "runtime_dir": str(self.runtime_dir), "state_dir": str(self.state),
            "metrics_file": str(self.state / "test.prom"), "service": sensor_unit,
            "socket": str(self.runtime_dir / "suricata.socket"), "binary": str(binary),
            "suricata_config": str(config), "rules_file": str(self.directory / "local.rules")})
        self.nft("delete table bridge cs_public0_test\n")
        self.nft(runtime.ruleset(cfg))
        runtime.atomic(self.runtime_dir / "owner.json", json.dumps(runtime.identity(cfg)))
        runtime.owned(cfg)
        sensor = self.unit(sensor_unit, [str(binary), "-c", str(config), "-q", "100",
                                       "--init-errors-fatal", "--set", "stream.inline=yes"])
        require(sensor.returncode == 0, sensor.stderr)
        def ready():
            state = activation.systemd(sensor_unit, ("MainPID", "ActiveState"))
            return state["MainPID"] != "0" and state["ActiveState"] == "active" and Path(cfg["socket"]).exists()
        self.wait(ready, "sensor startup failed", 20)
        cfg_path = self.state / "config.json"
        cfg_path.write_bytes(release.json_bytes(cfg))
        monitor_script = self.state / "monitor.py"
        monitor_script.write_text("import subprocess,sys,time\nwhile True:\n"
            " r=subprocess.run([sys.executable,'-B'," + repr(str(modules / "cs_public0.py")) +
            ", '--config'," + repr(str(cfg_path)) + ",'monitor'],capture_output=True,text=True,timeout=8)\n"
            " print(r.stdout,flush=True); print(r.stderr,file=sys.stderr,flush=True)\n time.sleep(1)\n")
        monitor = self.unit("cs-public0-monitor-" + self.token + ".service",
                            [sys.executable, "-u", str(monitor_script)])
        require(monitor.returncode == 0, monitor.stderr)
        def monitor_ready():
            try:
                return json.loads((self.state / "monitor.json").read_text()).get("current_sample_valid") is True
            except FileNotFoundError:
                return False
        self.wait(monitor_ready, "monitor did not publish a valid observation", 15)
        compressed = gzip.compress(RULE, mtime=0)
        (self.directory / "local.rules.gz").write_bytes(compressed)
        pins = {str(p): release.sha(p.read_bytes()) for p in [binary, config, *modules.glob("*.py")]}
        require(len(pins) <= 20, "explicit immutable source set too large")
        old = release.make_release(RULE, compressed, FILES, pins)
        (self.directory / "manifest.json").write_bytes(release.json_bytes(release.manifest_for({}, old)))
        release.initialize(self.directory, FILES, list(pins))
        store, candidate = self.state / "journal", self.state / "candidate"
        store.mkdir(mode=0o700)
        candidate.mkdir(mode=0o700)
        (candidate / "candidate.rules").write_bytes(NEW)
        (candidate / "candidate.rules.gz").write_bytes(gzip.compress(NEW, mtime=0))
        pid = int(activation.systemd(sensor_unit, ("MainPID",))["MainPID"])
        # Binding and selector must be read in the same real namespace as the controller.
        context_code = ("import sys,json;sys.path.insert(0," + repr(str(modules)) + ");"
            "import activate_rules as a,cs_public0 as r;from suricata_commands import process_binding;"
            "c=json.loads(sys.argv[1]);print(json.dumps({'binding':process_binding(" + str(pid) + "),"
            "'selector_sha256':a.selector_hash(r.table(c))}))")
        context = json.loads(self.inside("bridge", [sys.executable, "-c", context_code, json.dumps(cfg)]).stdout)
        nonce = secrets.token_hex(32)
        plan = {"schema": activation.SCHEMA, "nonce": nonce,
            "controller_unit": "cs-public0-activate-" + nonce[:16] + ".service",
            "target": str(self.directory), "store": str(store), "candidate": str(candidate),
            "candidate_rules": "candidate.rules", "candidate_gzip": "candidate.rules.gz",
            "candidate_rules_sha256": release.sha(NEW),
            "candidate_gzip_sha256": release.sha(gzip.compress(NEW, mtime=0)),
            "expected_old": {n: release.sha(b) for n, b in file_set(self.directory).items()},
            "cfg": {k: cfg[k] for k in ("service", "queue", "table", "bridge", "priority", "socket", "binary",
                                        "suricata_config", "rules_file")},
            "binding": context["binding"],
            "unit": activation.systemd(sensor_unit, ("MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState")),
            "selector_sha256": context["selector_sha256"],
            "qualification_settings": ["stream.inline=yes"], "startup_check": None}
        plan["cfg"].update(chain="forward_ipv4", monitor_state=str(self.state / "monitor.json"))
        raw = release.json_bytes(plan)
        activation.parse_plan(raw)
        plan_path = self.state / "accepted-plan.json"
        plan_path.write_bytes(raw)
        generator = threading.Thread(target=self.traffic)
        generator.start()
        try:
            response = self.unit(plan["controller_unit"], [sys.executable, "-B", str(modules / "activate_rules.py"),
                "--plan", str(plan_path), "--plan-sha256", release.sha(raw)],
                wait=True, memory="2G", lifetime=240)
        finally:
            self.stop_traffic.set()
            generator.join(timeout=6)
        require(not generator.is_alive(), "generator survived stop")
        require(response.returncode == 0, response.stdout + response.stderr)
        result = json.loads(response.stdout)
        require(result["phase"] == "ACTIVATED", "controller did not accept activation")
        require(self.traffic_count > 0 and not self.traffic_errors, "legal traffic failed during activation")
        require(release.verify_release(self.directory / "release.json")["rules_alert"] == 2, "new release missing")
        marker = "/new-" + secrets.token_hex(12)
        require(self.http(marker), "new rule request failed")
        def new_alert():
            for line in (self.directory / "eve.json").read_text().splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (row.get("alert", {}).get("signature_id") == 9100102
                        and row.get("http", {}).get("url") == marker
                        and row.get("alert", {}).get("action") == "allowed"):
                    return True
            return False
        self.wait(new_alert, "newly activated rule did not produce a correlated alert")
        require(self.sentinel() == self.sentinel_before, "foreign sentinel changed")
        faults = self.state / "faults"
        faults.mkdir(mode=0o700)
        crashes = crash_cases(faults, binary, config)
        return {"result": "PASS_REAL_FOUR_FILE_ACTIVATION_AND_PROCESS_DEATH_RECOVERY_LAB_ONLY",
                "activation": result, "controller_stdout": response.stdout, "controller_stderr": response.stderr,
                "new_correlated_alert": 9100102, "legal_attempts": self.traffic_count,
                "legal_errors": self.traffic_errors, "process_death_cases": crashes,
                "production_ready": False, "measurement_eligible": False, "G6": "OPEN"}

    def cleanup(self):
        self.stop_traffic.set()
        errors = []
        for unit in reversed(self.units):
            try:
                description = run(["systemctl", "show", unit, "-p", "Description", "--value"]).stdout.strip()
                if description == self.owner:
                    stopped = run(["systemctl", "stop", unit], check=False, timeout=15)
                    if stopped.returncode:
                        errors.append(unit + ": " + stopped.stderr)
                state = run(["systemctl", "show", unit, "-p", "MainPID", "--value"]).stdout.strip()
                if state != "0":
                    errors.append("registered unit still has a main process: " + unit)
            except BaseException as error:
                errors.append(unit + ": " + repr(error))
        try:
            super().cleanup()
        except BaseException as error:
            errors.append("namespace/child cleanup: " + repr(error))
        require(not errors, "; ".join(errors))


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise Unavailable("Run only on a disposable GitHub Actions VM, never a production host")
    prerequisites()
    require(Path("/run/systemd/system").is_dir(), "systemd is required")
    token = secrets.token_hex(8)
    paths = [Path("/etc/csp0-qual-" + token), Path("/var/lib/csp0-qual-" + token), Path("/run/csp0-qual-" + token)]
    created, lab, cleanup_complete = [], None, False
    def abort(signum, frame):
        raise RuntimeError("qualification interrupted: " + str(signum))
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(number, abort)
    # Includes setup, controller's own 240s bound and all four fault fixtures.
    signal.alarm(420)
    try:
        for path in paths:
            path.mkdir(mode=0o700)
            created.append(path)
        lab = ActivationLab(*paths, token)
        try:
            lab.setup()
            result = lab.exercise()
        finally:
            signal.alarm(0)
            lab.cleanup()
            cleanup_complete = True
        result["cleanup"] = "complete"
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        if cleanup_complete or lab is None:
            for path in reversed(created):
                require(path in paths and path.name == "csp0-qual-" + token and not path.is_symlink(),
                        "refusing unrelated cleanup path")
                shutil.rmtree(path)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Unavailable as error:
        print(json.dumps({"result": "SKIP", "reason": str(error)}))
        sys.exit(77)
