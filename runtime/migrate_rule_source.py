#!/usr/bin/env python3
"""One controlled -S to YAML migration. Preserve old bytes; never roll back automatically."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

from activate_rules import (activation_lock, child_limits, own_resources, probe, systemd,
                            validate_context, MIGRATION_LIMIT_SECONDS)
from rule_release import (absolute, bootstrap, json_bytes, read_path, sha, verify_release)
from rule_update_journal import directory, file_info, pin, read_file, require, unique, write_file
from suricata_commands import bounded_read, process_binding, ruleset, SuricataCommands

SCHEMA = "cs-public0-yaml-migration-v1"
# Stop 25 + verify 20 + daemon-reload 15 + start 90 + timer 15 +
# post-start observation 20 + 10 seconds for local bookkeeping.
POST_STOP_RESERVE_NS = 195_000_000_000
LIFETIME_NS = MIGRATION_LIMIT_SECONDS * 1_000_000_000


def require_stop_budget(started_ns):
    elapsed = time.monotonic_ns() - started_ns
    require(0 <= elapsed <= LIFETIME_NS - POST_STOP_RESERVE_NS,
            "insufficient controller lifetime before sensor stop")


def parse(raw):
    require(type(raw) is bytes and len(raw) <= 16384, "bounded migration plan required")
    p = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(p, dict) and set(p) == {"schema", "nonce", "controller_unit", "before", "target",
            "stage", "files", "startup_check", "immutable", "monitor_timer", "monitor_service",
            "passive_service", "rules_sha256", "rules_count"} and p["schema"] == SCHEMA, "invalid migration plan")
    require(pin(p["nonce"]) and pin(p["rules_sha256"]) and type(p["rules_count"]) is int
            and 0 < p["rules_count"] <= 1000000, "explicit migration pins/count required")
    require(p["controller_unit"] == "cs-public0-activate-" + p["nonce"][:16] + ".service", "wrong migration unit")
    for k in ("target", "stage", "startup_check"):
        absolute(p[k])
    require(p["target"] != p["stage"], "separate migration stage required")
    for k, suffix in (("monitor_timer", "timer"), ("monitor_service", "service"), ("passive_service", "service")):
        require(isinstance(p[k], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}\." + suffix, p[k]), "invalid auxiliary unit")
    b = p["before"]
    require(isinstance(b, dict) and set(b) == {"cfg", "binding", "unit", "selector_sha256", "qualification_settings"},
            "invalid old sensor context")
    validate_context(b, cli_rule_file=True)
    require(isinstance(p["immutable"], dict) and 1 <= len(p["immutable"]) <= 20
            and all(pin(v) for v in p["immutable"].values()), "immutable source pins required")
    for name in p["immutable"]: absolute(name)
    cfg = b["cfg"]
    require(cfg["suricata_config"] == str(Path(p["target"]) / "suricata.yaml")
            and cfg["rules_file"] == str(Path(p["target"]) / "production.rules"), "migration profile differs")
    roles = {"config": cfg["suricata_config"], "manifest": str(Path(p["target"]) / "manifest.json"),
             "unit": "/etc/systemd/system/" + cfg["service"], "verifier": p["startup_check"]}
    require(isinstance(p["files"], dict) and set(p["files"]) == set(roles), "four migration assets required")
    for role, value in p["files"].items():
        require(isinstance(value, dict) and set(value) == {"target", "source", "old_sha256", "new_sha256", "mode"}
                and value["target"] == roles[role] and pin(value["old_sha256"]) and pin(value["new_sha256"])
                and type(value["mode"]) is int and value["mode"] == (0o755 if role == "verifier" else 0o644),
                "invalid migration asset")
        require(isinstance(value["source"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", value["source"])
                and value["source"] not in {".", "..", "migration-request.json", "migration-status.json",
                    "monitor-state.before.json", "qualification.stdout", "engine", ".monitor.lock"}
                and not value["source"].endswith(".before"), "invalid migration source")
    require(len({v["source"] for v in p["files"].values()}) == 4, "migration sources must differ")
    require(p["monitor_timer"] != p["monitor_service"] and p["monitor_service"] != cfg["service"]
            and p["passive_service"] not in {cfg["service"], p["monitor_service"]}, "auxiliary units overlap")
    require(not (Path(p["stage"]).is_relative_to(p["target"])
                 or Path(p["target"]).is_relative_to(p["stage"])), "migration directories overlap")
    require(cfg["binary"] in p["immutable"] and cfg["suricata_config"] in p["immutable"]
            and p["startup_check"] in p["immutable"]
            and all(v.split("=", 1)[1] in p["immutable"] for v in b["qualification_settings"]
                    if not v.startswith("stream.inline=")), "migration lacks immutable engine/startup pins")
    require(all(p["immutable"].get(v["target"]) == v["new_sha256"] for k, v in p["files"].items()
                if k != "manifest"), "migration policy must pin all new startup assets")
    return p


def semantic_unit(raw):
    lines = [line.strip() for line in raw.decode().splitlines() if line.strip() and not line.lstrip().startswith("#")]
    starts = [line for line in lines if line.startswith("ExecStart=")]
    require(len(starts) == 1, "one sensor ExecStart required")
    return [line for line in lines if not line.startswith("ExecStart=")], shlex.split(starts[0].partition("=")[2])


def verify_transition(p, old, new):
    old_lines, args = semantic_unit(old["unit"])
    new_lines, new_args = semantic_unit(new["unit"])
    require(args.count("-S") == 1 and "-s" not in args, "one exact old -S pair required")
    index = args.index("-S")
    require(index + 1 < len(args) and args[index + 1] == p["before"]["cfg"]["rules_file"], "old rule source differs")
    require(old_lines == new_lines and args[:index] + args[index + 2:] == new_args,
            "migration unit may only remove the exact -S pair")
    old_manifest = json.loads(old["manifest"], object_pairs_hook=unique)
    new_manifest = json.loads(new["manifest"], object_pairs_hook=unique)
    expected = json.loads(json.dumps(old_manifest))
    expected["config_sha256"] = sha(new["config"])
    expected["artifacts"]["config_sha256"] = sha(new["config"])
    require(new_manifest == expected and old_manifest["rules_sha256"] == p["rules_sha256"]
            and old_manifest["rules_alert"] == p["rules_count"] and old_manifest["rules_drop"] == 0,
            "only the configuration pin may change in the initial manifest")
    require(new_args[0] == p["before"]["cfg"]["binary"], "binary differs")
    return new_args


def verify_transition_sources(p, new):
    staged = {item["target"]: new[role] for role, item in p["files"].items() if role != "manifest"}
    for path, expected in p["immutable"].items():
        raw = staged[path] if path in staged else read_path(path)
        require(sha(raw) == expected, "migration immutable source changed: " + path)


def qualify_yaml(p, new_config):
    before = p["before"]
    cfg = before["cfg"]
    import cs_public0 as runtime
    test_cfg = {**cfg, "suricata_config": str(new_config)}
    runtime.selected_rules(test_cfg, Path(cfg["binary"]))
    log_dir = Path(p["stage"]) / "engine"
    os.mkdir(log_dir, 0o700)
    argv = [cfg["binary"], "-T", "--simulate-ips", "-c", str(new_config), "-l", str(log_dir), "--init-errors-fatal"]
    for value in before["qualification_settings"] + ["unix-command.enabled=no"]:
        argv += ["--set", value]
    error = None
    result = None
    with tempfile.TemporaryFile(dir=log_dir) as out:
        try:
            result = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT, timeout=120,
                                    preexec_fn=child_limits, start_new_session=True,
                                    env={**os.environ, "LC_ALL": "C"})
        except BaseException as exc:
            error = exc
        out.seek(0)
        raw = out.read(1024 * 1024 + 1)
    with directory(p["stage"], True) as fd:
        write_file(fd, "qualification.stdout", raw)
    if error is not None: raise error
    counts = re.findall(rb"(\d+) rules successfully loaded, (\d+) rules failed, (\d+) rules skipped", raw)
    require(result.returncode == 0 and len(raw) <= 1024 * 1024 and len(counts) == 1
            and tuple(map(int, counts[0])) == (p["rules_count"], 0, 0), "YAML qualification failed")
    return {"argv": argv, "exit_code": result.returncode, "stdout_bytes": len(raw), "stdout_sha256": sha(raw)}


def migrate(p, raw_plan, started_ns=None):
    started_ns = time.monotonic_ns() if started_ns is None else started_ns
    cfg = p["before"]["cfg"]
    target, stage = Path(p["target"]), Path(p["stage"])
    require(not (target / "release.json").exists() and not (target / "release.json").is_symlink(),
            "already pinned release requires a separate immutable-policy migration")
    timer_stopped = False
    result = {"schema": SCHEMA, "phase": "REQUEST", "started_ns": started_ns,
              "old_binding": p["before"]["binding"], "new_binding": None}
    with activation_lock(target), directory(stage, True) as stage_fd:
        write_file(stage_fd, "migration-request.json", raw_plan)
        def save(phase):
            result.update(phase=phase, updated_ns=time.monotonic_ns())
            write_file(stage_fd, "migration-status.json", json_bytes(result), replace=True)
        save("PREFLIGHT")
        old, new = {}, {}
        for role, item in p["files"].items():
            old[role] = read_path(item["target"], 1024 * 1024)
            new[role] = read_file(stage_fd, item["source"], 1024 * 1024)[0]
            require(sha(old[role]) == item["old_sha256"] and sha(new[role]) == item["new_sha256"],
                    "migration asset changed: " + role)
            write_file(stage_fd, role + ".before", old[role])
        verify_transition(p, old, new)
        verify_transition_sources(p, new)
        require(sha(read_path(cfg["rules_file"])) == p["rules_sha256"], "active rule pin differs")
        passive = systemd(p["passive_service"], ("ActiveState", "UnitFileState"))
        require(passive["ActiveState"] == "inactive" and passive["UnitFileState"] in {"disabled", "masked"},
                "passive sensor must remain inactive and disabled")
        before = probe(p["before"])
        state = Path(cfg["monitor_state"])
        require(state.parent.stat().st_dev == stage.stat().st_dev, "epoch archive must share the state filesystem")
        result["qualification"] = qualify_yaml(p, stage / p["files"]["config"]["source"])
        for role, item in p["files"].items():
            require(read_file(stage_fd, item["source"], 1024 * 1024)[0] == new[role],
                    "migration source changed during qualification")
        require(sha(read_path(cfg["rules_file"])) == p["rules_sha256"], "rules changed during qualification")
        probe(p["before"])
        save("QUALIFIED")
        try:
            # Claim before the manager can stop the timer and lose its reply.
            # The launcher's ExecStopPost also starts this timer after SIGKILL.
            timer_stopped = True
            for unit in (p["monitor_timer"], p["monitor_service"]):
                subprocess.run(["/usr/bin/systemctl", "stop", unit], check=True, timeout=15)
            # Every monitor writer uses this lock. Keep the exact prior epoch.
            lock = os.open(state.parent / ".monitor.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                file_info(os.fstat(lock), True)
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                original_state = read_path(state, 65536)
                saved = json.loads(original_state, object_pairs_hook=unique)
                require(saved["latched"] is False and saved["current_sample_valid"] is True
                        and saved["kernel_accounting"]["unexplained_gap"] == 0
                        and saved["kernel_accounting"]["gap_history_latched"] is False
                        and saved["kernel_accounting"].get("observation_gap_history_latched", False) is False,
                        "do not clear an unresolved old epoch")
                verify_transition_sources(p, new)
                # A slow qualification or monitor stop must leave the sensor
                # running, rather than consume its stop/start recovery budget.
                require_stop_budget(started_ns)
                save("STOP_REQUEST")
                subprocess.run(["/usr/bin/systemctl", "stop", cfg["service"]], check=True, timeout=25)
                stopped = systemd(cfg["service"], ("MainPID", "ActiveState"))
                require(stopped == {"MainPID": "0", "ActiveState": "inactive"}, "sensor did not stop cleanly")
                require(not (stage / "monitor-state.before.json").exists(), "epoch archive already exists")
                require(read_path(state, 65536) == original_state, "monitor state changed despite its lock")
                os.rename(state, stage / "monitor-state.before.json")
                os.fsync(stage_fd)
                with directory(state.parent, True) as state_fd: os.fsync(state_fd)
                result["old_monitor_sha256"] = sha(original_state)
                save("STOPPED_OLD_EPOCH_ARCHIVED")
                for role, item in p["files"].items():
                    require(sha(read_path(item["target"], 1024 * 1024)) == item["old_sha256"],
                            "foreign migration write: " + role)
                    path = Path(item["target"])
                    with directory(path.parent) as fd:
                        write_file(fd, path.name, new[role], item["mode"], replace=True)
                save("NEW_FILES_INSTALLED")
                for path, expected in p["immutable"].items():
                    require(sha(read_path(path)) == expected, "new immutable source differs: " + path)
                release = bootstrap(target, {"rules": "production.rules", "gzip": "production.rules.gz",
                                             "manifest": "manifest.json"}, list(p["immutable"]))
                require(release["immutable"] == p["immutable"], "bootstrap pins differ")
                subprocess.run([p["startup_check"], "verify"], check=True, timeout=20)
                subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True, timeout=15)
                save("START_REQUEST")
                subprocess.run(["/usr/bin/systemctl", "start", cfg["service"]], check=True, timeout=90)
                unit = systemd(cfg["service"], tuple(p["before"]["unit"]))
                binding = process_binding(int(unit["MainPID"]))
                require(unit["ActiveState"] == "active" and unit["SubState"] == "running"
                        and unit["InvocationID"] != p["before"]["unit"]["InvocationID"]
                        and not binding["cli_rule_file"], "new YAML sensor instance was not established")
                result["new_binding"] = binding
                result["new_unit"] = unit
                save("NEW_SENSOR_STARTED")
            finally:
                os.close(lock)
        finally:
            if timer_stopped:
                subprocess.run(["/usr/bin/systemctl", "start", p["monitor_timer"]], check=True, timeout=15)
        # The old monitor JSON is retained verbatim; the timer establishes a new epoch.
        deadline = time.monotonic_ns() + 20_000_000_000
        with SuricataCommands(cfg["socket"], binding) as session:
            session.require_reloadable()
            require(session.query("capture-mode") == "NFQ", "new capture mode is not NFQ")
            ruleset(session.query("ruleset-stats"), p["rules_count"])
        while True:
            try:
                # Handles change after the intentional remove/install, so pin this
                # newly created selector only after checking its exact semantics.
                import cs_public0 as runtime
                from activate_rules import exact_selector, selector_hash
                doc = runtime.table(cfg)
                require(exact_selector(doc, cfg), "new selector differs")
                after = probe({**p["before"], "binding": binding, "unit": unit,
                               "selector_sha256": selector_hash(doc)})
                if after["packets"] > 0: break
            except Exception:
                if time.monotonic_ns() >= deadline: raise
            require(time.monotonic_ns() < deadline, "new monitor/traffic progress not observed")
            time.sleep(0.5)
        require(sha(read_path(cfg["rules_file"])) == p["rules_sha256"], "rules changed during YAML migration")
        verify_release(target / "release.json")
        result["after"] = after
        save("MIGRATED")
        return result


def main():
    started_ns = time.monotonic_ns()
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and pin(args.plan_sha256), "root and explicit migration plan SHA required")
    raw = read_path(absolute(args.plan), 16384)
    require(sha(raw) == args.plan_sha256, "migration plan changed")
    p = parse(raw)
    own_resources(p["controller_unit"], lifetime_seconds=MIGRATION_LIMIT_SECONDS)
    try:
        result = migrate(p, raw, started_ns)
    except BaseException:
        print(json.dumps({"schema": SCHEMA, "phase": "INCOMPLETE", "stage": p["stage"],
                          "automatic_rollback": False}), file=sys.stderr)
        raise
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
