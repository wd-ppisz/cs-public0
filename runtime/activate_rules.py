#!/usr/bin/env python3
"""One explicit, bounded rule activation. No feed polling, signals or rollback."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import time

import cs_public0 as runtime
from rule_release import (MAX_METADATA, absolute, json_bytes, prepare_images,
                          read_path, sha, verify_release)
from rule_update_journal import (MAX_FILE, RuleFileJournal, directory, encoded,
                                 file_info, pin, read_file, require, unique, write_file)
from suricata_commands import (SuricataCommands, bounded_read, process_binding,
                               reload_installed, ruleset, validate_binding)

SCHEMA = "cs-public0-activation-v1"
SELF_LIMIT_SECONDS = 240
MIGRATION_LIMIT_SECONDS = 360
PROBE_LIMIT_NS = 1_000_000_000
HEALTH_AGE_NS = 30_000_000_000
MAX_LOG = 1024 * 1024


def systemd(unit, properties):
    require(re.fullmatch(r"[A-Za-z0-9_.@-]{1,120}\.service", unit), "invalid unit")
    raw = runtime.run(["/usr/bin/systemctl", "show", unit,
                      "--property=" + ",".join(properties)]).stdout
    rows = {}
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in properties and key not in rows, "invalid unit readback")
        rows[key] = value
    require(set(rows) == set(properties), "incomplete unit readback")
    return rows


def own_resources(unit, lifetime_seconds=SELF_LIMIT_SECONDS):
    lifetimes = {SELF_LIMIT_SECONDS: "4min", MIGRATION_LIMIT_SECONDS: "6min"}
    require(type(lifetime_seconds) is int and lifetime_seconds in lifetimes, "unsupported controller lifetime")
    require(re.fullmatch(r"cs-public0-activate-[a-f0-9]{16}\.service", unit), "unexpected controller unit")
    keys = ("MainPID", "InvocationID", "ControlGroup", "KillMode", "Restart", "RuntimeMaxUSec", "TimeoutStopUSec")
    rows = systemd(unit, keys)
    require(rows["MainPID"] == str(os.getpid()) and rows["InvocationID"]
            and rows["InvocationID"] == os.environ.get("INVOCATION_ID"), "not the expected systemd main process")
    require(rows["KillMode"] == "control-group" and rows["Restart"] == "no"
            and rows["RuntimeMaxUSec"] == lifetimes[lifetime_seconds] and rows["TimeoutStopUSec"] == "10s",
            "controller lifetime or cleanup limits differ")
    group = rows["ControlGroup"]
    require(group.startswith("/system.slice/") and ".." not in group.split("/"), "unexpected controller cgroup")
    membership = bounded_read("/proc/self/cgroup", 8192).decode().splitlines()
    require(membership == ["0::" + group], "controller cgroup differs")
    root = Path("/sys/fs/cgroup" + group)
    memory = int(bounded_read(root / "memory.max", 64))
    tasks = int(bounded_read(root / "pids.max", 64))
    quota, period = map(int, bounded_read(root / "cpu.max", 64).split())
    require(0 < memory <= 2 * 1024**3 and 0 < tasks <= 32 and quota > 0
            and period > 0 and quota <= period and int(bounded_read(root / "memory.swap.max", 64)) == 0,
            "effective controller resources exceed the accepted envelope")
    return {"unit": unit, "invocation": rows["InvocationID"], "cgroup": group,
            "memory_max": memory, "tasks_max": tasks, "cpu_quota": quota, "cpu_period": period}


def parse_plan(raw):
    require(type(raw) is bytes and len(raw) <= MAX_METADATA, "bounded plan required")
    p = json.loads(raw, object_pairs_hook=unique)
    keys = {"schema", "nonce", "controller_unit", "target", "store", "candidate",
            "candidate_rules", "candidate_gzip", "candidate_rules_sha256", "candidate_gzip_sha256",
            "expected_old", "cfg", "binding", "unit", "selector_sha256", "qualification_settings",
            "startup_check"}
    require(isinstance(p, dict) and set(p) in (keys, keys | {"drop_sids"}) and p["schema"] == SCHEMA,
            "invalid activation plan")
    if "drop_sids" in p:
        sids = p["drop_sids"]
        require(isinstance(sids, list) and len(sids) <= 128
                and all(type(s) is int and 1 <= s <= 4294967295 for s in sids)
                and sids == sorted(set(sids)), "invalid explicit DROP policy")
    require(pin(p["nonce"]) and pin(p["selector_sha256"]), "explicit nonce/selector pin required")
    for key in ("target", "store", "candidate"):
        absolute(p[key])
    require(len({p["target"], p["store"], p["candidate"]}) == 3, "separate directories required")
    for key in ("candidate_rules", "candidate_gzip"):
        require(isinstance(p[key], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", p[key])
                and p[key] not in {".", ".."}, "invalid candidate name")
    require(p["candidate_rules"] != p["candidate_gzip"]
            and pin(p["candidate_rules_sha256"]) and pin(p["candidate_gzip_sha256"]), "candidate pin required")
    require(isinstance(p["expected_old"], dict) and len(p["expected_old"]) == 4
            and all(pin(v) for v in p["expected_old"].values()), "four old asset pins required")
    validate_context(p, cli_rule_file=False)
    startup = p["startup_check"]
    require(startup is None or isinstance(startup, str), "invalid startup check")
    if startup:
        absolute(startup)
    return p


def validate_context(p, cli_rule_file=False):
    """Validate a process-bound probe, including explicit qualification overrides."""
    cfg = p["cfg"]
    require(isinstance(cfg, dict) and set(cfg) == {"service", "queue", "table", "bridge", "chain", "priority", "socket",
            "binary", "suricata_config", "rules_file", "monitor_state"}, "invalid probe configuration")
    require(isinstance(cfg["service"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}\.service", cfg["service"]),
            "invalid sensor service")
    require(type(cfg["queue"]) is int and 0 <= cfg["queue"] <= 65535
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,62}", cfg["table"]), "invalid NFQUEUE selector")
    require(isinstance(cfg["bridge"], str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,14}", cfg["bridge"])
            and type(cfg["priority"]) is int and -300 <= cfg["priority"] <= 300, "invalid bridge/priority")
    require(isinstance(cfg["chain"], str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,62}", cfg["chain"]),
            "invalid chain")
    for k in ("socket", "binary", "suricata_config", "rules_file", "monitor_state"):
        absolute(cfg[k])
    validate_binding(p["binding"])
    require(p["binding"]["cli_rule_file"] is cli_rule_file, "unexpected -S/-s process binding")
    require(isinstance(p["unit"], dict) and set(p["unit"]) ==
            {"MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState"}
            and all(isinstance(v, str) for v in p["unit"].values()), "explicit sensor unit binding required")
    require(p["unit"]["MainPID"] == str(p["binding"]["pid"])
            and re.fullmatch(r"[a-f0-9]{32}", p["unit"]["InvocationID"])
            and p["unit"]["ControlGroup"] == "/system.slice/" + cfg["service"]
            and p["unit"]["ActiveState"] == "active" and p["unit"]["SubState"] == "running",
            "sensor unit does not match the accepted process")
    require(pin(p["selector_sha256"]), "explicit selector pin required")
    settings = p["qualification_settings"]
    allowed = {"classification-file", "reference-config-file", "threshold-file", "stream.inline"}
    require(isinstance(settings, list) and len(settings) <= 4, "invalid qualification settings")
    names = [s.partition("=")[0] for s in settings if isinstance(s, str)]
    require(len(names) == len(settings) and len(set(names)) == len(names) and set(names) <= allowed,
            "unsupported engine override")
    require("stream.inline=yes" in settings, "IPS stream setting required")
    for setting in settings:
        key, sep, value = setting.partition("=")
        require(sep and (value == "yes" if key == "stream.inline" else absolute(value)), "invalid engine setting")


@contextlib.contextmanager
def activation_lock(target):
    with directory(target) as fd:
        lock = os.open(".activation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=fd)
        try:
            file_info(os.fstat(lock), True)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(lock)


def selector_hash(document):
    require(isinstance(document, dict) and set(document) == {"nftables"}, "invalid nft document")
    rows = []
    for item in document["nftables"]:
        require(isinstance(item, dict) and len(item) == 1, "invalid nft row")
        if "metainfo" in item:
            continue
        item = json.loads(json.dumps(item))
        if "counter" in item:
            item["counter"].pop("packets", None)
            item["counter"].pop("bytes", None)
        rows.append(item)
    return sha(encoded(rows))


def exact_selector(document, cfg):
    # Normalize a provider's explicit chain name only after checking that name.
    normalized = json.loads(json.dumps(document))
    chains = [row["chain"] for row in normalized["nftables"] if "chain" in row]
    rules = [row["rule"] for row in normalized["nftables"] if "rule" in row]
    require(len(chains) == len(rules) == 1 and chains[0]["name"] == cfg["chain"]
            and rules[0]["chain"] == cfg["chain"], "chain differs from the accepted selector")
    chains[0]["name"] = rules[0]["chain"] = "forward_ipv4"
    return runtime.exact_table(normalized, cfg)


def monitor_health(path, binding):
    state = json.loads(read_path(path, 65536), object_pairs_hook=unique)
    require(state.get("latched") is False and state.get("current_sample_valid") is True,
            "monitor is degraded or current observation is incomplete")
    accounting = state["kernel_accounting"]
    require(type(accounting["unexplained_gap"]) is int and accounting["unexplained_gap"] == 0
            and accounting["gap_history_latched"] is False
            and accounting.get("observation_gap_history_latched", False) is False, "unresolved monitor history")
    sample = accounting["sample"]
    finished = sample["finished_ns"]
    require(type(finished) is int and 0 <= time.monotonic_ns() - finished <= HEALTH_AGE_NS
            and sample["boot_id"] == binding["boot_id"], "stale or foreign monitor epoch")
    require(state["sensor"]["pid"] == binding["pid"]
            and state["sensor"]["start_ticks"] == binding["start_ticks"], "foreign monitor sensor")
    return {"finished_ns": finished, "sequence": state.get("sequence"),
            "socket": [sample["after"]["portid"], sample["after"]["inode"]],
            "gap": 0, "degraded": False}


def effective_settings(plan):
    raw = bounded_read("/proc/" + str(plan["binding"]["pid"]) + "/cmdline", 65536)
    require(raw.endswith(b"\0"), "incomplete engine command line")
    args = [s.decode() for s in raw.split(b"\0")[:-1]]
    require(args and args[0] == plan["cfg"]["binary"], "unexpected engine executable argument")
    overrides, options = {}, {}
    wanted = {s.partition("=")[0] for s in plan["qualification_settings"]}
    safe = {"unix-command.enabled", "unix-command.filename", "nfq.fail-open", "nfq.batchcount",
            "max-pending-packets", "stats.interval", "nfq.gso", "nfq.rcvbuf-size"}
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == "--set":
            require(i + 1 < len(args), "incomplete engine override")
            key, sep, value = args[i + 1].partition("=")
            require(sep and value and key in wanted | safe and key not in overrides,
                    "unsupported or ambiguous engine override")
            require(key != "nfq.gso" or value == "yes", "GSO override must be enabled")
            if key == "nfq.rcvbuf-size":
                require(re.fullmatch(r"[1-9][0-9]{6,7}", value) and
                        1048576 <= int(value) <= 67108864, "invalid receive buffer override")
            overrides[key] = value
            i += 2
        elif arg in {"-c", "-q", "-l", "-S"}:
            require(i + 1 < len(args) and arg not in options, "ambiguous engine option")
            require(arg != "-S" or plan["binding"]["cli_rule_file"] is True, "unexpected -S source")
            options[arg] = args[i + 1]
            i += 2
        else:
            require(arg in {"--runmode=workers", "--init-errors-fatal"} and arg not in options,
                    "unsupported engine argument")
            options[arg] = True
            i += 1
    require(options.get("-c") == plan["cfg"]["suricata_config"]
            and options.get("-q") == str(plan["cfg"]["queue"]), "active YAML or NFQUEUE differs")
    if "-l" in options: absolute(options["-l"])
    if plan["binding"]["cli_rule_file"]:
        require(options.get("-S") == plan["cfg"]["rules_file"], "old -S rule path differs")
    selected = {key: value for key, value in overrides.items() if key in wanted}
    require(selected == dict(s.split("=", 1) for s in plan["qualification_settings"]),
            "qualification differs from active engine overrides")


def monitor_ready_after(plan, completed):
    """Wait for a whole new observation; kernel-only samples remain UNKNOWN."""
    state = json.loads(read_path(plan["cfg"]["monitor_state"], 65536), object_pairs_hook=unique)
    accounting = state.get("kernel_accounting", {})
    require(state.get("latched") is False
            and accounting.get("gap_history_latched") is False
            and accounting.get("observation_gap_history_latched", False) is False,
            "post-reload monitor has unresolved degradation or history")
    sensor, sample = state.get("sensor", {}), accounting.get("sample", {})
    require(sensor.get("pid") == plan["binding"]["pid"]
            and sensor.get("start_ticks") == plan["binding"]["start_ticks"]
            and sample.get("boot_id") == plan["binding"]["boot_id"],
            "post-reload monitor sensor epoch changed")
    finished = sample.get("finished_ns")
    return (state.get("current_sample_valid") is True and type(finished) is int
            and finished > completed)


def probe(plan):
    cfg, binding = plan["cfg"], plan["binding"]
    started = time.monotonic_ns()
    require(systemd(cfg["service"], tuple(plan["unit"])) == plan["unit"], "sensor unit changed")
    require(plan["unit"]["MainPID"] == str(binding["pid"])
            and plan["unit"]["ActiveState"] == "active" and plan["unit"]["SubState"] == "running"
            and plan["unit"]["InvocationID"], "sensor unit is not the accepted active instance")
    require(process_binding(binding["pid"]) == binding, "sensor process changed")
    executable = os.stat(cfg["binary"])
    require([executable.st_dev, executable.st_ino] == binding["exe"], "qualified binary is not the running executable")
    netns = os.stat("/proc/self/ns/net")
    require([netns.st_dev, netns.st_ino] == binding["netns"], "controller must share sensor netns")
    require(bounded_read("/proc/" + str(binding["pid"]) + "/cgroup", 8192).decode().splitlines()
            == ["0::" + plan["unit"]["ControlGroup"]], "sensor unit cgroup differs")
    effective_settings(plan)
    before = runtime.queue(cfg, binding["pid"])
    document = runtime.table(cfg)
    require(exact_selector(document, cfg), "selector is not the exact IPv4 bridge NFQUEUE rule")
    require(selector_hash(document) == plan["selector_sha256"], "selector changed")
    counter = [row["counter"] for row in document["nftables"] if "counter" in row]
    require(len(counter) == 1 and type(counter[0].get("packets")) is int, "one named counter required")
    after = runtime.queue(cfg, binding["pid"])
    require([before["portid"], before["inode"]] == [after["portid"], after["inode"]]
            and all(q[k] == 0 for q in (before, after)
                    for k in ("kernel_dropped", "user_dropped", "netlink_dropped")),
            "queue loss or socket replacement")
    health = monitor_health(cfg["monitor_state"], binding)
    require(health["socket"] == [after["portid"], after["inode"]], "monitor queue socket differs")
    require(time.monotonic_ns() - started <= PROBE_LIMIT_NS, "control-plane probe exceeded one second")
    return {"queue": after, "packets": counter[0]["packets"], "health": health,
            "finished_ns": time.monotonic_ns()}


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))


def qualify(plan, rules_path, log_directory):
    cfg = plan["cfg"]
    argv = [cfg["binary"], "-T", "--simulate-ips", "-c", cfg["suricata_config"], "-S",
            str(rules_path), "-l", str(log_directory), "--init-errors-fatal"]
    for setting in plan["qualification_settings"] + ["unix-command.enabled=no"]:
        argv += ["--set", setting]
    started = time.monotonic_ns()
    failure = None
    result = None
    with tempfile.TemporaryFile(dir=log_directory) as out:
        try:
            result = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT, timeout=120,
                                    preexec_fn=child_limits, start_new_session=True,
                                    env={**os.environ, "LC_ALL": "C"})
        except BaseException as error:
            failure = error
        require(out.tell() <= MAX_LOG, "qualification log exceeds bound")
        out.seek(0)
        raw = out.read(MAX_LOG + 1)
    with directory(log_directory, True) as fd:
        write_file(fd, "stdout.log", raw)
    if failure is not None:
        raise failure
    require(result.returncode == 0 and len(raw) <= MAX_LOG, "candidate engine qualification failed")
    rows = re.findall(rb"(\d+) rules successfully loaded, (\d+) rules failed, (\d+) rules skipped", raw)
    require(len(rows) == 1 and tuple(map(int, rows[0])) ==
            (plan["_new_count"], 0, 0), "qualification counts absent, ambiguous or incorrect")
    return {"argv": argv, "started_ns": started, "finished_ns": time.monotonic_ns(),
            "exit_code": result.returncode, "log_bytes": len(raw), "log_sha256": sha(raw)}, raw


def startup_check(plan):
    release = verify_release(Path(plan["target"]) / "release.json")
    path = plan["startup_check"]
    if path:
        require(path in release["immutable"], "startup verifier must be pinned as immutable")
        runtime.run([path, "verify"], timeout=30)
    return release


def activate(plan, raw_plan, check_only=False):
    """Every writer must use this outer lock. Unknown reloads are never retried."""
    transaction = sha(raw_plan)
    target, store, candidate = map(Path, (plan["target"], plan["store"], plan["candidate"]))
    with activation_lock(target), directory(store, True) as store_fd, directory(candidate) as candidate_fd:
        # The request is owned before a child can allocate. Replays remain visible.
        write_file(store_fd, "request-" + transaction + ".json", raw_plan)
        raw = read_file(candidate_fd, plan["candidate_rules"], MAX_FILE)[0]
        compressed = read_file(candidate_fd, plan["candidate_gzip"], MAX_FILE)[0]
        require(sha(raw) == plan["candidate_rules_sha256"]
                and sha(compressed) == plan["candidate_gzip_sha256"], "candidate bytes changed")
        old, new, images, before = prepare_images(target, raw, compressed, plan.get("drop_sids"))
        require(before == plan["expected_old"], "installed release changed since approval")
        require(Path(plan["cfg"]["rules_file"]) == target / old["names"]["rules"], "rules target differs")
        require(plan["cfg"]["binary"] in old["immutable"]
                and plan["cfg"]["suricata_config"] in old["immutable"], "binary and YAML must be pinned")
        require(all(value.partition("=")[2] in old["immutable"]
                    for value in plan["qualification_settings"] if not value.startswith("stream.inline=")),
                "engine support file must be pinned")
        runtime.selected_rules(plan["cfg"], Path(plan["cfg"]["binary"]))
        startup_check(plan)
        first = probe(plan)
        with SuricataCommands(plan["cfg"]["socket"], plan["binding"]) as session:
            session.require_reloadable()
            require(session.query("capture-mode") == "NFQ", "sensor is not in NFQ mode")
            ruleset(session.query("ruleset-stats"), old["rules_alert"] + old["rules_drop"])
        # An exclusive snapshot supplies the actual bytes consumed by -T.
        log_dir = store / ("qualification-" + transaction)
        os.mkdir(log_dir, 0o700)
        with directory(log_dir, True) as log_fd:
            write_file(log_fd, "candidate.rules", raw)
        qualification, log = qualify({**plan, "_new_count": new["rules_alert"] + new["rules_drop"]},
                                     log_dir / "candidate.rules", log_dir)
        with directory(log_dir, True) as log_fd:
            require(sha(read_file(log_fd, "candidate.rules", MAX_FILE)[0]) == new["rules_sha256"],
                    "qualified snapshot changed")
        # The engine test cannot consume the state accepted before a long pause.
        require(verify_release(target / "release.json") == old, "release changed during qualification")
        second = probe(plan)
        result = {"schema": SCHEMA, "transaction": transaction, "qualification": qualification,
                  "before": first, "after_qualification": second, "phase": "QUALIFIED_ONLY"}
        if check_only:
            write_file(store_fd, "result-" + transaction + ".json", encoded(result))
            return result
        journal = RuleFileJournal(target, store)
        journal.prepare(transaction, images, before, {name: sha(data) for name, data in images.items()})
        journal.install(transaction)
        require(startup_check(plan) == new, "new startup verification failed")
        probe(plan)
        with SuricataCommands(plan["cfg"]["socket"], plan["binding"]) as session:
            state = reload_installed(journal, transaction, session, old["rules_alert"] + old["rules_drop"],
                                     new["rules_alert"] + new["rules_drop"])
            completed = session.events[-1]["finished_ns"]
        # COMMITTED is the command/file receipt, not complete health acceptance.
        result["phase"] = state["phase"]
        deadline = time.monotonic_ns() + 20_000_000_000
        while True:
            if monitor_ready_after(plan, completed):
                after = probe(plan)
                if after["health"]["finished_ns"] > completed:
                    break
            require(time.monotonic_ns() < deadline, "no fresh post-reload monitor observation")
            time.sleep(0.25)
        require(after["packets"] > second["packets"], "no observed post-reload traffic progress")
        require([after["queue"]["portid"], after["queue"]["inode"]]
                == [second["queue"]["portid"], second["queue"]["inode"]], "NFQUEUE socket changed during reload")
        delta = (after["queue"]["id_sequence"] - second["queue"]["id_sequence"]) % (1 << 32)
        require(0 < delta < (1 << 31), "no unambiguous NFQUEUE sequence progress")
        require(verify_release(target / "release.json") == new, "new release changed after reload")
        result.update(phase="ACTIVATED", after=after, finished_ns=time.monotonic_ns())
        write_file(store_fd, "result-" + transaction + ".json", encoded(result))
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    require(os.geteuid() == 0 and pin(args.plan_sha256), "root and explicit plan SHA256 required")
    raw = read_path(absolute(args.plan), MAX_METADATA)
    require(sha(raw) == args.plan_sha256, "plan SHA256 differs")
    plan = parse_plan(raw)
    resources = own_resources(plan["controller_unit"])
    result = activate(plan, raw, args.check_only)
    print(json.dumps({**result, "resources": resources}, sort_keys=True))


if __name__ == "__main__":
    main()
