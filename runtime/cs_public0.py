#!/usr/bin/env python3
"""Manage one IPv4 bridge NFQUEUE selector and report inspection health."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import struct
import subprocess
import sys
import time

DEFAULTS = {
    "bridge": "public0", "table": "cs_public0", "queue": 100, "priority": -240,
    "runtime_dir": "/run/cs-public0", "state_dir": "/var/lib/cs-public0",
    "metrics_file": "/var/lib/node_exporter/textfile_collector/cs_public0.prom",
    "socket": "/run/cs-public0/suricata.socket", "service": "cs-public0.service",
    "rules_file": "/etc/cs-public0/rules/local.rules", "binary": "/usr/bin/suricata",
    "suricata_config": "/etc/cs-public0/suricata.yaml",
}
LOSS_COUNTERS = ("flow.memcap", "tcp.ssn_memcap_drop", "tcp.segment_memcap_drop")
MAX_MESSAGE = 4 * 1024 * 1024
MAX_STATE = 65536
MAX_RULES_BYTES = 64 * 1024 * 1024
MAX_RULE_LINE_BYTES = 4096
ENGINE_TEST_TIMEOUT_SECONDS = 180
SENSOR_READY_TIMEOUT_SECONDS = 240
SEQUENCE_MODULUS = 1 << 32
MAX_OBSERVATION_GAP_NS = 60 * 1000000000


def require(value, message):
    if not value:
        raise RuntimeError(message)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key: " + key)
        value[key] = item
    return value


def validate_config(value):
    require(isinstance(value, dict) and not set(value) - set(DEFAULTS), "unknown configuration keys")
    cfg = {**DEFAULTS, **value}
    for key in ("bridge", "table"):
        require(isinstance(cfg[key], str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,14}", cfg[key]),
                "invalid " + key)
    require(isinstance(cfg["service"], str) and
            re.fullmatch(r"[A-Za-z0-9_-]{1,80}\.service", cfg["service"]), "invalid service")
    require(type(cfg["queue"]) is int and 0 <= cfg["queue"] <= 65535, "invalid queue")
    require(type(cfg["priority"]) is int and -300 <= cfg["priority"] <= 300, "invalid priority")
    for key in ("runtime_dir", "state_dir", "metrics_file", "socket", "rules_file", "binary", "suricata_config"):
        path = cfg[key]
        require(isinstance(path, str) and re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
                and str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts,
                "invalid path: " + key)
    require(re.fullmatch(r"/run/[A-Za-z0-9_-]+", cfg["runtime_dir"]), "unsafe runtime directory")
    require(re.fullmatch(r"/var/lib/[A-Za-z0-9_-]+", cfg["state_dir"]), "unsafe state directory")
    require(cfg["socket"].startswith(cfg["runtime_dir"] + "/") and cfg["socket"].endswith(".socket"),
            "socket must be inside runtime directory")
    for key, prefix, suffix in (("rules_file", "/etc/", ".rules"),
                                ("suricata_config", "/etc/", ".yaml"),
                                ("metrics_file", "/var/lib/", ".prom")):
        require(cfg[key].startswith(prefix) and cfg[key].endswith(suffix)
                and len(PurePosixPath(cfg[key]).parts) >= 4, "unsafe " + key)
    require(cfg["binary"].startswith(("/usr/bin/", "/usr/local/bin/", "/opt/")), "unsafe binary")
    require(len(set(cfg[key] for key in ("runtime_dir", "state_dir", "metrics_file", "socket",
                                        "rules_file", "binary", "suricata_config"))) == 7,
            "configuration paths must be distinct")
    return cfg


def secure_path(path, directory=False):
    path = Path(path)
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe ownership or permissions: " + str(parent))
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            "unexpected file type: " + str(path))
    return path


def load_config(path):
    path = secure_path(path)
    require(path.stat().st_size <= 16384, "configuration too large")
    return validate_config(json.loads(path.read_text(), object_pairs_hook=unique))


def run(argv, data=None, check=True, timeout=15):
    result = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=timeout,
                            env={**os.environ, "LC_ALL": "C"})
    if check:
        require(result.returncode == 0, "command failed: " + argv[0] + ": " + result.stderr[:500])
    return result


def ruleset(cfg):
    return ('table bridge {table} {{\n counter queued {{}}\n chain forward_ipv4 {{\n'
            ' type filter hook forward priority {priority}; policy accept;\n'
            ' meta ibrname "{bridge}" meta obrname "{bridge}" ether type ip '
            'counter name queued queue num {queue} bypass\n }}\n}}\n').format(**cfg)


def expected_expressions(cfg):
    return [{"match": {"op": "==", "left": {"meta": {"key": name}}, "right": cfg["bridge"]}}
            for name in ("ibrname", "obrname")] + [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ether", "field": "type"}}, "right": "ip"}},
        {"counter": "queued"}, {"queue": {"num": cfg["queue"], "flags": ["bypass"]}}]


def exact_table(document, cfg):
    try:
        typed = {}
        for item in document["nftables"]:
            if "metainfo" in item:
                continue
            require(len(item) == 1, "nft object")
            kind, body = next(iter(item.items()))
            typed.setdefault(kind, []).append(body)
        if set(typed) != {"table", "counter", "chain", "rule"} or any(len(v) != 1 for v in typed.values()):
            return False
        table, counter, chain, rule = (typed[k][0] for k in ("table", "counter", "chain", "rule"))
        expr = json.loads(json.dumps(rule["expr"]))
        if isinstance(expr[-1].get("queue", {}).get("flags"), str):
            expr[-1]["queue"]["flags"] = [expr[-1]["queue"]["flags"]]
        return (all(obj.get("family") == "bridge" for obj in (table, counter, chain, rule))
                and table.get("name") == cfg["table"]
                and all(obj.get("table") == cfg["table"] for obj in (counter, chain, rule))
                and counter.get("name") == "queued" and chain.get("name") == "forward_ipv4"
                and chain.get("type") == "filter" and chain.get("hook") == "forward"
                and chain.get("prio") == cfg["priority"] and chain.get("policy") == "accept"
                and rule.get("chain") == "forward_ipv4" and expr == expected_expressions(cfg))
    except (KeyError, TypeError, IndexError, RuntimeError, AttributeError):
        return False


def table(cfg):
    result = run(["/usr/sbin/nft", "-j", "list", "table", "bridge", cfg["table"]], check=False)
    if result.returncode:
        require("No such file or directory" in result.stderr, "cannot inspect nft table: " + result.stderr[:300])
        return None
    return json.loads(result.stdout)


def identity(cfg):
    return {"project": "cs-public0", **{k: cfg[k] for k in ("bridge", "table", "queue", "priority")}}


def owned(cfg):
    marker = secure_path(Path(cfg["runtime_dir"]) / "owner.json")
    require(marker.stat().st_size <= 4096 and not marker.stat().st_mode & 0o077, "unsafe owner marker")
    require(json.loads(marker.read_text()) == identity(cfg), "foreign owner marker")


def atomic(path, value, mode=0o600):
    path = Path(path)
    secure_path(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        secure_path(path)
    temporary = path.with_name(path.name + ".tmp-" + str(os.getpid()))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_rules_bytes(raw, drop_sids=()):
    """Validate an already bounded snapshot without performing I/O."""
    require(len(raw) <= MAX_RULES_BYTES, "rules file too large")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("rules file must be valid UTF-8") from error
    require(all(char in "\t\n" or char.isprintable() for char in source),
            "rules contain unsupported control or non-printable characters; use LF line endings")
    require(isinstance(drop_sids, (list, tuple)) and len(drop_sids) <= 128
            and all(type(s) is int and 1 <= s <= 4294967295 for s in drop_sids)
            and list(drop_sids) == sorted(set(drop_sids)), "canonical DROP SID allowlist required")
    selected, dropped = set(drop_sids), set()
    occurrences = {}
    count = 0
    for raw_line in source.split("\n"):
        require(len(raw_line.encode("utf-8")) <= MAX_RULE_LINE_BYTES, "physical rule-file line too long")
        line = raw_line.strip(" \t")
        if line and not line.startswith("#"):
            require(raw_line[0] not in " \t", "active rules must start in column one")
            require(not line.endswith("\\"), "rule continuations are not accepted")
            require(re.match(r"^(?:alert|drop)[ \t]+[^\n]+\([^\n]*\)[ \t]*$", line),
                    "only single-line alert or explicitly allowed drop rules are accepted")
            options = line.split("(", 1)[1].rsplit(")", 1)[0]
            # Suricata 8 SigParseOptions splits at a semicolon unless its previous
            # byte is a backslash, including inside quoted option values.
            names = [option.partition(":")[0].strip(" \t").lower()
                     for option in re.split(r"(?<!\\);", options)]
            for forbidden in ("bypass", "replace"):
                require(forbidden not in names, f"{forbidden} rule options are not accepted")
            action = line.split(None, 1)[0]
            sid_options = [o.partition(":")[2].strip() for o in re.split(r"(?<!\\);", options)
                           if o.partition(":")[0].strip().lower() == "sid"]
            if selected or action == "drop":
                require(len(sid_options) == 1 and re.fullmatch(r"[1-9][0-9]{0,9}", sid_options[0]),
                        "one canonical SID required by blocking policy")
                sid = int(sid_options[0])
                occurrences[sid] = occurrences.get(sid, 0) + 1
                if action == "drop":
                    require(sid in selected and sid not in dropped, "unapproved or duplicate DROP SID")
                    dropped.add(sid)
                else:
                    require(sid not in selected, "selected SID is still alert")
            count += 1
    require(dropped == selected and all(occurrences[s] == 1 for s in selected),
            "missing or duplicate selected DROP SID")
    require(count > 0, "rules file has no active rules")
    return count


def validate_rules(cfg):
    path = secure_path(cfg["rules_file"])
    require(path.stat().st_size <= MAX_RULES_BYTES, "rules file too large")
    policy = ()
    configured_path = Path(cfg["rules_file"])
    release_path = configured_path.parent / "release.json"
    if release_path.exists() or release_path.is_symlink():
        # The explicit pinned release is the policy authority. Merely placing
        # DROP bytes beside the default configuration never enables blocking.
        from rule_release import verify_release
        release = verify_release(release_path)
        require(release["names"]["rules"] == configured_path.name, "release rule path differs")
        policy = release.get("drop_sids", ())
    with path.open("rb") as stream:
        return validate_rules_bytes(stream.read(MAX_RULES_BYTES + 1), policy)


def selected_rules(cfg, binary):
    """Use the engine's YAML parser to bind selection to the validated file.

    --dump-config exits without starting capture or compiling another engine.
    Only the managed, single-file rule-files profile is accepted here.
    """
    raw = run([str(binary), "--dump-config", "-c", cfg["suricata_config"]]).stdout
    require(len(raw.encode("utf-8")) <= MAX_MESSAGE, "configuration dump exceeds bound")
    rows = {}
    for line in raw.splitlines():
        key, sep, value = line.partition(" = ")
        if key in ("firewall.enabled", "multi-detect.enabled"):
            require(sep and value.lower() in ("no", "false"), "unsupported firewall or multi-detect mode")
        elif key in ("firewall", "multi-detect"):
            require(sep and value in ("(null)", ""), "unsupported engine mode")
        else:
            require(not key.startswith(("firewall", "multi-detect")), "unsupported secondary rules profile")
        if any(part in ("rule-files", "rule-path", "default-rule-path")
               or part.endswith(("-rule-files", "-rule-path")) for part in key.split(".")):
            require(key in ("default-rule-path", "rule-files", "rule-files.0"), "unsupported rule source")
            require(sep and key not in rows, "ambiguous rule selection in configuration dump")
            rows[key] = value
    path = Path(cfg["rules_file"])
    require(set(rows) == {"default-rule-path", "rule-files", "rule-files.0"}
            and rows["default-rule-path"] == str(path.parent)
            and rows["rule-files"] in ("(null)", "")
            and rows["rule-files.0"] == path.name,
            "effective YAML must select only the validated alert rules file")


def preflight(cfg, test_engine=True):
    require(Path("/sys/class/net", cfg["bridge"], "bridge").is_dir(), "configured interface is not a bridge")
    validate_rules(cfg)
    secure_path(cfg["suricata_config"])
    binary = Path(cfg["binary"]).resolve(strict=True)
    secure_path(binary)
    require("NFQueue support:" in (info := run([str(binary), "--build-info"]).stdout)
            and re.search(r"Suricata version 8\.", info)
            and re.search(r"NFQueue support:\s+yes", info), "Suricata 8.x with NFQUEUE support is required")
    selected_rules(cfg, binary)
    current = table(cfg)
    if current is not None:
        owned(cfg)
        require(exact_table(current, cfg), "foreign or modified nft table")
    run(["/usr/sbin/nft", "-c", "-f", "-"], ruleset(cfg))
    if test_engine:
        run([str(binary), "-T", "--simulate-ips", "-c", cfg["suricata_config"],
             "--init-errors-fatal", "--set", "unix-command.enabled=no"], timeout=ENGINE_TEST_TIMEOUT_SECONDS)


def sensor(cfg):
    pid = int(run(["/usr/bin/systemctl", "show", cfg["service"], "-p", "MainPID", "--value"]).stdout.strip())
    require(pid > 1, "service has no MainPID")
    require(Path("/proc", str(pid), "exe").resolve() == Path(cfg["binary"]).resolve(), "unexpected sensor executable")
    fields = Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()
    require(fields[0] != "Z", "sensor is a zombie")
    return {"pid": pid, "start_ticks": int(fields[19]),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}


def queue(cfg, pid):
    rows = [line.split() for line in Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines()]
    rows = [row for row in rows if row and row[0] == str(cfg["queue"])]
    require(len(rows) == 1 and len(rows[0]) == 9, "queue has no unique listener")
    values = [int(item) for item in rows[0]]
    require(all(item >= 0 for item in values) and values[3] == 2
            and 0 < values[4] <= 65535 and values[7] < SEQUENCE_MODULUS, "invalid queue schema")
    # A portid is not a process identity. Bind the unique NETLINK_NETFILTER
    # socket inode to a descriptor of the current sensor.
    sockets = [line.split() for line in Path("/proc/net/netlink").read_text().splitlines()[1:]]
    sockets = [row for row in sockets if len(row) == 10 and row[1] == "12"
               and row[2] == str(values[1])]
    require(len(sockets) == 1, "no unique NFQUEUE netlink socket")
    inode, drops = int(sockets[0][9]), int(sockets[0][8])
    require(inode > 0 and drops >= 0, "invalid netlink socket schema")
    wanted = "socket:[" + str(inode) + "]"
    found = False
    for fd in Path("/proc", str(pid), "fd").iterdir():
        try:
            found = os.readlink(fd) == wanted
        except FileNotFoundError:
            continue
        if found:
            break
    require(found, "NFQUEUE listener is not owned by the sensor")
    return {"pending": values[2], "kernel_dropped": values[5], "user_dropped": values[6],
            "id_sequence": values[7], "portid": values[1], "inode": inode, "netlink_dropped": drops}


def kernel_sample(cfg, current, observed=None):
    started = time.monotonic_ns()
    before = dict(queue(cfg, current["pid"]))
    if observed is not None:
        observed["queue_listener"] = 1
    document = table(cfg)
    owned(cfg)
    require(exact_table(document, cfg), "selector is absent or modified")
    if observed is not None:
        observed["nft_rule"] = 1
    objects = {kind: body for item in document["nftables"] for kind, body in item.items()
               if kind != "metainfo"}
    handles = [objects[kind].get("handle") for kind in ("table", "counter", "chain", "rule")]
    require(all(type(item) is int and item > 0 for item in handles), "missing nft object identity")
    packets = objects["counter"]["packets"]
    require(type(packets) is int and packets >= 0, "invalid nft packet counter")
    after = dict(queue(cfg, current["pid"]))
    finished = time.monotonic_ns()
    require((before["portid"], before["inode"]) == (after["portid"], after["inode"]),
            "socket changed during sample")
    require(sensor(cfg) == current, "sensor changed during sample")
    require(0 <= finished - started <= 1000000000, "kernel sample exceeded timing bound")
    return {"before": before, "after": after, "nft": {"packets": packets, "handles": handles},
            "started_ns": started, "finished_ns": finished, "boot_id": current["boot_id"]}


def sequence_delta(new, old):
    delta = (new - old) % SEQUENCE_MODULUS
    require(delta < SEQUENCE_MODULUS // 2, "queue sequence reset or ambiguous wrap")
    return delta


def account_kernel(previous, sample, current):
    """Bracket the nft counter with kernel sequence reads, not decoder stats.

    A positive gap is UNKNOWN: an in-flight packet and a loss cannot be
    distinguished by this observation. GSO may hide a gap. No gap is never
    proof of full inspection.
    """
    before, after = sample["before"], sample["after"]
    width = sequence_delta(after["id_sequence"], before["id_sequence"])
    prior = previous.get("kernel_accounting")
    reason = None
    total_before = 0
    ceiling = sample["nft"]["packets"]
    if isinstance(prior, dict):
        try:
            old = prior["sample"]
            same = (previous.get("sensor") == current and old["boot_id"] == sample["boot_id"]
                    and old["nft"]["handles"] == sample["nft"]["handles"]
                    and (old["after"]["portid"], old["after"]["inode"])
                    == (after["portid"], after["inode"]))
            elapsed = sample["started_ns"] - old["finished_ns"]
            require(same and elapsed >= 0, "observation continuity")
            growth = sample["nft"]["packets"] - old["nft"]["packets"]
            require(growth >= 0, "counter reset")
            if elapsed > MAX_OBSERVATION_GAP_NS:
                # A whole number of uint32 wraps cannot be ruled out by a
                # small modulo delta. Keep this coverage gap separate from loss.
                reason = "nfqueue.observation_gap"
            else:
                require(growth < SEQUENCE_MODULUS // 2, "ambiguous number of wraps")
                total_before = prior["total_after"] + sequence_delta(
                    before["id_sequence"], old["after"]["id_sequence"])
                ceiling = prior["offset_ceiling"]
        except (KeyError, TypeError, RuntimeError):
            reason = "nfqueue.observation_discontinuity"
            total_before = 0
            ceiling = sample["nft"]["packets"]
    elif previous.get("sensor") not in (None, current):
        reason = "nfqueue.observation_discontinuity"
    total_after = total_before + width
    low, high = sample["nft"]["packets"] - total_after, sample["nft"]["packets"] - total_before
    gap = max(0, low - ceiling)
    history = [gap]
    if isinstance(prior, dict):
        history += [prior.get("gap_history_peak", 0), prior.get("unexplained_gap", 0)]
    require(all(type(value) is int and value >= 0 for value in history),
            "invalid accounting gap history")
    history_latched = prior.get("gap_history_latched", max(history) > 0) if isinstance(prior, dict) else False
    observation_latched = prior.get("observation_gap_history_latched", False) if isinstance(prior, dict) else False
    require(type(history_latched) is bool and type(observation_latched) is bool,
            "invalid accounting history latch")
    state = {"sample": sample, "total_after": total_after,
             "offset_ceiling": min(ceiling, high), "unexplained_gap": gap,
             "gap_history_peak": max(history), "gap_history_latched": bool(history_latched or gap),
             "observation_gap_history_latched": bool(observation_latched or reason == "nfqueue.observation_gap")}
    return state, gap, reason


def flatten(value, prefix=""):
    result = {}
    if isinstance(value, dict):
        for name, item in value.items():
            if name != "threads":
                result.update(flatten(item, prefix + "." + name if prefix else name))
    elif type(value) is int and value >= 0:
        result[prefix] = value
    return result


def receive(stream):
    raw = bytearray()
    while len(raw) < MAX_MESSAGE:
        chunk = stream.recv(min(65536, MAX_MESSAGE - len(raw)))
        require(chunk, "sensor socket EOF")
        raw.extend(chunk)
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            pass
    raise RuntimeError("sensor response too large")


def counters(cfg, pid):
    require(not Path(cfg["socket"]).is_symlink(), "socket must not be a symlink")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect(cfg["socket"])
        peer = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer[0] == pid and peer[1] == 0, "foreign sensor socket peer")
        stream.sendall(b'{"version":"0.2"}\n')
        require(receive(stream).get("return") == "OK", "socket handshake failed")
        stream.sendall(b'{"command":"dump-counters"}\n')
        response = receive(stream)
    require(response.get("return") == "OK" and isinstance(response.get("message"), dict), "invalid counters")
    return flatten(response["message"])


def arm(cfg):
    preflight(cfg, test_engine=False)
    deadline = time.monotonic() + SENSOR_READY_TIMEOUT_SECONDS
    while True:
        try:
            current_sensor = sensor(cfg)
            queue(cfg, current_sensor["pid"])
            counters(cfg, current_sensor["pid"])
            break
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, IndexError):
            require(time.monotonic() < deadline, "sensor listener did not become ready")
            time.sleep(0.25)
    current = table(cfg)
    if current is not None:
        owned(cfg)
        require(exact_table(current, cfg), "foreign or modified nft table after sensor readiness")
        return
    atomic(Path(cfg["runtime_dir"]) / "owner.json", json.dumps(identity(cfg)))
    transaction = "create table bridge " + cfg["table"] + "\n" + ruleset(cfg)
    result = run(["/usr/sbin/nft", "-f", "-"], transaction, check=False)
    if result.returncode > 0:
        # The atomic transaction was rejected; the marker must not claim a racing table.
        (Path(cfg["runtime_dir"]) / "owner.json").unlink(missing_ok=True)
    require(result.returncode == 0, "nft transaction failed: " + result.stderr[:500])
    require(exact_table(table(cfg), cfg), "installed nft table does not match")


def disarm(cfg):
    current = table(cfg)
    if current is not None:
        owned(cfg)
        require(exact_table(current, cfg), "refusing to delete a foreign or modified table")
        run(["/usr/sbin/nft", "delete", "table", "bridge", cfg["table"]])
        require(table(cfg) is None, "nft table still exists")
    marker = Path(cfg["runtime_dir"]) / "owner.json"
    if marker.exists():
        owned(cfg)
        marker.unlink()


def midstream_counter(name):
    return name.startswith(("tcp.midstream_exception_policy.", "exception_policy.tcp.midstream."))


def observe(cfg, previous=None):
    previous = previous or {"latched": False, "sensor": None}
    prior_accounting = previous.get("kernel_accounting")
    prior_history = isinstance(prior_accounting, dict) and any(prior_accounting.get(name) is True for name in
        ("gap_history_latched", "observation_gap_history_latched"))
    metrics = {"telemetry_known": 0, "sensor_up": 0, "queue_listener": 0, "nft_rule": 0,
               "degraded_latched": int(previous["latched"] or prior_history), "full_inspection_verified": 0,
               "last_publish_unix_seconds": time.time()}
    state = {**previous, "current_sample_valid": False, "kernel_sample_valid": False}
    try:
        current = sensor(cfg)
        metrics["sensor_up"] = 1
        sample = kernel_sample(cfg, current, metrics)
        q = sample["after"]
        packets = sample["nft"]["packets"]
        metrics.update({"queue_listener": 1, "nft_rule": 1})
        # Preserve independently observed kernel continuity even when the Unix
        # manager is busy with a blocking reload and dump-counters times out.
        accounting, gap, continuity_reason = account_kernel(previous, sample, current)
        baseline = previous.get("counters", {}) if previous.get("sensor") == current else {}
        kernel_reasons = ["nfqueue." + name for name in
                          ("kernel_dropped", "user_dropped", "netlink_dropped")
                          if max(sample["before"][name], q[name]) != baseline.get("nfqueue." + name, 0)]
        if continuity_reason and continuity_reason != "nfqueue.observation_gap":
            kernel_reasons.append(continuity_reason)
        state = {**state, "sensor": current, "kernel_accounting": accounting,
                 "accounting_status": "UNKNOWN_GAP" if gap else
                     ("UNKNOWN_DISCONTINUITY" if continuity_reason else "OBSERVED_NO_GAP"),
                 "kernel_sample_valid": True, "reasons": kernel_reasons,
                 "counters": previous.get("counters", {}) if previous.get("sensor") == current else {},
                 "latched": bool(previous["latched"] or kernel_reasons),
                 "gap_acknowledgements": previous.get("gap_acknowledgements", [])}
        state["accounting_claim_sha256"] = accounting_claim(state)
        metrics.update({"nft_packets_total": packets,
                        "accounting_unexplained_gap": gap,
                        "accounting_gap_history_peak": accounting["gap_history_peak"],
                        "accounting_gap_history_latched": int(accounting["gap_history_latched"]),
                        "accounting_observation_gap_history_latched": int(accounting["observation_gap_history_latched"]),
                        "degraded_latched": int(state["latched"] or accounting["gap_history_latched"]
                                                or accounting["observation_gap_history_latched"]),
                        **{"queue_" + key: q[key] for key in
                           ("pending", "kernel_dropped", "user_dropped", "netlink_dropped", "id_sequence")}})
        data = counters(cfg, current["pid"])
        require(all(name in data for name in (*LOSS_COUNTERS, "decoder.pkts", "uptime"))
                and data["uptime"] > 0, "incomplete counters")
        watched = {name: value for name, value in data.items() if not midstream_counter(name) and
                   (name in LOSS_COUNTERS or any("exception_policy" in segment for segment in name.split(".")) or
                    name.startswith("capture.nfq.copy_") or name in ("defrag.max_frags_reached",
                    "defrag.max_trackers_reached", "defrag.tracker_hard_reuse"))}
        watched.update({"nfqueue." + name: max(sample["before"][name], q[name])
                        for name in ("kernel_dropped", "user_dropped", "netlink_dropped")})
        same_sensor = previous.get("sensor") == current
        prior_counters = previous.get("counters", {}) if same_sensor else {}
        require(isinstance(prior_counters, dict) and all(type(v) is int and v >= 0 for v in prior_counters.values()),
                "invalid previous counters")
        require(set(prior_counters).issubset(watched), "previously observed counter is missing")
        reasons = [name for name, value in watched.items() if value > prior_counters.get(name, 0)]
        if any(value < prior_counters.get(name, 0) for name, value in watched.items()):
            reasons.append("counter_reset")
        if previous.get("sensor") not in (None, current):
            reasons.append("sensor_restarted")
        history_gap = accounting["gap_history_peak"]
        if continuity_reason and continuity_reason != "nfqueue.observation_gap":
            reasons.append(continuity_reason)
        candidate = {"kernel_accounting": accounting, "kernel_sample_valid": True,
                     "current_sample_valid": not continuity_reason,
                     "accounting_status": "UNKNOWN_GAP" if gap else
                        ("UNKNOWN_DISCONTINUITY" if continuity_reason else "OBSERVED_NO_GAP"),
                     "gap_acknowledgements": previous.get("gap_acknowledgements", []),
                     "sensor": current, "latched": bool(previous["latched"] or reasons), "reasons": reasons,
                     "counters": watched}
        candidate["accounting_claim_sha256"] = accounting_claim(candidate)
        require(len(json.dumps(candidate).encode()) <= MAX_STATE, "observed state too large")
        state = candidate
        midstream = [value for name, value in data.items() if midstream_counter(name)]
        if midstream:
            metrics["midstream_policy_events_total"] = sum(midstream)
        metrics.update({"telemetry_known": int(not gap and not continuity_reason),
                        "accounting_gap_history_peak": history_gap,
                        "accounting_gap_history_latched": int(accounting["gap_history_latched"]),
                        "accounting_observation_gap_history_latched": int(accounting["observation_gap_history_latched"]),
                        "accounting_unexplained_gap": gap,
                        "degraded_latched": int(state["latched"] or accounting["gap_history_latched"]
                                                or accounting["observation_gap_history_latched"]),
                        "nft_packets_total": packets,
                        "decoder_packets_total": data["decoder.pkts"], "sensor_uptime_seconds": data["uptime"],
                        **{"queue_" + key: q[key] for key in
                           ("pending", "kernel_dropped", "user_dropped", "netlink_dropped", "id_sequence")}})
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        state["error"] = str(error)[:240]
    return {"metrics": metrics, "state": state}


@contextlib.contextmanager
def locked(cfg):
    import fcntl
    secure_path(cfg["runtime_dir"], directory=True)
    fd = os.open(Path(cfg["runtime_dir"]) / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, "unsafe lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def previous_state(cfg):
    path = Path(cfg["state_dir"]) / "monitor.json"
    previous = None
    if path.exists() or path.is_symlink():
        try:
            secure_path(path)
            require(path.stat().st_size <= MAX_STATE, "state too large")
            previous = json.loads(path.read_text(), object_pairs_hook=unique)
            require(isinstance(previous, dict) and type(previous["latched"]) is bool, "invalid latch")
            saved_counters = previous.get("counters", {})
            require(isinstance(saved_counters, dict) and all(isinstance(k, str) and type(v) is int and v >= 0
                    for k, v in saved_counters.items()), "invalid saved counters")
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            previous = {"latched": True, "sensor": None}
    return previous


def accounting_claim(state):
    accounting = state["kernel_accounting"]
    sample = accounting["sample"]
    claim = {"schema": "public0-accounting-claim-v1", "sensor": state.get("sensor"),
        "boot_id": sample["boot_id"], "socket": [sample["after"]["portid"], sample["after"]["inode"]],
        "nft_handles": sample["nft"]["handles"], "gap": accounting["unexplained_gap"],
        "peak": accounting["gap_history_peak"], "gap_history": accounting["gap_history_latched"],
        "observation_history": accounting.get("observation_gap_history_latched", False),
        "ack_count": len(state.get("gap_acknowledgements", []))}
    return hashlib.sha256(json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def acknowledge_accounting_gap(state, metrics, evidence, expected_history=None):
    """Record an explicit operator decision and fresh baseline in the same state write.

    The supplied SHA references evidence; its format does not attest that evidence.
    Other degradation latches and the historical peak are never cleared here.
    """
    require(isinstance(evidence, str) and re.fullmatch(r"[0-9a-f]{64}", evidence), "evidence SHA256 required")
    require(state.get("current_sample_valid") is True, "cannot acknowledge incomplete current observation")
    require(isinstance(expected_history, str) and re.fullmatch(r"[0-9a-f]{64}", expected_history)
            and expected_history == accounting_claim(state), "accounting history changed or expected claim missing")
    accounting = state["kernel_accounting"]
    require(accounting["gap_history_latched"] or accounting.get("observation_gap_history_latched", False),
            "no historical gap to acknowledge")
    log = state.get("gap_acknowledgements", [])
    require(isinstance(log, list) and len(log) < 32, "accounting acknowledgement audit bound reached")
    before = json.loads(json.dumps(accounting))
    state["gap_acknowledgements"] = log + [{"evidence_sha256": evidence, "expected_history_sha256": expected_history,
        "before": before,
        "monotonic_ns": time.monotonic_ns(), "unix_ns": time.time_ns(),
        "other_latch_preserved": state["latched"]}]
    sample = accounting["sample"]
    accounting.update(total_after=sequence_delta(sample["after"]["id_sequence"], sample["before"]["id_sequence"]),
                      offset_ceiling=sample["nft"]["packets"], gap_history_latched=False,
                      observation_gap_history_latched=False, unexplained_gap=0)
    state["accounting_status"] = "ACKNOWLEDGED_GAP_HISTORY"
    state["accounting_claim_sha256"] = accounting_claim(state)
    metrics.update(accounting_gap_history_latched=0, accounting_observation_gap_history_latched=0,
                   accounting_unexplained_gap=0, degraded_latched=int(state["latched"]))


def monitor(cfg, acknowledge=False, accounting_gap_evidence=None, accounting_gap_expected=None):
    path = Path(cfg["state_dir"]) / "monitor.json"
    result = observe(cfg, previous_state(cfg))
    if acknowledge:
        require(result["metrics"]["telemetry_known"] == 1, "cannot acknowledge unknown telemetry")
        result["state"].update({"latched": False, "reasons": []})
        accounting = result["state"]["kernel_accounting"]
        result["metrics"]["degraded_latched"] = int(accounting["gap_history_latched"]
            or accounting.get("observation_gap_history_latched", False))
    if accounting_gap_evidence is not None:
        acknowledge_accounting_gap(result["state"], result["metrics"], accounting_gap_evidence,
                                   accounting_gap_expected)
    state_json = json.dumps(result["state"], sort_keys=True)
    require(len(state_json.encode()) <= MAX_STATE, "state publication too large")
    atomic(path, state_json)
    publish_metrics(cfg, result["metrics"])
    return result


def publish_metrics(cfg, metrics):
    labels = '{bridge="' + cfg["bridge"] + '",queue="' + str(cfg["queue"]) + '"}'
    output = "# cs-public0 runtime telemetry\n" + "".join(
        "cs_public0_" + name + labels + " " + format(value, ".17g") + "\n"
        for name, value in sorted(metrics.items()))
    atomic(cfg["metrics_file"], output, 0o644)


@contextlib.contextmanager
def monitored_lock(cfg, monitored):
    with locked(cfg):
        if not monitored:
            yield
            return
        try:
            yield
        except Exception:
            # All publishers retain the state lock. A lock acquisition failure
            # leaves the old timestamp for freshness monitoring instead.
            try:
                prior = previous_state(cfg) or {"latched": False}
                accounting = prior.get("kernel_accounting", {})
                require(type(prior["latched"]) is bool and isinstance(accounting, dict), "invalid fallback state")
                retained = prior["latched"] or any(accounting.get(name) is True for name in
                    ("gap_history_latched", "observation_gap_history_latched"))
            except Exception:
                retained = True
            try:
                publish_metrics(cfg, {"telemetry_known": 0, "degraded_latched": int(retained),
                    "full_inspection_verified": 0, "last_publish_unix_seconds": time.time()})
            except Exception as publication_error:
                print("UNKNOWN publication failed: " + type(publication_error).__name__, file=sys.stderr)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/cs-public0/config.json")
    parser.add_argument("command", choices=("check", "arm", "disarm", "status", "monitor", "acknowledge", "validate-rules", "acknowledge-accounting-gap"))
    parser.add_argument("--evidence-sha256")
    parser.add_argument("--expected-history-sha256")
    args = parser.parse_args()
    require((args.command == "acknowledge-accounting-gap") == (args.evidence_sha256 is not None)
            and (args.command == "acknowledge-accounting-gap") == (args.expected_history_sha256 is not None),
            "evidence and expected history are required only for acknowledge-accounting-gap")
    require(os.geteuid() == 0, "root required")
    cfg = load_config(args.config)
    with monitored_lock(cfg, args.command == "monitor"):
        if args.command == "validate-rules":
            result = {"alert_rules": validate_rules(cfg)}
        elif args.command == "status":
            result = observe(cfg, previous_state(cfg))
        elif args.command in ("monitor", "acknowledge", "acknowledge-accounting-gap"):
            result = monitor(cfg, acknowledge=args.command == "acknowledge",
                             accounting_gap_evidence=args.evidence_sha256,
                             accounting_gap_expected=args.expected_history_sha256)
        else:
            {"check": preflight, "arm": arm, "disarm": disarm}[args.command](cfg)
            result = {"command": args.command, "ok": True}
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
