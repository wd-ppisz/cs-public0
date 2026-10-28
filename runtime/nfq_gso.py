#!/usr/bin/env python3
"""Verify explicit GSO activation for one pinned NFQUEUE engine invocation.

The acknowledgement is specific to the optional source-nfq GSO patch. Stock
Suricata accepting an unknown YAML key is not evidence of GSO activation.
This program never installs a selector, stops a service or changes NIC offloads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(argv):
    result = subprocess.run(argv, capture_output=True, timeout=5, check=True)
    require(len(result.stdout) <= 65536, "GSO observation exceeds bound")
    return result.stdout.decode("utf-8", "strict")


def unit_state(unit):
    raw = command(["systemctl", "show", unit, "-p", "MainPID", "-p", "InvocationID",
                   "-p", "ActiveState"])
    result = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    require(set(result) == {"MainPID", "InvocationID", "ActiveState"}, "incomplete unit state")
    return result


def explicit_gso(argv):
    settings = [value for value in argv if value.startswith("nfq.gso=")]
    return (settings == ["nfq.gso=yes"] and
            any(a == "--set" and b == "nfq.gso=yes" for a, b in zip(argv, argv[1:])))


def observe(unit, binary_sha256, queue):
    value = {"known": False, "enabled": False, "pid": 0, "invocation": None,
             "sample_unix_seconds": time.time()}
    try:
        before = unit_state(unit)
        require(before["ActiveState"] in ("active", "activating"), "sensor is inactive")
        pid = int(before["MainPID"])
        invocation = before["InvocationID"]
        require(pid > 1 and re.fullmatch(r"[a-f0-9]{32}", invocation), "unknown invocation")
        process = Path("/proc") / str(pid)
        start = (process / "stat").read_bytes().rsplit(b")", 1)[1].split()[19]
        argv = (process / "cmdline").read_bytes().decode().rstrip("\0").split("\0")
        require(explicit_gso(argv), "explicit nfq.gso=yes is missing or overridden")
        require(hashlib.sha256((process / "exe").read_bytes()).hexdigest() == binary_sha256,
                "unexpected engine binary")
        rows = [line.split() for line in Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines()
                if line.split() and line.split()[0] == str(queue)]
        require(len(rows) == 1 and len(rows[0]) == 9 and int(rows[0][1]) == pid,
                "queue does not belong to the bound process")
        acknowledgement = command(["journalctl", "--no-pager", "-o", "cat", "-n", "1",
                                   "-u", unit, "_SYSTEMD_INVOCATION_ID=" + invocation,
                                   "--grep=NFQUEUE GSO enabled"])
        require(any(line.strip().endswith("NFQUEUE GSO enabled")
                    for line in acknowledgement.splitlines()), "GSO acknowledgement is absent")
        require(unit_state(unit) == before and
                (process / "stat").read_bytes().rsplit(b")", 1)[1].split()[19] == start,
                "sensor invocation changed during observation")
        value.update(known=True, enabled=True, pid=pid, invocation=invocation)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        value["error"] = str(error)[:240]
    return value


def metrics(value, host):
    require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", host), "invalid metric host")
    labels = '{host="' + host + '",profile="public0-ipv4-alert"}'
    fields = {"known": int(value["known"]), "enabled": int(value["enabled"]),
              "last_publish_unix_seconds": value["sample_unix_seconds"]}
    return "".join("cs_public0_gso_" + name + labels + " " + str(number) + "\n"
                   for name, number in fields.items())


def publish(path, text):
    path = Path(path)
    require(path.is_absolute() and path.name.endswith(".prom") and ".." not in path.parts,
            "absolute textfile path required")
    for directory in (path.parent, *path.parent.parents):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe metrics directory")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe existing metrics file")
    temporary = path.with_name(path.name + ".tmp-" + str(os.getpid()))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(text.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--queue", type=int, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--metrics-file")
    parser.add_argument("--require", action="store_true", help="refuse startup without GSO")
    parser.add_argument("--wait-seconds", type=int, default=0)
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,80}\.service", args.unit), "invalid unit")
    require(re.fullmatch(r"[a-f0-9]{64}", args.binary_sha256), "explicit engine pin required")
    require(0 <= args.queue <= 65535 and 0 <= args.wait_seconds <= 90, "invalid bound")
    deadline = time.monotonic() + args.wait_seconds
    while True:
        value = observe(args.unit, args.binary_sha256, args.queue)
        if value["enabled"] or time.monotonic() >= deadline:
            break
        time.sleep(.5)
    if args.metrics_file:
        publish(args.metrics_file, metrics(value, args.host))
    print(json.dumps(value, sort_keys=True))
    if args.require and not value["enabled"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
