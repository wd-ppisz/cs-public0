#!/usr/bin/env python3
"""Journal an explicit verifier/monitor/controller-pin refresh, without a reload.

Stage all new controller sources first. Apply under a bounded systemd unit with
this helper's recover command as ExecStopPost. Rule activation is a separate plan.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat

import observer_refresh as io


def load(path, expected):
    raw = io.read(path, 16384)
    io.require(io.digest(raw) == expected, "policy refresh plan changed")
    p = json.loads(raw)
    io.require(set(p) == {"schema", "host", "unit", "binding", "timer", "store", "state",
                           "targets", "verifier", "gso_argv", "preserve"}
               and p["schema"] == "cs-public0-policy-refresh-v1", "policy refresh schema")
    io.require(os.geteuid() == 0 and socket.getfqdn() == p["host"], "exact root host required")
    io.require(re.fullmatch(r"[A-Za-z0-9_-]{1,80}\.service", p["unit"])
               and re.fullmatch(r"[A-Za-z0-9_-]{1,80}\.timer", p["timer"]), "invalid unit scope")
    store = Path(p["store"])
    io.require(store == Path(path).parent and len(p["targets"]) == 3
               and p["verifier"] in p["targets"] and p["state"] not in p["targets"],
               "separate exact refresh scope required")
    io.require(p["timer"].endswith(".timer") and p["timer"][:-6] + ".service" != p["unit"],
               "sensor is not the monitor")
    for target, spec in p["targets"].items():
        io.require(set(spec) == {"before_sha256", "after_sha256", "image", "mode", "gid"}
                   and Path(spec["image"]).name == spec["image"]
                   and spec["mode"] in (0o600, 0o644, 0o755)
                   and type(spec["gid"]) is int and spec["gid"] >= 0,
                   "invalid target image contract")
        io.require(all(isinstance(spec[k], str) and re.fullmatch("[a-f0-9]{64}", spec[k])
                       for k in ("before_sha256", "after_sha256")), "canonical image pins required")
        io.require(io.digest(io.read(store / spec["image"])) == spec["after_sha256"],
                   "candidate image changed")
    return p


def timers(p):
    io.command(["systemctl", "start", p["timer"]])


def restore(p):
    store = Path(p["store"])
    try:
        if (store / "started.json").exists() and not (store / "committed.json").exists():
            for number, (target, spec) in enumerate(p["targets"].items()):
                raw = io.read(store / ("before-" + str(number)))
                io.require(io.digest(raw) == spec["before_sha256"], "rollback image differs")
                io.replace(target, raw, {spec["before_sha256"], spec["after_sha256"]},
                           spec["mode"], spec["gid"])
            io.command([p["verifier"], "verify"])
    finally:
        timers(p)


def apply(p):
    store = Path(p["store"])
    io.require(not (store / "started.json").exists(), "refresh is one-shot; inspect existing journal")
    io.require(io.binding(p["unit"]) == p["binding"], "sensor changed")
    io.command([p["verifier"], "verify"])
    guard = json.loads(io.command(p["gso_argv"]))
    io.require(guard.get("known") is True and guard.get("enabled") is True
               and guard.get("invocation") == p["binding"]["InvocationID"], "GSO/buffer unknown")
    for path, pin in p["preserve"].items():
        io.require(io.digest(io.read(path, 64 * 1024 * 1024)) == pin, "preserved source differs")
    for number, (target, spec) in enumerate(p["targets"].items()):
        raw = io.read(target)
        io.require(io.digest(raw) == spec["before_sha256"], "refresh baseline differs")
        info = Path(target).stat()
        io.require(info.st_gid == spec["gid"] and (info.st_mode & 0o777) == spec["mode"],
                   "target metadata differs")
        io.create(store / ("before-" + str(number)), raw)
    # All rollback images precede the intent and first target write.
    io.create(store / "started.json", io.encoded({"phase": "STARTED", "binding": p["binding"]}))
    try:
        io.command(["systemctl", "stop", p["timer"], p["timer"][:-6] + ".service"])
        history = io.read(p["state"], 65536)
        io.create(store / "monitor-history.json", history)
        io.require(io.binding(p["unit"]) == p["binding"], "sensor changed before write")
        for target, spec in p["targets"].items():
            io.replace(target, io.read(store / spec["image"]), {spec["before_sha256"]},
                       spec["mode"], spec["gid"])
        io.command([p["verifier"], "verify"])
        io.require(io.binding(p["unit"]) == p["binding"], "sensor changed during refresh")
        io.require(io.read(p["state"], 65536) == history, "monitor history changed during refresh")
        for path, pin in p["preserve"].items():
            io.require(io.digest(io.read(path, 64 * 1024 * 1024)) == pin, "preserved source changed")
        io.create(store / "committed.json", io.encoded({"phase": "COMMITTED_RULES_UNCHANGED",
                  "binding": p["binding"], "history_sha256": io.digest(history)}))
    except BaseException:
        restore(p)
        raise
    finally:
        timers(p)


def main():
    a = argparse.ArgumentParser()
    a.add_argument("command", choices=("apply", "recover"))
    a.add_argument("--plan", required=True)
    a.add_argument("--plan-sha256", required=True)
    args = a.parse_args()
    p = load(args.plan, args.plan_sha256)
    # Same lock domain as rule activation. No concurrent metadata writer.
    # The existing release target supplies the activation lock, never libexec.
    releases = [Path(t) for t in p["targets"] if Path(t).name == "release.json"]
    io.require(len(releases) == 1, "one release target required")
    io.read(releases[0], 16384)  # Validate root-owned ancestry before creating a lock.
    lock_path = releases[0].parent / ".activation.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        io.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                   and not info.st_mode & 0o077,
                   "unsafe activation lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (apply if args.command == "apply" else restore)(p)
        print(json.dumps({"command": args.command, "committed":
                          (Path(p["store"]) / "committed.json").exists()}))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
