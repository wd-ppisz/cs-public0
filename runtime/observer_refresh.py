#!/usr/bin/env python3
"""Refresh pinned observer code without changing the running sensor or rules.

Run apply under a bounded systemd transient service with rollback as ExecStopPost.
The profile, helper, plan and before/new images must be root-owned regular files.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit=524288):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute path required")
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe parent")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= limit, "unsafe file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        require(len(raw) <= limit and all(getattr(info, k) == getattr(after, k) for k in
                ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")), "file changed")
        return raw
    finally:
        os.close(fd)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def create(path, raw, mode=0o600, gid=0):
    # Validate every ancestor before creating a new leaf.
    for parent in Path(path).parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe image parent")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def replace(path, raw, allowed, mode, gid=0):
    require(digest(read(path)) in allowed, "foreign target")
    tmp = Path(path).with_name(".observer-refresh-" + secrets.token_hex(16))
    try:
        create(tmp, raw, mode, gid)
        require(digest(read(path)) in allowed, "target changed")
        os.replace(tmp, path)
        info = Path(path).lstat()
        require(info.st_uid == 0 and info.st_gid == gid and
                stat.S_IMODE(info.st_mode) == mode, "replacement metadata differs")
        fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    require(result.returncode == 0, "command failed: " + argv[0] + ": " + result.stderr[:500])
    require(len(result.stdout.encode()) <= 65536, "command output exceeds bound")
    return result.stdout


def binding(unit):
    raw = command(["systemctl", "show", unit, "-p", "MainPID", "-p", "InvocationID",
                   "-p", "ActiveState", "-p", "SubState"])
    result = dict(line.split("=", 1) for line in raw.splitlines())
    require(set(result) == {"MainPID", "InvocationID", "ActiveState", "SubState"}
            and result["ActiveState"] == "active" and result["SubState"] == "running"
            and int(result["MainPID"]) > 1
            and re.fullmatch("[a-f0-9]{32}", result["InvocationID"]), "unknown sensor binding")
    result["start_ticks"] = Path("/proc", result["MainPID"], "stat").read_text().rsplit(")", 1)[1].split()[19]
    return result


def check_profile(p):
    expected = {"host", "unit", "state_dir", "release", "release_sha256", "observer_paths",
                "candidate", "candidate_sha256", "verifier", "verifier_sha256",
                "binary_sha256", "queue", "rcvbuf_size", "timer_units"}
    require(set(p) == expected and socket.getfqdn() == p["host"], "profile/host differs")
    require(re.fullmatch("[A-Za-z0-9_-]{1,80}\\.service", p["unit"]), "invalid sensor unit")
    require(type(p["queue"]) is int and 0 <= p["queue"] <= 65535, "invalid queue")
    require(type(p["rcvbuf_size"]) is int and
            (p["rcvbuf_size"] == 0 or 1048576 <= p["rcvbuf_size"] <= 67108864), "invalid buffer")
    require(isinstance(p["observer_paths"], dict) and 1 <= len(p["observer_paths"]) <= 2,
            "one or two exact observer targets required")
    require(isinstance(p["timer_units"], list) and len(p["timer_units"]) == 2
            and len(set(p["timer_units"])) == 2 and
            all(re.fullmatch("[A-Za-z0-9_-]{1,80}\\.timer", x) for x in p["timer_units"]) and
            p["unit"] not in [x[:-6] + ".service" for x in p["timer_units"]], "invalid monitor scope")
    for value in [p["release_sha256"], p["candidate_sha256"], p["verifier_sha256"],
                  p["binary_sha256"], *p["observer_paths"].values()]:
        require(isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value), "invalid pin")
    for path in [p["state_dir"], p["release"], p["verifier"], p["candidate"], *p["observer_paths"]]:
        require(isinstance(path, str) and re.fullmatch("/[A-Za-z0-9_./-]{1,220}", path)
                and ".." not in Path(path).parts, "unsafe profile path")
    require(len(set([p["release"], p["verifier"], p["candidate"], *p["observer_paths"]])) ==
            3 + len(p["observer_paths"]), "overlapping profile paths")


def verify(profile):
    require(digest(read(profile["verifier"])) == profile["verifier_sha256"], "verifier differs")
    command([profile["verifier"], "verify"])


def active_monitors(profile):
    for timer in profile["timer_units"]:
        require(command(["systemctl", "is-active", timer]).strip() == "active", "monitor timer inactive")


def prepare(profile_path, expected):
    raw = read(profile_path)
    require(digest(raw) == expected, "profile pin differs")
    profile = json.loads(raw)
    check_profile(profile)
    candidate = read(profile["candidate"], 131072)
    require(digest(candidate) == profile["candidate_sha256"], "candidate differs")
    compile(candidate, "<observer>", "exec")
    release_raw = read(profile["release"], 16384)
    require(digest(release_raw) == profile["release_sha256"], "release baseline differs")
    release = json.loads(release_raw)
    require(release["schema"] in ("cs-public0-rule-release-v1", "cs-public0-rule-release-v2")
            and isinstance(release["immutable"], dict) and len(release["immutable"]) <= 32,
            "unsupported release")
    verify(profile)
    active_monitors(profile)
    identity = binding(profile["unit"])
    images = {}
    updated = copy.deepcopy(release)
    for path, old_sha in profile["observer_paths"].items():
        old = read(path, 131072)
        require(digest(old) == old_sha, "observer baseline differs")
        if path in updated["immutable"]:
            require(updated["immutable"][path] == old_sha, "release observer pin differs")
            updated["immutable"][path] = digest(candidate)
        images[path] = {"old": old.hex(), "new": candidate.hex(),
                        "mode": stat.S_IMODE(Path(path).stat().st_mode),
                        "gid": Path(path).stat().st_gid}
    new_release = encoded(updated) if updated != release else release_raw
    require(len(new_release) <= 16384, "release exceeds existing bound")
    images[profile["release"]] = {"old": release_raw.hex(), "new": new_release.hex(),
                                 "mode": stat.S_IMODE(Path(profile["release"]).stat().st_mode),
                                 "gid": Path(profile["release"]).stat().st_gid}
    token = secrets.token_hex(16)
    directory = Path(profile["state_dir"]) / ("observer-refresh-" + token)
    # Existing state directory is required; never create arbitrary parent paths.
    for parent in (directory.parent, *directory.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe state directory")
    directory.mkdir(mode=0o700)
    plan = {"schema": "cs-public0-observer-refresh-v1", "token": token, "profile": profile,
            "binding": identity, "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "helper": str(Path(__file__).resolve()), "helper_sha256": digest(read(__file__)),
            "images": images}
    create(directory / "plan.json", encoded(plan))
    create(directory / "state.json", encoded({"phase": "PREPARED"}))
    require(binding(profile["unit"]) == identity, "sensor changed during preparation")
    return {"plan": str(directory / "plan.json"), "sha256": digest(encoded(plan))}


def load_plan(path, expected, recovery=False):
    raw = read(path)
    require(digest(raw) == expected, "plan pin differs")
    p = json.loads(raw)
    check_profile(p["profile"])
    require(p["schema"] == "cs-public0-observer-refresh-v1"
            and re.fullmatch("[a-f0-9]{32}", p["token"])
            and Path(path) == Path(p["profile"]["state_dir"]) / ("observer-refresh-" + p["token"]) / "plan.json"
            and p["helper"] == str(Path(__file__).resolve())
            and digest(read(__file__)) == p["helper_sha256"], "plan binding differs")
    if not recovery:
        require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == p["boot"],
                "plan boot differs")
    require(set(p["images"]) == {p["profile"]["release"], *p["profile"]["observer_paths"]},
            "plan target scope differs")
    return p


def state(path, phase):
    dest = Path(path).with_name("state.json")
    replace(dest, encoded({"phase": phase}), {digest(read(dest))}, 0o600)


def known(p):
    for path, row in p["images"].items():
        require(digest(read(path)) in {digest(bytes.fromhex(row["old"])),
                                      digest(bytes.fromhex(row["new"]))}, "foreign target")


def monitors(p, action):
    timers = p["profile"]["timer_units"]
    services = [x[:-6] + ".service" for x in timers]
    command(["systemctl", action, *timers, *services])


def install(p, side):
    for path, row in p["images"].items():
        raw = bytes.fromhex(row[side])
        replace(path, raw, {digest(bytes.fromhex(row["old"])), digest(bytes.fromhex(row["new"]))},
                row["mode"], row["gid"])


def rollback(path, p):
    phase = json.loads(read(Path(path).with_name("state.json")))["phase"]
    if phase in ("PREPARED", "COMMITTED", "ROLLED_BACK"):
        return {"phase": phase, "action": "NONE"}
    require(phase == "APPLYING", "unknown transaction phase")
    known(p)
    monitors(p, "stop")
    install(p, "old")
    try:
        verify(p["profile"])
    finally:
        monitors(p, "start")
    state(path, "ROLLED_BACK")
    return {"phase": "ROLLED_BACK"}


def execution_guard(path, p):
    unit = "cs-public0-observer-refresh-" + p["token"] + ".service"
    props = ["InvocationID", "MainPID", "Type", "RuntimeMaxUSec", "TimeoutStopUSec", "KillMode", "ExecStopPost"]
    argv = ["systemctl", "show", unit]
    for name in props:
        argv += ["-p", name]
    raw = command(argv)
    values = dict(line.split("=", 1) for line in raw.splitlines())
    expected = ("argv[]=/usr/bin/python3 -B " + p["helper"] + " rollback --file " +
                str(path) + " --sha256 " + digest(read(path)) + " ;")
    require(set(values) == set(props) and
            re.fullmatch("[a-f0-9]{32}", values["InvocationID"]) and
            values["InvocationID"] == os.environ.get("INVOCATION_ID") and
            values["MainPID"] == str(os.getpid()) and values["Type"] == "exec" and
            values["RuntimeMaxUSec"] in ("1min 30s", "1min30s", "90s") and
            values["TimeoutStopUSec"] in ("2min", "2min 0s", "120s") and
            values["KillMode"] == "control-group" and values["ExecStopPost"].count("argv[]=") == 1
            and values["ExecStopPost"].startswith(
                "{ path=/usr/bin/python3 ; " + expected + " ignore_errors=no ;"),
            "bounded systemd service with exact ExecStopPost rollback required")


def apply(path, p):
    execution_guard(path, p)
    require(json.loads(read(Path(path).with_name("state.json")))["phase"] == "PREPARED",
            "plan already used")
    known(p)
    verify(p["profile"])
    for target, row in p["images"].items():
        require(read(target) == bytes.fromhex(row["old"]), "old target set differs")
    require(binding(p["profile"]["unit"]) == p["binding"], "sensor epoch changed")
    active_monitors(p["profile"])
    deadline = time.monotonic() + 75
    state(path, "APPLYING")
    try:
        monitors(p, "stop")
        install(p, "new")
        profile = p["profile"]
        verify(profile)
        argv = [next(iter(profile["observer_paths"])), "--unit", profile["unit"],
                "--binary-sha256", profile["binary_sha256"], "--queue", str(profile["queue"]),
                "--host", profile["host"].split(".")[0], "--require"]
        if profile["rcvbuf_size"]:
            argv += ["--rcvbuf-size", str(profile["rcvbuf_size"])]
        observed = json.loads(command(argv))
        require(observed["known"] is True and observed["enabled"] is True
                and (not profile["rcvbuf_size"] or (observed["rcvbuf_known"] is True
                     and observed["rcvbuf_effective_bytes"] == profile["rcvbuf_size"] * 2)),
                "new observer did not verify current sensor")
        monitors(p, "start")
        require(binding(profile["unit"]) == p["binding"], "sensor changed during refresh")
        known(p)
        require(all(read(target) == bytes.fromhex(row["new"]) for target, row in p["images"].items()),
                "new target set differs")
        require(time.monotonic() < deadline, "refresh deadline exhausted")
        state(path, "COMMITTED")
        return {"phase": "COMMITTED", "binding": p["binding"], "observation": observed}
    except BaseException:
        rollback(path, p)
        raise


def activation_lock(fd, recovery):
    deadline = time.monotonic() + 10
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if not recovery:
                raise
            require(time.monotonic() < deadline, "recovery activation lock remained busy")
            time.sleep(0.05)


def recovery_sigterm(signum, frame):
    raise SystemExit(143)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "apply", "rollback"))
    parser.add_argument("--file", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    if args.phase == "rollback":
        signal.signal(signal.SIGTERM, recovery_sigterm)
    if args.phase == "prepare":
        result = prepare(args.file, args.sha256)
    else:
        p = load_plan(args.file, args.sha256, recovery=args.phase == "rollback")
        lock_path = Path(p["profile"]["release"]).parent / ".activation.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o077, "unsafe activation lock")
            activation_lock(fd, recovery=args.phase == "rollback")
            result = apply(args.file, p) if args.phase == "apply" else rollback(args.file, p)
        finally:
            os.close(fd)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
