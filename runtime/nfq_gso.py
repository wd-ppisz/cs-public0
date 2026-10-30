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


MAX_WAIT_SECONDS = 240


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


def socket_identity(process, portid):
    rows = [line.split() for line in Path("/proc/net/netlink").read_text().splitlines()
            if len(line.split()) == 10 and line.split()[1:3] == ["12", str(portid)]]
    require(len(rows) == 1 and rows[0][9].isdigit(), "ambiguous NFQUEUE socket")
    inode = rows[0][9]
    require(any(os.readlink(fd) == "socket:[" + inode + "]" for fd in (process / "fd").iterdir()),
            "NFQUEUE socket is not owned by the bound process")
    return inode


def diagnostic_portid(portid):
    # /proc keeps uint32; ss formats and filters this field as signed int32.
    require(type(portid) is int and 0 < portid <= 4294967295, "invalid netlink port")
    return portid - 4294967296 if portid >= 2147483648 else portid


def socket_rcvbuf(raw, portid):
    # ss netlink diagnostics identifies the protocol and socket port ID. Bind it
    # to an owned inode via /proc before AND after this separate observation.
    rows = [line for line in raw.splitlines()
            if len(line.split()) >= 6 and line.split()[3] == "12:" + str(diagnostic_portid(portid))]
    require(len(rows) == 1, "ambiguous socket buffer diagnostic")
    values = re.findall(r"\bskmem:\(r\d+,rb(\d+),", rows[0])
    require(len(values) == 1 and 0 < int(values[0]) <= 134217728,
            "unknown effective socket buffer")
    return int(values[0])


def queue_socket_identity(process, queue):
    rows = [line.split() for line in Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines()
            if line.split() and line.split()[0] == str(queue)]
    require(len(rows) == 1 and len(rows[0]) == 9 and rows[0][1].isascii()
            and rows[0][1].isdigit() and 0 < int(rows[0][1]) <= 4294967295,
            "unknown or ambiguous NFQUEUE port")
    portid = int(rows[0][1])
    # Netlink port IDs identify sockets; they need not equal the owner's PID.
    return portid, socket_identity(process, portid)


def verify_rcvbuf(process, argv, unit, invocation, queue, portid, requested):
    require(type(requested) is int and 1048576 <= requested <= 67108864,
            "receive buffer request outside 1..64 MiB")
    setting = "nfq.rcvbuf-size=" + str(requested)
    require([value for value in argv if value.startswith("nfq.rcvbuf-size=")] == [setting] and
            any(a == "--set" and b == setting for a, b in zip(argv, argv[1:])),
            "explicit receive buffer request is missing or overridden")
    inode = socket_identity(process, portid)
    effective = socket_rcvbuf(command(["ss", "-a", "-n", "-m", "-e", "-f", "netlink",
                                      "src", "12:" + str(diagnostic_portid(portid))]), portid)
    require(effective == requested * 2, "effective receive buffer differs from requirement")
    expected = ("NFQUEUE receive buffer verified queue=" + str(queue) + " requested=" +
                str(requested) + " effective=" + str(effective))
    acknowledgement = command(["journalctl", "--no-pager", "-o", "cat", "-n", "1",
                               "-u", unit, "_SYSTEMD_INVOCATION_ID=" + invocation,
                               "--grep=NFQUEUE receive buffer verified"])
    require(any(line.strip().endswith(expected) for line in acknowledgement.splitlines()),
            "receive buffer acknowledgement is absent or differs")
    require(socket_identity(process, portid) == inode, "NFQUEUE socket changed")
    return effective


def file_sha256(path):
    # Bound additional Python memory independently of executable file size.
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def observe(unit, binary_sha256, queue, rcvbuf_size=0):
    value = {"known": False, "enabled": False, "pid": 0, "invocation": None,
             "sample_unix_seconds": time.time(), "rcvbuf_known": False,
             "rcvbuf_effective_bytes": 0, "rcvbuf_required_bytes": rcvbuf_size * 2}
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
        require(file_sha256(process / "exe") == binary_sha256,
                "unexpected engine binary")
        queue_socket = queue_socket_identity(process, queue)
        acknowledgement = command(["journalctl", "--no-pager", "-o", "cat", "-n", "1",
                                   "-u", unit, "_SYSTEMD_INVOCATION_ID=" + invocation,
                                   "--grep=NFQUEUE GSO enabled"])
        require(any(line.strip().endswith("NFQUEUE GSO enabled")
                    for line in acknowledgement.splitlines()), "GSO acknowledgement is absent")
        effective = 0
        if rcvbuf_size:
            effective = verify_rcvbuf(process, argv, unit, invocation, queue, queue_socket[0], rcvbuf_size)
        require(unit_state(unit) == before and
                (process / "stat").read_bytes().rsplit(b")", 1)[1].split()[19] == start,
                "sensor invocation changed during observation")
        require(queue_socket_identity(process, queue) == queue_socket,
                "queue socket changed during observation")
        value.update(known=True, enabled=True, pid=pid, invocation=invocation,
                     rcvbuf_known=bool(rcvbuf_size), rcvbuf_effective_bytes=effective)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        value["error"] = str(error)[:240]
    return value


def metrics(value, host):
    require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", host), "invalid metric host")
    labels = '{host="' + host + '",profile="public0-ipv4-alert"}'
    fields = {"known": int(value["known"]), "enabled": int(value["enabled"]),
              "last_publish_unix_seconds": value["sample_unix_seconds"]}
    result = "".join("cs_public0_gso_" + name + labels + " " + str(number) + "\n"
                     for name, number in fields.items())
    for name in ("known", "effective_bytes", "required_bytes"):
        result += "cs_public0_nfq_rcvbuf_" + name + labels + " " + str(int(value.get("rcvbuf_" + name, 0))) + "\n"
    return result


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
    parser.add_argument("--rcvbuf-size", type=int, default=0,
                        help="explicit SO_RCVBUF request in bytes; 0 disables this additional gate")
    parser.add_argument("--require", action="store_true", help="refuse startup without GSO")
    parser.add_argument("--wait-seconds", type=int, default=0)
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    require(re.fullmatch(r"[a-zA-Z0-9_-]{1,80}\.service", args.unit), "invalid unit")
    require(re.fullmatch(r"[a-f0-9]{64}", args.binary_sha256), "explicit engine pin required")
    require(0 <= args.queue <= 65535 and 0 <= args.wait_seconds <= MAX_WAIT_SECONDS, "invalid bound")
    require(args.rcvbuf_size == 0 or 1048576 <= args.rcvbuf_size <= 67108864, "invalid buffer bound")
    deadline = time.monotonic() + args.wait_seconds
    while True:
        value = observe(args.unit, args.binary_sha256, args.queue, args.rcvbuf_size)
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
