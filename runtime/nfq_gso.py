#!/usr/bin/env python3
"""Verify explicit GSO activation for one pinned NFQUEUE engine invocation.

The acknowledgement is specific to the optional source-nfq GSO patch. Stock
Suricata accepting an unknown YAML key is not evidence of GSO activation.
This program never installs a selector, stops a service or changes NIC offloads.

Suricata logs both acknowledgements once per start. When journald has rotated
them away, a root-owned evidence record written by the monitor while the
journal still held them may replace ONLY those log lines, and only for the same
unit invocation, PID, process start time, engine binary and queue. The command
line, NFQUEUE socket ownership and effective receive buffer are still verified
live on every observation. Only an explicit --evidence-dir writes evidence;
library callers such as the policy controller only read the default path.
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
DEFAULT_EVIDENCE_DIR = "/var/lib/cs-public0-nfq-evidence"
EVIDENCE_SCHEMA = "cs-public0-nfq-evidence-v1"
EVIDENCE_MAX_BYTES = 4096
# Tests substitute their own UID; production evidence must be root-owned.
EVIDENCE_OWNER_UID = 0
GSO_ACKNOWLEDGEMENT = "NFQUEUE GSO enabled"
UNIT_PATTERN = r"[a-zA-Z0-9_-]{1,80}\.service"


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


def rcvbuf_acknowledgement(queue, requested, effective):
    return ("NFQUEUE receive buffer verified queue=" + str(queue) + " requested=" +
            str(requested) + " effective=" + str(effective))


def journal_acknowledged(unit, invocation, needle, expected):
    """Return whether this invocation's journal still holds the exact line.

    journalctl --grep exits 1 when nothing matches; that is absence, not a
    failure. Any other failure propagates and keeps the observation unknown.
    """
    try:
        raw = command(["journalctl", "--no-pager", "-o", "cat", "-n", "1",
                       "-u", unit, "_SYSTEMD_INVOCATION_ID=" + invocation, "--grep=" + needle])
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
        return False
    return any(line.strip().endswith(expected) for line in raw.splitlines())


def verify_rcvbuf(process, argv, unit, invocation, queue, portid, requested, fallback=None):
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
    expected = rcvbuf_acknowledgement(queue, requested, effective)
    # Persisted evidence can replace only this log line; the effective
    # capacity above is always measured live.
    require(journal_acknowledged(unit, invocation, "NFQUEUE receive buffer verified", expected)
            or (fallback is not None and fallback(expected)),
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


def evidence_path(evidence_dir, unit):
    require(isinstance(evidence_dir, str) and evidence_dir.startswith("/") and evidence_dir != "/"
            and os.path.normpath(evidence_dir).replace("\\", "/") == evidence_dir
            and ".." not in evidence_dir.split("/"), "absolute normalized evidence directory required")
    require(isinstance(unit, str) and re.fullmatch(UNIT_PATTERN, unit), "invalid evidence unit")
    return evidence_dir + "/" + unit + ".json"


def trusted_chain(directory):
    chain = [directory]
    while chain[-1] != os.path.dirname(chain[-1]):
        chain.append(os.path.dirname(chain[-1]))
    return chain


def require_safe_directories(directory):
    for current in trusted_chain(directory):
        info = os.lstat(current)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == EVIDENCE_OWNER_UID
                and not info.st_mode & 0o022, "unsafe evidence directory")


def require_safe_file(info):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == EVIDENCE_OWNER_UID
            and not info.st_mode & 0o022 and info.st_nlink == 1, "unsafe evidence file")


def evidence_identity(unit, invocation, pid, start_ticks, binary_sha256, queue, rcvbuf_size):
    return {"schema": EVIDENCE_SCHEMA, "unit": unit, "invocation": invocation, "pid": pid,
            "start_ticks": start_ticks, "binary_sha256": binary_sha256, "queue": queue,
            "gso_acknowledgement": GSO_ACKNOWLEDGEMENT, "rcvbuf_requested_bytes": rcvbuf_size,
            "rcvbuf_effective_bytes": rcvbuf_size * 2,
            "rcvbuf_acknowledgement": (rcvbuf_acknowledgement(queue, rcvbuf_size, rcvbuf_size * 2)
                                       if rcvbuf_size else "")}


def read_evidence(evidence_dir, unit):
    path = evidence_path(evidence_dir, unit)
    require_safe_directories(os.path.dirname(path))
    # O_NONBLOCK: a planted FIFO must not stall the observer before fstat.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require_safe_file(os.fstat(fd))
        raw = os.read(fd, EVIDENCE_MAX_BYTES + 1)
    finally:
        os.close(fd)
    require(len(raw) <= EVIDENCE_MAX_BYTES, "evidence exceeds bound")
    return json.loads(raw.decode("utf-8", "strict"))


def evidence_matches(record, identity):
    """Exact identity match; JSON types are compared, so True never equals 1."""
    return (isinstance(record, dict) and set(record) == set(identity) | {"observed_unix_seconds"}
            and all(type(record[key]) is type(expected) and record[key] == expected
                    for key, expected in identity.items())
            and type(record["observed_unix_seconds"]) is int
            and 0 < record["observed_unix_seconds"] <= time.time() + 300)


def write_evidence(evidence_dir, record):
    path = evidence_path(evidence_dir, record["unit"])
    directory = os.path.dirname(path)
    if not os.path.lexists(directory):
        require_safe_directories(os.path.dirname(directory))
        os.mkdir(directory, 0o700)
    require_safe_directories(directory)
    if os.path.lexists(path):
        require_safe_file(os.lstat(path))
    temporary = path + ".tmp-" + str(os.getpid())
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(record, sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def observe(unit, binary_sha256, queue, rcvbuf_size=0, evidence_dir=DEFAULT_EVIDENCE_DIR, persist=False):
    value = {"known": False, "enabled": False, "pid": 0, "invocation": None,
             "sample_unix_seconds": time.time(), "rcvbuf_known": False,
             "rcvbuf_effective_bytes": 0, "rcvbuf_required_bytes": rcvbuf_size * 2,
             "evidence_source": None}
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
        identity = evidence_identity(unit, invocation, pid, int(start), binary_sha256, queue, rcvbuf_size)
        used = []

        def persisted(expected_line):
            # Replaces one missing journal line, never a live check above or below.
            try:
                record = read_evidence(evidence_dir, unit)
                require(evidence_matches(record, identity),
                        "persisted evidence belongs to another sensor epoch")
                require(expected_line in (identity["gso_acknowledgement"], identity["rcvbuf_acknowledgement"]),
                        "persisted evidence differs from the required acknowledgement")
            except (OSError, ValueError, RuntimeError) as error:
                value["evidence_error"] = str(error)[:240]
                return False
            used.append(record["observed_unix_seconds"])
            return True

        require(journal_acknowledged(unit, invocation, GSO_ACKNOWLEDGEMENT, GSO_ACKNOWLEDGEMENT)
                or persisted(GSO_ACKNOWLEDGEMENT), "GSO acknowledgement is absent")
        effective = 0
        if rcvbuf_size:
            effective = verify_rcvbuf(process, argv, unit, invocation, queue, queue_socket[0], rcvbuf_size,
                                      fallback=persisted)
        require(unit_state(unit) == before and
                (process / "stat").read_bytes().rsplit(b")", 1)[1].split()[19] == start,
                "sensor invocation changed during observation")
        require(queue_socket_identity(process, queue) == queue_socket,
                "queue socket changed during observation")
        value.update(known=True, enabled=True, pid=pid, invocation=invocation,
                     rcvbuf_known=bool(rcvbuf_size), rcvbuf_effective_bytes=effective,
                     evidence_source="persisted" if used else "journal")
        value.pop("evidence_error", None)
        if used:
            value["evidence_observed_unix_seconds"] = used[0]
        elif persist:
            # Written only after every live re-check succeeded for this exact epoch.
            try:
                try:
                    current = evidence_matches(read_evidence(evidence_dir, unit), identity)
                except (OSError, ValueError, RuntimeError):
                    current = False
                if not current:
                    write_evidence(evidence_dir, dict(identity, observed_unix_seconds=int(time.time())))
            except (OSError, ValueError, RuntimeError) as error:
                value["evidence_write_error"] = str(error)[:240]
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        value["error"] = str(error)[:240]
    return value


def metrics(value, host):
    require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", host), "invalid metric host")
    labels = '{host="' + host + '",profile="public0-ipv4-alert"}'
    fields = {"known": int(value["known"]), "enabled": int(value["enabled"]),
              "last_publish_unix_seconds": value["sample_unix_seconds"],
              "evidence_persisted": int(value.get("evidence_source") == "persisted")}
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
    parser.add_argument("--evidence-dir",
                        help="write root-owned startup evidence here; without it evidence is only read from "
                             + DEFAULT_EVIDENCE_DIR)
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    require(re.fullmatch(UNIT_PATTERN, args.unit), "invalid unit")
    if args.evidence_dir is not None:
        evidence_path(args.evidence_dir, args.unit)
    require(re.fullmatch(r"[a-f0-9]{64}", args.binary_sha256), "explicit engine pin required")
    require(0 <= args.queue <= 65535 and 0 <= args.wait_seconds <= MAX_WAIT_SECONDS, "invalid bound")
    require(args.rcvbuf_size == 0 or 1048576 <= args.rcvbuf_size <= 67108864, "invalid buffer bound")
    deadline = time.monotonic() + args.wait_seconds
    while True:
        value = observe(args.unit, args.binary_sha256, args.queue, args.rcvbuf_size,
                        evidence_dir=args.evidence_dir or DEFAULT_EVIDENCE_DIR,
                        persist=args.evidence_dir is not None)
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
