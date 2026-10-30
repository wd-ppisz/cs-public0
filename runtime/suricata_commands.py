"""Bounded Linux command socket transport; no CLI, signals or service actions.

The caller supplies a separately accepted process binding. This module checks
that binding against Linux and SO_PEERCRED, but does not identify a systemd
unit, qualify a candidate, or establish resource/monitoring acceptance.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import time

from rule_update_journal import directory, encoded, pin, require, unique

MAX_RESPONSE = 65536
READ_COMMANDS = {"command-list", "version", "running-mode", "capture-mode",
                 "ruleset-stats", "ruleset-reload-time"}


class CommandRejected(RuntimeError):
    def __init__(self, response):
        super().__init__("command refused by the bound peer")
        self.response = response


def bounded_read(path, limit):
    with open(path, "rb", buffering=0) as stream:
        chunks, size = [], 0
        for _ in range(128):
            chunk = stream.read(min(4096, limit + 1 - size))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            size += len(chunk)
            require(size <= limit, "process source exceeds bound")
    raise RuntimeError("process source chunk bound exceeded")


def process_binding(pid):
    require(type(pid) is int and pid > 1, "explicit process PID required")
    root = Path("/proc") / str(pid)
    before = bounded_read(root / "stat", 8192).rsplit(b")", 1)[1].split()
    require(before[0] != b"Z", "process is a zombie")
    command = bounded_read(root / "cmdline", 65536)
    require(command and command.endswith(b"\0"), "missing process command line")
    args = command.split(b"\0")[:-1]
    exe, net = os.stat(root / "exe"), os.stat(root / "ns/net")
    result = {"pid": pid, "start_ticks": int(before[19]), "uid": root.stat().st_uid,
              "boot_id": bounded_read("/proc/sys/kernel/random/boot_id", 64).decode("ascii").strip(),
              "exe": [exe.st_dev, exe.st_ino], "netns": [net.st_dev, net.st_ino],
              "command_sha256": hashlib.sha256(command).hexdigest(),
              "cgroup_sha256": hashlib.sha256(bounded_read(root / "cgroup", 8192)).hexdigest(),
              "cli_rule_file": any(arg.startswith((b"-S", b"-s")) for arg in args[1:])}
    after = bounded_read(root / "stat", 8192).rsplit(b")", 1)[1].split()
    require(before[19] == after[19] and after[0] != b"Z", "process changed during binding")
    return result


def validate_binding(value):
    keys = {"pid", "start_ticks", "uid", "boot_id", "exe", "netns",
            "command_sha256", "cgroup_sha256", "cli_rule_file"}
    require(isinstance(value, dict) and set(value) == keys, "invalid process binding")
    require(all(type(value[k]) is int and value[k] >= 0 for k in ("pid", "start_ticks", "uid"))
            and value["pid"] > 1 and value["start_ticks"] > 0, "invalid process identity")
    require(type(value["cli_rule_file"]) is bool and isinstance(value["boot_id"], str)
            and len(value["boot_id"]) == 36 and pin(value["command_sha256"])
            and pin(value["cgroup_sha256"]), "invalid process binding fields")
    for name in ("exe", "netns"):
        require(isinstance(value[name], list) and len(value[name]) == 2
                and all(type(x) is int and x >= 0 for x in value[name]), "invalid process inode")


class SuricataCommands:
    def __init__(self, path, binding, timeout_ns=120_000_000_000):
        validate_binding(binding)
        require(type(timeout_ns) is int and 1_000_000 <= timeout_ns <= 120_000_000_000,
                "bounded session timeout required")
        self.path = Path(path)
        require(self.path.is_absolute() and ".." not in self.path.parts, "absolute socket path required")
        self.binding = json.loads(json.dumps(binding))
        self.timeout_ns = timeout_ns
        self.stream = self.pidfd = self.parent = None
        self.failed = self.reload_attempted = False
        self.events = []

    def __enter__(self):
        require(self.pidfd is None and not self.failed, "session cannot be reused")
        self.deadline = time.monotonic_ns() + self.timeout_ns
        try:
            self.pidfd = os.pidfd_open(self.binding["pid"], 0)
            with directory(self.path.parent) as fd:
                self.parent = os.dup(fd)
            info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid == self.binding["uid"]
                    and info.st_nlink == 1, "unsafe command socket")
            self.socket_identity = [info.st_dev, info.st_ino]
            self.guard()
            self.stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.stream.settimeout(self.remaining(self.deadline))
            self.stream.connect("/proc/self/fd/" + str(self.parent) + "/" + self.path.name)
            peer = struct.unpack("3i", self.stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer[:2] == (self.binding["pid"], self.binding["uid"]), "foreign command socket peer")
            self.guard()
            self._exchange({"version": "0.2"}, 3_000_000_000)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        self.failed = True
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        for name in ("pidfd", "parent"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def remaining(self, deadline):
        left = deadline - time.monotonic_ns()
        require(left > 0, "command deadline exceeded")
        return left / 1_000_000_000

    def guard(self):
        require(not self.failed and self.pidfd is not None
                and not select.select([self.pidfd], [], [], 0)[0], "bound process exited")
        require(process_binding(self.binding["pid"]) == self.binding, "process binding changed")
        info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and [info.st_dev, info.st_ino] == self.socket_identity
                and info.st_uid == self.binding["uid"], "command socket replaced")

    def _exchange(self, payload, budget_ns):
        require(not self.failed and self.stream is not None and len(self.events) < 16,
                "command session is unavailable or exhausted")
        started = time.monotonic_ns()
        deadline = min(self.deadline, started + budget_ns)
        event = {"command": payload.get("command", "handshake"), "started_ns": started,
                 "finished_ns": None, "response_sha256": None, "outcome": "UNKNOWN"}
        self.events.append(event)
        try:
            self.guard()
            self.stream.settimeout(self.remaining(deadline))
            self.stream.sendall(encoded(payload))
            raw = bytearray()
            while b"\n" not in raw:
                self.stream.settimeout(self.remaining(deadline))
                chunk = self.stream.recv(min(4096, MAX_RESPONSE + 1 - len(raw)))
                require(chunk, "command socket EOF")
                raw.extend(chunk)
                require(len(raw) <= MAX_RESPONSE, "command response exceeds bound")
            line, tail = bytes(raw).split(b"\n", 1)
            require(not tail.strip(), "unsolicited extra command response")
            response = json.loads(line, object_pairs_hook=unique)
            require(isinstance(response, dict) and set(response) <= {"return", "message"}
                    and response.get("return") in ("OK", "NOK"), "invalid command response")
            if response["return"] == "NOK":
                raise CommandRejected(response)
            self.remaining(deadline)
            self.guard()
            self.remaining(deadline)
            event.update(finished_ns=time.monotonic_ns(), response_sha256=hashlib.sha256(raw).hexdigest(),
                         outcome="OK")
            return response
        except BaseException:
            self.failed = True
            raise

    def query(self, command):
        require(command in READ_COMMANDS, "command is not in the read-only allowlist")
        return self._exchange({"command": command}, 3_000_000_000).get("message")

    def require_reloadable(self):
        self.guard()
        require(not self.binding["cli_rule_file"], "reload unavailable with -S/-s; use pinned YAML rule-files")

    def reload_rules(self):
        self.require_reloadable()
        require(not self.reload_attempted, "reload already attempted; do not retry an unknown outcome")
        self.reload_attempted = True
        response = self._exchange({"command": "ruleset-reload-rules"}, self.timeout_ns)
        require(response.get("message") == "done", "reload completion was not acknowledged")
        return response


def ruleset(message, expected):
    require(type(expected) is int and expected > 0 and isinstance(message, list)
            and len(message) == 1, "one non-tenant ruleset required")
    row = message[0]
    keys = {"id", "rules_loaded", "rules_failed", "rules_skipped"}
    require(isinstance(row, dict) and set(row) == keys
            and all(type(row[k]) is int for k in keys)
            and row == {"id": 0, "rules_loaded": expected, "rules_failed": 0, "rules_skipped": 0},
            "ruleset count, tenant, failure or skipped mismatch")
    return row


def reload_time(message):
    require(isinstance(message, list) and len(message) == 1 and isinstance(message[0], dict)
            and set(message[0]) == {"id", "last_reload"} and type(message[0]["id"]) is int
            and message[0]["id"] == 0 and isinstance(message[0]["last_reload"], str),
            "invalid reload time schema")
    raw = message[0]["last_reload"]
    # Python 3.10 accepts extended offsets; Suricata emits the basic +HHMM form.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    if len(raw) >= 5 and raw[-5] in "+-" and raw[-4:].isascii() and raw[-4:].isdigit():
        raw = raw[:-2] + ":" + raw[-2:]
    value = datetime.datetime.fromisoformat(raw)
    require(value.tzinfo is not None, "reload timestamp requires timezone")
    return value


def reload_installed(journal, transaction, session, old_count, new_count):
    """Join an installed file transaction to one blocking reload, without retry.

    This is not a systemd activation entrypoint. Unit ownership, startup guard,
    candidate qualification, budgets and monitoring must be supplied separately.
    Any failure after the intent remains RELOAD_PENDING, including a late OK.
    """
    require(all(type(n) is int and n > 0 for n in (old_count, new_count)),
            "explicit positive old/new rule counts required")
    require(journal.status(transaction)["state"]["phase"] == "INSTALLED", "files are not installed")
    session.require_reloadable()
    require(session.query("capture-mode") == "NFQ", "reload requires the accepted NFQ capture mode")
    ruleset(session.query("ruleset-stats"), old_count)
    before = session.query("ruleset-reload-time")
    before_time = reload_time(before)
    journal.mark_reload_pending(transaction)
    session.reload_rules()
    after = session.query("ruleset-reload-time")
    require(reload_time(after) > before_time, "reload time did not advance")
    observed = ruleset(session.query("ruleset-stats"), new_count)
    require(session.query("ruleset-reload-time") == after, "another reload changed the observation")
    session.guard()
    receipt = encoded({"schema": "cs-public0-command-reload-v1", "transaction": transaction,
                       "binding": session.binding, "before": before, "after": after,
                       "ruleset": observed, "events": session.events})
    return journal.record_reload_receipt(transaction, receipt)
