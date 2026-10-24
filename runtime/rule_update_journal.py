"""Linux file-transaction journal. No network, engine, service or reload actions.

Callers must coordinate every writer through this one store and qualify the
candidate, startup verifier and sensor separately. A caller receipt records a
controller decision; this module cannot attest that a reload actually happened.
Construction and import do not access installation files.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

MAX_FILE = 64 * 1024 * 1024
MAX_SET = 256 * 1024 * 1024
MAX_JSON = 32768
MAX_RECEIPT = 8192
PHASES = {"PREPARED", "INSTALLING", "INSTALLED", "RELOAD_PENDING", "RESTORING",
          "RESTORED", "ABANDONED_PREPARATION", "COMMITTED"}
MODES = {0o600, 0o640, 0o644, 0o700, 0o750, 0o755}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def name_ok(value):
    return (isinstance(value, str) and value not in {".", ".."}
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", value) is not None)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate journal key")
        result[key] = value
    return result


def encoded(value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= MAX_JSON, "journal metadata too large")
    return raw


def file_info(info, private=False):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.geteuid(), "unsafe file ownership/type/links")
    mode = stat.S_IMODE(info.st_mode)
    require(mode == 0o600 if private else mode in MODES, "unsafe file mode")
    return mode


def read_file(directory, name, limit, private=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        mode = file_info(before, private)
        require(before.st_size <= limit, "file exceeds bound")
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            require(count <= limit, "file exceeds bound")
        after = os.fstat(fd)
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, k) == getattr(after, k) for k in keys), "file changed during read")
        return b"".join(chunks), mode, after.st_gid
    finally:
        os.close(fd)


def write_file(directory, name, raw, mode=0o600, replace=False, gid=None):
    temporary = ".journal-" + secrets.token_hex(16) if replace else name
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            if gid is not None and os.fstat(fd).st_gid != gid:
                os.fchown(fd, -1, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
    finally:
        os.close(fd)
    if replace:
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
    # Failed temporaries are retained. Never unlink an unverified pathname.


@contextlib.contextmanager
def directory(path, private=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute canonical directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in {0, os.geteuid()}, "foreign directory owner")
            writable = info.st_mode & 0o022
            require(not writable or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                    "writable directory ancestor")
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "unsafe target directory")
        if private:
            require(stat.S_IMODE(info.st_mode) == 0o700, "journal directory must be private")
        yield fd
    finally:
        os.close(fd)


def identity(fd):
    info = os.fstat(fd)
    return [info.st_dev, info.st_ino]


def permitted_gids():
    return None if os.geteuid() == 0 else {os.getegid(), *os.getgroups()}


class RuleFileJournal:
    def __init__(self, target_directory, journal_directory):
        self.target_directory = Path(target_directory)
        self.journal_directory = Path(journal_directory)

    @contextlib.contextmanager
    def _locked(self):
        import fcntl
        with directory(self.target_directory) as target, directory(self.journal_directory, True) as store:
            require(identity(target) != identity(store), "target and journal must differ")
            fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=store)
            try:
                file_info(os.fstat(fd), True)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield target, store
            finally:
                os.close(fd)

    def _validate_plan(self, plan, target, store, transaction):
        require(isinstance(plan, dict) and set(plan) == {"schema", "transaction", "target", "store", "assets"},
                "invalid journal plan")
        require(plan["schema"] == "cs-public0-file-journal-v1" and pin(transaction)
                and plan["transaction"] == transaction, "wrong transaction")
        for key, fd in (("target", target), ("store", store)):
            require(isinstance(plan[key], list) and len(plan[key]) == 2
                    and all(type(v) is int and v >= 0 for v in plan[key])
                    and plan[key] == identity(fd), "directory identity changed")
        assets = plan["assets"]
        require(isinstance(assets, list) and 1 <= len(assets) <= 4, "invalid asset set")
        names = []
        groups = permitted_gids()
        for item in assets:
            require(isinstance(item, dict) and set(item) == {"name", "old", "new", "mode", "gid"}
                    and name_ok(item["name"]) and type(item["mode"]) is int
                    and item["mode"] in MODES and type(item["gid"]) is int
                    and 0 <= item["gid"] < 2**32 - 1, "invalid asset metadata")
            require(groups is None or item["gid"] in groups, "asset group is not restorable")
            names.append(item["name"])
            for side in ("old", "new"):
                row = item[side]
                require(isinstance(row, dict) and set(row) == {"sha256", "bytes"}
                        and pin(row["sha256"]) and type(row["bytes"]) is int
                        and 0 <= row["bytes"] <= MAX_FILE, "invalid asset pin/size")
        require(len(set(names)) == len(names) and names == sorted(names), "duplicate/unordered assets")
        require(all(sum(a[side]["bytes"] for a in assets) <= MAX_SET for side in ("old", "new")),
                "asset set exceeds bound")
        return plan

    def _active(self, target, store, transaction):
        raw, _, _ = read_file(store, "active.json", MAX_JSON, True)
        return self._validate_plan(json.loads(raw, object_pairs_hook=unique), target, store, transaction)

    @contextlib.contextmanager
    def _transaction(self, target, store, transaction):
        plan = self._active(target, store, transaction)
        fd = os.open(transaction, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=store)
        try:
            info = os.fstat(fd)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "unsafe transaction directory")
            raw, _, _ = read_file(fd, "state.json", MAX_JSON, True)
            state = json.loads(raw, object_pairs_hook=unique)
            require(isinstance(state, dict) and set(state) == {"plan", "phase", "revision", "receipt"}
                    and state["plan"] == plan and state["phase"] in PHASES
                    and type(state["revision"]) is int and 1 <= state["revision"] <= 1000000,
                    "invalid transaction state")
            receipt = state["receipt"]
            if state["phase"] == "COMMITTED":
                raw_receipt, _, _ = read_file(fd, "receipt", MAX_RECEIPT, True)
                require(isinstance(receipt, dict) and set(receipt) == {"sha256", "bytes"}
                        and type(receipt["bytes"]) is int
                        and receipt == {"sha256": digest(raw_receipt), "bytes": len(raw_receipt)}
                        and raw_receipt, "missing/changed caller receipt")
            else:
                require(receipt is None, "unexpected caller receipt")
            yield fd, state
        finally:
            os.close(fd)

    def _save(self, transaction_fd, state, phase, receipt=None):
        state = {**state, "phase": phase, "revision": state["revision"] + 1, "receipt": receipt}
        require(state["revision"] <= 1000000, "revision bound exceeded")
        write_file(transaction_fd, "state.json", encoded(state), replace=True)
        return state

    def _current(self, target, plan):
        result = []
        for item in plan["assets"]:
            raw, mode, gid = read_file(target, item["name"], MAX_FILE)
            observed = {"sha256": digest(raw), "bytes": len(raw)}
            require(mode == item["mode"] and gid == item["gid"]
                    and observed in (item["old"], item["new"]),
                    "foreign/changed target: " + item["name"])
            result.append("old" if observed == item["old"] else "new")
        return result

    def _images(self, transaction_fd, plan):
        for index, item in enumerate(plan["assets"]):
            for side in ("old", "new"):
                raw, _, _ = read_file(transaction_fd, str(index) + "-" + side, MAX_FILE, True)
                require({"sha256": digest(raw), "bytes": len(raw)} == item[side], "changed transaction image")

    def _require_side(self, target, plan, side):
        require(all(value == side or item["old"] == item["new"]
                    for value, item in zip(self._current(target, plan), plan["assets"])),
                "target set does not match " + side + " images")

    def _replace(self, target, transaction_fd, item, index, side):
        raw, _, _ = read_file(transaction_fd, str(index) + "-" + side, MAX_FILE, True)
        require({"sha256": digest(raw), "bytes": len(raw)} == item[side], "changed transaction image")
        write_file(target, item["name"], raw, item["mode"], replace=True, gid=item["gid"])

    def _clear(self, target, store, state):
        require(state["phase"] in {"COMMITTED", "RESTORED", "ABANDONED_PREPARATION"}, "not terminal")
        require(self._active(target, store, state["plan"]["transaction"]) == state["plan"],
                "active plan changed")
        os.unlink("active.json", dir_fd=store)
        os.fsync(store)

    def prepare(self, transaction, updates, expected_old, expected_new):
        require(pin(transaction), "canonical transaction id required")
        require(isinstance(updates, dict) and 1 <= len(updates) <= 4
                and set(updates) == set(expected_old) == set(expected_new), "invalid update set")
        require(all(name_ok(name) and type(raw) is bytes and len(raw) <= MAX_FILE
                    and pin(expected_old[name]) and pin(expected_new[name])
                    and digest(raw) == expected_new[name] for name, raw in updates.items())
                and sum(map(len, updates.values())) <= MAX_SET, "invalid new image/pin/bound")
        with self._locked() as (target, store):
            try:
                os.stat("active.json", dir_fd=store, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("an active transaction already exists")
            try:
                os.stat(transaction, dir_fd=store, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("transaction id already used")
            old, assets = {}, []
            for name in sorted(updates):
                raw, mode, gid = read_file(target, name, MAX_FILE)
                require(digest(raw) == expected_old[name], "old image SHA256 mismatch")
                old[name] = raw
                assets.append({"name": name, "mode": mode, "gid": gid,
                    "old": {"sha256": digest(raw), "bytes": len(raw)},
                    "new": {"sha256": expected_new[name], "bytes": len(updates[name])}})
            plan = {"schema": "cs-public0-file-journal-v1", "transaction": transaction,
                    "target": identity(target), "store": identity(store), "assets": assets}
            self._validate_plan(plan, target, store, transaction)
            require(any(item["old"] != item["new"] for item in assets), "update set is unchanged")
            write_file(store, "active.json", encoded(plan), replace=True)
            os.mkdir(transaction, 0o700, dir_fd=store)
            os.fsync(store)
            fd = os.open(transaction, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=store)
            try:
                for index, item in enumerate(assets):
                    write_file(fd, str(index) + "-old", old[item["name"]])
                    write_file(fd, str(index) + "-new", updates[item["name"]])
                require(all(v == "old" for v in self._current(target, plan)), "target changed during preparation")
                state = {"plan": plan, "phase": "PREPARED", "revision": 1, "receipt": None}
                write_file(fd, "state.json", encoded(state), replace=True)
                return state
            finally:
                os.close(fd)

    def status(self, transaction):
        with self._locked() as (target, store):
            with self._transaction(target, store, transaction) as (_, state):
                return {"state": state, "files": self._current(target, state["plan"])}

    def install(self, transaction):
        with self._locked() as (target, store):
            with self._transaction(target, store, transaction) as (fd, state):
                require(state["phase"] in {"PREPARED", "INSTALLING", "INSTALLED"}, "installation is blocked")
                self._images(fd, state["plan"])
                self._current(target, state["plan"])
                if state["phase"] == "INSTALLED":
                    self._require_side(target, state["plan"], "new")
                    return state
                state = self._save(fd, state, "INSTALLING")
                for index, item in enumerate(state["plan"]["assets"]):
                    self._replace(target, fd, item, index, "new")
                self._require_side(target, state["plan"], "new")
                return self._save(fd, state, "INSTALLED")

    def restore(self, transaction):
        with self._locked() as (target, store):
            with self._transaction(target, store, transaction) as (fd, state):
                require(state["phase"] in {"PREPARED", "INSTALLING", "INSTALLED", "RESTORING"},
                        "restore blocked: reload may be in flight or transaction is terminal")
                self._images(fd, state["plan"])
                self._current(target, state["plan"])
                state = self._save(fd, state, "RESTORING")
                for index in reversed(range(len(state["plan"]["assets"]))):
                    self._replace(target, fd, state["plan"]["assets"][index], index, "old")
                self._require_side(target, state["plan"], "old")
                state = self._save(fd, state, "RESTORED")
                self._clear(target, store, state)
                return state

    def mark_reload_pending(self, transaction):
        with self._locked() as (target, store):
            with self._transaction(target, store, transaction) as (fd, state):
                require(state["phase"] == "INSTALLED", "reload intent requires installed files")
                self._images(fd, state["plan"])
                self._require_side(target, state["plan"], "new")
                return self._save(fd, state, "RELOAD_PENDING")

    def record_reload_receipt(self, transaction, caller_receipt):
        """Record a caller decision, without performing or attesting a reload."""
        require(type(caller_receipt) is bytes and 0 < len(caller_receipt) <= MAX_RECEIPT,
                "bounded nonempty caller receipt required")
        with self._locked() as (target, store):
            with self._transaction(target, store, transaction) as (fd, state):
                require(state["phase"] == "RELOAD_PENDING", "no unresolved reload intent")
                self._images(fd, state["plan"])
                self._require_side(target, state["plan"], "new")
                try:
                    raw, _, _ = read_file(fd, "receipt", MAX_RECEIPT, True)
                    require(raw == caller_receipt, "different caller receipt already exists")
                except FileNotFoundError:
                    write_file(fd, "receipt", caller_receipt, replace=True)
                state = self._save(fd, state, "COMMITTED",
                                  {"sha256": digest(caller_receipt), "bytes": len(caller_receipt)})
                self._clear(target, store, state)
                return state

    def retire_terminal(self, transaction):
        """Finish removal of an active marker after a terminal-state crash."""
        with self._locked() as (target, store):
            with self._transaction(target, store, transaction) as (_, state):
                require(state["phase"] in {"COMMITTED", "RESTORED", "ABANDONED_PREPARATION"},
                        "not a verifiable terminal state")
                side = "new" if state["phase"] == "COMMITTED" else "old"
                self._require_side(target, state["plan"], side)
                self._clear(target, store, state)

    def abandon_preparation(self, transaction):
        """Only release an incomplete preparation when every target is still old."""
        with self._locked() as (target, store):
            plan = self._active(target, store, transaction)
            try:
                os.mkdir(transaction, 0o700, dir_fd=store)
                os.fsync(store)
            except FileExistsError:
                pass
            fd = os.open(transaction, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=store)
            try:
                info = os.fstat(fd)
                require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        "unsafe transaction directory")
                try:
                    read_file(fd, "state.json", MAX_JSON, True)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeError("preparation already has a state; do not abandon it")
                require(all(v == "old" for v in self._current(target, plan)), "target changed during preparation")
                state = {"plan": plan, "phase": "ABANDONED_PREPARATION", "revision": 1, "receipt": None}
                write_file(fd, "state.json", encoded(state), replace=True)
                self._clear(target, store, state)
            finally:
                os.close(fd)
