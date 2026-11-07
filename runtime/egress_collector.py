"""Bounded EVE consumer with transactional counters, cursors and a delivery outbox.

No sensor control, network calls or enforcement. Run by a separate oneshot timer.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import sqlite3
import stat
import tempfile
import time

from egress_model import (CATEGORIES, DIRECTIONS, MAX_RECORD, SEVERITIES, Catalog,
                          IOC, direction, flow_key, integer, networks, observation, strict_json, timestamp, validate_config)

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 1000
MAX_JOIN = 4096
MAX_SEEN = 10000
MAX_TABLE_BYTES = 2 * 1024 * 1024
MAX_TRANSITION_KEYS = 8192
MAX_LOG = 4 * 1024 * 1024
OUTCOMES = ("alert", "flow", "stats", "ignored", "unmapped", "duplicate",
            "invalid", "oversize", "partial", "join_expired", "accepted", "backpressure", "cache_evicted",
            "dedup_evicted", "join_evicted")
GAPS = ("inode_change", "truncated", "fingerprint_changed", "sensor_epoch",
        "join_eviction", "initial_boundary", "clock", "catalog")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def plain_file(path, maximum=None):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
            raise ValueError("expected regular single-link file")
        if maximum is not None and s.st_size > maximum:
            raise ValueError("input size bound")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def atomic(path, raw):
    path = pathlib.Path(path)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("unsafe publication target")
    fd, temporary = tempfile.mkstemp(prefix=".egress-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Store:
    def __init__(self, path):
        path = pathlib.Path(path)
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise ValueError("unsafe state path")
        self.db = sqlite3.connect(path, timeout=0.1)
        os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        self.db.execute("PRAGMA max_page_count=" + str(33554432 // page_size))
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS counts (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, accepted REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS seen_age ON seen(accepted);
            CREATE TABLE IF NOT EXISTS flows (id TEXT PRIMARY KEY, received REAL NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, flow_key TEXT NOT NULL,
                received REAL NOT NULL, body TEXT NOT NULL, reference TEXT NOT NULL, epoch TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS pending_flow_key ON pending(flow_key);
            CREATE INDEX IF NOT EXISTS pending_age ON pending(received);
            CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cache_usage (name TEXT PRIMARY KEY,
                rows INTEGER NOT NULL CHECK(rows>=0), bytes INTEGER NOT NULL CHECK(bytes>=0));
        """)
        fields = {"flows": ("id", "body"), "pending": ("id", "flow_key", "body", "reference", "epoch"),
                  "outbox": ("id", "body"), "seen": ("id",)}
        for table, names in fields.items():
            def cost(prefix=""):
                return "+".join("length(CAST("+prefix+name+" AS BLOB))" for name in names)+"+512"
            if not self.db.execute("SELECT 1 FROM cache_usage WHERE name=?", (table,)).fetchone():
                # One-time migration only. Normal publications never scan bodies.
                self.db.execute("INSERT INTO cache_usage SELECT ?,count(*),coalesce(sum("+cost()+"),0) FROM "+table,
                                (table,))
            self.db.executescript("""
                CREATE TRIGGER IF NOT EXISTS egress_{table}_insert AFTER INSERT ON {table} BEGIN
                    UPDATE cache_usage SET rows=rows+1, bytes=bytes+({new}) WHERE name='{table}'; END;
                CREATE TRIGGER IF NOT EXISTS egress_{table}_delete AFTER DELETE ON {table} BEGIN
                    UPDATE cache_usage SET rows=rows-1, bytes=bytes-({old}) WHERE name='{table}'; END;
                CREATE TRIGGER IF NOT EXISTS egress_{table}_update AFTER UPDATE ON {table} BEGIN
                    UPDATE cache_usage SET bytes=bytes-({old})+({new}) WHERE name='{table}'; END;
            """.format(table=table, new=cost("NEW."), old=cost("OLD.")))
        self.db.commit()

    def get(self, key, default=None):
        row = self.db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, value):
        self.db.execute("INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, canonical(value)))

    def count(self, key, amount=1):
        self.db.execute("INSERT INTO counts VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=value+excluded.value",
                        (key, amount))

    def size(self, table):
        if table not in ("seen", "flows", "pending", "outbox"):
            raise ValueError("table")
        return self.db.execute("SELECT rows FROM cache_usage WHERE name=?", (table,)).fetchone()[0]

    def storage(self, table):
        if table not in ("flows", "pending", "outbox"):
            raise ValueError("table")
        # Triggers update both accounting values in the data transaction, so
        # SAVEPOINT/SQLITE_FULL rollback also restores the exact cached usage.
        return self.db.execute("SELECT bytes FROM cache_usage WHERE name=?", (table,)).fetchone()[0]

    def gap(self, reason, now=None):
        if reason not in GAPS:
            raise ValueError("gap reason")
        self.count("gap:" + reason)
        self.put("continuity", False)
        self.put("last_gap", self.get("last_run", 0) if now is None else now)


def lean(row):
    out = {k: row[k] for k in ("timestamp", "event_type", "proto", "src_ip", "dest_ip",
                              "src_port", "dest_port", "flow_id") if k in row}
    if isinstance(row.get("flow"), dict):
        out["flow"] = {k: row["flow"][k] for k in ("start", "state", "exception_policy") if k in row["flow"]}
    if isinstance(row.get("tcp"), dict):
        out["tcp"] = {k: row["tcp"][k] for k in ("state", "tcp_flags_ts", "tcp_flags_tc", "midstream", "ts_gap", "tc_gap") if k in row["tcp"]}
    if isinstance(row.get("alert"), dict):
        out["alert"] = {k: row["alert"][k] for k in ("gid", "signature_id", "rev", "metadata") if k in row["alert"]}
    return out


class Consumer:
    def __init__(self, store, config, catalog, ioc=None):
        self.s = store
        self.config = config
        self.catalog = catalog
        self.ioc = ioc

    def context(self, epoch=None):
        return {**self.config, "sensor_epoch": epoch or self.config["sensor_epoch"] + ":" + str(self.s.get("generation", 0)),
                "clock_skew_allowance_seconds": self.s.get("clock_skew_allowance", 0)}

    def emit(self, row, flow, ref, now, epoch=None):
        item = observation(row, flow, self.context(epoch), self.catalog, ref, now,
                           self.config["active_rules_sha256"], self.ioc)
        if item is None:
            self.s.count("record:unmapped")
            return
        self.publish(item, row, flow, now)

    def publish(self, candidate, row, flow, now):
        # Qualification is frozen at admission. A later rule/feed update cannot
        # erase a previously accepted signature or rewrite its source binding.
        item = json.loads(canonical(candidate))
        d, basis, connection, limits = direction(row, flow, networks(self.config["owned_ipv4_networks"]))
        item.update(direction=d, direction_basis=basis, connection_evidence=connection, published_unix=now)
        item["limitations"] = sorted(set(item["limitations"] + limits))
        if item["observed_unix"] > now + 5:
            item["limitations"].append("SOURCE_CLOCK_SKEW_AFTER_COLLECTOR_REVERSAL")
        if item.get("ioc") and now >= item["ioc"]["expires_unix"]:
            item["limitations"].append("IOC_EXPIRED_AFTER_ADMISSION")
        if self.s.db.execute("SELECT 1 FROM seen WHERE id=?", (item["event_id"],)).fetchone():
            self.s.count("record:duplicate")
            return
        serialized = canonical(item)
        cost = len(item["event_id"].encode()) + len(serialized.encode()) + 512
        if self.s.size("outbox") >= MAX_JOIN or self.s.storage("outbox") + cost > MAX_TABLE_BYTES:
            raise OverflowError("bounded output storage")
        excess = self.s.size("seen") - MAX_SEEN + 1
        if excess > 0:
            self.s.db.execute("DELETE FROM seen WHERE id IN (SELECT id FROM seen ORDER BY accepted,rowid LIMIT ?)",
                              (excess,))
            self.s.count("record:dedup_evicted", excess)
        self.s.db.execute("INSERT INTO seen VALUES (?,?)", (item["event_id"], now))
        self.s.db.execute("INSERT INTO outbox VALUES (?,?)", (item["event_id"], serialized))
        self.s.count("observation:" + ":".join(item[k] for k in ("category", "severity", "direction")))
        self.s.count("record:accepted")

    def accept(self, row, ref, now):
        kind = row.get("event_type")
        observed = timestamp(row["timestamp"])
        if observed > now + 5 + self.s.get("clock_skew_allowance", 0):
            raise ValueError("future source record")
        self.s.put("last_event", observed)
        if kind == "stats":
            uptime = integer(row["stats"]["uptime"])
            old = self.s.get("uptime")
            if old is not None and uptime < old:
                self.expire(now, all_pending=True)
                self.s.db.execute("DELETE FROM flows")
                self.s.put("generation", self.s.get("generation", 0) + 1)
                self.s.gap("sensor_epoch")
            if old is None or uptime != old:
                self.s.put("last_stats", observed)
            self.s.put("uptime", uptime)
            self.s.count("record:stats")
            return
        if kind not in ("alert", "flow"):
            self.s.count("record:ignored")
            return
        if row.get("ip_v") == 6 or row.get("proto") not in ("TCP", "UDP"):
            self.s.count("record:ignored")
            return
        addresses = [ipaddress.ip_address(row[k]) for k in ("src_ip", "dest_ip")]
        if any(a.version != 4 or a.is_multicast or a.is_unspecified for a in addresses):
            self.s.count("record:ignored")
            return
        row = lean(row)
        if ("flow_id" not in row or not isinstance(row.get("flow"), dict) or
                "start" not in row["flow"]):
            if kind == "alert":
                self.s.count("record:alert")
                self.emit(row, None, ref, now)
            else:
                self.s.count("record:ignored")
            return
        key = canonical(flow_key(row))
        self.s.count("record:" + kind)
        if kind == "flow":
            body = canonical(row)
            cost = len(key.encode()) + len(body.encode()) + 512
            if cost > MAX_TABLE_BYTES:
                raise OverflowError("bounded flow record storage")
            self.s.db.execute("DELETE FROM flows WHERE id=?", (key,))
            while self.s.size("flows") >= MAX_JOIN or self.s.storage("flows") + cost > MAX_TABLE_BYTES:
                self.s.db.execute("DELETE FROM flows WHERE id=(SELECT id FROM flows ORDER BY received LIMIT 1)")
                self.s.count("record:cache_evicted")
            self.s.db.execute("INSERT INTO flows VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET received=excluded.received,body=excluded.body",
                              (key, now, body))
            pending = self.s.db.execute("SELECT id,body,reference,epoch FROM pending WHERE flow_key=?", (key,)).fetchall()
            for identifier, body, source, epoch in pending:
                packed = json.loads(body)
                self.publish(packed["candidate"], packed["event"], row, now)
                self.s.db.execute("DELETE FROM pending WHERE id=?", (identifier,))
            self.emit(row, row, ref, now)
            return
        candidate = observation(row, None, self.context(), self.catalog, ref, now,
                                self.config["active_rules_sha256"], self.ioc)
        if candidate is None:
            self.s.count("record:unmapped")
            return
        if not self.config.get("flow_join_enabled", False):
            self.publish(candidate, row, None, now)
            return
        match = self.s.db.execute("SELECT body FROM flows WHERE id=?", (key,)).fetchone()
        if match:
            self.publish(candidate, row, json.loads(match[0]), now)
        else:
            exists = self.s.db.execute("SELECT 1 FROM pending WHERE id=?", (candidate["event_id"],)).fetchone()
            body = canonical({"event": row, "candidate": candidate})
            reference = canonical(ref)
            epoch = self.context()["sensor_epoch"]
            cost = sum(len(x.encode()) for x in (candidate["event_id"], key, body, reference, epoch)) + 512
            if cost > MAX_TABLE_BYTES:
                raise OverflowError("bounded pending record storage")
            while not exists and (self.s.size("pending") >= MAX_JOIN or self.s.storage("pending") + cost > MAX_TABLE_BYTES):
                old_id, old_body = self.s.db.execute("SELECT id,body FROM pending ORDER BY received,rowid LIMIT 1").fetchone()
                packed = json.loads(old_body)
                packed["candidate"]["limitations"].append("JOIN_EVICTED_EARLY")
                self.publish(packed["candidate"], packed["event"], None, now)
                self.s.db.execute("DELETE FROM pending WHERE id=?", (old_id,))
                self.s.count("record:join_evicted")
            self.s.db.execute("INSERT OR IGNORE INTO pending VALUES (?,?,?,?,?,?)",
                              (candidate["event_id"], key, now, body, reference, epoch))

    def expire(self, now, all_pending=False):
        self.s.db.execute("DELETE FROM seen WHERE accepted<?", (now - 86400,))
        retention = integer(self.config.get("join_wait_seconds", 15), 0, 86400)
        limit = 1e30 if all_pending else now - retention
        for identifier, body, ref, epoch in self.s.db.execute(
                "SELECT id,body,reference,epoch FROM pending WHERE received<=?", (limit,)).fetchall():
            packed = json.loads(body)
            self.publish(packed["candidate"], packed["event"], None, now)
            self.s.count("record:join_expired")
            self.s.db.execute("DELETE FROM pending WHERE id=?", (identifier,))
        self.s.db.execute("DELETE FROM flows WHERE received<?", (now - retention,))


def metrics(store, now, success, available, ioc, catalog_ready=None):
    ready = store.get("catalog_ready", False) if catalog_ready is None else catalog_ready
    counts = dict(store.db.execute("SELECT key,value FROM counts"))
    lines = []
    for category in CATEGORIES:
        for severity in SEVERITIES:
            for direction in DIRECTIONS:
                key = "observation:" + ":".join((category, severity, direction))
                lines.append('cs_public0_egress_observations_total{category="%s",severity="%s",direction="%s"} %d' %
                             (category, severity, direction, counts.get(key, 0)))
    for outcome in OUTCOMES:
        lines.append('cs_public0_egress_records_total{outcome="%s"} %d' % (outcome, counts.get("record:" + outcome, 0)))
    for reason in GAPS:
        lines.append('cs_public0_egress_collection_gaps_total{reason="%s"} %d' % (reason, counts.get("gap:" + reason, 0)))
    last = store.get("last_event")
    values = {"collector_up": int(success), "source_available": int(available),
              "last_read_unix_seconds": store.get("last_read", 0),
              "last_publish_unix_seconds": now,
              "last_sensor_stats_unix_seconds": store.get("last_stats", 0),
              "processing_lag_seconds": max(0, now - last) if last is not None else 0,
              "lag_known": int(last is not None), "pending_records": store.size("pending"),
              "collection_continuity_known": int(success and available and ready
                  and store.get("backlog_bytes", 1) == 0 and 0 <= now - store.get("last_stats", 0) <= 30
                  and now - store.get("last_gap", now) >= 60
                  and now - store.get("last_invalid", -1e30) >= 60),
              "last_gap_unix_seconds": store.get("last_gap", 0),
              "ioc_fresh": int(ioc is not None and ioc.fresh(now)),
              "ioc_expires_unix_seconds": ioc.expires if ioc is not None else 0,
              "source_fresh": int(success and available and ready and
                                  store.get("backlog_bytes", 1) == 0 and
                                  now - store.get("last_invalid", -1e30) >= 60 and
                                  0 <= now - store.get("last_stats", 0) <= 30),
              "catalog_ready": int(ready),
              "backlog_bytes": store.get("backlog_bytes", 0)}
    lines.extend("cs_public0_egress_%s %s" % (k, v) for k, v in values.items())
    if len(lines) > 86:
        raise ValueError("metric series budget")
    return ("\n".join(lines) + "\n").encode()


def deliver(store, log_path, deadline=None):
    """At-least-once JSON delivery; consumers deduplicate stable event IDs."""
    target = pathlib.Path(log_path)
    rows = store.db.execute("SELECT id,body FROM outbox ORDER BY rowid LIMIT 1000").fetchall()
    while rows and (deadline is None or time.monotonic() < deadline):
        batch = []
        size = 0
        for identifier, body in rows:
            raw = body.encode() + b"\n"
            if len(raw) > MAX_RECORD:
                raise ValueError("safe output record bound")
            if size + len(raw) > 262144:
                break
            batch.append((identifier, raw))
            size += len(raw)
        raw = b"".join(item[1] for item in batch)
        if not batch or len(raw) > MAX_LOG:
            raise ValueError("safe output record bound")
        if target.exists():
            if target.is_symlink() or not target.is_file():
                raise ValueError("unsafe detail log")
            if target.stat().st_size + len(raw) + 1 > MAX_LOG:
                previous = target.with_suffix(target.suffix + ".1")
                if previous.is_symlink():
                    raise ValueError("unsafe detail archive")
                os.replace(target, previous)
        fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o640)
        with os.fdopen(fd, "a+b") as f:
            if os.fstat(f.fileno()).st_size:
                f.seek(-1, os.SEEK_END)
                if f.read(1) != b"\n":
                    # Isolate a fragment left by a killed/short previous append.
                    # The durable outbox retries the complete event on a new line.
                    f.write(b"\n")
            if f.write(raw) != len(raw):
                raise OSError("incomplete detail append")
            f.flush()
            os.fsync(f.fileno())
        with store.db:
            store.db.executemany("DELETE FROM outbox WHERE id=?", [(item[0],) for item in batch])
        rows = rows[len(batch):]


def fingerprint(f, offset):
    f.seek(max(0, offset - 128))
    return digest(f.read(min(128, offset)))


def source_cursor(store, f, info, config, now):
    cursor = store.get("cursor")
    if cursor is None:
        offset = info.st_size if config.get("initial_position", "end") == "end" else 0
        store.gap("initial_boundary", now)
        return {"device": info.st_dev, "inode": info.st_ino, "offset": offset,
                "fingerprint": fingerprint(f, offset), "discarding": False}
    if (cursor["device"], cursor["inode"]) != (info.st_dev, info.st_ino):
        store.gap("inode_change", now)
        return {"device": info.st_dev, "inode": info.st_ino, "offset": 0,
                "fingerprint": digest(b""), "discarding": False}
    if info.st_size < cursor["offset"]:
        store.gap("truncated", now)
        cursor.update(offset=0, fingerprint=digest(b""), discarding=False)
    elif fingerprint(f, cursor["offset"]) != cursor["fingerprint"]:
        store.gap("fingerprint_changed", now)
        # Regrown copytruncate: reset all three fields, including during cursor hold.
        cursor.update(offset=0, fingerprint=digest(b""), discarding=False)
    return cursor


def run(config, now=None):
    now = time.time() if now is None else now
    state_dir = pathlib.Path(config["state_directory"])
    if not state_dir.is_dir() or state_dir.is_symlink():
        raise ValueError("state directory must be installed")
    import fcntl
    lock_fd = os.open(state_dir / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _run_locked(config, state_dir, now)
    finally:
        os.close(lock_fd)


def _run_locked(config, state_dir, now):
    catalog = None
    catalog_content_hash = None
    ioc = None
    s = Store(state_dir / "state.sqlite3")
    success = False
    available = False
    error = None
    current_ready = False
    started = time.monotonic()
    try:
        config_valid = True
        try:
            validate_config(config)
        except (ValueError, TypeError, KeyError):
            config_valid = False
        try:
            with plain_file(config["catalog_file"], 4 * 1024 * 1024) as f:
                raw_catalog = f.read()
                catalog = Catalog(json.loads(raw_catalog))
                catalog_content_hash = digest(raw_catalog)
        except Exception:
            pass  # Unavailable/malformed catalog follows the unhealthy cursor-hold path.
        if config.get("ioc_file"):
            try:
                with plain_file(config["ioc_file"], 4 * 1024 * 1024) as f:
                    ioc = IOC(json.load(f))
            except Exception:
                pass  # Optional malformed IOC never disables signature observations.
        deliver(s, config["details_file"], started + 1)
        if now < s.get("last_run", 0):
            with s.db:
                delta = now - s.get("last_run")
                s.gap("clock", now)
                s.put("source_clock_ceiling", max(s.get("source_clock_ceiling", 0), s.get("last_run")))
                # Rebase retention ages, never rewrite source observation times.
                for table, field in (("seen", "accepted"), ("flows", "received"), ("pending", "received")):
                    s.db.execute("UPDATE " + table + " SET " + field + "=" + field + "+?", (delta,))
                if s.get("last_invalid") is not None:
                    s.put("last_invalid", s.get("last_invalid") + delta)
                s.put("last_run", now)
        with s.db:
            identity = (catalog.identity if catalog is not None else None) or config["rules_identity"]
            ready = False
            try:
                with plain_file(config["rules_file"]) as rf:
                    rs = os.fstat(rf.fileno())
                current = {"device": rs.st_dev, "inode": rs.st_ino,
                           "size": rs.st_size, "mtime_ns": rs.st_mtime_ns, "ctime_ns": rs.st_ctime_ns}
                ready = current == {k: identity[k] for k in current}
            except (OSError, ValueError, KeyError, TypeError):
                pass
            # Identity is captured with a full SHA read before/after installation.
            # A rules update invalidates the catalog; never hash a large ruleset
            # every five seconds or silently trust an old configured SHA.
            ready = ready and catalog is not None and identity["sha256"] == catalog.rules_sha256
            previous_catalog = s.get("catalog_content_hash")
            if not ready or (previous_catalog is not None and previous_catalog != catalog_content_hash):
                if not s.get("pending_ruleset_transition", False):
                    s.put("pending_ruleset_transition", True)
                    if ready:
                        s.gap("catalog", now)
            transition_capacity = False
            if ready:
                current_keys = {(gid, sid) for gid, sid, _ in catalog.entries}
                transition_keys = set()
                if s.get("pending_ruleset_transition", False) or s.get("ruleset_transition") is not None:
                    transition_keys = (current_keys |
                        {tuple(key) for key in s.get("catalog_signature_keys", [])} |
                        {tuple(key) for key in s.get("ruleset_transition_keys", [])})
                if len(transition_keys) > MAX_TRANSITION_KEYS:
                    # Do not broaden to all alerts or forget older unread
                    # catalog identities when several reloads outpace input.
                    ready = False
                    transition_capacity = True
                else:
                    s.put("catalog_content_hash", catalog_content_hash)
                    s.put("catalog_signature_keys", sorted(current_keys))
                    s.put("ruleset_transition_keys", sorted(transition_keys))
            current_ready = ready
            config = {**config, "active_rules_sha256": identity["sha256"] if ready else "0" * 64}
            if not ready and s.get("catalog_ready") is not False:
                s.gap("catalog", now)
            s.put("catalog_ready", ready)
            s.put("last_run", now)
            s.put("clock_skew_allowance", max(0, s.get("source_clock_ceiling", 0) - now))
            if not ready or not config_valid:
                # Preserve both pending admissions and unread alerts until a
                # qualified current catalog is installed. A finite rotated
                # source may still lose bytes; health never claims coverage.
                s.db.commit()
                with plain_file(config["eve_file"]) as f:
                    info = os.fstat(f.fileno())
                    hold_config = {**config, "initial_position": config.get("initial_position", "end")
                                   if config.get("initial_position", "end") in ("begin", "end") else "end"}
                    cursor = source_cursor(s, f, info, hold_config, now)
                    s.put("cursor", cursor)
                    s.put("backlog_bytes", max(0, info.st_size - cursor["offset"]))
                    available = True
                s.db.commit()
                error = ("ConfigInvalid" if not config_valid else
                         "CatalogTransitionCapacity" if transition_capacity else "CatalogUnavailable")
                return {"success": False, "error": error, "sensor_action": "NONE"}
            config["transition_signature_keys"] = frozenset(tuple(key) for key in s.get("ruleset_transition_keys", []))
            consumer = Consumer(s, config, catalog, ioc)
            consumer.expire(now)
            s.db.commit()  # Retention and previously admitted expirations survive a later full input batch.
            # SAVEPOINT alone starts an outer transaction; RELEASE would then
            # commit every row while leaving the old cursor. Keep data, sensor
            # epoch and cursor inside one explicit input-batch transaction.
            s.db.execute("BEGIN")
            with plain_file(config["eve_file"]) as f:
                info = os.fstat(f.fileno())
                cursor = source_cursor(s, f, info, config, now)
                transition = s.get("ruleset_transition")
                if s.get("pending_ruleset_transition", False) or (transition is not None and
                        (transition["device"], transition["inode"]) != (info.st_dev, info.st_ino)):
                    # This is a bounded unread-prefix boundary, not a claim of
                    # the engine's exact reload time or active ruleset identity.
                    transition = {"device": info.st_dev, "inode": info.st_ino, "end": info.st_size}
                    s.put("ruleset_transition", transition)
                    s.put("pending_ruleset_transition", False)
                f.seek(cursor["offset"])
                consumed = 0
                for _ in range(MAX_ROWS):
                    if consumed >= MAX_BYTES or time.monotonic() - started >= 3:
                        break
                    offset = f.tell()
                    raw = f.readline(min(MAX_RECORD + 1, MAX_BYTES - consumed))
                    if not raw:
                        break
                    consumed += len(raw)
                    if cursor["discarding"]:
                        cursor["discarding"] = not raw.endswith(b"\n")
                    elif len(raw) > MAX_RECORD:
                        cursor["discarding"] = not raw.endswith(b"\n")
                        s.count("record:oversize")
                        s.put("last_invalid", now)
                    elif not raw.endswith(b"\n"):
                        if len(raw) <= MAX_RECORD:
                            f.seek(offset)
                            s.count("record:partial")
                            break
                    else:
                        ref = {"device": info.st_dev, "inode": info.st_ino, "offset": offset,
                               "length": len(raw), "record_sha256": digest(raw)}
                        s.db.execute("SAVEPOINT input_record")
                        try:
                            consumer.config["ruleset_transition_unqualified"] = transition is not None and offset < transition["end"]
                            consumer.accept(strict_json(raw), ref, now)
                        except (ValueError, KeyError, TypeError, RecursionError, OverflowError) as exc:
                            s.db.execute("ROLLBACK TO input_record")
                            if isinstance(exc, OverflowError):
                                s.count("record:backpressure")
                                f.seek(offset)
                                error = "Backpressure"
                                break
                            s.count("record:invalid")
                            s.put("last_invalid", now)
                        finally:
                            # SQLITE_FULL can roll back the entire transaction,
                            # including this savepoint. Preserve the real error.
                            if s.db.in_transaction:
                                s.db.execute("RELEASE input_record")
                    cursor["offset"] = f.tell()
                cursor["offset"] = f.tell()
                cursor["fingerprint"] = fingerprint(f, cursor["offset"])
                s.put("cursor", cursor)
                if transition is not None and cursor["offset"] >= transition["end"]:
                    s.put("ruleset_transition", None)
                    s.put("ruleset_transition_keys", [])
                s.put("backlog_bytes", max(0, os.fstat(f.fileno()).st_size - cursor["offset"]))
                s.put("last_read", now)
                available = True
            success = error is None and ready
        deliver(s, config["details_file"], started + 4)
    except (OSError, ValueError, sqlite3.Error, OverflowError) as exc:
        success = False
        current_ready = False
        error = type(exc).__name__  # Never serialize source/payload/credential text.
        s.db.rollback()
        if isinstance(exc, sqlite3.Error) and (getattr(exc, "sqlite_errorcode", None) == getattr(sqlite3, "SQLITE_FULL", 13) or
                                               str(exc) == "database or disk is full"):
            error = "Backpressure"
            try:
                # Commit cache recovery independently of the rolled-back input
                # batch. Pending admissions/outbox and the committed cursor stay.
                with s.db:
                    flows = s.size("flows")
                    seen = s.size("seen")
                    s.db.execute("DELETE FROM flows")
                    s.db.execute("DELETE FROM seen WHERE id IN (SELECT id FROM seen ORDER BY accepted,rowid LIMIT ?)",
                                 ((seen+1)//2,))
                    s.count("record:cache_evicted", flows)
                    s.count("record:dedup_evicted", (seen+1)//2)
                    s.count("record:backpressure")
            except sqlite3.Error:
                s.db.rollback()  # Physical disk exhaustion remains unhealthy.
    finally:
        try:
            atomic(config["metrics_file"], metrics(s, now, success, available, ioc, current_ready))
        finally:
            s.db.close()
    return {"success": success, "error": error, "sensor_action": "NONE"}


def main():
    import signal
    def terminated(_signum, _frame):
        raise TimeoutError("collector terminated")
    signal.signal(signal.SIGTERM, terminated)
    p = argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    args = p.parse_args()
    with plain_file(args.config, 4 * 1024 * 1024) as f:
        cfg = json.load(f)
    result = run(cfg)
    print(canonical(result))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
