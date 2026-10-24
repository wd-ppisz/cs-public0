#!/usr/bin/env python3
"""Build a pinned alert-only candidate; never install, reload or fetch rules."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

from cs_public0 import MAX_RULES_BYTES, require, validate_rules_bytes

CONVERTIBLE = frozenset(("drop", "reject", "rejectsrc", "rejectdst", "rejectboth"))


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned_snapshot(path, expected_sha256):
    require(re.fullmatch(r"[a-f0-9]{64}", expected_sha256), "expected source SHA256 is required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "source must be a regular file")
        require(before.st_size <= MAX_RULES_BYTES, "rules file too large")
        raw = stream.read(MAX_RULES_BYTES + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(all(getattr(before, key) == getattr(after, key) for key in fields), "source changed during read")
    require(len(raw) <= MAX_RULES_BYTES and sha256(raw) == expected_sha256, "source SHA256 mismatch")
    return raw


def prepare(raw, expected_sha256):
    require(re.fullmatch(r"[a-f0-9]{64}", expected_sha256) and sha256(raw) == expected_sha256,
            "source SHA256 mismatch")
    require(len(raw) <= MAX_RULES_BYTES, "rules file too large")
    # Preserve every byte except the explicitly converted action at column one.
    lines, actions, converted = [], {}, 0
    for line in raw.split(b"\n"):
        stripped = line.strip(b" \t")
        if stripped and not stripped.startswith(b"#"):
            match = re.match(rb"^([a-z]+)([ \t]+)", line)
            require(match is not None, "active rule must start with a supported action in column one")
            action = match[1].decode("ascii")
            require(action == "alert" or action in CONVERTIBLE, "unsupported action: " + action)
            actions[action] = actions.get(action, 0) + 1
            if action != "alert":
                line = b"alert" + line[len(match[1]):]
                converted += 1
        lines.append(line)
    candidate = b"\n".join(lines)
    count = validate_rules_bytes(candidate)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
        stream.write(candidate)
    compressed = buffer.getvalue()
    manifest = {
        "schema": "cs-public0-alert-candidate-v1",
        "source": {"sha256": expected_sha256, "bytes": len(raw), "actions": actions},
        "candidate": {"sha256": sha256(candidate), "bytes": len(candidate),
                      "alert_rules": count, "drop_rules": 0},
        "gzip": {"sha256": sha256(compressed), "bytes": len(compressed)},
        "converted_actions": converted,
        "transformation": "only listed enforcement actions at column one become alert",
        "engine_test": "NOT_PERFORMED", "activation": "NOT_PERFORMED",
        "production_ready": False, "measurement_eligible": False,
    }
    return candidate, compressed, manifest


def write_candidate(directory, candidate, compressed, manifest):
    # A fresh directory is the transaction boundary. A partial directory is
    # retained on failure and never treated as installable or overwritten.
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    values = {"candidate.rules": candidate, "candidate.rules.gz": compressed,
              "manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()}
    for name, raw in values.items():
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, help="new directory; omission performs read-only preparation")
    args = parser.parse_args()
    raw = pinned_snapshot(args.source, args.source_sha256)
    candidate, compressed, manifest = prepare(raw, args.source_sha256)
    if args.output_dir is not None:
        write_candidate(args.output_dir, candidate, compressed, manifest)
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
