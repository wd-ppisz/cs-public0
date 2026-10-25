#!/usr/bin/env python3
"""Pinned rule release and startup verification. No service or reload actions."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys

from cs_public0 import validate_rules_bytes
from rule_update_journal import (MAX_FILE, directory, pin, read_file, require,
                                 unique, write_file)

SCHEMA = "cs-public0-rule-release-v1"
MAX_METADATA = 16384


def json_bytes(value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(len(raw) <= MAX_METADATA, "release metadata exceeds bound")
    return raw


def read_path(path, limit=MAX_FILE):
    path = Path(path)
    with directory(path.parent) as fd:
        return read_file(fd, path.name, limit)[0]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute(value):
    require(isinstance(value, str), "path must be a string")
    p = Path(value)
    require(p.is_absolute() and str(p) == value and ".." not in p.parts, "canonical absolute path required")
    return p


def names(value):
    require(isinstance(value, dict) and set(value) == {"rules", "gzip", "manifest"}, "invalid release names")
    for name in value.values():
        require(isinstance(name, str) and "/" not in name and name not in {"", ".", "..", "release.json"}
                and len(name) <= 96 and all(c.isascii() and (c.isalnum() or c in "._-") for c in name),
                "unsafe release filename")
    require(len(set(value.values())) == 3, "release filenames must differ")


def validate_release(value):
    keys = {"schema", "names", "rules_sha256", "rules_gzip_sha256", "rules_alert", "rules_drop", "immutable"}
    require(isinstance(value, dict) and set(value) == keys and value["schema"] == SCHEMA,
            "invalid release schema")
    names(value["names"])
    require(pin(value["rules_sha256"]) and pin(value["rules_gzip_sha256"]), "invalid rule pin")
    require(type(value["rules_alert"]) is int and 0 < value["rules_alert"] <= 1000000
            and type(value["rules_drop"]) is int and value["rules_drop"] == 0, "alert-only counts required")
    immutable = value["immutable"]
    require(isinstance(immutable, dict) and 1 <= len(immutable) <= 20, "explicit immutable pins required")
    for path, expected in immutable.items():
        absolute(path)
        require(pin(expected), "invalid immutable pin")
    return value


def unpack(compressed):
    require(type(compressed) is bytes and len(compressed) <= MAX_FILE, "gzip exceeds bound")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
        raw = stream.read(MAX_FILE + 1)
        require(len(raw) <= MAX_FILE, "expanded rules exceed bound")
        require(not stream.read(1), "expanded rules exceed bound")
    return raw


def make_release(raw, compressed, file_names, immutable):
    names(file_names)
    count = validate_rules_bytes(raw)
    require(unpack(compressed) == raw, "gzip differs from the exact rule bytes")
    return validate_release({"schema": SCHEMA, "names": dict(file_names), "rules_sha256": sha(raw),
        "rules_gzip_sha256": sha(compressed), "rules_alert": count, "rules_drop": 0,
        "immutable": dict(immutable)})


def manifest_for(previous, release):
    """Preserve provider metadata; update only the exact rule-related fields."""
    validate_release(release)
    require(isinstance(previous, dict), "manifest must be an object")
    value = json.loads(json.dumps(previous))
    artifacts = value.get("artifacts", {})
    require(isinstance(artifacts, dict), "invalid artifact map")
    value.update(rules_sha256=release["rules_sha256"], rules_gzip_sha256=release["rules_gzip_sha256"],
                 rules_alert=release["rules_alert"], rules_drop=0, actions={"alert": release["rules_alert"]})
    value["artifacts"] = {**artifacts, "rules_sha256": release["rules_sha256"],
                           "rules_gzip_sha256": release["rules_gzip_sha256"]}
    json_bytes(value)
    return value


def verify_metadata(manifest, release):
    require(manifest_for(manifest, release) == manifest, "manifest and release pins differ")


def verify_immutable(release):
    for path, expected in release["immutable"].items():
        require(sha(read_path(path)) == expected, "immutable source changed: " + path)


def verify_release(path, immutable=True):
    path = absolute(str(path))
    require(path.name == "release.json", "release must be named release.json")
    with directory(path.parent) as fd:
        value = validate_release(json.loads(read_file(fd, path.name, MAX_METADATA)[0],
                                             object_pairs_hook=unique))
        require(not set(value["names"].values()) & {Path(p).name for p in value["immutable"]
                    if Path(p).parent == path.parent}, "mutable and immutable assets overlap")
        raw = read_file(fd, value["names"]["rules"], MAX_FILE)[0]
        compressed = read_file(fd, value["names"]["gzip"], MAX_FILE)[0]
        require(sha(raw) == value["rules_sha256"] and sha(compressed) == value["rules_gzip_sha256"],
                "installed rule bytes changed")
        require(make_release(raw, compressed, value["names"], value["immutable"]) == value,
                "installed rules do not match release")
        manifest = json.loads(read_file(fd, value["names"]["manifest"], MAX_METADATA)[0],
                              object_pairs_hook=unique)
        verify_metadata(manifest, value)
    if immutable:
        verify_immutable(value)
    return value


def prepare_images(target, raw, compressed):
    """Snapshot a verified current installation; return four coherent new images."""
    old = verify_release(Path(target) / "release.json")
    new = make_release(raw, compressed, old["names"], old["immutable"])
    with directory(target) as fd:
        manifest = json.loads(read_file(fd, old["names"]["manifest"], MAX_METADATA)[0],
                              object_pairs_hook=unique)
        images = {new["names"]["rules"]: raw, new["names"]["gzip"]: compressed,
                  new["names"]["manifest"]: json_bytes(manifest_for(manifest, new)),
                  "release.json": json_bytes(new)}
        before = {name: sha(read_file(fd, name, MAX_FILE)[0]) for name in images}
    return old, new, images, before


def initialize(target, file_names, immutable_paths):
    """Explicit bootstrap only. Existing release or manifest changes are refused."""
    target = absolute(str(target))
    names(file_names)
    pins = {str(absolute(p)): sha(read_path(p)) for p in immutable_paths}
    require(len(pins) == len(immutable_paths), "duplicate immutable source")
    with directory(target) as fd:
        try:
            read_file(fd, "release.json", MAX_METADATA)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("release already initialized")
        raw = read_file(fd, file_names["rules"], MAX_FILE)[0]
        compressed = read_file(fd, file_names["gzip"], MAX_FILE)[0]
        release = make_release(raw, compressed, file_names, pins)
        manifest = json.loads(read_file(fd, file_names["manifest"], MAX_METADATA)[0],
                              object_pairs_hook=unique)
        verify_metadata(manifest, release)
        write_file(fd, "release.json", json_bytes(release), mode=0o644)
    return verify_release(target / "release.json")


def bootstrap(target, file_names, immutable_paths):
    """Add missing metadata only. Never replace an existing rule/manifest/release."""
    target = absolute(str(target))
    names(file_names)
    with directory(target) as fd:
        try:
            read_file(fd, "release.json", MAX_METADATA)
        except FileNotFoundError:
            pass
        else:
            current = verify_release(target / "release.json")
            require(set(current["immutable"]) == set(immutable_paths), "immutable source set differs")
            return current
        raw = read_file(fd, file_names["rules"], MAX_FILE)[0]
        validate_rules_bytes(raw)
        try:
            compressed = read_file(fd, file_names["gzip"], MAX_FILE)[0]
        except FileNotFoundError:
            compressed = gzip.compress(raw, mtime=0)
            write_file(fd, file_names["gzip"], compressed, mode=0o644)
        pins = {str(absolute(p)): sha(read_path(p)) for p in immutable_paths}
        require(len(pins) == len(immutable_paths), "duplicate immutable source")
        value = make_release(raw, compressed, file_names, pins)
        try:
            manifest = json.loads(read_file(fd, file_names["manifest"], MAX_METADATA)[0],
                                  object_pairs_hook=unique)
        except FileNotFoundError:
            write_file(fd, file_names["manifest"], json_bytes(manifest_for({}, value)), mode=0o644)
        else:
            verify_metadata(manifest, value)
    return initialize(target, file_names, immutable_paths)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("verify", "initialize", "bootstrap"))
    parser.add_argument("--directory", required=True)
    parser.add_argument("--rules", default="local.rules")
    parser.add_argument("--gzip", default="local.rules.gz")
    parser.add_argument("--manifest", default="manifest.json")
    parser.add_argument("--immutable", action="append", default=[])
    args = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    if args.command == "verify":
        require(not args.immutable, "verify uses the installed immutable pins")
        result = verify_release(absolute(args.directory) / "release.json")
    else:
        function = bootstrap if args.command == "bootstrap" else initialize
        result = function(args.directory, {"rules": args.rules, "gzip": args.gzip,
                                           "manifest": args.manifest}, args.immutable)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
