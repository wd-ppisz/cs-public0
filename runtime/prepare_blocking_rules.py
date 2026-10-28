#!/usr/bin/env python3
"""Prepare exact selected DROP actions offline. Never changes a service or feed."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

from cs_public0 import require, validate_rules_bytes


def convert(raw, drop_sids):
    validate_rules_bytes(raw)  # input is always the reviewed alert-only snapshot
    require(isinstance(drop_sids, list) and 0 < len(drop_sids) <= 128
            and all(type(s) is int and 1 <= s <= 4294967295 for s in drop_sids)
            and drop_sids == sorted(set(drop_sids)), "canonical nonempty SID list required")
    result = []
    found = set()
    for line in raw.splitlines(keepends=True):
        if line.startswith(b"alert " ) or line.startswith(b"alert\t"):
            options = line.split(b"(", 1)[1].rsplit(b")", 1)[0]
            parts = re.split(rb"(?<!\\);", options)
            values = [v.partition(b":")[2].strip() for v in parts
                      if v.partition(b":")[0].strip().lower() == b"sid"]
            require(len(values) == 1 and re.fullmatch(rb"[1-9][0-9]{0,9}", values[0]),
                    "one SID required")
            sid = int(values[0])
            if sid in drop_sids:
                require(sid not in found, "duplicate selected SID")
                found.add(sid)
                line = b"drop" + line[5:]
        result.append(line)
    require(found == set(drop_sids), "selected SID missing from exact input")
    output = b"".join(result)
    validate_rules_bytes(output, drop_sids)
    return output


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--input-sha256", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--drop-sid", type=int, action="append", required=True)
    a = p.parse_args()
    source = Path(a.input)
    require(source.stat().st_size <= 64 * 1024**2, "input too large")
    raw = source.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == a.input_sha256, "input pin differs")
    output = convert(raw, a.drop_sid)
    destination = Path(a.output)
    with destination.open("xb") as f:
        f.write(output)
    with Path(str(destination) + ".gz").open("xb") as f:
        f.write(gzip.compress(output, mtime=0))
    print(json.dumps({"rules_sha256": hashlib.sha256(output).hexdigest(),
                      "drop_sids": a.drop_sid, "activated": False}))


if __name__ == "__main__":
    main()
