#!/usr/bin/env python3
"""Build/audit the optional NFQUEUE engine. No service installation or activation."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

RELEASE_SHA = "a9d46a9c8f40e81f8a6df3ecc2c5a9a8e8da985876299108d92da547c013ba8c"
UPSTREAM_C_SHA = "afcb44676f30a8cfbc481a8eb5631da293da4ce50c7e0587ed5ca884880f3f67"
GSO_C_SHA = "f0ba2295976247597adcca6616ac7df55a2c51769359721a16b9e8951bfc8f4d"
FINAL_C_SHA = "b44165142a4194b6719972901835ac191b0dc36b2c6d4d93e59960b9b9f51f47"
PATCHES = {
    "suricata-8.0.7-nfq-gso-copy.patch": "1c8e377227b709f4ddabd8d0c36de819fa7a2c5fa45f3e0023e2126d9a5599aa",
    "suricata-8.0.7-nfq-rcvbuf.patch": "5eb25112e74d0be1d05b3780c7a1a2b0b6d679d248e0ef141e025b1f0026823f",
}
HEADER_SHA = "f3eeb058550fdefafb5e8d67f2399ee75fed410d7baf7bcb1e998e9a62a9a478"
PREFIX = "opt/webdisk/suricata-8.0.7-nfq-rcvbuf-v1"
PACKAGE = "webdisk-suricata-public0-rcvbuf_8.0.7-1wdrcvbuf1_amd64.deb"
PROJECT = Path(__file__).resolve().parents[1]
PAYLOAD = {PREFIX + "/bin/suricata", *(PREFIX + "/share/" + n for n in
           ("COPYING", "classification.config", "reference.config"))}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(name):
    require(isinstance(name, str) and "\0" not in name, "invalid archive path")
    name = name.removeprefix("./").rstrip("/")
    p = PurePosixPath(name)
    require(not p.is_absolute() and ".." not in p.parts and "\\" not in name, "unsafe archive path")
    require(name in ("", ".") or str(p) == name, "noncanonical archive path")
    return name


def extract_source(archive, destination):
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        require(len(members) <= 20000 and sum(x.size for x in members) <= 536870912,
                "source archive exceeds bound")
        for member in members:
            name = canonical(member.name)
            require(name == "suricata-8.0.7" or name.startswith("suricata-8.0.7/"),
                    "unexpected source root")
            require(member.isdir() or member.isfile(), "source links or devices forbidden")
        stream.extractall(destination, members=members, filter="data")


def prepare(archive, destination, project=PROJECT):
    require(archive.is_file() and archive.stat().st_size <= 67108864
            and sha(archive.read_bytes()) == RELEASE_SHA, "upstream archive pin differs")
    pins = {name: sha((project / "patches" / name).read_bytes()) for name in PATCHES}
    require(pins == PATCHES, "source patch pin differs")
    header = (project / "patches/source-nfq-rcvbuf.h").read_bytes()
    require(sha(header) == HEADER_SHA, "receive buffer header pin differs")
    require(not destination.exists(), "source destination occupied")
    destination.mkdir()
    extract_source(archive, destination)
    src = destination / "suricata-8.0.7"
    require(sha((src / "src/source-nfq.c").read_bytes()) == UPSTREAM_C_SHA, "upstream source differs")
    for name, expected in zip(PATCHES, (GSO_C_SHA, FINAL_C_SHA)):
        subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i",
                        str(project / "patches" / name)], cwd=src, check=True,
                       capture_output=True, timeout=20)
        require(sha((src / "src/source-nfq.c").read_bytes()) == expected, "patched source differs")
    (src / "src/source-nfq-rcvbuf.h").write_bytes(header)
    configure = src / "configure.ac"
    text = configure.read_text()
    needle = "        # check if the argument to nfq_get_payload is signed or unsigned"
    require(text.count(needle) == 1 and 'SECCFLAGS="-fstack-protector"' in text
            and ('SECCFLAGS="' + chr(36) + '{SECCFLAGS} -D_FORTIFY_SOURCE=2"') in text,
            "configure probes differ")
    text = text.replace(needle,
        "        AC_CHECK_LIB([netfilter_queue], [nfq_get_skbinfo],"
        "AC_DEFINE_UNQUOTED([HAVE_NFQ_GET_SKBINFO],[1],[Found skb metadata API]),"
        "AC_MSG_ERROR([nfq_get_skbinfo required]),[-lnfnetlink])\n" + needle)
    configure.write_text(text.replace("-fstack-protector", "-fstack-protector-strong")
                         .replace("-D_FORTIFY_SOURCE=2", "-D_FORTIFY_SOURCE=3"))
    return src


def deb_members(raw):
    require(type(raw) is bytes and len(raw) <= 16777216 and raw.startswith(b"!<arch>\n"),
            "invalid or oversized deb")
    cursor, result = 8, {}
    while cursor < len(raw):
        require(cursor + 60 <= len(raw), "short ar header")
        header = raw[cursor:cursor + 60]
        require(header[-2:] == b"\x60\n", "invalid ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size_text = header[48:58].decode("ascii").strip()
        require(size_text.isdecimal(), "invalid ar size")
        size = int(size_text); cursor += 60
        require(name not in result and cursor + size <= len(raw), "duplicate or short ar member")
        result[name] = raw[cursor:cursor + size]
        cursor += size + size % 2
    require(cursor == len(raw) and set(result) == {"debian-binary", "control.tar.xz", "data.tar.xz"}
            and result["debian-binary"] == b"2.0\n", "unexpected deb members")
    return result


def tar_members(compressed, limit, directories=()):
    decoder = lzma.LZMADecompressor(memlimit=134217728)
    raw = decoder.decompress(compressed, max_length=limit + 1)
    require(len(raw) <= limit and decoder.eof and not decoder.unused_data,
            "compressed package member exceeds bound or has trailing data")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        members = stream.getmembers()
        require(len(members) <= 64, "too many package entries")
        for member in members:
            name = canonical(member.name)
            require(member.uid == 0 and member.gid == 0 and not member.mode & 0o7022,
                    "unsafe package ownership or mode")
            if member.isdir():
                require(name in {"", ".", *directories} and member.mode == 0o755,
                        "unexpected package directory or directory mode")
                continue
            require(member.isfile() and name not in files and member.size <= 16777216,
                    "package link, duplicate or oversized file")
            files[name] = stream.extractfile(member).read()
    return files


def audit(package, expected_package, expected_binary):
    require(package.stat().st_size <= 16777216, "package exceeds bound")
    raw = package.read_bytes()
    require(re.fullmatch(r"[a-f0-9]{64}", expected_package) and sha(raw) == expected_package,
            "package pin differs")
    require(re.fullmatch(r"[a-f0-9]{64}", expected_binary), "invalid binary pin")
    members = deb_members(raw)
    control = tar_members(members["control.tar.xz"], 131072)
    require(set(control) == {"control"}, "maintainer scripts or unknown control files forbidden")
    fields = {}
    for line in control["control"].decode().splitlines():
        if not line or line.startswith(" "):
            continue
        key, value = line.split(": ", 1)
        require(key not in fields, "duplicate control field")
        fields[key] = value
    require(fields.get("Package") == "webdisk-suricata-public0-rcvbuf"
            and fields.get("Version") == "8.0.7-1wdrcvbuf1"
            and fields.get("Architecture") == "amd64" and bool(fields.get("Depends")),
            "package identity differs")
    directories = {str(parent) for path in PAYLOAD for parent in PurePosixPath(path).parents
                   if str(parent) != "."}
    payload = tar_members(members["data.tar.xz"], 33554432, directories)
    require(set(payload) == PAYLOAD, "unexpected package payload")
    binary = payload[PREFIX + "/bin/suricata"]
    require(sha(binary) == expected_binary and len(binary) >= 64
            and binary.startswith(b"\x7fELF\x02\x01") and binary[18:20] == b"\x3e\x00",
            "binary pin or ELF architecture differs")
    return {"package_sha256": sha(raw), "package_bytes": len(raw),
            "binary_sha256": sha(binary), "binary_bytes": len(binary),
            "payload": {n: {"sha256": sha(v), "bytes": len(v)} for n, v in payload.items()},
            "maintainer_scripts": False, "services_in_package": False}


def build(archive, output, source_commit):
    require(re.fullmatch(r"[a-f0-9]{40}", source_commit), "exact source commit required")
    require(not output.exists(), "output occupied")
    output.mkdir()
    calls = []
    with tempfile.TemporaryDirectory(prefix="cs-public0-build-") as temp:
        work = Path(temp)
        os.environ["TMPDIR"] = str(work)
        os.environ["CARGO_NET_OFFLINE"] = "true"
        src = prepare(archive, work / "source")
        def run(argv, cwd=src, timeout=90):
            p = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout)
            record = {"argv": argv, "cwd": str(cwd), "rc": p.returncode,
                      "stdout": p.stdout.decode("utf8", "backslashreplace"),
                      "stderr": p.stderr.decode("utf8", "backslashreplace")}
            calls.append(record)
            (output / "commands.json").write_text(json.dumps(calls, indent=2) + "\n")
            require(p.returncode == 0, "build command failed: " + str(argv))
            return record["stdout"]
        run(["autoreconf", "-fi"], timeout=180)
        run(["./configure", "--enable-nfqueue", "--enable-gccprotect", "--enable-pie",
             "--disable-unittests", "--disable-gccmarch-native", "--disable-python",
             "--prefix=/" + PREFIX, "CFLAGS=-O2 -g", "RUSTFLAGS=-C relocation-model=pic"], timeout=240)
        run(["make", "-j2"], timeout=1500)
        binary = work / "suricata"
        shutil.copy2(src / "src/suricata", binary)
        run(["strip", "--strip-unneeded", str(binary)])
        info = run([str(binary), "--build-info"])
        require(re.search(r"NFQueue support:\s+yes", info) and re.search(r"Hyperscan support:\s+yes", info)
                and re.search(r"Unit tests enabled:\s+no", info)
                and "-fstack-protector-strong" in info and "-D_FORTIFY_SOURCE=3" in info,
                "unexpected build profile")
        elf = {kind: run(["readelf", flag, str(binary)]) for kind, flag in
               (("header", "-hW"), ("program", "-lW"), ("dynamic", "-dW"), ("symbols", "-Ws"))}
        require(re.search(r"Type:\s+DYN", elf["header"]) and "GNU_RELRO" in elf["program"]
                and "NOW" in elf["dynamic"] and "__stack_chk_fail" in elf["symbols"]
                and "RWE" not in next(x for x in elf["program"].splitlines() if "GNU_STACK" in x),
                "ELF hardening differs")
        libraries = run(["ldd", str(binary)])
        require("not found" not in libraries, "unresolved runtime library")
        log = work / "config"; log.mkdir()
        empty = work / "empty.rules"; empty.touch()
        run([str(binary), "-T", "-c", str(src / "suricata.yaml"), "-S", str(empty),
             "-l", str(log), "--set", "nfq.gso=yes", "--set", "nfq.rcvbuf-size=16777216",
             "--set", "mpm-algo=hs", "--set", "spm-algo=hs",
             "--set", "classification-file=" + str(src / "etc/classification.config"),
             "--set", "reference-config-file=" + str(src / "etc/reference.config")])
        package_root = work / "package"
        dest = package_root / PREFIX
        (dest / "bin").mkdir(parents=True); (dest / "share").mkdir()
        shutil.copy2(binary, dest / "bin/suricata")
        for name in ("classification.config", "reference.config"):
            shutil.copy2(src / "etc" / name, dest / "share" / name)
        shutil.copy2(src / "COPYING", dest / "share/COPYING")
        debian = work / "packaging/debian"; debian.mkdir(parents=True)
        (debian / "control").write_text("Source: webdisk-suricata-public0-rcvbuf\n\n"
            "Package: webdisk-suricata-public0-rcvbuf\nArchitecture: amd64\n"
            "Description: Optional NFQUEUE engine\n")
        dependencies = run(["dpkg-shlibdeps", "-O", "-e" + str(binary)], cwd=debian.parent)
        require(dependencies.startswith("shlibs:Depends="), "missing dependencies")
        (package_root / "DEBIAN").mkdir()
        (package_root / "DEBIAN/control").write_text(
            "Package: webdisk-suricata-public0-rcvbuf\nVersion: 8.0.7-1wdrcvbuf1\nArchitecture: amd64\n"
            "Maintainer: WebDisk Infrastructure <infra@webdisk.io>\nDepends: " +
            dependencies.strip().split("=", 1)[1] +
            "\nDescription: Optional GSO and bounded-copy NFQUEUE engine\n"
            " Side-by-side engine. No service or activation scripts.\n")
        package = output / PACKAGE
        run(["dpkg-deb", "--root-owner-group", "-Zxz", "-z6", "--build", str(package_root), str(package)])
        report = audit(package, sha(package.read_bytes()), sha(binary.read_bytes()))
        report.update(schema="cs-public0-nfq-engine-build-v1", source_commit=source_commit,
                      release_sha256=RELEASE_SHA, patches=PATCHES, header_sha256=HEADER_SHA,
                      source_nfq_sha256=FINAL_C_SHA, prefix="/" + PREFIX, package_file=PACKAGE,
                      config_test_passed=True, runtime_nfqueue_test_performed=False,
                      production_ready=False, measurement_eligible=False, G6="OPEN",
                      build_info=info, runtime_libraries=libraries, packages=run(["dpkg-query", "-W"]), elf=elf)
        (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
        return report


def main():
    a = argparse.ArgumentParser(description=__doc__)
    sub = a.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--archive", type=Path, required=True)
    b.add_argument("--output", type=Path, required=True)
    b.add_argument("--source-commit", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    c = sub.add_parser("audit")
    c.add_argument("--package", type=Path, required=True)
    c.add_argument("--package-sha256", required=True)
    c.add_argument("--binary-sha256", required=True)
    args = a.parse_args()
    if args.command == "build":
        value = build(args.archive.resolve(), args.output.resolve(), args.source_commit)
    elif args.command == "prepare":
        value = {"source": str(prepare(args.archive.resolve(), args.output.resolve())),
                 "runtime_test_performed": False}
    else:
        value = audit(args.package, args.package_sha256, args.binary_sha256)
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
