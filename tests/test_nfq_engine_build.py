import importlib.util
import io
import lzma
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("nfq_build", Path(__file__).parents[1] / "tools/build_nfq_engine.py")
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)


def tar_bytes(files, extra=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as stream:
        for name, raw in files.items():
            member = tarfile.TarInfo(name); member.size = len(raw); member.mode = 0o644
            stream.addfile(member, io.BytesIO(raw))
        for member in extra:
            stream.addfile(member)
    return lzma.compress(buffer.getvalue())


def ar_bytes(members):
    raw = b"!<arch>\n"
    for name, data in members:
        header = (name + "/").ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
        header += "100644".ljust(8) + str(len(data)).ljust(10) + "\x60\n"
        raw += header.encode() + data + (b"\n" if len(data) % 2 else b"")
    return raw


CONTROL = (b"Package: webdisk-suricata-public0-rcvbuf\nVersion: 8.0.7-1wdrcvbuf1\n"
           b"Architecture: amd64\nDepends: libc6\nDescription: Synthetic package fixture\n")


def fixture(control=None, payload=None, extra=()):
    # Structural ELF fixture only; this test never claims an executable engine.
    binary = bytearray(128); binary[:6] = b"\x7fELF\x02\x01"; binary[18:20] = b"\x3e\x00"
    payload = payload if payload is not None else {p: bytes(binary) if p.endswith("/suricata") else b"fixture" for p in b.PAYLOAD}
    return ar_bytes([("debian-binary", b"2.0\n"),
                     ("control.tar.xz", tar_bytes({"control": control or CONTROL})),
                     ("data.tar.xz", tar_bytes(payload, extra))]), bytes(binary)


class PackageAudit(unittest.TestCase):
    def audit(self, raw, binary):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "candidate.deb"; p.write_bytes(raw)
            return b.audit(p, b.sha(raw), b.sha(binary))

    def test_structural_fixture_is_not_runtime_qualification(self):
        raw, binary = fixture()
        result = self.audit(raw, binary)
        self.assertEqual(result["binary_bytes"], 128)
        self.assertFalse(result["maintainer_scripts"])
        self.assertEqual(set(result["payload"]), b.PAYLOAD)

    def test_wrong_package_pin_rejects_before_decode(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "candidate.deb"; p.write_bytes(b"not a package")
            with self.assertRaisesRegex(RuntimeError, "package pin"):
                b.audit(p, "0" * 64, "1" * 64)

    def test_additional_payload_rejected(self):
        raw, binary = fixture()
        contents = b.tar_members(b.deb_members(raw)["data.tar.xz"], 33554432)
        contents["etc/cron.d/activate"] = b"forbidden"
        raw, binary = fixture(payload=contents)
        with self.assertRaisesRegex(RuntimeError, "payload"):
            self.audit(raw, binary)

    def test_maintainer_script_rejected(self):
        raw, binary = fixture()
        members = b.deb_members(raw)
        members["control.tar.xz"] = tar_bytes({"control": CONTROL, "postinst": b"#!/bin/sh\n"})
        with self.assertRaisesRegex(RuntimeError, "maintainer"):
            self.audit(ar_bytes(list(members.items())), binary)

    def test_symbolic_link_rejected(self):
        link = tarfile.TarInfo(b.PREFIX + "/share/link"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/shadow"
        raw, binary = fixture(extra=[link])
        with self.assertRaisesRegex(RuntimeError, "link"):
            self.audit(raw, binary)

    def test_traversal_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unsafe archive"):
            b.tar_members(tar_bytes({"../escape": b"x"}), 32768)

    def test_duplicate_ar_member_rejected(self):
        raw, _ = fixture()
        members = list(b.deb_members(raw).items())
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            b.deb_members(ar_bytes(members + members[:1]))

    def test_truncated_ar_rejected(self):
        raw, _ = fixture()
        with self.assertRaises(RuntimeError):
            b.deb_members(raw[:-17])

    def test_wrong_elf_architecture_rejected(self):
        raw, binary = fixture()
        contents = b.tar_members(b.deb_members(raw)["data.tar.xz"], 33554432)
        other = bytearray(binary); other[18:20] = b"\xb7\x00"
        contents[b.PREFIX + "/bin/suricata"] = bytes(other)
        raw, _ = fixture(payload=contents)
        with self.assertRaisesRegex(RuntimeError, "ELF"):
            self.audit(raw, bytes(other))

    def test_duplicate_control_field_rejected(self):
        raw, binary = fixture(control=CONTROL + b"Architecture: amd64\n")
        with self.assertRaisesRegex(RuntimeError, "duplicate control"):
            self.audit(raw, binary)


    def test_unexpected_directory_rejected(self):
        directory = tarfile.TarInfo("etc/cron.d"); directory.type = tarfile.DIRTYPE; directory.mode = 0o755
        raw, binary = fixture(extra=[directory])
        with self.assertRaisesRegex(RuntimeError, "directory"):
            self.audit(raw, binary)

    def test_root_or_payload_directory_permissions_cannot_change(self):
        for name in (".", b.PREFIX):
            directory = tarfile.TarInfo(name); directory.type = tarfile.DIRTYPE; directory.mode = 0o700
            raw, binary = fixture(extra=[directory])
            with self.assertRaisesRegex(RuntimeError, "directory"):
                self.audit(raw, binary)

    def test_standard_payload_directory_allowed(self):
        directory = tarfile.TarInfo(b.PREFIX); directory.type = tarfile.DIRTYPE; directory.mode = 0o755
        raw, binary = fixture(extra=[directory])
        self.assertEqual(self.audit(raw, binary)["binary_bytes"], 128)

    def test_xz_expansion_and_concatenation_rejected(self):
        for data in (lzma.compress(b"x" * 1025), lzma.compress(b"x") + lzma.compress(b"y")):
            with self.assertRaisesRegex(RuntimeError, "bound|trailing"):
                b.tar_members(data, 1024)

    def test_upstream_pin_rejected_without_extract(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "upstream.tar.gz"; p.write_bytes(b"wrong")
            out = Path(temp) / "out"
            with self.assertRaisesRegex(RuntimeError, "upstream archive pin"):
                b.prepare(p, out)
            self.assertFalse(out.exists())

    def test_source_traversal_rejected_without_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "source.tar.gz"
            with tarfile.open(p, "w:gz") as stream:
                member = tarfile.TarInfo("../escape"); member.size = 1
                stream.addfile(member, io.BytesIO(b"x"))
            out = Path(temp) / "out"; out.mkdir()
            with self.assertRaisesRegex(RuntimeError, "unsafe archive"):
                b.extract_source(p, out)
            self.assertFalse((Path(temp) / "escape").exists())


if __name__ == "__main__":
    unittest.main()
