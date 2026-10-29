import hashlib
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "runtime" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


gso, forwarding = module("nfq_gso"), module("forwarding_probe")


class GSOTests(unittest.TestCase):
    def test_socket_buffer_selects_exact_netfilter_port(self):
        raw = ("UNCONN 0 0 0:123 * skmem:(r0,rb999,t0)\n"
               "UNCONN 0 0 12:123 * sk=0 skmem:(r0,rb33554432,t0)\n"
               "UNCONN 0 0 12:1234 * skmem:(r0,rb888,t0)\n")
        self.assertEqual(gso.socket_rcvbuf(raw, 123), 33554432)
        for bad in ("", raw + raw, raw.replace("rb33554432", "rb0"),
                    raw.replace("rb33554432", "rb999999999999")):
            with self.assertRaises(RuntimeError): gso.socket_rcvbuf(bad, 123)

    def test_buffer_requires_explicit_bound_setting_ack_and_effective_capacity(self):
        argv = ["suricata", "--set", "nfq.rcvbuf-size=16777216"]
        ack = "Info: NFQUEUE receive buffer verified queue=32201 requested=16777216 effective=33554432\n"
        diag = "UNCONN 0 0 12:123 * skmem:(r0,rb33554432,t0)\n"
        with patch.object(gso, "socket_identity", side_effect=["77", "77"]), \
             patch.object(gso, "command", side_effect=[diag, ack]):
            self.assertEqual(gso.verify_rcvbuf(None, argv, "test.service", "a" * 32, 32201, 123, 16777216), 33554432)
        for fault in ("clamp", "ack", "socket", "duplicate", "setting", "boolean"):
            bad_argv = argv + ["--set", "nfq.rcvbuf-size=16777216"] if fault == "duplicate" else argv
            if fault == "setting": bad_argv = ["suricata", "nfq.rcvbuf-size=16777216"]
            with self.subTest(fault=fault), \
                 patch.object(gso, "socket_identity", side_effect=["77", "88" if fault == "socket" else "77"]), \
                 patch.object(gso, "command", side_effect=[diag.replace("33554432", "1536000") if fault == "clamp" else diag,
                                                         ack.replace("32201", "32202") if fault == "ack" else ack]):
                with self.assertRaises(RuntimeError):
                    gso.verify_rcvbuf(None, bad_argv, "test.service", "a" * 32, 32201, 123,
                                      True if fault == "boolean" else 16777216)

    def test_socket_inode_requires_bound_process_fd_and_unique_netlink_row(self):
        process = SimpleNamespace(__truediv__=lambda *a: None)
        class Process:
            def __truediv__(self, part):
                self.assert_part = part
                return SimpleNamespace(iterdir=lambda: ["/proc/123/fd/4"])
        row = "0000 12 123 0 0 0 0 2 0 77\n"
        for raw, target, success in ((row, "socket:[77]", True), (row, "socket:[88]", False),
                                     (row + row, "socket:[77]", False), (row.replace("12", "11", 1), "socket:[77]", False)):
            with patch.object(gso, "Path", return_value=SimpleNamespace(read_text=lambda: raw)), \
                 patch.object(gso.os, "readlink", return_value=target):
                if success: self.assertEqual(gso.socket_identity(Process(), 123), "77")
                else:
                    with self.assertRaises(RuntimeError): gso.socket_identity(Process(), 123)

    def test_requires_one_explicit_unoverridden_cli_setting(self):
        self.assertTrue(gso.explicit_gso(["suricata", "--set", "nfq.gso=yes"]))
        for argv in (["suricata"], ["suricata", "nfq.gso=yes"],
                     ["suricata", "--set", "nfq.gso=no"],
                     ["suricata", "--set", "nfq.gso=yes", "--set", "nfq.gso=no"],
                     ["suricata", "--set", "nfq.gso=yes", "--set", "nfq.gso=yes"]):
            self.assertFalse(gso.explicit_gso(argv))

    def observe(self, fault=None):
        state = {"MainPID": "123", "InvocationID": "a" * 32, "ActiveState": "active"}
        after = dict(state, InvocationID="b" * 32) if fault == "epoch" else state
        class File:
            def __init__(self, path): self.path = str(path)
            def __truediv__(self, part): return File(self.path + "/" + str(part))
            def read_bytes(self):
                if self.path.endswith("/stat"): return b"123 (sensor name) " + b" ".join([b"0"] * 19 + [b"99"])
                if self.path.endswith("/exe"): return b"engine"
                if self.path.endswith("/cmdline"):
                    return b"suricata\0--set\0nfq.gso=no\0" if fault == "setting" else b"suricata\0--set\0nfq.gso=yes\0"
                raise AssertionError(self.path)
            def read_text(self):
                return "32201 " + ("124" if fault == "peer" else "123") + " 0 2 65531 0 0 42 1\n"
        with patch.object(gso, "Path", File), patch.object(gso, "unit_state", side_effect=[state, after]), \
             patch.object(gso, "command", return_value="" if fault == "ack" else "Info: nfq: NFQUEUE GSO enabled\n"):
            pin = "0" * 64 if fault == "binary" else hashlib.sha256(b"engine").hexdigest()
            return gso.observe("cs-public0.service", pin, 32201)

    def test_bound_acknowledged_gso(self):
        self.assertTrue(self.observe()["enabled"])

    def test_missing_flag_ack_foreign_queue_binary_and_epoch_are_unknown(self):
        for fault in ("setting", "ack", "peer", "binary", "epoch"):
            with self.subTest(fault=fault):
                value = self.observe(fault)
                self.assertFalse(value["enabled"])
                self.assertFalse(value["known"])
                self.assertIn("error", value)

    def test_unknown_sample_is_exported_as_unknown(self):
        text = gso.metrics({"known": False, "enabled": False, "sample_unix_seconds": 10}, "host-a")
        self.assertIn('cs_public0_gso_known{host="host-a",profile="public0-ipv4-alert"} 0', text)
        with self.assertRaises(RuntimeError): gso.metrics({}, 'x"}\ninjected 1')

    def test_tcp_info_exact_kernel_offset_and_short_data(self):
        raw = bytearray(160);struct.pack_into("=I", raw, 100, 13)
        stream = SimpleNamespace(getsockopt=lambda *a: bytes(raw))
        with patch.object(forwarding.socket, "TCP_INFO", 11, create=True):
            self.assertEqual(forwarding.tcp_info(stream), 13)
            stream.getsockopt = lambda *a: bytes(100)
            with self.assertRaises(RuntimeError): forwarding.tcp_info(stream)

    def test_probe_failure_does_not_report_tcp_info_known(self):
        with patch.object(forwarding.socket, "create_connection", side_effect=TimeoutError("fixture")):
            value = forwarding.probe("fixture.invalid", 8080, b"ok")
        self.assertEqual(value["success"], 0)
        self.assertEqual(value["tcp_info_known"], 0)
        self.assertIn("error", value)
        self.assertIn('scope="external_owned_upload"', forwarding.metrics(value, "host-a"))


if __name__ == "__main__":
    unittest.main()
