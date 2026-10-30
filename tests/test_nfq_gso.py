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
    @staticmethod
    def startup_arguments(wait):
        return ["nfq-gso", "--unit", "cs-public0.service", "--binary-sha256", "a"*64,
                "--queue", "32201", "--host", "fixture", "--require", "--wait-seconds", str(wait)]

    def test_startup_can_wait_beyond_ninety_seconds_with_the_readiness_budget(self):
        import io
        with patch("sys.argv", self.startup_arguments(240)), \
             patch.object(gso.os, "geteuid", return_value=0), \
             patch.object(gso, "observe", side_effect=[{"known":False,"enabled":False},
                                                       {"known":True,"enabled":True}]) as observe, \
             patch.object(gso.time, "monotonic", side_effect=[0, 91]), \
             patch.object(gso.time, "sleep") as sleep, patch("sys.stdout", io.StringIO()):
            gso.main()
            self.assertEqual(observe.call_count, 2)
            sleep.assert_called_once_with(.5)

    def test_startup_budget_is_finite_and_rejects_an_unbounded_wait(self):
        import io
        with patch("sys.argv", self.startup_arguments(gso.MAX_WAIT_SECONDS)), \
             patch.object(gso.os, "geteuid", return_value=0), \
             patch.object(gso, "observe", return_value={"known":False,"enabled":False}), \
             patch.object(gso.time, "monotonic", side_effect=[0, gso.MAX_WAIT_SECONDS+1]), \
             patch.object(gso.time, "sleep") as sleep, patch("sys.stdout", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                gso.main()
            self.assertEqual(raised.exception.code, 1)
            sleep.assert_not_called()
        with patch("sys.argv", self.startup_arguments(gso.MAX_WAIT_SECONDS+1)), \
             patch.object(gso.os, "geteuid", return_value=0), patch.object(gso, "observe") as observe:
            with self.assertRaisesRegex(RuntimeError, "invalid bound"):
                gso.main()
            observe.assert_not_called()

    def test_signed_diagnostic_ports_preserve_the_full_unsigned_proc_identity(self):
        for unsigned, signed in [(1,1),(2147483647,2147483647),
                                 (2147483648,-2147483648),(3000000000,-1294967296),
                                 (4294967295,-1)]:
            with self.subTest(unsigned=unsigned):
                self.assertEqual(gso.diagnostic_portid(unsigned),signed)
                raw="UNCONN 0 0 12:"+str(signed)+" * sk=0 skmem:(r0,rb33554432,t0)\n"
                self.assertEqual(gso.socket_rcvbuf(raw,unsigned),33554432)
        for invalid in [0,-1,4294967296,True,"3000000000"]:
            with self.subTest(invalid=invalid), self.assertRaisesRegex(RuntimeError,"invalid netlink port"):
                gso.diagnostic_portid(invalid)

    def test_highbit_port_is_signed_only_for_ss_and_keeps_unsigned_inode_binding(self):
        port=3000000000
        proc=Path("/proc/123")
        ack="NFQUEUE receive buffer verified queue=32201 requested=16777216 effective=33554432\n"
        raw="UNCONN 0 0 12:-1294967296 * sk=0 skmem:(r0,rb33554432,t0)\n"
        with patch.object(gso,"socket_identity",side_effect=["77","77"]) as identity, \
             patch.object(gso,"command",side_effect=[raw,ack]) as command:
            self.assertEqual(gso.verify_rcvbuf(proc,["suricata","--set","nfq.rcvbuf-size=16777216"],
                             "cs-public0.service","a"*32,32201,port,16777216),33554432)
            self.assertEqual(command.call_args_list[0].args[0][-2:],["src","12:-1294967296"])
            self.assertEqual([call.args for call in identity.call_args_list],[(proc,port),(proc,port)])

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

    def test_queue_port_can_differ_from_pid_but_must_have_an_owned_socket(self):
        process = object()
        raw = "32201 456 0 2 65531 0 0 42 1\n"
        with patch.object(gso, "Path", return_value=SimpleNamespace(read_text=lambda: raw)), \
                patch.object(gso, "socket_identity", return_value="77") as identity:
            self.assertEqual(gso.queue_socket_identity(process, 32201), (456, "77"))
            identity.assert_called_once_with(process, 456)
        for bad in (raw + raw, raw.replace("456", "0"), raw.replace("456", "4294967296"), ""):
            with self.subTest(raw=bad), \
                    patch.object(gso, "Path", return_value=SimpleNamespace(read_text=lambda: bad)), \
                    self.assertRaises(RuntimeError):
                gso.queue_socket_identity(process, 32201)

    def test_buffer_query_filters_before_the_existing_output_bound(self):
        diag = b"UNCONN 0 0 12:456 * skmem:(r0,rb33554432,t0)\n"
        ack = b"NFQUEUE receive buffer verified queue=32201 requested=16777216 effective=33554432\n"
        def execute(argv, **kwargs):
            if argv[0] == "ss":
                return SimpleNamespace(stdout=diag if argv[-2:] == ["src", "12:456"] else b"x" * 65537)
            return SimpleNamespace(stdout=ack)
        with patch.object(gso, "socket_identity", return_value="77"), \
                patch.object(gso.subprocess, "run", side_effect=execute):
            self.assertEqual(gso.verify_rcvbuf(None, ["suricata", "--set", "nfq.rcvbuf-size=16777216"],
                             "test.service", "a" * 32, 32201, 456, 16777216), 33554432)

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
            def open(self, mode):
                import io
                if self.path.endswith("/exe") and mode == "rb":
                    return io.BytesIO(b"engine")
                raise AssertionError((self.path, mode))
            reads = 0
            def read_text(self):
                File.reads += 1
                port = "457" if fault == "port" and File.reads > 1 else "456"
                return "32201 " + port + " 0 2 65531 0 0 42 1\n"
        with patch.object(gso, "Path", File), patch.object(gso, "unit_state", side_effect=[state, after]), \
             patch.object(gso, "socket_identity", side_effect=RuntimeError("foreign socket") if fault == "peer"
                          else ["77", "88" if fault == "inode" else "77"]), \
             patch.object(gso, "command", return_value="" if fault == "ack" else "Info: nfq: NFQUEUE GSO enabled\n"):
            pin = "0" * 64 if fault == "binary" else hashlib.sha256(b"engine").hexdigest()
            return gso.observe("cs-public0.service", pin, 32201)

    def test_binary_hash_reads_bounded_chunks_and_preserves_exact_digest(self):
        import io
        payload = b"engine" * (1024 * 1024)
        calls = []
        class Bounded(io.BytesIO):
            def read(self, size=-1):
                calls.append(size)
                if size < 0 or size > 1024 * 1024:
                    raise AssertionError("unbounded executable read")
                return super().read(size)
        source = SimpleNamespace(open=lambda mode: Bounded(payload))
        self.assertEqual(gso.file_sha256(source), hashlib.sha256(payload).hexdigest())
        self.assertGreater(len(calls), 2)
        self.assertEqual(set(calls), {1024 * 1024})

    def test_lost_startup_ack_is_unknown_evidence_not_proof_gso_is_disabled(self):
        value = self.observe("ack")
        self.assertFalse(value["known"])
        self.assertFalse(value["enabled"])
        self.assertEqual(value["error"], "GSO acknowledgement is absent")
        text = gso.metrics(value, "fixture")
        self.assertIn('cs_public0_gso_known{host="fixture",profile="public0-ipv4-alert"} 0', text)

    def test_bound_acknowledged_gso(self):
        self.assertTrue(self.observe()["enabled"])

    def test_missing_flag_ack_foreign_queue_binary_and_epoch_are_unknown(self):
        for fault in ("setting", "ack", "peer", "binary", "epoch", "port", "inode"):
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
