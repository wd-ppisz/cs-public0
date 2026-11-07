"""Synthetic public addresses and EVE shapes; no network or customer data."""
import copy
import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "runtime"))
import egress_model as m

PIN = "a" * 64


def catalog(pin=PIN):
    return m.Catalog({"schema": "cs-public0-egress-catalog-v1", "version": "fixture-1",
                      "rules_sha256": pin, "entries": [{"gid": 1, "sid": 9900001,
                      "rev": 2, "category": "c2", "severity": "high",
                      "metadata": {"malware_family": ["TEST_ONLY"]},
                      "source": "owned-lab-signature"}]})


def alert():
    return {"timestamp": "2026-11-07T08:00:01Z", "event_type": "alert", "proto": "TCP",
            "src_ip": "192.0.2.4", "src_port": 44000, "dest_ip": "198.51.100.7", "dest_port": 8080,
            "flow_id": 18446744073709551610, "flow": {"start": "2026-11-07T08:00:00Z"},
            "direction": "to_server", "alert": {"gid": 1, "signature_id": 9900001,
            "rev": 2, "signature": "DO NOT CLASSIFY BY THIS STRING", "metadata": {"malware_family": ["TEST_ONLY"]}},
            "payload": "secret", "http": {"url": "/password?secret", "body": "private"}}


def flow():
    a = alert()
    return {k: a[k] for k in ("timestamp", "proto", "src_ip", "src_port", "dest_ip", "dest_port", "flow_id")} | {
            "event_type": "flow", "flow": {"start": a["flow"]["start"], "state": "established"},
            "tcp": {"state": "established", "tcp_flags_ts": "1b", "tcp_flags_tc": "1b"}}


def config():
    return {"owned_ipv4_networks": ["192.0.2.0/24"], "sensor_id": "lab", "sensor_epoch": "boot-a"}


def reference(raw=b"event"):
    return {"device": 1, "inode": 2, "offset": 0, "length": len(raw), "record_sha256": hashlib.sha256(raw).hexdigest()}


NOW = m.timestamp("2026-11-07T08:00:02Z")


class EgressModel(unittest.TestCase):
    def observe(self, a=None, f=None, cfg=None, ioc=None):
        return m.observation(a or alert(), f, cfg or config(), catalog(), reference(), NOW, PIN, ioc)

    def test_outbound_signature_with_matching_client_syn(self):
        item = self.observe(f=flow())
        self.assertEqual((item["direction"], item["category"]), ("egress", "c2"))
        self.assertEqual(item["connection_evidence"], "sensor_observed_established")
        self.assertEqual(item["flow_id"], "18446744073709551610")
        self.assertIn("NOT_PROOF_OF_COMPROMISE", item["limitations"])

    def test_reply_to_inbound_scan_is_not_outbound_c2(self):
        f = flow()
        f["src_ip"], f["dest_ip"] = f["dest_ip"], f["src_ip"]
        f["src_port"], f["dest_port"] = f["dest_port"], f["src_port"]
        a = alert()  # The observed packet still has the owned source.
        a["direction"] = "to_client"
        self.assertEqual(self.observe(a, f)["direction"], "ingress")

    def test_packet_source_and_to_server_alone_are_unknown(self):
        item = self.observe()
        self.assertEqual(item["direction"], "unknown")
        self.assertEqual(item["attribution"]["level"], "public_ip")

    def test_closed_flow_is_not_mislabeled_as_a_connection_attempt(self):
        for state in ("closed", "time_wait", "fin_wait1", "fin_wait2"):
            f = flow(); f["flow"]["state"] = "closed"; f["tcp"]["state"] = state
            item = self.observe(f=f)
            self.assertEqual(item["direction"], "egress")
            self.assertEqual(item["connection_evidence"], "unknown")
            self.assertIn("CONNECTION_HISTORY_NOT_PROVEN_BY_FINAL_STATE", item["limitations"])

    def test_shared_snat_can_be_attributed_to_vr_not_all_guests(self):
        cfg = config()
        cfg["attribution"] = {"192.0.2.4": {"vr_ref": "owned-vr-test"}}
        item = self.observe(f=flow(), cfg=cfg)
        self.assertEqual(item["attribution"]["level"], "vr")
        self.assertNotIn("vm_ref", item["attribution"])

    def test_vm_requires_explicit_exclusive_mapping(self):
        cfg = config()
        cfg["attribution"] = {"192.0.2.4": {"vm_ref": "lab-vm", "exclusive": False}}
        with self.assertRaises(ValueError):
            self.observe(f=flow(), cfg=cfg)
        cfg["attribution"]["192.0.2.4"]["exclusive"] = True
        self.assertEqual(self.observe(f=flow(), cfg=cfg)["attribution"]["level"], "vm")

    def test_missing_syn_exception_and_udp_remain_unknown(self):
        for mutation in ("no_syn", "synack_only", "exception", "midstream", "udp"):
            with self.subTest(mutation=mutation):
                f, a = flow(), alert()
                if mutation == "no_syn": f["tcp"]["tcp_flags_ts"] = "18"
                if mutation == "synack_only": f["tcp"]["tcp_flags_ts"] = "12"
                if mutation == "exception": f["flow"]["exception_policy"] = {"target": "flow"}
                if mutation == "midstream": f["tcp"]["midstream"] = True
                if mutation == "udp": f["proto"] = a["proto"] = "UDP"
                self.assertEqual(self.observe(a, f)["direction"], "unknown")

    def test_wrong_flow_epoch_or_tuple_does_not_establish_direction(self):
        for key in ("flow_id", "tuple", "start"):
            f = flow()
            if key == "flow_id": f["flow_id"] += 1
            if key == "tuple": f["dest_port"] += 1
            if key == "start": f["flow"]["start"] = "2026-11-06T08:00:00Z"
            self.assertEqual(self.observe(f=f)["direction"], "unknown")

    def test_revision_metadata_and_rules_hash_must_match(self):
        for key in ("rev", "metadata", "pin"):
            a = alert()
            if key == "rev": a["alert"]["rev"] += 1
            if key == "metadata": a["alert"]["metadata"]["malware_family"] = ["OTHER"]
            self.assertIsNone(m.observation(a, flow(), config(), catalog(), reference(), NOW,
                                           "b" * 64 if key == "pin" else PIN))

    def test_dynamic_catalog_binding_requires_typed_exact_hash_identity(self):
        data = {"schema": "cs-public0-egress-catalog-v1", "version": "fixture", "rules_sha256": PIN,
                "entries": [], "rules_identity": {"device": 1, "inode": 2, "size": 3, "mtime_ns": 4, "ctime_ns": 5, "sha256": PIN}}
        self.assertEqual(m.Catalog(data).identity["inode"], 2)
        data["rules_identity"]["inode"] = True
        with self.assertRaises(ValueError): m.Catalog(data)
        data["rules_identity"]["inode"] = 2
        data["rules_identity"]["sha256"] = "b"*64
        with self.assertRaises(ValueError): m.Catalog(data)

    def test_signature_name_does_not_classify_unknown_sid(self):
        a = alert()
        a["alert"]["signature_id"] += 1
        a["alert"]["signature"] = "C2 BOTNET MALWARE EVIL"
        self.assertIsNone(self.observe(a, flow()))

    def test_no_payload_http_body_or_signature_text_in_details(self):
        raw = json.dumps(self.observe(f=flow()))
        for forbidden in ("password", "private", "secret", "payload", "DO NOT CLASSIFY"):
            self.assertNotIn(forbidden, raw)

    def test_actual_suricata_timestamp_and_reply_remote_endpoint(self):
        self.assertAlmostEqual(m.timestamp("2026-11-07T08:00:01.123456+0000"),
                               m.timestamp("2026-11-07T08:00:01.123456Z"))
        a, f = alert(), flow()
        a["src_ip"], a["dest_ip"] = a["dest_ip"], a["src_ip"]
        a["src_port"], a["dest_port"] = a["dest_port"], a["src_port"]
        self.assertEqual(self.observe(a, f)["remote_ip"], "198.51.100.7")

    def test_known_stream_gaps_do_not_qualify_direction(self):
        for key in ("ts_gap", "tc_gap"):
            f = flow(); f["tcp"][key] = True
            self.assertEqual(self.observe(f=f)["direction"], "unknown")

    def test_cumulative_server_synack_flags_without_peer_syn_are_unknown(self):
        for value in ("12", "1a", "1b"):
            f = flow()
            f["tcp"]["tcp_flags_ts"], f["tcp"]["tcp_flags_tc"] = value, "18"
            self.assertEqual(self.observe(f=f)["direction"], "unknown")
        f = flow()
        f["tcp"]["tcp_flags_ts"], f["tcp"]["tcp_flags_tc"] = "02", "00"
        self.assertEqual(self.observe(f=f)["direction"], "egress")

    def test_ioc_current_and_expired_are_distinct(self):
        addr = "198.51.100.7"
        ioc = m.IOC({"schema": "cs-public0-egress-ioc-v1", "source": "OWNED_LAB",
                     "version": "1", "content_sha256": hashlib.sha256((addr + "\n").encode()).hexdigest(),
                     "fetched_unix": int(NOW) - 10, "published_unix": int(NOW) - 20,
                     "expires_unix": int(NOW) + 20, "addresses": [addr]})
        item = self.observe(f=flow(), ioc=ioc)
        self.assertEqual(item["ioc"]["source"], "OWNED_LAB")
        ioc.expires = int(NOW) - 1
        item = self.observe(f=flow(), ioc=ioc)
        self.assertIsNone(item["ioc"])
        self.assertIn("IOC_NOT_CURRENT", item["limitations"])

    def test_flow_ioc_contact_is_attempt_not_signature(self):
        addr = "198.51.100.7"
        ioc = m.IOC({"schema": "cs-public0-egress-ioc-v1", "source": "OWNED_LAB", "version": "1",
                     "content_sha256": hashlib.sha256((addr + "\n").encode()).hexdigest(),
                     "published_unix": int(NOW)-2, "fetched_unix": int(NOW)-1,
                     "expires_unix": int(NOW)+100, "addresses": [addr]})
        f = flow()
        f["tcp"]["state"] = f["flow"]["state"] = "syn_sent"
        item = self.observe(f, ioc=ioc)
        self.assertEqual((item["category"], item["connection_evidence"]), ("ioc", "attempted"))
        self.assertIsNone(item["signature"])

    def test_ioc_hash_and_publisher_freshness_are_validated(self):
        with self.assertRaises(ValueError):
            m.IOC({"schema": "cs-public0-egress-ioc-v1", "source": "x", "version": "1",
                   "content_sha256": "0"*64, "published_unix": 1, "fetched_unix": 2,
                   "expires_unix": 90000, "addresses": ["198.51.100.1"]})

    def test_duplicate_json_nonfinite_and_invalid_scope_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'[]', b'x'*65537):
            with self.assertRaises(ValueError): m.strict_json(raw)
        with self.assertRaises(ValueError): m.networks(["0.0.0.0/0"])
        with self.assertRaises(ValueError): m.networks(["2001:db8::/32"])

    def test_bool_is_not_sid_and_future_event_is_not_accepted(self):
        a = alert()
        a["alert"]["signature_id"] = True
        with self.assertRaises(ValueError): self.observe(a)
        a = alert()
        a["timestamp"] = "2027-11-07T08:00:00Z"
        with self.assertRaises(ValueError): self.observe(a)


if __name__ == "__main__":
    unittest.main()
