"""Bounded, pure classification of EVE observations; no enforcement or I/O."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime

CATEGORIES = ("c2", "ioc", "scan", "other")
SEVERITIES = ("high", "medium", "low", "unknown")
DIRECTIONS = ("egress", "ingress", "unknown")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECORD = 65536


def integer(value, minimum=0, maximum=2**64 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("integer outside contract")
    return value


def text(value, limit=256):
    if not isinstance(value, str) or not value or len(value.encode()) > limit:
        raise ValueError("text outside contract")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("control character")
    return value


def strict_json(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_RECORD:
        raise ValueError("record size")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def invalid(_):
        raise ValueError("nonfinite number")

    def number(token):
        value = float(token)
        if not math.isfinite(value):
            raise ValueError("nonfinite number")
        return value

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=number)
    if not isinstance(value, dict):
        raise ValueError("record must be an object")
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 64:
            raise ValueError("JSON nesting bound")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("timestamp")
    normalized = value.replace("Z", "+00:00")
    normalized = re.sub(r"([+-][0-9]{2})([0-9]{2})$", r"\1:\2", normalized)
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.timestamp()


def ipv4(value):
    result = ipaddress.ip_address(text(value, 45))
    if result.version != 4 or result.is_multicast or result.is_unspecified:
        raise ValueError("unsupported address")
    return str(result)


def networks(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise ValueError("owned networks")
    out = []
    for value in values:
        n = ipaddress.ip_network(value, strict=True)
        if n.version != 4 or n.prefixlen < 8:
            raise ValueError("owned network scope")
        out.append(n)
    return tuple(out)


def owned(address, nets):
    return any(ipaddress.ip_address(address) in net for net in nets)


def validate_config(config):
    """Validate operator classification policy before any source is consumed."""
    nets = networks(config["owned_ipv4_networks"])
    text(config["sensor_id"], 64)
    text(config["sensor_epoch"], 96)  # Leave room for the bounded local generation suffix.
    text(config.get("observation_point", "public0_post_snat_ipv4"), 128)
    if config.get("initial_position", "end") not in ("begin", "end"):
        raise ValueError("initial position")
    if type(config.get("flow_join_enabled", False)) is not bool:
        raise ValueError("flow join mode")
    integer(config.get("join_wait_seconds", 15), 0, 86400)
    mappings = config.get("attribution", {})
    if not isinstance(mappings, dict) or len(mappings) > 4096:
        raise ValueError("attribution configuration")
    for address, mapping in mappings.items():
        if not owned(ipv4(address), nets) or not isinstance(mapping, dict):
            raise ValueError("attribution scope")
        if "exclusive" in mapping and type(mapping["exclusive"]) is not bool:
            raise ValueError("exclusive mapping flag")
        for key in ("vr_ref", "vm_ref"):
            if key in mapping: text(mapping[key], 128)
        if "vm_ref" in mapping and mapping.get("exclusive") is not True:
            raise ValueError("VM attribution requires exclusive mapping")


def tuple_of(row):
    return {"src_ip": ipv4(row["src_ip"]),
            "dest_ip": ipv4(row["dest_ip"]),
            "src_port": integer(row["src_port"], 0, 65535),
            "dest_port": integer(row["dest_port"], 0, 65535)}


def metadata(value):
    if not isinstance(value, dict) or len(value) > 32:
        raise ValueError("metadata")
    out = {}
    for key, values in value.items():
        text(key, 64)
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise ValueError("metadata values")
        out[key] = tuple(sorted(text(v, 128) for v in values))
    return out


class Catalog:
    def __init__(self, data):
        if not isinstance(data, dict) or data.get("schema") != "cs-public0-egress-catalog-v1":
            raise ValueError("catalog schema")
        self.version = text(data["version"], 128)
        self.rules_sha256 = text(data["rules_sha256"], 64)
        if not SHA.fullmatch(self.rules_sha256):
            raise ValueError("rules pin")
        self.identity = data.get("rules_identity")
        if self.identity is not None:
            if not isinstance(self.identity, dict) or set(self.identity) != {"device", "inode", "size", "mtime_ns", "ctime_ns", "sha256"}:
                raise ValueError("catalog rule identity")
            for key in ("device", "inode", "size", "mtime_ns", "ctime_ns"):
                integer(self.identity[key])
            if self.identity["sha256"] != self.rules_sha256:
                raise ValueError("catalog identity pin")
        rows = data["entries"]
        if not isinstance(rows, list) or len(rows) > 4096:
            raise ValueError("catalog entries")
        self.entries = {}
        for row in rows:
            key = tuple(integer(row[k], 1, 2**32 - 1) for k in ("gid", "sid", "rev"))
            if key in self.entries or row["category"] not in CATEGORIES:
                raise ValueError("catalog key/category")
            if row["severity"] not in SEVERITIES:
                raise ValueError("catalog severity")
            self.entries[key] = {"category": row["category"],
                                 "severity": row["severity"],
                                 "metadata": metadata(row.get("metadata", {})),
                                 "source": text(row["source"], 256)}
        self.signature_keys = frozenset((gid, sid) for gid, sid, _ in self.entries)

    def match(self, event, active_rules_sha256):
        if active_rules_sha256 != self.rules_sha256:
            return None
        alert = event.get("alert")
        if not isinstance(alert, dict):
            return None
        key = (integer(alert.get("gid", 1), 1, 2**32 - 1),
               integer(alert["signature_id"], 1, 2**32 - 1),
               integer(alert["rev"], 1, 2**32 - 1))
        entry = self.entries.get(key)
        if entry is None:
            return None
        actual = metadata(alert.get("metadata", {}))
        if any(actual.get(k) != v for k, v in entry["metadata"].items()):
            return None
        return {**entry, "gid": key[0], "sid": key[1], "revision": key[2],
                "catalog_version": self.version, "catalog_rules_sha256": self.rules_sha256}


def flow_key(row):
    flow = row.get("flow", {})
    if not isinstance(flow, dict):
        raise ValueError("flow object")
    flow_id = integer(row["flow_id"], 0)
    start = flow["start"]
    timestamp(start)
    return str(flow_id), start


def direction(event, flow, nets):
    """Use an independent matching flow and observed client SYN, never packet src."""
    limitations = []
    if not isinstance(flow, dict) or flow.get("event_type") != "flow":
        return "unknown", "NO_MATCHING_FLOW", "unknown", limitations
    if ("flow_id" not in event or not isinstance(event.get("flow"), dict) or
            "start" not in event["flow"]):
        return "unknown", "NO_MATCHING_FLOW", "unknown", limitations
    if flow_key(event) != flow_key(flow) or event.get("proto") != flow.get("proto"):
        return "unknown", "FLOW_IDENTITY_MISMATCH", "unknown", limitations
    packet = tuple_of(event)
    endpoints = tuple_of(flow)
    direct = packet == endpoints
    reverse = (packet["src_ip"] == endpoints["dest_ip"] and
               packet["dest_ip"] == endpoints["src_ip"] and
               packet["src_port"] == endpoints["dest_port"] and
               packet["dest_port"] == endpoints["src_port"])
    if not (direct or reverse):
        return "unknown", "TUPLE_MISMATCH", "unknown", limitations
    if flow.get("proto") != "TCP":
        return "unknown", "NO_UDP_INITIATOR_EVIDENCE", "unknown", limitations
    tcp = flow.get("tcp", {})
    info = flow.get("flow", {})
    if not isinstance(tcp, dict) or not isinstance(info, dict):
        raise ValueError("TCP/flow shape")
    flags = tcp.get("tcp_flags_ts")
    if not isinstance(flags, str) or not re.fullmatch(r"[0-9a-fA-F]{2}", flags):
        return "unknown", "NO_CLIENT_SYN_EVIDENCE", "unknown", limitations
    flags_int = int(flags, 16)
    peer_flags = tcp.get("tcp_flags_tc")
    peer_syn = isinstance(peer_flags, str) and re.fullmatch(r"[0-9a-fA-F]{2}", peer_flags) and int(peer_flags, 16) & 2
    if (not flags_int & 2 or flags_int == 0x12 or tcp.get("midstream") or
            (flags_int & 0x10 and not peer_syn) or
            tcp.get("ts_gap") or tcp.get("tc_gap") or
            info.get("exception_policy")):
        return "unknown", "INCOMPLETE_INITIATION_EVIDENCE", "unknown", limitations
    local_client = owned(endpoints["src_ip"], nets)
    local_server = owned(endpoints["dest_ip"], nets)
    if local_client == local_server:
        return "unknown", "ENDPOINT_SCOPE_AMBIGUOUS", "unknown", limitations
    limitations.append("INITIATOR_ROLE_IS_SENSOR_OBSERVATION_NOT_GUEST_ATTESTATION")
    connection = "unknown"
    if tcp.get("state") == "established" and info.get("state") == "established":
        connection = "sensor_observed_established"
    elif tcp.get("state") in ("syn_sent", "syn_recv") or flags_int == 2:
        connection = "attempted"
    else:
        # Final closed states and OR-ed flags do not retain handshake ordering.
        limitations.append("CONNECTION_HISTORY_NOT_PROVEN_BY_FINAL_STATE")
    return ("egress" if local_client else "ingress",
            "MATCHED_FLOW_CLIENT_SYN", connection, limitations)


class IOC:
    def __init__(self, data):
        if not isinstance(data, dict) or data.get("schema") not in {"cs-public0-egress-ioc-v1", "cs-public0-egress-ioc-v2"}:
            raise ValueError("IOC schema")
        self.source = text(data["source"], 256)
        self.version = text(data["version"], 128)
        self.content_sha256 = text(data["content_sha256"], 64)
        if not SHA.fullmatch(self.content_sha256):
            raise ValueError("IOC hash")
        self.fetched = integer(data["fetched_unix"])
        self.published = integer(data["published_unix"])
        self.expires = integer(data["expires_unix"])
        if not self.published <= self.fetched < self.expires <= self.published + 86400:
            raise ValueError("IOC freshness bounds")
        addresses = data["addresses"]
        if not isinstance(addresses, list) or len(addresses) > 65536:
            raise ValueError("IOC address bound")
        self.addresses = frozenset(ipv4(x) for x in addresses)
        self.prefixes = {}
        if data["schema"] == "cs-public0-egress-ioc-v2":
            raw_networks = data["networks"]
            if not isinstance(raw_networks, list) or len(raw_networks) > 65536:
                raise ValueError("IOC prefix bound")
            parsed = []
            for value in raw_networks:
                net = ipaddress.ip_network(value, strict=True)
                if net.version != 4 or str(net) != value or net.prefixlen < 8:
                    raise ValueError("IOC prefix")
                self.prefixes.setdefault(net.prefixlen, set()).add(int(net.network_address))
                parsed.append(value)
            if raw_networks != sorted(set(parsed)):
                raise ValueError("IOC prefix canonical order")
            canonical = json.dumps({"addresses": sorted(self.addresses), "networks": raw_networks},
                                   sort_keys=True, separators=(",", ":")).encode()
        else:
            canonical = ("\n".join(sorted(self.addresses)) + "\n").encode()
        if hashlib.sha256(canonical).hexdigest() != self.content_sha256:
            raise ValueError("IOC content mismatch")

    def fresh(self, now):
        return self.fetched <= now < self.expires

    def match(self, address, now):
        if not self.fresh(now):
            return None
        prefix = None
        if address not in self.addresses:
            numeric = int(ipaddress.IPv4Address(address))
            for length, starts in self.prefixes.items():
                masked = numeric & ((2**32 - 1) ^ (2**(32 - length) - 1))
                if masked in starts:
                    prefix = str(ipaddress.IPv4Network((masked, length)))
                    break
            if prefix is None:
                return None
        return {"source": self.source, "version": self.version,
                "content_sha256": self.content_sha256, "published_unix": self.published,
                "fetched_unix": self.fetched, "expires_unix": self.expires,
                **({"matched_prefix": prefix} if prefix is not None else {})}


def observation(event, flow, config, catalog, source_ref, received_unix, rules_sha256, ioc=None):
    """Return a minimal safe observation or None for an unmatched event."""
    kind = event.get("event_type")
    if kind not in ("alert", "flow"):
        return None
    if kind == "flow" and ioc is None:
        return None
    nets = networks(config["owned_ipv4_networks"])
    point = tuple_of(event)
    match = catalog.match(event, rules_sha256) if kind == "alert" else None
    transition = config.get("ruleset_transition_unqualified", False)
    unqualified_signature = None
    if kind == "alert" and transition:
        # The unread prefix can straddle an engine reload. Keep the observed
        # SID/revision, but do not qualify it with either guessed ruleset.
        match = None
        a = event["alert"]
        gid = integer(a.get("gid", 1), 1, 2**32-1)
        sid = integer(a["signature_id"], 1, 2**32-1)
        eligible = config.get("transition_signature_keys", frozenset())
        if (gid, sid) in eligible or (gid, sid) in catalog.signature_keys:
            unqualified_signature = {"gid": gid, "sid": sid,
                "revision": integer(a["rev"], 1, 2**32-1),
                "catalog_rules_sha256": None, "source": "UNQUALIFIED_RULESET_TRANSITION"}
    ioc_match = None
    for address in (point["src_ip"], point["dest_ip"]):
        if not owned(address, nets) and ioc is not None:
            ioc_match = ioc.match(address, received_unix)
            if ioc_match:
                break
    if match is None and ioc_match is None and unqualified_signature is None:
        return None
    observed = timestamp(event["timestamp"])
    skew = config.get("clock_skew_allowance_seconds", 0)
    if observed > received_unix + 5 + skew:
        raise ValueError("future event timestamp")
    d, basis, connection, limits = direction(event, event if kind == "flow" else flow, nets)
    limits.append("CATALOG_RULESET_SHA_IS_NOT_PRODUCER_RULESET_ATTESTATION")
    if transition:
        limits.append("RULESET_TRANSITION_UNQUALIFIED")
    if observed > received_unix + 5:
        limits.append("SOURCE_CLOCK_SKEW_AFTER_COLLECTOR_REVERSAL")
    if ioc is not None and not ioc.fresh(received_unix):
        limits.append("IOC_NOT_CURRENT")
    local_ips = sorted({x for x in (point["src_ip"], point["dest_ip"]) if owned(x, nets)})
    remote_ips = sorted({x for x in (point["src_ip"], point["dest_ip"]) if not owned(x, nets)})
    attribution = {"level": "public_ip" if local_ips else "unknown", "public_ips": local_ips}
    mappings = config.get("attribution", {})
    if len(local_ips) == 1 and local_ips[0] in mappings:
        mapping = mappings[local_ips[0]]
        if not isinstance(mapping, dict):
            raise ValueError("attribution mapping")
        for name in ("vr_ref", "vm_ref"):
            if name in mapping:
                attribution[name] = text(mapping[name], 128)
        if "vm_ref" in mapping:
            if mapping.get("exclusive") is not True:
                raise ValueError("VM attribution requires exclusive mapping")
            attribution["level"] = "vm"
        elif "vr_ref" in mapping:
            attribution["level"] = "vr"
    event_hash = text(source_ref["record_sha256"], 64)
    if not SHA.fullmatch(event_hash):
        raise ValueError("source hash")
    sensor = text(config["sensor_id"], 64)
    epoch = text(config["sensor_epoch"], 128)
    identity = ("egress-v1\0" + sensor + "\0" + epoch + "\0" + event_hash).encode()
    category = match["category"] if match else "ioc" if ioc_match else "other"
    severity = match["severity"] if match else "high" if ioc_match else "unknown"
    has_flow = ("flow_id" in event and isinstance(event.get("flow"), dict) and
                "start" in event["flow"])
    return {"schema": "cs-public0-egress-event-v1",
            "event_id": hashlib.sha256(identity).hexdigest(),
            "observed_unix": observed, "received_unix": received_unix,
            "sensor_id": sensor, "sensor_epoch": epoch,
            "observation_point": text(config.get("observation_point", "public0_post_snat_ipv4"), 128),
            "packet_tuple": {**point, "protocol": text(event["proto"], 16)},
            "remote_ip": remote_ips[0] if len(remote_ips) == 1 else None,
            "flow_id": str(integer(event["flow_id"])) if has_flow else None,
            "flow_start": flow_key(event)[1] if has_flow else None,
            "direction": d, "direction_basis": basis, "connection_evidence": connection,
            "category": category, "severity": severity,
            "evidence_kind": "signature_match" if match else "ioc_contact_observation" if ioc_match else "signature_observation_unqualified",
            "signature": ({k: v for k, v in match.items() if k != "metadata"} if match else unqualified_signature),
            "ioc": ioc_match, "attribution": attribution,
            "limitations": limits + ["NOT_PROOF_OF_COMPROMISE", "INSPECTION_COVERAGE_UNQUALIFIED"],
            "source_ref": {k: source_ref[k] for k in ("device", "inode", "offset", "length", "record_sha256")}}
