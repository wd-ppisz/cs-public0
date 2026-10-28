#!/usr/bin/env python3
"""One bounded HTTP upload to an operator-owned echo backend, from an external client.

TCP_INFO counts retransmissions on this fresh connection. It does not measure
all forwarded flows and must not be presented as a whole-host retransmission rate.
Run once per timer tick; no catch-up or traffic generator is included.
"""
import argparse
import http.client
import ipaddress
import json
import re
import socket
import struct
import subprocess
import time
import urllib.request
import uuid

BODY = b"public0-owned-latency-probe\n" + b"a" * 60000


def tcp_info(sock):
    if not hasattr(socket, "TCP_INFO"):
        raise RuntimeError("Linux TCP_INFO is unavailable")
    raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
    if len(raw) < 104:
        raise RuntimeError("TCP_INFO does not contain total_retrans")
    return struct.unpack_from("=I", raw, 100)[0]


def probe(target, port, expected):
    started = time.monotonic()
    value = {"success": 0, "tcp_info_known": 0, "tcp_retransmissions": 0,
             "last_publish_unix_seconds": time.time()}
    try:
        with socket.create_connection((target, port), timeout=3) as stream:
            rid = "public0-monitor-" + uuid.uuid4().hex
            headers = ("POST /echo?e2e_id=" + rid + " HTTP/1.1\r\nHost: public0-probe.invalid\r\n"
                       "X-E2E-Id: " + rid + "\r\nContent-Length: " + str(len(BODY)) +
                       "\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n")
            stream.sendall(headers.encode() + BODY)
            response = http.client.HTTPResponse(stream)
            response.begin()
            body = response.read(4097)
            value.update(tcp_info_known=1, tcp_retransmissions=tcp_info(stream))
            if response.status != 200 or body != expected:
                raise RuntimeError("unexpected echo response")
            value["success"] = 1
    except (OSError, ValueError, RuntimeError, http.client.HTTPException) as error:
        value["error"] = str(error)[:200]
    value["duration_seconds"] = time.monotonic() - started
    return value


def metrics(value, host):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", host):
        raise RuntimeError("invalid metric host")
    labels = '{host="' + host + '",profile="public0-ipv4-alert",scope="external_owned_upload"}'
    names = ("success", "tcp_info_known", "tcp_retransmissions", "duration_seconds",
             "last_publish_unix_seconds")
    return "".join("cs_public0_probe_" + name + labels + " " + str(value[name]) + "\n"
                   for name in names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="operator-owned echo backend")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", required=True, help="monitored forwarding host label")
    parser.add_argument("--expected-response", default="E2E_BACKEND_OK")
    sink = parser.add_mutually_exclusive_group()
    sink.add_argument("--push-url", help="explicit private Prometheus text import endpoint")
    sink.add_argument("--push-victoriametrics-container", help="existing local Docker VictoriaMetrics container")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("invalid port")
    push_url = args.push_url
    if args.push_victoriametrics_container:
        name = args.push_victoriametrics_container
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", name):
            parser.error("invalid local container name")
        result = subprocess.run(["/usr/bin/docker", "inspect", "--format",
                                 "{{json .NetworkSettings.Networks}}", name],
                                capture_output=True, check=True, timeout=5)
        if len(result.stdout) > 16384:
            raise RuntimeError("container network response exceeds bound")
        networks = json.loads(result.stdout)
        addresses = {row["IPAddress"] for row in networks.values() if row.get("IPAddress")}
        if len(addresses) != 1:
            raise RuntimeError("one local VictoriaMetrics address required")
        address = ipaddress.ip_address(next(iter(addresses)))
        if address.version != 4 or not address.is_private:
            raise RuntimeError("private local VictoriaMetrics address required")
        push_url = "http://" + str(address) + ":8428/api/v1/import/prometheus"
    value = probe(args.target, args.port, (args.expected_response + "\n").encode())
    text = metrics(value, args.host)
    if push_url:
        request = urllib.request.Request(push_url, data=text.encode(), method="POST",
                                         headers={"Content-Type": "text/plain; version=0.0.4"})
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status not in (200, 204):
                raise RuntimeError("metric publication failed")
    print(json.dumps(value, sort_keys=True))
    if not push_url:
        print(text, end="")


if __name__ == "__main__":
    main()
