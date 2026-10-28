# Performance pitfalls in bridge NFQUEUE inspection

This document records lessons from a forwarding-latency incident on 28 October
2026. It separates observed results, a tested mitigation and remaining unknowns.
It is not a throughput certification for other kernels, NICs or hypervisors.

## Alert-only is still inline

An alert-only ruleset still requires a userspace verdict before a queued packet
continues through the bridge. Zero DROP signatures does not remove this wait.
Queue bypass helps when a listener is absent; it does not prove acceptable latency
while a listener is present. Do not assume it handles a stalled live process.

The affected deployment had substantial HTTP/TLS latency. Withdrawing inline
inspection restored application response times and interactive usability.

## Empty queues and spare CPU can hide a forwarding problem

The observed NFQUEUE pending, kernel-loss and userspace-loss counters were zero,
and CPU was not saturated. Those snapshots did not capture the TCP retransmissions
or the extra transfer delay. A running PID, successful configuration test, healthy
scrape or zero packet-loss counter is not a forwarding-latency acceptance test.

Keep latency and retransmission measurements alongside queue, CPU, memory,
inspection-loss and telemetry-freshness monitoring.

## GSO and checksum metadata need a compatible engine

The deployed engine contained an opt-in NFQUEUE GSO implementation, but its
service command did not enable it. A controlled comparison on an owned backend
reproduced the regression with the original profile. The same engine and rules
with explicit GSO activation returned close to the baseline:

| Owned upload, about 60 kB | Without inline | Original inline | GSO variant |
|---|---:|---:|---:|
| HTTP median | 193–195 ms | 685 ms | 196 ms |
| HTTPS median | 246–247 ms | 609 ms | 248 ms |
| Upload TCP retransmissions per connection | 0 | 11–15 | 0 |

There were three samples per case in each phase. Three successful comparisons
comprised 108 requests, each joined to one owned-backend record with matching
request ID, body digest and status. This is small diagnostic evidence, not a
population p99, capacity result or proof of complete inspection of every request.
The operator reported normal console operation in both the original-inline and
GSO windows; the earlier console slowdown was not reproduced in these windows.

Enabling GSO changes the representation passed from the kernel to userspace.
The engine must handle the entire copied packet and the checksum-not-ready
metadata correctly. Do not disable checksum validation globally as a shortcut.
Monitor incomplete/invalid NFQUEUE copies and invalid ready checksums separately.
The current comparison did not recapture the exact low-level frame defect; do
not present an older kernel-specific explanation as a new packet capture.

`nfq.gso` is not a portable setting for every stock Suricata 8 build. Accepting an
unknown YAML key, or printing it in a configuration dump, does not prove that
`NFQA_CFG_F_GSO` was set successfully. This repository's optional integration
requires an explicit compatible-engine SHA256 and the runtime acknowledgement
`NFQUEUE GSO enabled` from the same systemd invocation and queue owner.
See [the GSO profile](nfq-gso-profile.md).

## Measure the forwarded path, not an unrelated host TCP stack

Host `Tcp_RetransSegs` and `Tcp_OutSegs` describe TCP connections terminated by
that host. They do not establish retransmissions for VM traffic merely forwarded
through its bridge. Likewise, a probe that bypasses the selected bridge cannot
validate that bridge's inline path.

`runtime/forwarding_probe.py` measures Linux `TCP_INFO.total_retrans` on a fresh
connection to an operator-owned HTTP echo backend. Run it from a client whose
route is known to traverse the inspected bridge. Its metrics have
`scope="external_owned_upload"`; they cover that connection, not every tenant
flow. The latest-connection retransmission metric is a gauge. Do not apply
`rate()` to it or sum repeated Prometheus scrapes as distinct probe executions.
Missing TCP_INFO, probe failure or stale publication must have a separate alarm.

An initial alert threshold can be at least three retransmissions on successive
fresh probes for two minutes. Calibrate it against the path's baseline; a
retransmission does not by itself identify Suricata as its cause.

## Use a controlled comparison and retain failures

1. Record topology, kernel, engine hash, effective command, rules and offload
   settings. Keep configuration declarations separate from effective readback.
2. Measure the same owned HTTP/TLS workloads with inline absent.
3. Arm an independent expiry before starting the listener and selector. Preserve
   an independent management route and an explicit containment procedure.
4. Repeat the requests inline. Confirm the invocation and queue owner remain
   stable, counters progress, and no observation gap is hidden.
5. Withdraw the owned selector before stopping the listener, then repeat the
   baseline. Retain timeouts, errors and partial results as outcomes.
6. Join request IDs and body digests to the backend. Test inspection with an
   alert-only control as well as testing transport. Zero retransmissions alone
   does not establish inspection coverage.

Include larger bodies, both directions, long-lived interactive connections,
MTU variation and representative concurrency before broader deployment. Do not
enable every host at once because a small canary passed. Keep automatic rollback
windows in place until each candidate's measurements are accepted.

Include operator checks of VM VNC consoles and VDI or remote desktop sessions
alongside HTTP probes. A healthy short HTTP response can miss an interactive
workflow regression. Record when the operator tested each path and whether
inline was active. A confirmation of normal behavior is useful acceptance
evidence; it does not establish a latency percentile or capacity limit.

After transport validation, change signature actions in a separate, explicit
step using a small reviewed SID allowlist. Keep GSO and queue ownership checks
active during that reload. Preserve the alert-only snapshot and each rule's
revision and definition hash, and observe actual EVE decisions and service
behavior. Do not combine an offload repair with a blanket alert-to-DROP change.
