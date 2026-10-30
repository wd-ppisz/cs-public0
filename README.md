# cs-public0

> **Version 1.0 — known security limitation:** queue pressure can cause fail-open
> forwarding without inspection, including cases with zero exported Drops.
> A larger netlink receive buffer does not solve packet-queue saturation.
> Read [Known vulnerabilities and limitations](#known-vulnerabilities-and-limitations)
> before activation. Version 1.0 is a versioned baseline, not a universal capacity
> or loss-free inspection certification.

Read [performance pitfalls](docs/performance-pitfalls.md) for lessons from the
incident, including GSO, checksum metadata, retransmission monitoring and controlled
baseline comparisons. An [optional pinned GSO profile](docs/nfq-gso-profile.md)
is available for a separately qualified compatible engine.

Suricata inspection for IPv4 traffic forwarded through a Linux bridge, with an
Ansible installer, scoped nftables rules, systemd lifecycle and Prometheus metrics.
Apache CloudStack on KVM is one deployment example; the controller does not require
CloudStack APIs, credentials or agents.

The default profile accepts **alert-only** signatures and rejects `bypass` options.
The included signature is a connectivity example, not a threat feed. Operators supply and review their own
rulesets. The default installer requires a separately supplied Suricata engine;
the optional [pinned engine build](docs/nfq-engine-build.md) has a separate GPL license.
Threshold and rate-filter overrides are disabled with an explicit empty source
(`threshold-file: /dev/null`).

Rule files must use UTF-8 and LF line endings. Every physical line, including
comments and whitespace, is limited to 4096 UTF-8 bytes. Active `alert` rules start in column
one and occupy one physical line; continuation lines are not accepted. Other
control or non-printable characters are refused, including CR from CRLF files.
Tabs are allowed within a line. Escape literal semicolons as `\;`, including in
quoted option values. Option keywords are checked without case sensitivity, and
`bypass` is rejected in every case. Full Suricata syntax validation still runs
before activation.

## Traffic path

![Traffic path: Linux bridge forwarding queues IPv4 packets in NFQUEUE; Suricata analyzes a copy and returns a verdict. The health monitor exports Prometheus metrics, and Suricata writes EVE logs.](docs/assets/traffic-path.svg)

[Open full-size diagram](docs/assets/traffic-path.svg)

Suricata receives a packet copy and returns a verdict. The kernel keeps the
queued packet and resumes forwarding after the verdict.

The selector matches IPv4 with the same configured incoming and outgoing bridge.
Host input/output, IPv6 and traffic on other bridges remain outside this scope.
Existing firewall chains still apply after a packet leaves this inspection hook.

## Requirements

- Linux with bridge-family nftables, NFQUEUE and network namespace support.
- Suricata **8.x** built with NFQUEUE support; Python **3.10+**, nftables and systemd.
- Ansible Core **2.20.x** and Python **3.12+** on the deployment controller.
- An existing bridge and an operator-selected queue number unused by other services.
- Out-of-band access and a rollback window for first activation on each host type.

See [compatibility](docs/compatibility.md) for kernel, offload and validation limits.

## Installation: start here

Follow **[Install cs-public0 on one host, step by step](docs/installation.md)**.
It distinguishes controller commands from target commands, provides a complete
private inventory/settings example, and states what to check after each stage:

1. Prepare the controller, engine and target host.
2. Select one host and supply your reviewed alert-only ruleset.
3. Install and validate with interception disabled.
4. Activate explicitly and verify the queue, traffic and local telemetry.
5. Connect Prometheus/Grafana and optional Wazuh collection, with withdrawal ready.

`cs_public0_enabled` defaults to `false`. Suricata and a production ruleset are
external prerequisites; the bundled signature is a functional example.
For an existing installation, read the guide's update and rollback sections before
rerunning the installer, because a full install/update stops the managed sensor.

## Availability and inspection limits

`queue bypass` accepts new packets when no listener exists; `nfq.fail-open` allows
new packets when the queue overflows. Explicit memory exception policies prefer
forwarding over complete inspection. These mechanisms can reduce detection coverage.
A live but stalled listener can still hold queued packets. The monitor reports
observed problems; it does **not** automatically remove rules or restart services.

On Linux 6.8 and 6.11, fail-open can accept packets when the queue is full or
delivery to userspace fails without increasing the exported queue drop counters.
The monitor supplements these counters with bracketed queue ID observations,
socket loss and identity checks, but cannot prove absence of bypass.
`telemetry_known=1` means the expected observations are available; zero drops or
a clear degraded latch do not prove complete inspection. See the
[upstream references](docs/references.md) and qualify the actual kernel.

An alert-only ruleset does not guarantee zero packet loss: parser behavior, kernel
resources and software faults are independent of signature actions. TLS payloads
remain encrypted. No universal throughput or latency guarantee is implied.

## Known vulnerabilities and limitations

**Unresolved inspection bypass under NFQUEUE pressure affects version 1.0.**
With fail-open enabled, a full packet queue can accept packets without sending
them through Suricata. This can happen before an NFQUEUE packet ID is assigned
and without incrementing the queue kernel/user drop counters. Separately, a full
netlink receive buffer can lose delivery messages. Neither an alert-only ruleset,
low average CPU nor zero current Drops proves complete inspection.

The supported buffer option and observer improve delivery headroom and visibility;
they do not remove this security limitation. There is no verified universal safe
traffic rate, no CVE identifier assigned by this project, and no claim that every
observed accounting gap was caused by the same path. The detailed mechanism,
bounded observations and diagnostic limits are in
[NFQUEUE receive-buffer capacity](docs/nfq-receive-buffer.md).

Keep fail-open semantics explicit, retain history and alert on queue/socket loss,
unknown/stale telemetry, accounting gaps and service latency/retransmissions.
Qualify each host class and representative load with independent management and
rollback. Do not silently disable fail-open or increase queue depth as a purported
fix: that can trade incomplete inspection for forwarding delay or outage.

The [2026-10-28 latency incident](docs/inline-latency-advisory.md) additionally
demonstrated why an arbitrary stock engine/offload combination must not be assumed
safe. GSO operation requires a compatible, pinned and locally qualified engine.
See [version 1.0 release notes](docs/releases/v1.0.0.md) and [SECURITY.md](SECURITY.md).

## Tests

```sh
python3 -m unittest discover -s tests -v
# Isolated Linux dataplane smoke, requires root and the binaries listed above:
sudo python3 tests/integration/netns.py
```

The smoke creates disposable namespaces and veth pairs; it never changes physical
interfaces or the root namespace firewall. It checks a real HTTP response, a
correlated Suricata alert, traffic in both directions, bypass after sensor exit
and preservation of an unrelated table. Exit **77** means unavailable prerequisites,
not a passed test. This smoke does not replace systemd or physical-host qualification.

## Layout

| Path | Purpose |
|---|---|
| `runtime/` | Standard-library controller and telemetry collector |
| `ansible/` | Installation and explicit activation |
| `config/` | Suricata, service and retention templates |
| `monitoring/` | Prometheus alerts and Grafana dashboard |
| `examples/` | Documentation-only inventory and networks |
| `tests/` | Unit, template and isolated dataplane tests |
| `docs/` | Architecture, security model and operation |

## Roadmap and downstream changes

[public0 2.0](docs/roadmap/public0-2.0.md) proposes an anti-DDoS layer before
Suricata. It is a design proposal, not an implemented or enabled feature.

Reusable downstream fixes and features belong in this repository as well as in
the operator's deployment. Each delivery should link its community commit or PR,
include regression tests and documentation, and record any remaining difference.
Publish generic configuration and synthetic examples; keep credentials, customer
traffic, internal host inventories and third-party rules outside public history.

## License

Created and maintained by [WebDisk](https://webdisk.io).

The automation, templates, tests and documentation in this repository are licensed
under [Apache License 2.0](LICENSE). Suricata, third-party signature feeds and system
packages retain their own licenses; they are external dependencies. See
[NOTICE](NOTICE) and [SECURITY.md](SECURITY.md).

Explicit, per-host IPS opt-in is described in [Blocking policy](docs/blocking-policy.md).
