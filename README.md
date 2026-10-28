# cs-public0

> **Inline activation on hold (2026-10-28):** a multi-host deployment exhibited
> substantial TLS/HTTP latency despite zero observed NFQUEUE drops. See the
> [inline latency advisory](docs/inline-latency-advisory.md). Do not enable inline
> on production hosts until a packet-path fix is qualified.

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
rulesets. This project does not install or redistribute the Suricata engine.
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
