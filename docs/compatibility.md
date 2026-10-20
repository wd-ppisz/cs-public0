# Compatibility and acceptance

The target interface is Linux/systemd, Python 3.10+, nftables bridge/NFQUEUE and
Suricata 8.x compiled with NFQUEUE. Distribution package availability varies.
The installer requires a preinstalled binary and checks build support. This is
an interface requirement, not certification of every 8.x build or kernel.

| Check | Evidence supplied by this repository | Operator acceptance |
|---|---|---|
| Configuration and ownership | Unit and template tests | Review rendered target files |
| IPv4 bridge/NFQUEUE | Disposable namespace HTTP/alert/bypass smoke | Repeat on target kernel |
| systemd lifecycle | Unit structure and controller tests | Start/stop/restart/update on lab host |
| GRO/GSO, checksum and MTU | No blanket qualification | Exercise real uplink/tap traffic |
| Performance | No throughput/latency claim | Measure PPS, bandwidth, p99, CPU/RAM and queue drops |
| CloudStack lifecycle | No API dependency | Test VR replacement, tap churn, migration and HA |
| IPv6 and host traffic | Outside interception scope | Separate design and acceptance |

Bridge NFQUEUE behavior depends on kernel and engine support, especially for
GRO/GSO packets and checksum offloads. No engine patches or offload changes are
included. A passing small namespace test does not qualify a physical host.
TLS, fragmented traffic, PMTUD, UDP and storage workloads need representative tests.

CI runs offline checks and a Linux namespace smoke when supported by the runner.
A skipped smoke is a visible limitation, never an inferred pass. See the CI job
and its logs for the exact engine, kernel and tool versions used in a given run.
