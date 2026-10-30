# Optional NFQUEUE GSO profile

For an independent socket-capacity option and runtime verification, see
[NFQUEUE receive-buffer capacity](nfq-receive-buffer.md).

The default remains non-activating. `cs_public0_nfq_gso: true` is intended only
for an independently built and qualified engine implementing `nfq.gso` and the
runtime acknowledgement described below. This setting does not install or patch
Suricata and must not be used to claim compatibility with an arbitrary stock
build. Retain the [latency advisory](inline-latency-advisory.md) until your own
kernel, virtualization topology and workload are qualified.

Configure both values in the host's reviewed inventory:

```yaml
cs_public0_nfq_gso: true
cs_public0_nfq_gso_binary_sha256: "<64 lowercase hex characters from the qualified engine>"
```

The role checks the binary pin before changing services. Its sensor command adds
`--set nfq.gso=yes`. Before `cs-public0 arm` can install a selector,
`nfq_gso.py --require` verifies the live executable hash, one explicit unoverridden
argument, NFQUEUE owner and an acknowledgement from that systemd invocation.
Missing evidence refuses startup. The monitor publishes:

- `cs_public0_gso_known`
- `cs_public0_gso_enabled`
- `cs_public0_gso_last_publish_unix_seconds`

Alert when an expected active sensor lacks a fresh known/enabled observation.
Unknown or stale data must not be interpreted as GSO disabled with certainty or
as healthy inspection. Startup refusal is separate from a runtime alarm; the
observer never changes firewall state or stops a service.

The optional `forwarding_probe.py` runs on a separate external client. It sends
one approximately 60 kB HTTP upload to an **operator-owned** `/echo` endpoint,
requires the configured response and reads Linux TCP_INFO. An explicit
`--push-url` can publish Prometheus text to an existing private import endpoint.
Its response-body default is `E2E_BACKEND_OK` followed by LF; adapt this to your
owned backend. No backend credentials or deployment-specific addresses ship in
this repository. Run with a timer and a service execution limit, for example one
probe per minute with a 20-second service limit. There is no catch-up loop.

See [performance pitfalls](performance-pitfalls.md) for the incident evidence,
metric scope and acceptance procedure.

The production unit waits up to 240 seconds for the GSO acknowledgement, matching
the sensor readiness budget. Its 780-second systemd startup budget includes
configuration validation (180 seconds), the GSO gate (240 seconds), readiness
(240 seconds), and a 120-second allowance for other startup work and the final
observation. Local file I/O is still subject to the overall systemd timeout;
this arithmetic is not a measured startup or capacity guarantee. Site-specific
canary migrations may keep a shorter explicit gate to fit their independent
rollback window; this change does not extend those leases automatically.

The startup acknowledgement is evidence retained by journald, scoped to the
current systemd invocation. A journal vacuum, rotation, or volatile-journal loss
can remove it while the sensor keeps running. The observer then deliberately
reports UNKNOWN (known=0, with an acknowledgement error), because command-line
settings alone cannot establish that the kernel accepted GSO. The buffer gate
also requires its invocation acknowledgement as well as the current effective
socket capacity. UNKNOWN means missing verification evidence; it does not prove
GSO was disabled or that forwarding failed. Keep the alert actionable as a
monitoring-evidence problem. Do not automatically restart a healthy sensor,
clear history, or turn UNKNOWN into a known/enabled result to silence it.
Investigate journal retention and use a separately reviewed maintenance window
if renewed initialization evidence is necessary. A durable attestation cache is
not implemented by this observer; introducing one needs its own integrity and
process/socket-reuse tests.

Executable hashing uses 1 MiB reads instead of retaining the complete binary.
The observer still hashes each observation and rechecks process and socket
identity; this is a memory bound on the hash buffer, not a CPU, disk-I/O, total
cgroup memory, or startup-time qualification.
