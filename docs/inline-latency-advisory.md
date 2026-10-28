# Inline latency advisory - 2026-10-28

**Status: inline production activation is on hold. No packet-path fix has been qualified.**

A multi-host deployment using Suricata 8.0.7, NFQUEUE and an alert-only ruleset
showed substantial TLS handshake and HTTP transfer latency. Internal checks reached
roughly 0.5-1.5 seconds for services previously answering in tens or low hundreds of
milliseconds. Interactive desktop usability was also affected.

CPU was not saturated, queue occupancy was usually zero, and the observed NFQUEUE
kernel/user loss counters were zero. Those indicators did not establish acceptable
forwarding latency. Alert-only inspection still waits for userspace verdicts.

Withdrawing inline inspection on the desktop host immediately returned its HTTP
probe to roughly 15-17 ms and TLS to about 8 ms. After withdrawing the other inline
instances, application probes returned close to their earlier baseline.
This identifies the deployed inline packet path as an operational cause.
The exact code/kernel/offload mechanism remains under investigation. A checksum,
GSO/GRO, TCP reassembly or verdict-path explanation has not been proven.

## Operator action

Do not enable this inline profile on additional production hosts or re-enable an
affected installation until a fix passes representative TCP/TLS and latency tests.
Keep existing configurations, EVE logs and monitoring state for investigation.

For a deployment using the repository's default service name:

```sh
sudo /usr/local/libexec/cs-public0 disarm
sudo systemctl disable --now cs-public0.service
sudo systemctl show cs-public0.service -p ActiveState -p MainPID -p UnitFileState
```

The guarded `disarm` removes the project's owned selector before the listener
stops. Use the actual installed service name and pass `--config` to the helper
if customized. The repository enforces `queue ... bypass`; retain that flag.
Its existing guarded `ExecStopPost` repeats the owned-selector cleanup. Verify that the
project's NFQUEUE listener and nftables table are absent, then verify natural
service probes. Do not flush shared firewall rules, restart virtual routers or
disable unrelated security agents. Do not automatically enable a passive sensor
with an unverified interface configuration.

The repository's default remains non-activating; this advisory does not withdraw
independent passive VM sensors. Existing monitoring should continue to report
the inline sensor as absent/unknown, rather than claiming inspection is healthy.

Before resuming, qualify baseline-versus-inline latency distributions, TLS
handshakes, long-lived WebSockets/interactive sessions, offloaded and segmented
TCP, both traffic directions, and the actual virtualization/router topology.
Zero queue drops, successful unit tests or an alert-only ruleset are insufficient.
