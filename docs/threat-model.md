# Threat model

The host administrator, configuration management controller and Suricata binary
are trusted. All traffic and signature inputs require validation. The kernel,
systemd and nftables are part of the trusted computing base. The runtime does not
accept remote control requests; its command socket is local and root-controlled.

## Boundaries

- Dedicated bridge table and root-only ownership record protect against accidental
  modification of another service's firewall objects. A root compromise is outside
  this boundary. Ownership checks do not arbitrate a hostile concurrent root writer.
- PID/thread and Unix socket peer checks prevent arming against an unrelated listener.
- Alert-only validation avoids silently enabling signature blocking or inspection
  bypass through `pass` rules. It does not prove that the engine cannot drop traffic.
- Configuration paths and names are validated. Packet payloads and EVE events may
  contain sensitive data; log access and retention are the operator's responsibility.
- The monitor detects unknown and degraded observations but makes no firewall changes.

## Availability tradeoff

No listener: nft queue bypass accepts new packets. Full queue: NFQUEUE fail-open
accepts new packets at the cost of inspection. Memory exceptions prefer pass-packet
or pass-flow. A stalled listener and already queued packets remain a separate risk.
On Linux 6.8 and 6.11, fail-open does not increment the exported queue drop fields
when a full queue or failed delivery to userspace causes bypass. The monitor has
no direct measurement of these events. Known telemetry and a clear degraded latch
do not guarantee inspection coverage. See the [kernel references](references.md).
Set alerts, keep recovery access and measure the complete host workload.

## Coverage

Only forwarded IPv4 on the selected bridge is covered. Host traffic, IPv6, other
bridges, VLAN paths that do not traverse the selector and encrypted payloads may
remain uninspected. No compliance certification or complete attack prevention is
claimed. Additional firewall rules, TLS termination controls and endpoint security
have independent roles.
