# Architecture

The controller owns one `bridge` family nftables table, containing one counter,
one forward base chain and one queue rule. It validates the complete rule AST
before treating an existing table as its own. It never flushes the host ruleset,
changes physical interfaces, adjusts offloads or sets bridge netfilter sysctls.

The chain uses priority `-240` by default. Both `meta ibrname` and `meta obrname`
must match the configured bridge. The Ethernet protocol must be IPv4. This captures
forwarded traffic through that bridge in both directions without modifying
CloudStack virtual router configuration.

## Start and stop

1. Validate configuration, alert-only rules, bridge, build and table ownership.
2. Start Suricata as the main systemd process with a private command socket.
3. Wait for the configured NFQUEUE listener and verify its process/thread identity.
4. Authenticate the socket peer and add the selector as one nftables transaction.
5. Read back the exact installed table.

`ExecStopPost` removes the selector using its ownership record and exact table
shape. Cleanup refuses an altered or foreign table. An error requires operator
inspection rather than deleting unknown firewall state. systemd retains the
runtime directory across restarts so the ownership marker survives cleanup.

## Telemetry

The systemd timer samples the service PID, command socket, NFQUEUE and nftables.
Observed increases in loss and exception counters, sensor restarts and reported
queue drops feed
a persisted degraded latch. Counter baselines belong to the sensor PID/start-time
epoch; the first observation is compared with zero. Expected midstream exceptions
are excluded from the latch because existing TCP flows can predate activation.
This exclusion does not restore inspection of those flows. Missing or malformed
telemetry is reported as unknown rather than a healthy zero. The textfile collector
publishes metrics atomically.

The nftables and decoder packet counters are reported independently. Their
aggregation times differ, so their instantaneous difference is not used to
infer inspection loss or latch degradation.

On the inspected Linux 6.8 and 6.11 kernels, NFQUEUE fail-open accepts packets on
queue saturation or failed userspace delivery without incrementing the exported
queue drop fields. The monitor supplements these with bracketed queue IDs,
socket loss counters and object identity; see [kernel accounting](kernel-accounting.md).
There is still no complete direct bypass counter. `telemetry_known=1` describes observation availability only;
a clear latch and zero reported drops do not establish complete inspection.

There is no traffic generator or automatic recovery action in the monitor.
Metrics describe observations, not proof that every packet was inspected.

The explicit `acknowledge` command clears the latch and records current counters
as the new baseline only after a complete, known observation. New counter
increases can latch degradation again. It does not restart or modify the sensor.
