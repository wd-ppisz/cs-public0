# Troubleshooting

Start with read-only observations:

```sh
sudo /usr/local/libexec/cs-public0 status
sudo systemctl status cs-public0.service cs-public0-monitor.timer
sudo journalctl -u cs-public0.service -u cs-public0-monitor.service -n 100
sudo cat /proc/net/netfilter/nfnetlink_queue
sudo nft -j list table bridge cs_public0
```

Use the configured table name when overriding the default.

**Startup rejected:** inspect the Suricata build, alert-only rules, existing bridge,
queue collision, ownership marker and exact table shape. Run `suricata -T` with
the installed configuration and rules. Do not delete a foreign table to force start.

**Missing metrics:** check node_exporter's textfile directory and the timer. A
stopped timer leaves an old file; monitor its timestamp as well as scrape health.
Unknown telemetry must not be replaced by zero with a PromQL fallback.

**Zero queue drops:** fail-open bypass on queue saturation or failed delivery to
userspace is not counted in the exported drop fields on Linux 6.8 and 6.11. This
monitor does not detect these events. `telemetry_known=1` and a clear latch do not
prove complete inspection. Review the actual kernel behavior and workload
qualification when investigating coverage.

**Degraded state:** inspect reported queue drops, Suricata exception counters, logs and
resource pressure. The latch persists across sensor restarts. After diagnosing
and fixing the cause, archive `/var/lib/cs-public0/monitor.json`, then explicitly
acknowledge the observed counters:

```sh
sudo /usr/local/libexec/cs-public0 acknowledge
```

This takes the same lock as the monitor, requires complete current telemetry and
records the current cumulative counters as the new baseline. A later increase
sets the latch again. If telemetry is unknown, acknowledgement fails and preserves
the saved state. Do not delete the state file to acknowledge an alarm: its absence
makes historical counters visible as a first observation again. A new sensor epoch
does not prove that the underlying problem has been fixed. Expected midstream
exceptions are excluded from the latch; existing flows still need separate
inspection-coverage assessment.

**Service unexpectedly stopped:** a distribution updater may have started the
conflicting `suricata.service`. Review `systemctl cat suricata-update.service` and
its timers. The installer never edits another service's updater.

**Traffic stalls with a live sensor:** NFQUEUE bypass is not a stalled-listener
watchdog. Use independent access and follow [rollback](rollback.md), disarming
the owned selector first. Do not flush unrelated firewall rules.
