# Forward EVE events to Wazuh

cs-public0 can use an existing Wazuh agent as an EVE log collector. Agent
installation, enrollment, manager configuration and retention remain operator
responsibilities. This integration does not change packet handling.

Point the agent at the **active cs-public0 log directory**, rather than an old
distribution Suricata log. With the default `cs_public0_log_dir`, add the following
source inside the agent's existing `ossec_config` in `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/cs-public0/eve.json</location>
</localfile>
```

If you override the log directory, update this path as well. Preserve unrelated
agent settings and check for an existing source to avoid duplicate collection.
Validate the agent configuration, then restart only that host's `wazuh-agent`
service during its maintenance window.

Verify collection independently of the Prometheus health metrics: confirm the
agent is connected, the log collector opened the current EVE file, and a naturally
occurring Suricata alert reaches the manager. An empty alert search alone cannot
distinguish quiet traffic from missing collection. Do not generate attacks on
customer networks as a collection check.

EVE events may contain customer network metadata. Keep events and agent credentials
out of public repositories.

References: [Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
and [localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).

## Grafana: top alert signatures and source IPs

Import [the optional dashboard](../monitoring/grafana/wazuh-alert-details.json) into Grafana
and select a VictoriaLogs datasource. The template includes four TOP 30 tables:
alert signatures, alert source IPs, blocked signatures and blocked source IPs.

This optional dashboard requires a separate Wazuh-to-VictoriaLogs pipeline. It does
not install that pipeline or an agent. The log normalization contract is:

- `app=wazuh` and `rule_id` containing the Wazuh Suricata rule ID (86xxx).
- Preserve the decoded EVE fields under `data`: `event_type`, `src_ip`,
  `alert.signature_id`, `alert.signature`, `alert.category` and `alert.action`.
- Store the original event timestamp as the log timestamp. Count the selected
  Grafana time range across all agents. Apply access controls to network metadata.

The tables count collected alert events, not unique connections, packets or
successful attacks. Source IPs identify event sources; spoofing, shared addresses
and false positives require investigation. The blocked tables require the actual
`data.alert.action=blocked` field. A signature name containing `DROP` with action
`allowed` remains an alert, not a block. Capture/kernel/NFQUEUE losses are separate
health signals and do not belong in the blocked rankings.

An empty blocked table is expected for an alert-only ruleset, but empty search
results alone cannot establish collector health. Verify current-file collection
and fresh manager ingress as described above. These tables cover signature alerts
forwarded by Wazuh; they do not promise a complete ledger of all engine or firewall
drop reasons. No test attack or drop rule is required to use this dashboard.
