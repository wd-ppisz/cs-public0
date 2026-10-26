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
