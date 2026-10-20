# Installation and updates

Install Suricata 8.x with NFQUEUE using a trusted distribution or your own reviewed
build. This repository neither downloads binaries nor patches the engine. Check
`suricata --build-info`, `nft --version`, `python3 --version` and `systemctl --version`.
Install `nftables`, `iproute2`, `python3` and `logrotate` separately when absent.
The engine's classification and reference files are also required; their default
paths are `/etc/suricata/classification.config` and `/etc/suricata/reference.config`.
Custom builds may override `cs_public0_classification_file` and
`cs_public0_reference_file` to their installed locations.

Inspect `ip -d link show <bridge>` and the complete firewall. Select an unused
NFQUEUE number; the default is 100. Identify the distribution sensor, rule updater,
exporter and any other consumers of the Suricata command socket. Stop and disable
the distribution sensor before switching; record its previous state for rollback.
This project intentionally does not rewrite its updater or take ownership of it.

Deploy with `cs_public0_enabled: false` first. Read the rendered files under
`/etc/cs-public0`, run `cs-public0 check`, then activate explicitly through Ansible.

Pass command-line boolean overrides as JSON: `-e '{"cs_public0_enabled": true}'`
for activation or `-e '{"cs_public0_enabled": false}'` for a disabled installation.
A YAML variables file also preserves the required boolean type.
Keep independent host access available. Default memory limits are starting values,
not measured sizing recommendations.

The most relevant settings are:

| Variable | Default | Meaning |
|---|---|---|
| `cs_public0_bridge` | `public0` | Existing Linux bridge |
| `cs_public0_queue` | `100` | Unused NFQUEUE number |
| `cs_public0_table` | `cs_public0` | Dedicated nftables table |
| `cs_public0_enabled` | `false` | Explicit interception activation |
| `cs_public0_home_net` | `any` | Suricata signature network scope |
| `cs_public0_rules_source` | bundled example | Alert-only file on controller |
| `cs_public0_memory_max` | `2G` | systemd cgroup memory ceiling |
| `cs_public0_metrics_file` | node exporter textfile directory | Metrics destination |

The runtime JSON lives at `/etc/cs-public0/config.json`. The Ansible role generates
it; direct users may pass `--config PATH` to the controller. Its paths and identifier
validation are independent of Ansible. Review all variables before deployment.

## Rules and upgrades

Only `alert` actions are accepted. `drop`, `reject` and `pass` rules are refused.
The bundled HTTP signature is a functional example and provides no meaningful
threat coverage on its own. Third-party feeds require operator review and separate
license compliance. Convert actions and review the resulting file outside the
running service, then use `cs_public0_rules_source` to deploy it.

Keep active rules immutable between controlled updates. The playbook stops the
managed sensor, replaces artifacts, runs validation and restarts only if requested.
During replacement no listener is available and the queue bypass permits new
traffic. A failed validation leaves the sensor stopped; restore the previous
configuration and rules before starting it again. Preserve your previous files
in your configuration management; no in-place automatic rollback archive is kept.

The distribution `suricata-update.timer` does not update this project's rule file.
Do not make it start the conflicting distribution sensor. An in-engine rule reload
also changes the inspection epoch and requires renewed validation; this release
uses controlled restarts instead.

## Monitoring

Configure node_exporter with its textfile directory matching `cs_public0_metrics_file`.
Use a root-owned directory without group or world write permissions; the collector
only needs read access. The installer refuses unsafe existing parent directories.
Load `monitoring/prometheus/alerts.yml` and create the explicit expected series shown
in its comment for hosts you activate. Import the Grafana dashboard and choose a
Prometheus datasource. Check known/up/queue/nft, freshness and degraded separately.

Logs use copytruncate retention. It bounds local storage but has a small race that
can lose log lines during rotation. Use an external EVE collector if lossless audit
retention is required.
