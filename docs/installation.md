# Install cs-public0 on one host, step by step

This guide covers a first installation, from prerequisites to monitoring and
withdrawal. Start with **one host** and keep independent management access open.

| Where | What runs there |
|---|---|
| **Controller** | Git checkout, Python virtual environment, Ansible, private inventory and reviewed rules |
| **Target** | Existing Linux bridge, Suricata, nftables, cs-public0 services and logs |

Commands marked **Controller** run from the repository root in the same Linux
or WSL terminal. Commands marked **Target** run over your verified SSH connection
to the hypervisor. Replace the documentation addresses and usernames below.

## 1. Decide what you are installing

The installer supplies the cs-public0 controller, configuration, alert rules,
systemd service, monitoring timer and log retention. It does **not** install
Suricata, download a threat feed, create a bridge, configure CloudStack, or install
Prometheus, Grafana or node_exporter.

The default profile selects **IPv4 forwarded through the configured bridge**.
Host input/output, IPv6 and other bridges are outside its scope. It accepts
alert-only signatures and refuses drop/reject/pass actions and bypass options.
Read the [availability limits](../README.md#availability-and-inspection-limits).

**Before continuing:** choose one host, its existing bridge, an unused NFQUEUE
number, a change window and an independent recovery connection.

## 2. Prepare the deployment controller

Use Python **3.12+**. The dependency file pins supported Ansible Core **2.20.x**.

**Controller:**

```sh
git clone https://github.com/wd-ppisz/cs-public0.git
cd cs-public0
git rev-parse HEAD
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
ansible-playbook --version
```

Record the deployed commit. For subsequent installations, select your reviewed
release or commit before deployment; do not change the checkout during a rollout.

## 3. Inspect and prepare the target

Install a trusted **Suricata 8.x build with NFQUEUE support**, Python **3.10+**,
nftables, iproute2, logrotate and systemd using your distribution or reviewed build
procedure. Install Suricata's classification and reference files too. Those are
external prerequisites, not downloads performed by this project.

**Target — inspect first:**

```sh
suricata --build-info
python3 --version
nft --version
systemctl --version
ip -d link show public0
sudo nft list ruleset
sudo systemctl status suricata.service suricata-update.timer --no-pager
```

Confirm `Suricata version 8.x` and `NFQueue support: yes` in the build information.
Check the actual bridge name, firewall and existing queue users. A distribution
service reported as `not-found` is acceptable on a clean host.

The default paths are `/usr/bin/suricata`,
`/etc/suricata/classification.config` and `/etc/suricata/reference.config`.
Adjust their settings in step 4 for a custom build. The two configuration assets
must be regular, root-owned files without group/world write permission.

If a distribution sensor exists, record its previous state and stop and disable
it in the change window:

```sh
sudo systemctl disable --now suricata.service
```

Review its updater and other command-socket consumers separately. Do not leave
another manager able to restart the conflicting sensor. The installer deliberately
does not take ownership of your existing updater.

## 4. Create a private inventory and settings file

Keep host details and third-party rules **outside the public checkout**.

**Controller:**

```sh
mkdir -p ../cs-public0-site
cp examples/apache-cloudstack-kvm/settings.yml ../cs-public0-site/settings.yml
```

Create `../cs-public0-site/inventory.ini`:

```ini
[sensors]
hypervisor01 ansible_host=192.0.2.10 ansible_user=operator
```

Replace `192.0.2.10` with the management address and `operator` with your SSH
account. `hypervisor01` is the alias used throughout this guide. Use your verified
SSH identity; do not disable host-key checking.

Edit `../cs-public0-site/settings.yml`:

```yaml
---
cs_public0_enabled: false
cs_public0_bridge: public0
cs_public0_queue: 100
cs_public0_table: cs_public0
cs_public0_home_net: '[192.0.2.0/24,198.51.100.0/24]'

# TARGET paths: match your installed engine and its external assets.
cs_public0_binary: /usr/bin/suricata
cs_public0_classification_file: /etc/suricata/classification.config
cs_public0_reference_file: /etc/suricata/reference.config

# CONTROLLER path: supply your own reviewed alert-only file.
cs_public0_rules_source: /srv/public0-input/alert-only.rules

# Match the target node_exporter's actual textfile collector directory.
cs_public0_metrics_file: /var/lib/node_exporter/textfile_collector/cs_public0.prom
cs_public0_memory_max: 2G
```

Replace the networks with your intended signature scope. `home_net` does not
narrow the nftables selector: bridge and protocol selection determine which
forwarded packets enter the queue. Choose a queue unused by other services.
The memory setting is a cgroup ceiling, not reserved RAM or measured sizing.

Prepare the rules file at the exact controller path you configured. The bundled
`config/local.rules` has **one functional example**, not a production threat
feed. For a disposable functional setup you may use its absolute path instead.

Rules must use UTF-8 and LF, with one physical line per active alert rule starting
in column one. Each physical line is limited to 4096 UTF-8 bytes. Review feed
content and licensing separately; see [rule updates](rule-updates.md).

## 5. Verify access and select exactly one host

**Controller:**

```sh
ansible-playbook -i ../cs-public0-site/inventory.ini ansible/site.yml \
  --limit hypervisor01 -e @../cs-public0-site/settings.yml --list-hosts

ansible-playbook -i ../cs-public0-site/inventory.ini ansible/site.yml \
  --limit hypervisor01 -e @../cs-public0-site/settings.yml --syntax-check

ansible -i ../cs-public0-site/inventory.ini hypervisor01 \
  -m ansible.builtin.ping

ansible -i ../cs-public0-site/inventory.ini hypervisor01 \
  --become -m ansible.builtin.command -a 'id -u'
```

**Expected:** only the intended host is listed, ping succeeds and the privileged
command returns `0`. Add `--ask-become-pass` if sudo requires a password.
Syntax checking does not validate the host kernel or activate inspection.

## 6. Install with interception disabled

Confirm `cs_public0_enabled: false` is still set.

**Controller:**

```sh
ansible-playbook -i ../cs-public0-site/inventory.ini ansible/site.yml \
  --limit hypervisor01 -e @../cs-public0-site/settings.yml
```

This is a **real installation**, not a dry run. It writes files, validates the
alert-only rules and runs full Suricata `-T --simulate-ips` compilation. It leaves
the sensor and monitor timer stopped and disabled.

If cs-public0 already exists, the installer stops it before replacing files.
Plan a maintenance window for full installation updates as well.

**Expected:** no failed or unreachable host in the play recap. Correct any
validation failure before continuing.

## 7. Inspect the prepared files

**Target:**

```sh
sudo cat /etc/cs-public0/config.json
sudo /usr/local/libexec/cs-public0 validate-rules
sudo /usr/local/libexec/cs-public0 check
sudo systemctl is-active cs-public0.service
sudo systemctl is-enabled cs-public0.service
sudo nft list tables
```

Check the bridge, queue, binary and rules path in `config.json`. Both validation
commands must succeed. For this disabled first installation, the service must be
inactive/disabled and the project's table absent. The `systemctl` commands return
nonzero for that expected disabled state. Metrics are not expected yet because
the monitor timer is disabled too.

## 8. Activate explicitly

Keep your management connection and withdrawal commands available.

**Controller:**

```sh
ansible-playbook -i ../cs-public0-site/inventory.ini ansible/site.yml \
  --limit hypervisor01 -e @../cs-public0-site/settings.yml \
  -e '{"cs_public0_enabled": true}'
```

Use the JSON boolean override exactly as shown. `-e cs_public0_enabled=true`
would supply a string, which the role refuses. The override takes precedence
over `false` in the settings file.

Suricata starts before the selector. The startup hook verifies its command socket
and queue ownership before creating the dedicated table. The sensor and monitor
timer are enabled for subsequent boots. Qualify reboot behavior separately on your
platform; this procedure does not perform a reboot test.

## 9. Check the sensor and natural traffic

**Target:**

```sh
sudo systemctl status cs-public0.service cs-public0-monitor.timer --no-pager
sudo /usr/local/libexec/cs-public0 status
sudo /usr/local/libexec/cs-public0 monitor
sudo cat /proc/net/netfilter/nfnetlink_queue
sudo nft list table bridge cs_public0
sudo cat /var/lib/node_exporter/textfile_collector/cs_public0.prom
sudo journalctl -u cs-public0.service -n 50 --no-pager
```

Substitute your table and metrics path if changed. Repeat the readback after
natural traffic and another monitor cycle; no attack traffic or DROP rule is
needed for this check.

| Check | Expected result |
|---|---|
| Sensor and timer | Active, no unexpected restarts |
| Queue | Selected queue has a listener owned by this sensor |
| Selector | Only the dedicated bridge table; counters advance when selected traffic exists |
| Pending and drops | Inspect current values and deltas; investigate unexpected growth |
| `cs_public0_telemetry_known` | `1` once required observations are available |
| `cs_public0_degraded_latched` | `0` for a clean new run; investigate a latch before acknowledging it |
| Publication timestamp | Keeps advancing |
| Existing client services | Representative services remain reachable |

Known telemetry and zero drops do not prove complete inspection.
`cs_public0_full_inspection_verified` remains `0` by design. See
[kernel accounting](kernel-accounting.md) for the observation limits.

## 10. Connect monitoring and EVE collection

These are separate integrations; the sensor installer does not configure them.

1. Enable node_exporter's textfile collector for the directory from your settings.
   Its reader needs read access; keep the directory root-owned without group/world
   write permissions.
2. Scrape that node_exporter in Prometheus. Confirm `up=1` and this host's
   `cs_public0_*` series.
3. Load [the supplied alert rules](../monitoring/prometheus/alerts.yml) and define
   one explicit expected series per activated host. For example:

   ```yaml
   groups:
     - name: cs-public0-expectations
       rules:
         - record: cs_public0_expected
           expr: vector(1)
           labels:
             job: node
             instance: '192.0.2.10:9100'
             bridge: public0
             queue: '100'
   ```

   Match `job` and `instance` to the **actual scrape labels**, not necessarily the
   inventory alias. Adjust bridge/queue if changed. This expectation detects a
   completely missing sensor series.
4. Import the dashboard JSON from `monitoring/grafana/` and select your Prometheus
   datasource. Check freshness, known state and degraded state independently.
5. Forward `/var/log/cs-public0/eve.json` to your SIEM if required. For an existing
   Wazuh agent, follow [the EVE integration guide](wazuh-integration.md).
   A healthy scrape does not prove that EVE events reached the SIEM.

cs-public0 health metrics use node_exporter; the project does not install a
separate Suricata exporter. Local copytruncate retention can lose lines during
rotation; use an external collection design if lossless retention is required.

## 11. Disable or update the installation

For an operator-controlled withdrawal on a reachable target:

```sh
sudo /usr/local/libexec/cs-public0 disarm
sudo systemctl disable --now cs-public0-monitor.timer
sudo systemctl disable --now cs-public0.service
sudo nft list tables
```

Confirm the project's table is gone and client services work. Never use
`nft flush ruleset`: other tables are not owned by cs-public0. Already queued
packets may still time out. Restore a passive sensor/updater only according to the
state recorded before installation.

Keep your reviewed previous rules and configuration in your own deployment
management. A full `site.yml` update stops the sensor; validation failure leaves
it stopped. Compatible monitor-only updates and the optional manual activation
controller have separate procedures. Continue with [rollback](rollback.md),
[controller/monitor updates](kernel-accounting.md),
[rule activation](activation-controller.md) or [troubleshooting](troubleshooting.md).
