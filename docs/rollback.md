# Rollback

For a reachable host with the installed controller:

```sh
sudo /usr/local/libexec/cs-public0 disarm
sudo systemctl disable --now cs-public0-monitor.timer
sudo systemctl disable --now cs-public0.service
sudo nft list tables
```

Disarm first removes the owned queue selector, allowing new traffic to avoid a
stalled listener. Stopping the service also runs `ExecStopPost`. Already queued
packets may still time out; bypass is not a promise to drain pending packets.

Confirm the configured table is absent, the service is stopped and representative
traffic still works. Do not use `nft flush ruleset`. If the controller refuses an
ownership mismatch, inspect the table and marker from out-of-band access before
performing any manual change.

Re-enable a previous passive sensor or updater only according to the state recorded
before installation. This repository does not infer that prior state. Installed
files and logs remain for inspection. Remove them separately after confirming
that the services are disabled and no selector remains.

For a failed update, restore the previous reviewed rules and configuration using
your configuration management, run Suricata validation and `cs-public0 check`,
then explicitly start the service. Ansible with `cs_public0_enabled: false` is
also a controlled way to leave the installed service disabled.
