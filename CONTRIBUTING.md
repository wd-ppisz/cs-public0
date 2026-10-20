# Contributing

Keep changes small and explain the behavior being changed. Add regression tests
for controller, ownership, telemetry and lifecycle changes. Use documentation
addresses and hostnames in examples. Do not include real inventories, packet
captures, credentials or operational reports.

Run `python3 -m unittest discover -s tests -v`, render the templates and validate the
Ansible playbook. Changes affecting the dataplane also require the isolated Linux
smoke and a description of its kernel and Suricata version. State skipped checks.

Contributions are accepted under Apache License 2.0. Preserve applicable notices
and document any third-party code or assets added to the repository.
