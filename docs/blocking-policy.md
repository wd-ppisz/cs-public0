# Explicit IPS blocking policy

cs-public0 defaults to alert-only inspection. Blocking is an explicit per-host decision,
not a blanket conversion of severity levels, rule categories, scan alerts or IP reputation.

1. Inspect local EVE history and central log completeness. An alert is not proof of compromise.
2. Review the complete definitions and revisions of selected exploit signatures. Record a sorted,
   nonempty list of at most 128 SIDs against the exact input SHA256. Do not ship customer addresses.
3. Run `runtime/prepare_blocking_rules.py --input INPUT --input-sha256 SHA --output CANDIDATE
   --drop-sid SID` (repeat the SID option in ascending order). The input must be alert-only.
   This offline operation changes only the selected action tokens, rejects missing/duplicate SIDs,
   and does not reload a sensor. Keep an unmodified alert-only snapshot for explicit rollback.
4. Upgrade a pinned installation's controller/startup verifier through a separately reviewed
   immutable-policy maintenance plan. Do not overwrite pinned modules using the bootstrap playbook.
5. Use the existing bounded activation plan with an explicit `drop_sids` list. An empty list
   explicitly restores an alert-only candidate. A missing field preserves the installed policy.
   The v2 release records exact alert/drop counts and SIDs; v1 remains compatible and alert-only.
   The startup and rule-validation paths obtain the allowlist from the verified
   release; unpinned DROP bytes are still rejected. Existing GSO overrides must
   remain enabled and unambiguous during activation.
6. Qualify with the exact Suricata binary using `-T --simulate-ips`, then perform one journaled
   reload. Read back release SHA, ruleset counts, process/queue identity, progress, loss counters,
   fresh monitoring and central EVE. A successful compilation is not a packet-level blocking test.
7. Observe real traffic and false positives. Revert only through an explicit approved activation;
   never silently clear degraded history or retry an unknown reload result.

No default SIDs are supplied: operators must assess their own services and signature content.

### Explicit degraded-baseline operation

The default activation path requires healthy monitoring and resolved history. An
operator who deliberately keeps an existing degraded installation in service can
instead supply an `accepted_degradation` object in a selected-DROP plan. It names
`<store>/accepted-monitor-state.json`, its exact `sha256`, and the boolean
`allow_existing_accounting_gap`. The snapshot must be a root-owned, immutable
transaction input from the same sensor/boot, no older than 15 minutes.

This option requires a latched baseline with a valid current observation and no
current loss reasons. Critical loss counters, history flags and acknowledgement
lists must remain unchanged. An ongoing accounting gap is allowed only when it
already existed in the snapshot and was explicitly accepted; its magnitude can
change and remains unqualified. A baseline with zero gap must retain zero gap.
The ordinary fresh process, GSO/effective argument, exact source, queue/socket
zero-loss and post-reload progress checks still apply. No latch, counter, alarm
or acknowledgement is reset. The result is
`ACTIVATED_WITH_ACCEPTED_DEGRADATION`, never a healthy-inspection qualification.
This does not solve the known fail-open queue limitation or qualify capacity.

For existing installations, `runtime/rule_policy_refresh.py` can replace the
verifier, monitor and release metadata through a separate, exact three-image
plan after staging the new controller in a new root-owned directory. The plan
pins the old/new bytes and metadata, sensor identity, preserved rule/configuration
files and the GSO/buffer guard command. Run `apply` in a bounded systemd unit
with `recover` as `ExecStopPost`. All original images are saved before the first
write; an incomplete transaction restores only matching owned images. A committed
refresh leaves the running sensor and rules unchanged. Monitoring history must
remain byte-identical while its timer is paused. Rule activation, qualification
and the explicit degraded-baseline snapshot remain separate operations.

Blocking matches only traffic visible to Suricata; encrypted application content needs a separate
TLS visibility design. Availability exception policies and NFQUEUE bypass remain separate from
the chosen rule actions. Review every rule-feed update; selected SIDs do not attest to unchanged
signature semantics or rule quality. This feature does not claim complete DDoS protection,
full inspection under every failure mode, or G6 capacity qualification.
