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
Blocking matches only traffic visible to Suricata; encrypted application content needs a separate
TLS visibility design. Availability exception policies and NFQUEUE bypass remain separate from
the chosen rule actions. Review every rule-feed update; selected SIDs do not attest to unchanged
signature semantics or rule quality. This feature does not claim complete DDoS protection,
full inspection under every failure mode, or G6 capacity qualification.
