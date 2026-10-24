# Kernel accounting and monitor-only updates

The monitor brackets a read of the owned nft counter with two NFQUEUE reads.
It binds the NETLINK_NETFILTER socket inode to the sensor PID, start time and
boot identity. A netlink port ID alone does not identify a process. It also reads
the netlink socket's `Drops` counter; queue IDs are assigned before a successful
userspace delivery, so matching ID counts do not rule out socket loss.

The observation interval accounts for packets arriving while counters are read.
The 32-bit queue sequence is unrolled modulo 2^32 only when the inferred increment
is below half the range. A changed socket, sensor, boot or nft object handle, a
counter reset or reversed clock is an explicit discontinuity. It sets telemetry
unknown and latches degradation. Existing latches survive upgrades; old states
start a new kernel accounting baseline.

The supplied [monitor timer](../config/cs-public0-monitor.timer) uses
`OnUnitActiveSec=10s` and `AccuracySec=1s`. The 60-second continuity limit is a
deliberate maximum observation gap, not an expected sampling interval or proof
that packets were lost. A long monitor outage invalidates continuity even when
the next counters are equal: a whole number of 32-bit wraps can leave a small
modulo delta. The half-range delta checks alone do not rule that out. These
bounds do not qualify arbitrary traffic rates or eliminate all wrap ambiguity.
Do not use a timer interval of 60 seconds or more with this profile; changing
the cadence or continuity bound requires separate qualification.

An observation gap over 60 seconds with otherwise unchanged identities and
monotonic counters sets `nfqueue.observation_gap`, telemetry unknown and a separate
`accounting_observation_gap_history_latched`. This is missing coverage, not a
reported loss. It keeps the aggregate `degraded_latched=1` after current telemetry
recovers, without setting the physical-loss latch. Removing the time bound would
hide potential whole sequence wraps, so the bound remains in force.
When continuity is already missing because of time, even an nft increment of
2^31 or more belongs to that auditable coverage gap. The half-range check only
applies to a continuous interval; an actual counter decrease is still rejected.

After a discontinuity, the unknown sample becomes a fresh accounting baseline.
A subsequent complete, continuous sample without an unexplained gap can become
known again; the degraded latch remains set until an explicit `acknowledge`
succeeds on a known observation. The separate observation-gap history instead
requires the audited `acknowledge-accounting-gap` decision described below.
If every sample exceeds the continuity bound,
fix the sampling cadence or its execution failure first. Acknowledge does not
waive the observation requirements.

A positive unexplained gap produces `accounting_status=UNKNOWN_GAP` and
`telemetry_known=0`, including a single burst leaving a constant gap. It does not
claim a confirmed bypass. A later ID surplus can come from GSO and cannot
resolve the cause of an earlier gap. The monitor therefore retains
`accounting_gap_history_peak` and a separate `accounting_gap_history_latched`
across samples, monitor restarts and source discontinuities. Current quality
can become known again, but the historical latch keeps `degraded_latched=1`
and the existing Degraded alert active. It represents unresolved uncertainty,
including a possible read skew, not a confirmed bypass or packet-loss count.
New read failures still produce `telemetry_known=0` independently.
Reported queue/netlink loss has its own retained latch. Ordinary `acknowledge`
does not clear accounting history.

An explicit operator decision can start a fresh accounting baseline:

```sh
sudo /usr/local/libexec/cs-public0 acknowledge-accounting-gap \
  --evidence-sha256 SHA256_OF_THE_RETAINED_REPORT \
  --expected-history-sha256 ACCOUNTING_CLAIM_FROM_REVIEWED_STATUS
```

This accepts retained accounting-gap or observation-gap history, including a
persistent current gap after a burst. It requires a complete current source
observation with continuous identities and clocks (`current_sample_valid=true`),
not an unavailable, reset or discontinuous sample. A numeric gap still leaves
`telemetry_known=0`. The operator decision records
the previous accounting sample, evidence reference and actual integer wall /
monotonic timestamps in `gap_acknowledgements`, in the same atomic state write
as the new baseline. The historical peak and other degradation latches remain.
The full gap remains in the audit, while the new baseline starts with zero gap.
The acknowledgement does not change an UNKNOWN historical sample to known;
only a subsequent complete observation can become known on the new baseline.
The SHA is an operator-supplied reference, not evidence attestation. The monitor
also compares the required expected-history SHA with the fresh observation's
claim. Obtain `state.accounting_claim_sha256` from the reviewed `status` result.
It covers source identities, current gap, historical peak, both history flags
and acknowledgement count, excluding timestamps and ordinary packet progress.
A larger or otherwise changed gap, changed source or replay after another
acknowledgement refuses the operation. This claim is a concurrency guard, not a
signature or proof that the operator reviewed the referenced report. The monitor
timer never acknowledges automatically. Its existing lock serializes state
updates. The audit is bounded to 32 decisions and the existing 64 KiB state cap;
overflow refuses the operation and requires separately controlled archiving,
without automatic history deletion.

For an internal failure in the timer's `monitor` command, its command boundary
publishes UNKNOWN under the same state lock and preserves the actual retained
degradation flags. Operator validation refusals in `acknowledge*` do not publish
metrics. If retained state cannot be read or has invalid structure, the fallback
publishes conservative degradation uncertainty without changing that state. A
failure to publish the fallback is logged, and the original error is preserved.
A failure to acquire the lock never writes outside it: the command fails
and the old publish timestamp remains for the freshness alert. This deliberately
rejects an unlocked fallback publisher, which could overwrite the lock holder's
fresh result. If the metrics destination itself is unavailable, publication also
fails and freshness monitoring remains necessary.

Administrative `check`/`arm` can hold the shared lock beyond 60 seconds. Such a
controlled pause still lacks observation coverage and requires the explicit
audited acknowledgement after continuity returns; it is not silently treated as
lossless. The long-pause regression covers the resulting history and its exit.
Listener and nft selector indicators record independent successful reads; an nft
failure can leave `queue_listener=1` while overall telemetry remains UNKNOWN.

`decoder.pkts` remains independent telemetry. Its asynchronous aggregation cannot
create a kernel-accounting loss. GSO can generate multiple queue IDs for one nft
hit and mask a gap. This accounting cannot prove inspection of every packet:
`full_inspection_verified` remains zero. These are observations, not a capacity,
latency, clock-accuracy or security certification.

## Update an already active installation without a sensor restart

Use this path only when changing the compatible controller/monitor code; it does
not install units, change settings, rules, nft selectors or upgrade Suricata.
Initial installations and incompatible changes still use `site.yml` and an
explicit maintenance window. Coordinate with other operators first.

Read the current `/usr/local/libexec/cs-public0` SHA-256 from the selected host.
Then run from the repository's `ansible/` directory:

```sh
ansible-playbook -i ../examples/apache-cloudstack-kvm/inventory.ini monitor.yml \
  -e target=kvm-example.example.invalid \
  -e cs_public0_expected_runtime_sha256=REPLACE_WITH_64_HEX_DIGITS
```

The playbook requires one exact host and the installed hash. It stops only the
monitor timer and sample, atomically replaces the helper, starts a sample and
restores the timer even on error. Readback requires an unchanged sensor epoch,
preserved latch, new metric schema and fresh known telemetry. Failure leaves an
explicit error for operator investigation; it does not restart or remove the
sensor. Review [rollback](rollback.md) for sensor rollback, which is a separate
operation. Neither this path nor a passing unit test qualifies all live kernels.

See the [kernel references](references.md) for ID assignment, fail-open and netlink
overrun semantics. Validate the source and effective behavior of your own kernel.

The managed alert-only preflight rejects secondary rule-source keys and enabled
firewall/multi-detect profiles in the engine's effective dump, including sources
introduced by YAML includes. Only its exact single `rule-files.0` is accepted.
Rule-source matching uses path segments (`rule-files`, `rule-path`,
`default-rule-path` and their named prefixes), not a substring search for
`rules`. Diagnostic `engine-analysis.rules`, `profiling.rules.*` and Lua
permission keys do not select another rule file and are not rejected merely
because of their names. Their presence is not a qualification of those features.
This intentionally conservative profile is not a general Suricata configuration
validator. See the upstream [8.0.7 configuration](https://github.com/OISF/suricata/blob/suricata-8.0.7/suricata.yaml.in)
and [firewall design](https://docs.suricata.io/en/suricata-8.0.7/firewall/firewall-design.html)
for the separate firewall rule sources and policies.
