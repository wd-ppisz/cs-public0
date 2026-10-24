# Kernel accounting and monitor-only updates

The monitor brackets a read of the owned nft counter with two NFQUEUE reads.
It binds the NETLINK_NETFILTER socket inode to the sensor PID, start time and
boot identity. A netlink port ID alone does not identify a process. It also reads
the netlink socket's `Drops` counter; queue IDs are assigned before a successful
userspace delivery, so matching ID counts do not rule out socket loss.

The observation interval accounts for packets arriving while counters are read.
The 32-bit queue sequence is unrolled modulo 2^32 only when the inferred increment
is below half the range. A changed socket, sensor, boot or nft object handle, a
counter reset, reversed clock or observation gap over 60 seconds is an explicit
discontinuity. It sets telemetry unknown and latches degradation. Existing latches
survive upgrades; old states start a new kernel accounting baseline.

The supplied [monitor timer](../config/cs-public0-monitor.timer) uses
`OnUnitActiveSec=10s` and `AccuracySec=1s`. The 60-second continuity limit is a
deliberate maximum observation gap, not an expected sampling interval or proof
that packets were lost. A long monitor outage invalidates continuity even when
the next counters are equal: a whole number of 32-bit wraps can leave a small
modulo delta. The half-range delta checks alone do not rule that out. These
bounds do not qualify arbitrary traffic rates or eliminate all wrap ambiguity.
Do not use a timer interval of 60 seconds or more with this profile; changing
the cadence or continuity bound requires separate qualification.

After a discontinuity, the unknown sample becomes a fresh accounting baseline.
A subsequent complete, continuous sample without an unexplained gap can become
known again; the degraded latch remains set until an explicit `acknowledge`
succeeds on a known observation. If every sample exceeds the continuity bound,
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
  --evidence-sha256 SHA256_OF_THE_RETAINED_REPORT
```

This requires a known current observation without a current gap. It records
the previous accounting sample, evidence reference and actual integer wall /
monotonic timestamps in `gap_acknowledgements`, in the same atomic state write
as the new baseline. The historical peak and other degradation latches remain.
The SHA is an operator-supplied reference, not evidence attestation. The monitor
timer never acknowledges automatically. Its existing lock serializes state
updates. The audit is bounded to 32 decisions and the existing 64 KiB state cap;
overflow refuses the operation and requires separately controlled archiving,
without automatic history deletion.

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
