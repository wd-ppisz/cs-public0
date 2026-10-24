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

A positive unexplained gap produces `accounting_status=UNKNOWN_GAP` and
`telemetry_known=0`, including a single burst leaving a constant gap. It does not
claim a confirmed bypass. Pending enqueue work can resolve the gap later. The
existing unknown-telemetry alert covers persistent gaps. Reported queue/netlink
loss still latches degradation. `acknowledge` refuses an unknown observation.

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
