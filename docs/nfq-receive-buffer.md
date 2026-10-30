# NFQUEUE receive-buffer capacity

The packet queue awaiting a verdict and the netlink socket receive buffer are
different limits. Increasing one does not qualify the other. Low average CPU
load does not exclude a short scheduling or traffic burst exhausting a socket.

The optional incremental patch `patches/suricata-8.0.7-nfq-rcvbuf.patch` adds
`nfq.rcvbuf-size`: canonical decimal bytes between 1 MiB and 64 MiB. It leaves
`max-pending-packets`, packet queue depth, GSO, verdicts and fail-open unchanged.
Without this setting the existing engine behaviour remains.

## Build and enable deliberately

1. Start with your independently qualified Suricata 8.0.7 GSO/CAP_LEN source.
   The patch was checked against `src/source-nfq.c` SHA256
   `f0ba2295976247597adcca6616ac7df55a2c51769359721a16b9e8951bfc8f4d`.
   This patch does not implement GSO for arbitrary stock Suricata.
2. Apply it from the engine source root with
   `patch --batch --fuzz=0 -p1 < suricata-8.0.7-nfq-rcvbuf.patch` and copy
   this repository's `patches/source-nfq-rcvbuf.h` into the engine's `src/`.
   Compile and package using your existing hardening and dependency policy.
3. Compile the standalone fault fixtures using
   `gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined tests/test_nfq_rcvbuf.c -o /tmp/test-nfq-rcvbuf`
   and execute the test binary. Run the Python suite on Linux too.
4. Pin the resulting binary with `cs_public0_nfq_gso_binary_sha256`. Enable
   `cs_public0_nfq_gso: true` and set `cs_public0_nfq_rcvbuf_size: 16777216`
   for a deliberately chosen canary. This 16 MiB request is an initial
   engineering choice, not a universal capacity recommendation. Compare
   service latency, retransmissions, worker/IRQ pressure and socket loss under
   actual workload before expanding.
5. Keep independent management and previous artifacts. Use the existing
   maintenance and rollback procedure. The installation role stops managed
   services before replacing files; it is not a read-only capacity check.

Linux reports **twice** the `SO_RCVBUF` request, including bookkeeping space.
The example therefore requires 32 MiB effective. The patch uses `SO_RCVBUF`,
not `SO_RCVBUFFORCE`, refuses a clamped/unreadable result and changes no sysctl.
Its startup log includes queue, requested bytes and `getsockopt` effective bytes.

Before enabling the setting, read `sysctl net.core.rmem_max` on the canary.
The host limit must be at least the requested value: 16777216 for the example,
not the doubled effective value. A smaller limit makes startup fail before the
selector is armed. If a host-wide change is needed, approve and manage it through
your host IaC policy, then read it back; the installation role does not raise it
automatically. Keep the receive-buffer feature disabled until that prerequisite
is met. Do not use a successful YAML render as evidence of kernel capacity.

The observer checks the exact engine hash and non-overridden CLI argument,
service invocation/start ticks, owned socket inode, matching `ss` diagnostic
and current-invocation engine acknowledgement. The selector is armed only
after the additional gate succeeds. `ss` needs `iproute2` and netlink diagnostic
access; custom service sandboxes must allow `AF_NETLINK`. Identity reads bracket
a separate diagnostic and do not provide a kernel-atomic replacement guarantee.

## Observe inspection and forwarding separately

| Metric, labelled by `host` and `profile` | Meaning |
|---|---|
| `cs_public0_nfq_rcvbuf_known` | Current explicit buffer requirement verified |
| `cs_public0_nfq_rcvbuf_effective_bytes` | Verified kernel value; zero when unknown |
| `cs_public0_nfq_rcvbuf_required_bytes` | Twice the explicit request; zero when opt-out |

A failed buffer check makes the combined GSO/startup observation unknown.
Alert on missing/stale/unknown observations as well as insufficient capacity.
Unknown-sample zeros are not measured zero capacity. A larger setting neither
proves loss-free inspection nor reserves that much resident RAM in advance.

Retain `cs_public0_queue_netlink_dropped`, kernel/user queue counters,
`cs_public0_accounting_unexplained_gap` and history latches. With fail-open,
zero kernel/user drop counters do not exclude packets accepted without
inspection after failed netlink delivery. Socket Drops count lost messages;
the accounting gap is uncertainty between observation stages. Neither counts
attacks, lost HTTP requests or automatically confirmed fail-open packets.
Never clear history merely because the buffer was increased.

Scope end-to-end latency/retransmission probes to the connections and services
they actually observe. An upload probe for one host does not qualify all
clients or other hosts. Copy correctness, inspection completeness and
forwarding availability remain separate checks.

## Full packet queues can bypass inspection with zero Drops

The socket receive buffer and the queue of packets awaiting verdicts must also be diagnosed separately when the socket has stopped losing messages. In the [Linux 6.17 NFQUEUE implementation](https://github.com/torvalds/linux/blob/v6.17/net/netfilter/nfnetlink_queue.c), a full packet queue with `NFQA_CFG_F_FAIL_OPEN` accepts the packet before assigning its NFQUEUE packet ID. That path does not increment `queue_dropped` or `queue_user_dropped`. Successful fail-open delivery can therefore leave kernel, user and socket Drops at zero while inspection is incomplete. This is different from a rule-driven DROP verdict.

A bounded loopback experiment in a separate network namespace illustrates the distinction. The consumer deliberately held packets before issuing only `NF_ACCEPT` verdicts:

| Same 32 small UDP datagrams | Queue limit 4 | Queue limit 64 |
|---|---:|---:|
| nft counter | 32 | 32 |
| NFQUEUE IDs allocated | 4 | 32 |
| Delivered to the owned backend before any verdict | 28 | 0 |
| Delivered after draining the queue with ACCEPT | 32 | 32 |
| Kernel/user/socket Drops | 0/0/0 | 0/0/0 |
| nft minus allocated IDs after draining | 28 | 0 |

Read-only kernel instrumentation, calibrated against these two cases, observed all 64 enqueue calls and exactly 28 executions of the full-queue fail-open branch before ID assignment. This establishes the mechanism in that isolated case; it does not classify an arbitrary production accounting gap or prove that all uninspected traffic followed that branch.

A subsequent 60-second observation of natural traffic on one deployment directly observed 13 executions of the same branch with an effective queue limit and observed peak of 512 packets. Kernel, user and socket Drops remained zero. The separately instrumented pre-ID guard, message-allocation error and netlink-send error branches recorded no events in that window. This confirms that full-queue fail-open can occur in real traffic after socket-buffer loss has been addressed; it does not establish the cause of every historical gap or identify the worker scheduling, traffic burst or rule-processing cost that filled the queue. Instrumentation has processing overhead: this is not a capacity benchmark without probes. Exact instruction probes were tied to the inspected kernel module and calibrated first; those offsets are not portable diagnostics.

The queue capacity is not the byte capacity reported by `SO_RCVBUF`. Suricata 8.0.7's NFQUEUE initialization passes `max-pending-packets * NFQ_BURST_FACTOR` to the queue length setter; the burst factor in that source is 4. Check the effective queue and the exact engine build instead of interpreting a configuration value as a kernel observation. A 16 MiB socket request cannot prevent a separate packet queue from filling.

Keep history latched and compare queue pressure, enqueue-path fail-open, socket losses and the nft/ID bracket. A point-in-time pending value of zero does not exclude an earlier microburst. The accounting gap alone remains UNKNOWN: observation timing and packet transformations still need to be considered, and neither a gap nor a kernel packet count is an HTTP request count.

Do not solve this by disabling fail-open on a production host. Increasing queue depth without a measured processing and latency budget can trade an inspection gap for memory use or forwarding delay. First reproduce the condition in an isolated fixture, then qualify any queue/worker/rule-cost change on a canary with service latency, retransmissions and an independent rollback.
