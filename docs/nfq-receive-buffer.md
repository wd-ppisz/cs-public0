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
