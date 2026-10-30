# Refreshing a running NFQUEUE observer

The observer can be refreshed without restarting Suricata or changing selectors,
rules, offloads or inspection history. This operation updates existing observer
files and, when they are already pinned, only their entries in release.json.
It never adds an unpinned path to the immutable set. Keep the old bytes as evidence.

Use runtime/observer_refresh.py with an operator-reviewed, root-owned profile.
The profile names the exact host, active sensor unit, existing state directory,
release and its SHA256, one or two observer paths with their old SHA256, candidate
source and SHA256, verifier and SHA256, binary pin, queue, required receive-buffer
request and exactly two already-active monitor timers. All paths must be absolute.
The implementation deliberately refuses links, hard links and writable ancestors.

Prepare with phase prepare, --file PROFILE and --sha256 PROFILE_SHA. Retain the
returned plan path and SHA. No sensor or monitor service changes during prepare.
Copy the helper to a dedicated versioned root-owned directory before preparing;
retain that exact helper for recovery.

Apply only in a transient service named cs-public0-observer-refresh-TOKEN.service,
where TOKEN is the plan token. Use Type=exec, RuntimeMaxSec=90s,
KillMode=control-group and a root execution identity. ExecStart must invoke
/usr/bin/python3 -B HELPER apply --file PLAN --sha256 PLAN_SHA.
ExecStopPost must invoke the same command with phase rollback. The helper checks
these effective manager properties, its invocation and PID before writing.
Set TimeoutStopSec=120s and MemoryMax=128M; retain the complete manager output.
The helper verifies the effective 120-second recovery budget. Its bounded lock
wait plus three command timeouts use up to 70 seconds before filesystem overhead.

During apply only the two monitor timers and their services are briefly paused.
The sensor PID, invocation and start ticks must remain unchanged. The shared
activation lock serializes this transaction with rule activation. Each image is
installed by atomic rename; the pair of observer/release files is not one atomic
transaction. The unchanged release verifier and new observer must both succeed.
The original release policy and all non-observer immutable pins remain unchanged.
Original file groups and modes are preserved independently of the service umask.
Both monitor timers must still be active immediately before applying.

On exception or interrupted execution, rollback restores only known old/new
images and resumes the original active monitors. Foreign bytes are never
overwritten. ExecStopPost performs recovery if the apply process dies; it is a
no-op after COMMITTED or a completed rollback. A failed recovery remains a
reported failure requiring operator attention. It never restarts the sensor.
Blocking kernel I/O is not proven interruptible by the Python deadline.
Recovery waits up to 10 seconds for the shared activation lock; apply refuses
immediately when it is occupied. After all old images have been restored, monitor
restart is attempted even if release verification fails. Such a failure remains
APPLYING and is reported for operator recovery; it is never labelled ROLLED_BACK.
Recovery handles SIGTERM as an exception so the monitor restart finally block can
run when old images have already been restored. SIGKILL and uninterruptible I/O
still require the retained plan and explicit operator recovery.
After a host crash, an operator may invoke the pinned rollback command with the
original plan. Recovery accepts a changed boot ID while retaining host, helper,
plan and known-image checks; applying a stale plan still requires the same boot.

After the operation, read back source hashes, release verification, unchanged
sensor identity and rules, effective GSO/buffer and fresh monitor publications.
Continue observing queue loss, accounting gaps and service quality; the refresh
does not qualify capacity, full inspection or a production workload.
