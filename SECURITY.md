# Security policy

This project changes the packet path when explicitly activated. Review
[the threat model](docs/threat-model.md) and validate each host class before use.
Version 1.0.0 is the first tagged baseline. The current `main` branch carries
ongoing fixes; no long-term support window or universal throughput guarantee is
promised by the tag.

## Known issue in version 1.0

NFQUEUE saturation with fail-open enabled can forward packets without inspection,
even when exported kernel/user Drops remain zero. Socket receive-buffer exhaustion
is a separate delivery limit. The receive-buffer patch and monitoring mitigate
delivery pressure and expose uncertainty; they do not eliminate packet-queue
fail-open or qualify full-load capacity. Read the
[README security limitation](README.md#known-vulnerabilities-and-limitations) and
[technical explanation](docs/nfq-receive-buffer.md).

This is an acknowledged security limitation of the availability-oriented design,
not a claim of a newly assigned CVE or a complete diagnosis of every accounting
gap. Do not clear history or treat zero counters as proof of full inspection.

For a sensitive report, use the hosting provider's private vulnerability reporting
feature when enabled, or contact the repository owner privately. Do not post
credentials, addresses, packet captures or exploit details affecting a live system
in a public issue. Include a minimal sanitized reproducer, affected version and
kernel/engine information.

Third-party engines and signature feeds follow their respective security policies.
