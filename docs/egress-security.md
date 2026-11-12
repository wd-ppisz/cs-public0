# Egress security: observation without enforcement

Status: optional component released in [1.1](releases/v1.1.0.md). Installation
does not establish site-specific LAB, canary or production acceptance.

The optional collector reads the existing Suricata EVE file outside the packet
forwarding path. It writes bounded JSON details and a node_exporter textfile.
It does not call CloudStack, Wazuh, an LLM, a ticketing system or the sensor command
socket. It cannot activate rules, restart Suricata, quarantine guests or issue
network verdicts. A log shipper can forward its output independently of Wazuh.

## Delivery batches and acceptance

1. Establish the actual sensor/EVE schema, rotation, rule provenance, exporter,
   dashboard UID/version/folder and log transport. Preserve a private receipt.
2. Implement the event contract, conservative classification and bounded reader
   using existing alert/flow/stats records. Test restart, rotation and overload.
3. Add deployment-specific address/policy configuration, independent log transport,
   dashboard panels and notification rules. Keep site data in private IaC.
4. Replay an isolated LAB against an owned receiver; measure collector CPU, RSS,
   output and lag. Fixtures alone do not qualify the real dataplane or exporter.
5. Install one explicit canary, verify metrics through Prometheus and log queries
   through Grafana, observe it and roll out sequentially after acceptance.
6. Consider beaconing/fan-out or new DNS/TLS logging separately, after measuring
   cost and defining retention. Do not enable full traffic logging implicitly.

An alert/stats-only installation can classify signature observations but may have
unknown initiation direction. Existing flow logging can improve this without a
sensor restart; neither this document nor installation enables it automatically.

## Direction and attribution

Public-side observation is after source NAT for outbound traffic. An owned public
IP is a useful scope even when multiple guests share it. Never infer one VM or
attribute an event to all guests behind SNAT. Optional static, operator-managed
IP-to-VR/VM mappings are enrichment, not prerequisites.

The tuple of an alert is a packet tuple. `to_server`, a source IP in the operator's
network, a reputation match or an application name alone does not prove egress.
Use a sensor-epoch-bound flow with matching ID/start and matching endpoints. TCP
initiation requires observed SYN evidence in the flow's client direction, without
RST/exception/midstream evidence that contradicts the asserted role. Preserve the
method and its limitations. Absence of sufficient evidence produces `unknown`.
An alert on the reply to an inbound connection remains inbound/unknown even when
the reply packet's source is owned. UDP initiation is unknown in the first batch.

Keep four distinct statements: signature matched; a connection was attempted;
the sensor observed establishment; possible C2 communication. None proves intent,
guest compromise, end-to-end application success or complete inspection.

## Controlled policy and IOC contract

Classification revision 2 applies IPInsights only to attacker-source reputation
on an independently qualified ingress flow. Such observations use `reputation`
with low severity and no enforcement. IPInsights-only egress and unknown-direction
candidates are omitted from publication, not reinterpreted as abuse by a guest.
The filter runs after joining a pending event to its flow; a source-IP comparison
alone cannot qualify direction. Presence on the provider's IP list is not scan
detection. A separately qualified signature retains its category, including
a scan signature when the peer also happens to match IPInsights. Other IOC source
receipts remain visible and do not inherit the IPInsights-only downgrade.

New main dashboards use `cs_public0_egress_observations_v2_total` and exclude
`category="reputation"`; a separate context panel retains those observations.
`ipinsights_non_ingress_filtered_total` retains a bounded technical count of
omitted source-feed candidates. The v2 counter starts with the new collector and does not import legacy scan
counts. Old counters and SQLite state are retained, including the old meaning of
IPInsights-only `scan` for legacy consumers. Never subtract a guessed historical
amount, reset collection cursors, or present the old mixed count as proven scans.
`classification_v2_ready` identifies publication by the new observer; the existing
source/lag/continuity checks still determine whether collection is healthy.

Classification uses an operator-supplied catalog of exact GID/SID/revision,
category and required metadata, bound to an explicit rule-file artifact SHA256. An unreviewed
revision, changed ruleset or mismatched metadata is not silently accepted.
Signature text is display data, never the sole classification criterion.
The output calls this `catalog_rules_sha256`. It identifies the qualification
artifact; it is not proof of the ruleset loaded by the event-producing engine.

IOC data is optional and separately qualified: explicit source, version/content
hash, fetched time, publisher freshness when available and expiry. An unavailable
or expired artifact cannot produce a current-IOC match. Preserve stale/unknown
coverage separately; do not pretend that refreshing a download updates its source.
IP reputation is supporting evidence rather than proof of compromise. Do not
contact real C2 infrastructure to test the collector.

## Event contract: `cs-public0-egress-event-v1`

Each retained observation contains an immutable event ID; observed and received
times; sensor ID and epoch; observation point; packet tuple; optional flow ID and
flow start; direction and evidence method; GID/SID/revision; closed category and
severity; catalog/source version; optional IOC provenance/expiry; IP/VR/VM
attribution level; limitations; and a reference to the source inode, byte offset,
record length and record SHA256. Flow IDs are serialized as strings.

Allowlist fields explicitly. Do not copy payload, packet, HTTP bodies/headers,
URLs, credentials, file contents or full PCAP into the normal output. A source
reference does not promise that rotated source bytes remain archived forever.
Downstream consumers must deduplicate by event ID within their own retention.

## Metric contract in 1.1

The family prefix is `cs_public0_egress_`, alongside existing `cs_public0_*`
producers. Sensor identity comes from scrape labels or a configured bounded ID.
Public IP, remote IP, domain, port, SID, signature, flow ID, case ID and guest
identity must never become metric labels.

| Metric suffix | Type and meaning |
|---|---|
| `observations_total{category,severity,direction}` | Committed observations, not unique attacks or compromised guests |
| `observations_v2_total{category,severity,direction}` | Revision 2 observations; separate `reputation` context from security categories |
| `records_total{outcome}` | Processing-stage counters from a closed enumeration; stages can overlap and are not an exclusive input denominator |
| `collection_gaps_total{reason}` | Detected rotation/truncation/cursor/retention discontinuities |
| `collector_up` | Last run completed successfully; always gate by publication freshness |
| `source_available` | Source is present and passes the declared checks |
| `last_read_unix_seconds` | Last successful read, including a healthy EOF |
| `last_publish_unix_seconds` | Last atomic metric publication |
| `last_sensor_stats_unix_seconds` | Last accepted advancing sensor heartbeat |
| `processing_lag_seconds` | Age of the latest processed source record, with unknown represented separately |
| `pending_records` | Bounded observations waiting for flow evidence |
| `collection_continuity_known` | No detected gap in the last 60 seconds with fresh source and no backlog; historical gap counters remain |
| `last_gap_unix_seconds` | Time of the last detected collection gap |
| `ioc_fresh` | Qualified optional artifact is currently usable; not a feed fetch success |
| `ioc_expires_unix_seconds` | Qualified artifact expiry, absent when not known |
| `catalog_ready` | Current rule-file identity matches the installed full-SHA catalog binding |
| `backlog_bytes` | Unprocessed bytes remaining in the current source file |
| `source_fresh` / `lag_known` | Advancing heartbeat with no observed backlog / known latest record time |

Closed categories: `c2`, `ioc`, `scan`, `other`, `reputation`; severity: `high`,
`medium`, `low`, `unknown`; direction: `egress`, `ingress`, `unknown`. Legacy
observations retain 48 series; revision 2 adds up to 60, including reputation.
Together with processing, gap and scalar metrics, the collector enforces at most
148 application series per sensor, 740 for five sensors, excluding node_exporter
and scrape-added bookkeeping. These are bounded series, not attack counts.
Keep IOC versions in details rather than labels. Validate the actual exporter
against this budget.

Repeated packets, multiple signatures on a flow and multiple sensors can create
multiple observations. Cursor persistence and bounded event-ID deduplication stop
ordinary restart replay; they do not establish a global unique-attack count.
Document the finite deduplication horizon, eviction and explicit resets.

No alerts with advancing stats and fresh collection means valid zero. Missing
source, frozen stats, unprocessed backlog or stale publication means unknown
coverage. Never infer collector freshness from the last security alert. The
collection flags do not repair NFQUEUE accounting or fail-open uncertainty and
do not qualify IPv6, guest sensors or other bridges.

## Persistence, bounds and rotation

Persist cursor, committed counters, pending flow joins and bounded output records
transactionally. Metrics are a replaceable atomic snapshot of committed state.
Publish details with stable IDs; acknowledge possible delivery duplicates after
a crash rather than claiming an impossible filesystem-wide transaction.

Treat inode replacement and `copytruncate` separately. A size decrease or cursor
fingerprint mismatch marks a gap. Copytruncate can lose bytes between observations
without a detectable size decrease; expose this residual uncertainty. Never label
the absence of detected gaps as proof of lossless rotation or complete traffic.

The reader drains a retained, uncompressed `eve.json.1` through `eve.json.7`
before following the current file. It checks both the previously consumed
boundary and a stored initial prefix, retains archive progress transactionally
across process restarts, and reports archived plus live bytes as backlog. A
snapshot of the next generation also allows a retained intermediate rotation to
be recovered. It never selects an archive from its timestamp or size alone.

Recovery does not clear historical gap counters. Copytruncate still records a
gap because writes between copying and truncation cannot be proven retained.
Compressed, removed or unmatched archives are not silently treated as consumed;
the discontinuity stays explicit when the reader resumes the live source. A torn
final archive line is recorded as partial and invalidates continuity. Operators
must retain uncompressed generations long enough for their measured worst-case
backlog, and must keep alerting on gaps even after current backlog reaches zero.

Candidate engineering bounds: 64 KiB per record, 32 MiB/50000 records per run,
1-second inactive timer, 4-second cooperative work budget and 8-second systemd
deadline (including publication margin), 4096 catalog entries, 4096 pending joins,
24-hour/10000-ID deduplication horizon and a 32 MiB SQLite database. Each of
the flow, pending and outbox tables also has a 2 MiB serialized-byte budget,
including a 512-byte allowance per row for keys/index overhead. Its rollback
journal can additionally approach the database size; detail logs have a 4 MiB
current file and one 4 MiB archive. These disk bounds are not a measured RAM bound.
Full output queues or storage stop ingestion with an unhealthy/stale indicator.
The dedup cache evicts its oldest ID with `dedup_evicted`: its effective horizon
is at most 24 hours/10000 IDs and a replay after eviction can be counted again.
A full pending cache publishes its oldest qualified observation immediately as
unknown with `JOIN_EVICTED_EARLY` and increments `join_evicted`. Neither cache
alone stops reading the source. Candidate service limits:
CPUQuota=10%, MemoryMax=96 MiB, TasksMax=4. These are proposed controls, not measured
cost or performance guarantees; LAB must verify and revise the explicit budget.

By default `flow_join_enabled=false` publishes alerts immediately as unknown,
including sensors that emit only alert/stats. Sites with flow EVE may explicitly
enable a short correlation window; `join_wait_seconds` defaults to 15 seconds
and permits 0..86400. The WebDisk candidate explicitly uses 15 seconds. The next
scheduled run publishes unmatched events as unknown after this window; it does
not wait an hour for a long-lived C2 session to end. A longer custom window
delays publication and must be chosen consciously. No later enrichment is
claimed for an already published unknown event.
IPv6 and portless protocols are counted as ignored/unsupported, not malformed.
Multicast and unspecified addresses are also unsupported, rather than invalid
EVE. Classification configuration is validated before reading: invalid networks,
sensor IDs or exclusive attribution mappings hold the cursor as `ConfigInvalid`
and publish unhealthy metrics. The base sensor epoch is limited to 96 bytes to
leave room for its local generation suffix.
IPv6 is recognized from the address itself even when EVE omits `ip_v`. A
qualified IPv4 alert without flow identity is published immediately with nullable
flow identifiers and `direction=unknown`; it cannot be joined by guessing.
Missing/malformed catalog artifacts publish unhealthy metrics while preserving
the unread cursor. Malformed optional IOC artifacts disable only IOC matching.

`connection_evidence=sensor_observed_established` requires the sensor's explicit
established state. A final closed flow with cumulative TCP flags has unknown
connection history, rather than being mislabeled as a new attempt. OR-ed flags
do not preserve packet order and cannot prove a complete handshake. A SYN-only
observation or an explicit handshake-in-progress state can be called attempted.

A changed rule-file binding disables catalog qualification, sets unhealthy
collection using device/inode/size/mtime/ctime plus the installed full-SHA
artifact. Timestamp granularity is filesystem-dependent; these metadata checks
are not a cryptographic live attestation or protection against a privileged
writer preserving every observed identity field within a timestamp tick.
Publish rule updates atomically. A changed binding sets unhealthy
collection and records a catalog gap. The cursor and already qualified pending
events are preserved until a current catalog binding is installed. Finite source
rotation can still lose unread bytes during this hold. Pending events retain their
original qualification and receipt time; later publication adds its own timestamp.
Rules updated by another controller never silently
inherit an old SID/revision mapping. A publisher must refresh its qualified
artifact through the accepted delivery path. File identity checks are not an
attestation against a privileged process that forges file timestamps.

A separately installed artifact producer may embed `rules_identity` in the
catalog. The consumer validates its shape and SHA binding and compares it with
the current rule file. Publishing that one artifact atomically updates mapping
and binding together, without restarting a sensor. The static configuration
identity is the fallback for installations without an artifact producer. Such a
producer must preserve its reviewed class policy, all entry bounds and source
provenance, and remain outside the packet path.

Detail delivery batches at most 256 KiB per fsync and deletes delivered outbox
entries in one transaction. A crash between append and acknowledgement can still
duplicate event IDs. Hard syscall latency is not guaranteed; consumers must gate
health by publication age even when the last published value was healthy.
An interrupted partial detail line is separated before the durable outbox retries
its complete event. The fragment is not a valid observation; consumers still
deduplicate complete retries. Byte pressure evicts old flow evidence or publishes
old pending observations as unknown. Output pressure remains explicit backpressure.
An actual SQLITE_FULL rolls back the current input batch, preserves the previously
committed cursor and admissions, and separately commits removal of disposable
flow/dedup cache entries before retrying. Physical filesystem exhaustion remains
unhealthy; the 32 MiB cap is unchanged. These are engineering bounds, not a
throughput, memory or whole-host capacity qualification.
Each input batch explicitly begins a transaction before record savepoints, so
releasing a savepoint cannot commit a record without its corresponding cursor.
The full-disk handler also supports Python 3.10 without the newer SQLite error
constant/exception attributes.
SQLite triggers maintain row/byte accounting transactionally for INSERT, UPDATE
and DELETE, including savepoint rollback. Full scans occur only once when
initializing accounting for an older state schema, not per consumed flow.

Catalog changes create an explicit boundary covering the unread EVE prefix,
including a change published between two collector runs. Only GID/SID identities
from qualified catalogs are eligible within that prefix; unrelated alert noise
remains `unmapped`. Eligible alerts are preserved as
`signature_observation_unqualified`, category `other`, severity
`unknown`, with their observed GID/SID/revision and
`RULESET_TRANSITION_UNQUALIFIED`. They do not inherit a guessed catalog or engine
SHA. The prefix boundary is not an exact sensor reload timestamp. Already
admitted pending observations keep their original frozen artifact qualification.
After the prefix is drained, new observations use the current catalog mapping,
still without claiming producer-ruleset attestation.
The union of catalog identities needed by an unread prefix is bounded to 8192
GID/SID pairs, retained across successive reloads until that prefix is drained.
If reloads exceed this bound before collection catches up, input is held with
`CatalogTransitionCapacity` and unhealthy catalog coverage; no all-alert fallback
or silent forgetting of earlier eligible identities occurs. Operator recovery
must preserve the recorded discontinuity rather than acknowledge full coverage.

The unit has no DAC override capability. Set `cs_public0_egress_input_group` to
the existing sensor read group when EVE is owned by a separate sensor account
(default: `root`); the collector never changes source permissions or group
membership. Installation opens EVE after dropping capabilities with `setpriv`
and using the declared primary/supplementary groups. This checks DAC readability;
actual canary readback must still verify the complete service sandbox and LSM.
Clock reversal records one gap and rebases retention ages; source timestamps are
never rewritten. The known pre-correction source-clock ceiling permits draining
old-clock rows with an explicit clock-skew limitation, without treating their
timestamps as new-clock observations. A previously qualified pending event can
expire as unknown even while its original source time is ahead of the new clock.
Collection resumes without waiting for that old wall-clock value to catch up.
Python 3.10 or later is required by the installer.
Installer artifact and preflight payloads use base64 stdin, so older Ansible
cannot coerce JSON-looking strings into Python dict representations.

Installation requires root-owned directories and ancestors without group or
other write permission. Details use /var/lib/cs-public0-egress-log/events.jsonl,
whose dedicated parent is root-owned 0750 with the declared log-reader group.
This avoids relying on group-writable /var/log (for example 0775 root:syslog).
Owning only the leaf directory would not prevent a writer of its parent from
renaming/replacing that leaf. The installer never changes global log-directory
permissions or silently trusts the syslog group. More permissive parent/ACL
support requires a separate design.

Continuity is recomputed on every publication, including stale stats, missing
source and backlog. Malformed or oversized input makes source quality unknown
for 60 seconds. Bounded eviction of an unneeded flow cache is a processing outcome,
not evidence of losing an input record; a future unmatched alert remains unknown.

## Explicit isolated LAB entry point

`tests/test_egress_collector.py --lab` is separate from unittest discovery. Run it
only in an already-created systemd private network namespace with its own
`RuntimeDirectory=cs-public0-egress-lab-<unique-id>`, an exact engine SHA256 and
the parent host network namespace ID. It verifies that PID 1 remains in that
parent namespace and that the test has only loopback before assigning owned
documentation addresses. The corpus is two TCP connections to an owned receiver:
an outbound marker and a reply on an inbound connection, plus a controlled IOC.

The separate LAB engine uses one alert-only signature and no NFQUEUE selector.
The test retains its own EVE, backend digest, collector metrics, engine log and
resource observations. Its process RSS includes the test harness; it is not a
production collector peak or IPS cost. It does not qualify NAT, public0 forwarding,
node_exporter, Prometheus or Grafana. Those require their actual canary readbacks.

## Dashboard and notification contract

Extend the existing dashboard in place, preserving UID, folder, old panels and
public0/VM/all selectors. Egress panels must state public0/IPv4 scope, show unknown
direction and collection/inspection limitations, and hide unsupported VM coverage.
Use Prometheus for bounded aggregates. Use independent detail logs for top public
sources, top suspicious destinations, reasons, attribution and links to evidence.
An alert count is not total egress volume, bytes or flow population.

Detection notifications and collection-unavailable notifications are separate.
Use bounded grouping/suppression keys and measured thresholds; signature severity
is not an incident verdict. Do not synthesize attacks or stop real sensors to
exercise notification delivery. Record local tests, LAB, canary and live readback
as separate acceptance results.

## References

- [Suricata 8.0.7 EVE format](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html)
- [Suricata 8.0.7 EVE configuration](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-output.html)
- [Availability and inspection limits](../README.md#availability-and-inspection-limits)
