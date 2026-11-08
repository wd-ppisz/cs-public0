# IP intelligence on public0

This independent IPv4 policy complements qualified Suricata exploit signatures.
It does not restart Suricata, alter NFQUEUE, acknowledge inspection history, or
replace the existing exploit ruleset. Its owned `bridge cs_public0_ioc` table
matches both input and output bridge names `public0`, at priority `-250`.
Other bridges and host-local traffic are outside this scope.

| Source | Installed policy |
| --- | --- |
| IPInsights | Drop inbound packets whose source IP is listed |
| IPsum level 3 | Drop inbound sources present on at least three source lists |
| Spamhaus DROP | Drop listed networks in both directions; includes the former EDROP dataset |
| Feodo recommended | Drop outbound destinations, only while the source publication remains fresh |
| ThreatFox | Drop outbound `IP:port` pairs for `botnet_cc`, confidence at least 90; preserve the port |
| FireHOL level 1 | Detection context; not a broad automatic DROP policy |
| OTX subscribed pulses | Optional detection context with a separately configured API key |

Aggregated list counts are not independent proofs of maliciousness. Reputation
can produce false positives. The configured owned networks are excluded, as are
IPv6 and special-use IPv4 ranges. A prefix overlapping an owned network is
excluded as a whole. ThreatFox indicators below confidence 75 and IP indicators
last seen more than seven days ago are rejected. Its domains are retained as
context; the IP observer does not claim DNS or TLS coverage from them.

## Retrieval and expiry

Use the canonical HTTPS endpoints in the program. Redirects, environment
proxies, executable provider rules, malformed rows, excessive downloads and
overbroad public prefixes are refused. GitHub lists are fetched by an immutable
commit after verifying the publication time. HTTP completion time, publication
time, content hash, indicator count and result are recorded independently.
API keys are supplied through systemd credentials, never command-line arguments
or source files. Use the existing abuse.ch key for ThreatFox.

The scheduler runs every five minutes but respects provider intervals: Feodo
five minutes, the other providers at least one hour. Failed attempts also count
towards that interval. Spamhaus explicitly requires at least an hour between
automated downloads. A source growing by more than 50 percent, above a small
initial threshold, requires investigation; its last good snapshot is retained.

The first apply requires fresh IPInsights, IPsum, Spamhaus and ThreatFox data.
Later retrieval errors retain each last good source only until its expiry;
expired sources are excluded from the next candidate. The kernel elements
also have timeouts, at most an hour and bounded by the contributing sources'
remaining validity. Thus a stopped updater cannot leave permanent IP bans.
The eight existing exploit DROP rules have their independent lifecycle.

An update is one native nft transaction. It flushes only the three owned sets,
repopulates them and preserves the chains and named counters. Check syntax
before apply, then verify table ownership, exact rule expressions, set types,
expiry policy and the actual kernel members. An unknown outcome is retried by
an idempotent set replacement, without restarting a packet sensor.

## Observation and monitoring

`policy_inventory.py` publishes exact SID/revision/message/CVE rows from the
managed ruleset only when its bytes agree with release and controller state.
Sensor activity and inventory freshness are separate checks. Existing KEV/EPSS
receipts expose decision time; older receipts did not record HTTP completion,
so that historical timestamp is explicitly unknown rather than inferred from
filesystem mtime.

The IP updater records feed download/freshness/counts, the last successful
kernel transaction and named DROP counters. It can also publish a bounded
`cs-public0-egress-ioc-v2` file for the existing EVE observer: individual IPv4
addresses and prefixes are matched without expanding ranges. IPInsights is
not reclassified as a C2 source. A prefix match is an observation, not proof of
compromise. The generated snapshot time is distinct from each upstream feed's
publication time in the updater state.

If EVE only emits alert/flow/stats, domains in ThreatFox/OTX do not establish
domain detection. DNS logging, TLS metadata and DNS RPZ/sinkholing require a
separate accepted deployment. Full IPv6 and physical capacity/latency testing
also remain separate; passing the private fixture does not close G6.

## Acceptance

Run parser and expiry tests, then a private network fixture with real bridge
forwarding, positive/negative packets, per-port C2, list replacement, failed
transactions and kernel expiry without an updater. Exercise the full current
IPInsights size in that private namespace before a production canary. Verify
the production sensor identity and existing rule hash before and after each
host installation. Install one explicit target at a time through
`ansible/ip-intelligence.yml` with exact configuration bytes and source hashes.
Use `--preview` only to retrieve/validate data without nft operations.
