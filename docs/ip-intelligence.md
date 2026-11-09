# IP intelligence on public0

This independent IPv4 policy complements qualified Suricata exploit signatures.
It does not restart Suricata, alter NFQUEUE, acknowledge inspection history, or
replace the existing exploit ruleset. Its owned `bridge cs_public0_ioc` table
matches both input and output bridge names `public0`, at priority `-250`.
Other bridges and host-local traffic are outside this scope.

| Source | Installed policy |
| --- | --- |
| IPInsights | Detection only, low severity; never an input to automatic DROP |
| IPsum level 3 | Drop only an initial inbound TCP SYN from a listed source to an explicitly protected network |
| Spamhaus DROP | The same initial inbound TCP SYN policy; includes the former EDROP dataset |
| Feodo recommended | Detection only; VM egress is never blocked by IP reputation |
| ThreatFox | Detection only; retain source receipts and indicator context |
| FireHOL level 1 | Detection context; not a broad automatic DROP policy |
| OTX subscribed pulses | Optional detection context with a separately configured API key |

Aggregated list counts are not independent proofs of maliciousness. Reputation
can produce false positives. The configured owned networks are excluded, as are
IPv6 and special-use IPv4 ranges. A prefix overlapping an owned network is
excluded as a whole. ThreatFox indicators below confidence 75 and IP indicators
last seen more than seven days ago are rejected. Its domains are retained as
context; the IP observer does not claim DNS or TLS coverage from them.

## Direction contract after INC-2026-11-09

The withdrawn v3 updater matched source or destination addresses without proving
who initiated the connection. IPInsights contained public resolver addresses,
including `1.1.1.1` and `8.8.8.8`, so source-only blocking also dropped legitimate
replies. Keep that deployment withdrawn. The immutable v4 bundle implements
`ingress-syn-only-v2`: `ip daddr @protected ip saddr @incoming tcp flags &
(fin | syn | rst | ack) == syn`. Both bridge names must still be `public0`.

Only Spamhaus and IPsum contribute to `incoming`. `outgoing` and `c2_ports`
remain empty and have no DROP expressions. TCP SYN/ACK, ACK/data and RST,
UDP, ICMP, traffic to unprotected destinations, and VM-initiated traffic pass
this reputation layer. A missing conntrack entry is not evidence of initiation:
the policy requires the initial SYN in the current packet. UDP/ICMP initiator
tracking and broad source blocking are intentionally outside this contract.
No conntrack module or Suricata restart is introduced by this change.

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
Retrieval receipts and cache are persisted before policy construction, and the
apply intent is persisted before kernel operations. A killed process therefore
cannot erase the provider retry interval or claim a completed deployment. The
updater has a 3 GiB cgroup limit, sized for the full fresh-download/apply cycle,
including child processes; the smaller isolated subset alone is not sizing proof.

The first apply requires fresh IPInsights, IPsum, Spamhaus and ThreatFox data.
Later retrieval errors retain each last good source only until its expiry;
expired sources are excluded from the next candidate. The kernel elements
also have timeouts, at most an hour and bounded by the contributing sources'
remaining validity. Thus a stopped updater cannot leave permanent IP bans.
The eight existing exploit DROP rules have their independent lifecycle.

An update is one native nft transaction. It flushes only the four owned sets,
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
`cs-public0-egress-ioc-v3` file for the independently upgraded EVE observer.
It contains per-source packed IPv4 intervals (zlib/base64, no address expansion),
upstream SHA256, retrieval/expiry times and the source's detect/inbound policy.
The observer bounds the file at 4 MiB and all sources together at one million
intervals, validates decompression size, ordering, overlap and trailing data,
and uses binary search. Upgrade the observer to its immutable v3 bundle before
publishing the new format. Preserve its database, cursor and log history.
An IPInsights-only match is low-severity scan context with `enforcement=none`.
A reputation match is an observation, not proof of compromise. The generated
snapshot time is distinct from each upstream feed's publication time in the
updater state. The snapshot contains no secret or tenant identifier.

If EVE only emits alert/flow/stats, domains in ThreatFox/OTX do not establish
domain detection. DNS logging, TLS metadata and DNS RPZ/sinkholing require a
separate accepted deployment. Full IPv6 and physical capacity/latency testing
also remain separate; passing the private fixture does not close G6.

## Acceptance

Run parser and expiry tests, then a private network fixture with real bridge
forwarding, initial inbound SYN DROP, legitimate outgoing/reply packets, list replacement, failed
transactions and kernel expiry without an updater. Exercise the full current
IPInsights size in that private namespace before a production canary. Verify
the production sensor identity and existing rule hash before and after each
host installation. Install one explicit target at a time through
`ansible/ip-intelligence.yml` with exact configuration bytes and source hashes.
Use `--preview` only to retrieve/validate data without nft operations.

## CISA coverage is not the number of DROP rules

CISA KEV is a catalog of exploited CVEs, not a Suricata rule feed. A CVE may
have no applicable signature or several SIDs. The retained 2026-11-06 catalog
contained 1,769 CVEs. The installed replay corpus tested only eight synthetic
attack cases and ten benign cases; it does not prove full-CVE exploitation or
full KEV coverage. The latest qualification produced nine SID results: four
passed and five also matched benign traffic (`BENIGN_MATCH`), so the latter
were not promoted. Four existing baseline SIDs plus those four admitted SIDs
give eight active DROP rules on each of sda-sde. Remaining signatures keep
their existing ALERT action.

Promotion also requires KEV membership, EPSS >= 0.1, matching engine/rules/corpus
identities and complete loss-free replay accounting. The configured batch
limit is four new SIDs per controller decision. Increasing that limit cannot
replace missing positive/benign packet fixtures. Physical acceptance G6 stays
open and is separate from these offline tests.
