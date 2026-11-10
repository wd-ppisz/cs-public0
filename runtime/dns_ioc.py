"""Passive DNS IOC observations. No sockets, DNS queries or network verdicts.

The catalog is derived from the accepted IP updater's private state, whose
ThreatFox parser admits confidence >= 75 and at most seven-day-old indicators.
An exact queried-name match is an observation, never proof of guest compromise.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import argparse
import json
import os
from pathlib import Path
import sqlite3
import time

from egress_model import SHA, integer, ipv4, networks, owned, text, timestamp

DOMAIN = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
EPOCH = re.compile(r'[0-9a-f]{32}\Z')
MAX_DOMAINS = 100000
MAX_QUESTIONS = 16


def domain_name(value):
    if not isinstance(value, str) or not value.isascii() or len(value) > 254:
        raise ValueError('ASCII DNS presentation name required')
    result = value.lower().removesuffix('.')
    labels = result.split('.')
    if len(result) > 253 or len(labels) < 2 or not all(DOMAIN.fullmatch(x) for x in labels):
        raise ValueError('canonical complete DNS name required')
    try:
        ipaddress.ip_address(result)
    except ValueError:
        return result
    raise ValueError('address is not a domain IOC')


class DomainCatalog:
    """Small sanitized catalog; no provider code, URL indicators or suffix rules."""
    def __init__(self, value):
        if not isinstance(value, dict) or set(value) != {'schema', 'source', 'domains',
                'sha256', 'fetched_unix', 'published_unix', 'expires_unix'}:
            raise ValueError('domain catalog fields')
        if value['schema'] != 'cs-public0-domain-catalog-v1' or value['source'] != 'threatfox':
            raise ValueError('supported domain catalog source')
        if not isinstance(value['sha256'], str) or not SHA.fullmatch(value['sha256']):
            raise ValueError('domain source SHA256')
        fetched = integer(value['fetched_unix'])
        published = integer(value['published_unix'])
        expires = integer(value['expires_unix'])
        if not published <= fetched < expires <= published + 86400:
            raise ValueError('domain freshness interval')
        rows = value['domains']
        if not isinstance(rows, list) or len(rows) > MAX_DOMAINS:
            raise ValueError('domain catalog count')
        if any(domain_name(x) != x for x in rows) or rows != sorted(set(rows)):
            raise ValueError('canonical unique sorted domains required')
        self.names = frozenset(rows)
        self.receipt = {k: value[k] for k in ('source', 'sha256', 'fetched_unix',
                                               'published_unix', 'expires_unix')}

    @classmethod
    def from_updater_state(cls, state):
        feed = state['feeds']['threatfox']
        return cls({'schema': 'cs-public0-domain-catalog-v1', 'source': 'threatfox',
                    **{k: feed[k] for k in ('domains', 'sha256', 'fetched_unix',
                                             'published_unix', 'expires_unix')}})

    def fresh(self, now):
        return self.receipt['fetched_unix'] <= now < self.receipt['expires_unix']

    def match(self, name, now):
        return self.fresh(now) and domain_name(name) in self.names


def observe_dns(row, config, catalog, source_ref, now):
    """Match Suricata 8 DNS-v3 requests; replies cannot become guest egress.

    Source/destination orientation comes from the DNS request schema, including
    UDP. It is not inferred from packet direction or a DNS response's resolver.
    """
    if row.get('event_type') != 'dns':
        return []
    dns = row.get('dns')
    if not isinstance(dns, dict) or type(dns.get('version')) is not int or dns['version'] != 3:
        raise ValueError('explicit DNS EVE v3 required')
    if dns.get('type') == 'response':
        return []
    if (dns.get('type') != 'request' or dns.get('qr', False) is not False
            or type(dns.get('opcode')) is not int or dns['opcode'] != 0):
        raise ValueError('ordinary DNS request required')
    if dns.get('rrname_truncated', False) is not False:
        raise ValueError('truncated DNS name')
    questions = dns.get('queries')
    if not isinstance(questions, list) or not 1 <= len(questions) <= MAX_QUESTIONS:
        raise ValueError('DNS question bound')
    names = set()
    for question in questions:
        if not isinstance(question, dict) or question.get('rrname_truncated', False) is not False:
            raise ValueError('DNS question')
        presented, rrtype = text(question['rrname'], 254), text(question['rrtype'], 16)
        if not re.fullmatch(r'[A-Z0-9]+', rrtype):
            raise ValueError('DNS record type')
        try:name = domain_name(presented)
        except ValueError:
            # Legal DNS names such as _dmarc, SRV labels or a single local label
            # are outside the provider's domain IOC format, not capture loss.
            continue
        names.add((name, rrtype))
    epoch = row.get('host')
    if not isinstance(epoch, str) or not EPOCH.fullmatch(epoch):
        raise ValueError('producer invocation identity required')
    sensor = text(config['sensor_id'], 64)
    nets = networks(config['owned_ipv4_networks'])
    src, dst = ipv4(row['src_ip']), ipv4(row['dest_ip'])
    sport, dport = integer(row['src_port'], 1, 65535), integer(row['dest_port'], 1, 65535)
    if row.get('proto') not in {'UDP', 'TCP'} or dport != 53:
        raise ValueError('plain DNS capture contract')
    observed = timestamp(row['timestamp'])
    if not -5 <= now - observed <= 3600:
        raise ValueError('DNS observation age')
    if set(source_ref) != {'device', 'inode', 'offset', 'length', 'record_sha256'}:
        raise ValueError('exact original reference required')
    for key in ('device', 'inode', 'offset', 'length'):
        integer(source_ref[key], 1 if key == 'length' else 0)
    if not SHA.fullmatch(source_ref['record_sha256']):
        raise ValueError('original record SHA256')
    src_owned, dst_owned = owned(src, nets), owned(dst, nets)
    direction = ('egress' if src_owned else 'ingress') if src_owned != dst_owned else 'unknown'
    local = sorted({x for x in (src, dst) if owned(x, nets)})
    result = []
    for name, rrtype in sorted(names):
        if catalog is None or not catalog.match(name, now):
            continue
        identity = '\0'.join(('dns-v1', sensor, epoch, source_ref['record_sha256'], name, rrtype))
        result.append({'schema': 'cs-public0-dns-observation-v1',
            'event_id': hashlib.sha256(identity.encode()).hexdigest(),
            'sensor_id': sensor, 'sensor_epoch': epoch,
            'observed_unix': observed, 'received_unix': now,
            'flow_id': integer(row['flow_id']), 'dns_tx_id': integer(dns['tx_id']),
            'dns_id': integer(dns['id'], 0, 65535),
            'observation_point': 'public0_passive_plain_dns_ipv4',
            'direction': direction, 'direction_basis': 'DNS_V3_REQUEST_CLIENT_TUPLE',
            'client_ip': src, 'client_port': sport, 'resolver_ip': dst,
            'resolver_port': dport, 'proto': row['proto'], 'queried_name': name,
            'rrtype': rrtype, 'category': 'ioc', 'severity': 'medium',
            'evidence_kind': 'dns_ioc_query', 'enforcement': 'none',
            'ioc': {**catalog.receipt, 'minimum_confidence': 75, 'match': 'exact',
                    'matched_unix': now, 'maximum_indicator_age_days_at_fetch': 7},
            'attribution': {'level': 'public_ip' if local else 'unknown', 'public_ips': local},
            'source_ref': dict(source_ref),
            'limitations': ['IOC_CONTACT_IS_NOT_PROOF_OF_COMPROMISE',
                'PUBLIC_IP_MAY_REPRESENT_MULTIPLE_GUESTS', 'ENCRYPTED_DNS_NOT_VISIBLE',
                'IOC_CURRENT_AT_ADMISSION_NOT_HISTORICAL_ATTESTATION',
                'PASSIVE_CAPTURE_COMPLETENESS_REQUIRES_SEPARATE_HEALTH_EVIDENCE']})
    return result


def load_catalog(config, state_dir):
    """Reparse the large updater state only after its atomic inode changes."""
    from egress_collector import atomic, plain_file
    with plain_file(config['updater_module_file'], 128 * 1024) as f:
        if hashlib.sha256(f.read()).hexdigest() != config['updater_module_sha256']:
            raise ValueError('updater parser policy changed')
    with plain_file(config['updater_state_file'], 64 * 1024 * 1024) as f:
        st = os.fstat(f.fileno())
        identity = [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]
        cache_path = state_dir / 'domain-catalog.json'
        try:
            with plain_file(cache_path, 4 * 1024 * 1024) as cached:
                cache = json.load(cached)
            if cache['identity'] == identity and cache['policy'] == config['updater_module_sha256']:
                return DomainCatalog(cache['catalog'])
        except (OSError, ValueError, KeyError, TypeError):
            pass
        state = json.load(f)
    catalog = DomainCatalog.from_updater_state(state)
    value = {'schema': 'cs-public0-domain-catalog-v1', 'domains': sorted(catalog.names), **catalog.receipt}
    raw = (json.dumps({'identity': identity, 'policy': config['updater_module_sha256'],
                       'catalog': value}, sort_keys=True) + '\n').encode()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError('domain cache size')
    atomic(cache_path, raw)
    return catalog


def publish_metrics(store, path, now, success, available, catalog):
    from egress_collector import atomic
    counts = dict(store.db.execute('SELECT key,value FROM counts'))
    values = {'collector_up': int(success), 'source_available': int(available),
        'source_fresh': int(success and available and store.get('backlog_bytes', 1) == 0
            and -5 <= now - store.get('last_stats', 0) <= 30
            and now - store.get('last_invalid', -1e30) >= 60),
        'ioc_fresh': int(catalog is not None and catalog.fresh(now)),
        'ioc_domains': len(catalog.names) if catalog else 0,
        'ioc_expires_unix_seconds': catalog.receipt['expires_unix'] if catalog else 0,
        'last_publish_unix_seconds': now, 'last_stats_unix_seconds': store.get('last_stats', 0),
        'backlog_bytes': store.get('backlog_bytes', 0),
        'last_gap_unix_seconds': store.get('last_gap', 0),
        'collection_continuity_known': int(success and available
            and store.get('backlog_bytes', 1) == 0
            and -5 <= now - store.get('last_stats', 0) <= 30
            and now - store.get('last_gap', now) >= 60
            and now - store.get('last_invalid', -1e30) >= 60),
        'capture_loss_known': int(store.get('capture_loss_known', False)
            and -5 <= now - store.get('last_stats', 0) <= 30
            and now - store.get('last_invalid', -1e30) >= 60),
        'capture_drops_seen_total': counts.get('dns:capture_drops', 0)}
    lines = ['cs_public0_dns_%s %s' % (k, v) for k, v in values.items()]
    for outcome in ('request', 'response', 'stats', 'ignored', 'invalid', 'oversize', 'partial', 'backpressure', 'duplicate'):
        lines.append('cs_public0_dns_records_total{outcome="%s"} %d' % (outcome, counts.get('dns:' + outcome, 0)))
    for direction in ('egress', 'ingress', 'unknown'):
        lines.append('cs_public0_dns_ioc_observations_total{source="threatfox",direction="%s"} %d' %
                     (direction, counts.get('dns:matched:' + direction, 0)))
    from egress_collector import GAPS
    for reason in GAPS:
        lines.append('cs_public0_dns_collection_gaps_total{reason="%s"} %d' %
                     (reason, counts.get('gap:' + reason, 0)))
    atomic(path, ('\n'.join(lines) + '\n').encode())


def consume(store, row, config, catalog, ref, now):
    from egress_collector import MAX_JOIN, MAX_SEEN, MAX_TABLE_BYTES, canonical
    kind = row.get('event_type')
    if kind == 'stats':
        epoch = row.get('host')
        if not isinstance(epoch, str) or not EPOCH.fullmatch(epoch):
            raise ValueError('stats producer identity')
        observed = timestamp(row['timestamp'])
        if not -5 <= now - observed <= 30:
            raise ValueError('stale producer stats')
        previous_epoch = store.get('stats_epoch')
        if previous_epoch is not None and previous_epoch != epoch:
            store.gap('sensor_epoch', now)
        capture = row.get('stats', {}).get('capture', {})
        drops = capture.get('kernel_drops')
        known = type(drops) is int and drops >= 0
        if known:
            previous = store.get('capture_drops', 0) if previous_epoch == epoch else 0
            if drops < previous:
                raise ValueError('producer capture counter reversal')
            store.count('dns:capture_drops', drops - previous)
            store.put('capture_drops', drops)
        store.put('stats_epoch', epoch)
        store.put('capture_loss_known', known)
        store.put('last_stats', observed)
        store.count('dns:stats')
        return
    if kind != 'dns':
        store.count('dns:ignored')
        return
    observations = observe_dns(row, config, catalog, ref, now)
    store.count('dns:response' if row['dns']['type'] == 'response' else 'dns:request')
    for item in observations:
        identifier = item['event_id']
        if store.db.execute('SELECT 1 FROM seen WHERE id=?', (identifier,)).fetchone():
            store.count('dns:duplicate')
            continue
        body = canonical(item)
        if store.size('outbox') >= MAX_JOIN or store.storage('outbox') + len(body.encode()) + 1024 > MAX_TABLE_BYTES:
            raise OverflowError('bounded DNS outbox')
        excess = store.size('seen') - MAX_SEEN + 1
        if excess > 0:
            store.db.execute('DELETE FROM seen WHERE id IN (SELECT id FROM seen ORDER BY accepted,rowid LIMIT ?)', (excess,))
        store.db.execute('INSERT INTO seen VALUES (?,?)', (identifier, now))
        store.db.execute('INSERT INTO outbox VALUES (?,?)', (identifier, body))
        store.count('dns:matched:' + item['direction'])


def run(config, now=None):
    """Bounded, journaled reader; this process has no capture or control access."""
    import fcntl
    from egress_collector import (Store, deliver, digest, fingerprint, plain_file,
                                 source_cursor, MAX_BYTES, MAX_ROWS)
    from egress_model import strict_json, MAX_RECORD
    expected = {'schema', 'sensor_id', 'owned_ipv4_networks', 'state_directory', 'eve_file',
        'metrics_file', 'details_file', 'updater_state_file', 'updater_module_file',
        'updater_module_sha256', 'initial_position'}
    if not isinstance(config, dict) or set(config) != expected or config['schema'] != 'cs-public0-dns-config-v1':
        raise ValueError('DNS configuration fields')
    text(config['sensor_id'], 64); networks(config['owned_ipv4_networks'])
    if config['initial_position'] not in {'begin', 'end'} or not SHA.fullmatch(config['updater_module_sha256']):
        raise ValueError('DNS source configuration')
    state_dir = Path(config['state_directory'])
    if not state_dir.is_dir() or state_dir.is_symlink():
        raise ValueError('installed DNS state directory required')
    now = time.time() if now is None else now
    lock = os.open(state_dir / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    store = None
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = Store(state_dir / 'state.sqlite3')
        success = available = False
        catalog = None
        try:
            catalog = load_catalog(config, state_dir)
            deliver(store, config['details_file'], time.monotonic() + 1)
            if not catalog.fresh(now):
                raise ValueError('domain catalog not current')
            started = time.monotonic()
            with store.db:
                store.db.execute('DELETE FROM seen WHERE accepted<?', (now - 86400,))
                with plain_file(config['eve_file']) as f:
                    info = os.fstat(f.fileno());available = True
                    cursor = source_cursor(store, f, info, config, now)
                    f.seek(cursor['offset']);consumed = 0
                    for _ in range(MAX_ROWS):
                        if consumed >= MAX_BYTES or time.monotonic() - started >= 3:
                            break
                        offset = f.tell();raw = f.readline(min(MAX_RECORD + 1, MAX_BYTES - consumed))
                        if not raw:break
                        consumed += len(raw)
                        if cursor['discarding']:
                            cursor['discarding'] = not raw.endswith(b'\n')
                        elif len(raw) > MAX_RECORD:
                            cursor['discarding'] = not raw.endswith(b'\n');store.count('dns:oversize')
                            store.put('last_invalid', now)
                        elif not raw.endswith(b'\n'):
                            f.seek(offset);store.count('dns:partial');break
                        else:
                            ref = {'device': info.st_dev, 'inode': info.st_ino, 'offset': offset,
                                   'length': len(raw), 'record_sha256': digest(raw)}
                            store.db.execute('SAVEPOINT dns_record')
                            try:
                                consume(store, strict_json(raw), config, catalog, ref, now)
                            except (ValueError, KeyError, TypeError, RecursionError, OverflowError) as error:
                                store.db.execute('ROLLBACK TO dns_record')
                                if isinstance(error, OverflowError):
                                    f.seek(offset);store.count('dns:backpressure');break
                                store.count('dns:invalid')
                                store.put('last_invalid', now)
                            finally:
                                if store.db.in_transaction:store.db.execute('RELEASE dns_record')
                        cursor['offset'] = f.tell()
                    cursor['offset'] = f.tell();cursor['fingerprint'] = fingerprint(f, cursor['offset'])
                    store.put('cursor', cursor)
                    store.put('backlog_bytes', max(0, os.fstat(f.fileno()).st_size - cursor['offset']))
            deliver(store, config['details_file'], time.monotonic() + 1)
            success = True
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, OverflowError):
            store.db.rollback()
        publish_metrics(store, config['metrics_file'], now, success, available, catalog)
        return {'success': success, 'sensor_action': 'NONE', 'enforcement': 'none'}
    finally:
        if store is not None:store.db.close()
        os.close(lock)


def main():
    from egress_collector import plain_file
    from egress_model import strict_json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    with plain_file(args.config, 65536) as f:raw = f.read()
    if not SHA.fullmatch(args.config_sha256) or hashlib.sha256(raw).hexdigest() != args.config_sha256:
        raise ValueError('installed DNS configuration changed')
    result = run(strict_json(raw));print(json.dumps(result))
    return 0 if result['success'] else 1


if __name__ == '__main__':raise SystemExit(main())
