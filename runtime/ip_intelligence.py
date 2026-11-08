#!/usr/bin/env python3
"""Bounded IP intelligence ingestion and an independent IPv4/public0 nft policy.

Feed data is parsed as data. No provider rule or script is executed. Exploit
signatures, their journal, NFQUEUE and the Suricata process remain separately owned.
"""
import argparse
import concurrent.futures
import datetime as dt
import email.utils
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request

MAX_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 1000000
TABLE = 'cs_public0_ioc'
OWNER = 'cs-public0-ip-intelligence-v1'
SPECIAL = tuple(ipaddress.ip_network(x) for x in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'))
SOURCES = {
    'ipinsights': {'url': 'https://www.ipinsights.io/downloads/blocklist.txt', 'format': 'addresses', 'mode': 'inbound_drop', 'interval': 3600, 'age': 86400},
    'feodo': {'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', 'format': 'addresses', 'mode': 'outbound_drop', 'interval': 300, 'age': 86400},
    'ipsum3': {'url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', 'format': 'addresses', 'mode': 'inbound_drop', 'interval': 3600, 'age': 172800,
               'github': ('stamparm/ipsum', 'levels/3.txt')},
    'firehol1': {'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'format': 'networks', 'mode': 'detect', 'interval': 3600, 'age': 172800,
                 'github': ('firehol/blocklist-ipsets', 'firehol_level1.netset')},
    'spamhaus': {'url': 'https://www.spamhaus.org/drop/drop_v4.json', 'format': 'spamhaus', 'mode': 'both_drop', 'interval': 3600, 'age': 172800},
    'threatfox': {'url': 'https://threatfox-api.abuse.ch/api/v1/', 'format': 'threatfox', 'mode': 'c2_port_drop', 'interval': 3600, 'age': 86400},
    'otx': {'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50', 'format': 'otx', 'mode': 'detect', 'interval': 3600, 'age': 86400},
}


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def atomic(path, raw, mode=0o600):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('feed redirect refused')


def retrieve(url, *, key=None, data=None, limit=MAX_BYTES):
    allowed = {urllib.parse.urlsplit(s['url']).hostname for s in SOURCES.values()} | {'api.github.com'}
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == 'https' and parts.hostname in allowed and not parts.username
            and not parts.password and parts.port is None and not parts.fragment, 'source not allowed')
    headers = {'User-Agent': 'cs-public0-ip-intelligence/1', 'Accept-Encoding': 'identity'}
    if key:
        require(parts.hostname in {'threatfox-api.abuse.ch', 'otx.alienvault.com'}, 'credential destination refused')
        headers['Auth-Key' if parts.hostname == 'threatfox-api.abuse.ch' else 'X-OTX-API-KEY'] = key
    if data is not None:
        headers['Content-Type'] = 'application/json'
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with client.open(urllib.request.Request(url, headers=headers, data=data), timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, 'unexpected feed response')
        require(response.headers.get('Content-Encoding', 'identity') == 'identity', 'compressed transfer refused')
        raw = response.read(limit + 1)
        require(0 < len(raw) <= limit, 'feed response exceeds byte bound')
        modified = response.headers.get('Last-Modified')
        published = int(email.utils.parsedate_to_datetime(modified).timestamp()) if modified else None
    return raw, published


def network(value, *, prefixes=False):
    require(isinstance(value, str) and len(value) <= 43, 'invalid address field')
    net = ipaddress.ip_network(value, strict=True)
    require(net.version == 4 and (prefixes or net.prefixlen == 32), 'IPv4 host required')
    require(net.prefixlen >= 8, 'overbroad prefix refused')
    # is_global on a network alone is insufficient for a prefix crossing special-use space.
    require(net.network_address.is_global and net.broadcast_address.is_global
            and not any(net.overlaps(special) for special in SPECIAL), 'nonpublic network')
    return str(net)


def domain(value):
    require(isinstance(value, str), 'domain is not text')
    result = value.rstrip('.').lower().encode('idna').decode('ascii')
    require(1 < len(result) <= 253 and '.' in result and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
            for x in result.split('.')), 'invalid domain')
    return result


def parse(name, raw, now):
    spec = SOURCES[name]
    addresses, domains, endpoints = set(), set(), set()
    rejected = 0
    if spec['format'] in {'addresses', 'networks', 'spamhaus'}:
        for line in raw.decode('utf-8-sig').splitlines():
            text = line.strip()
            if not text or text[0] in '#;':
                continue
            if spec['format'] == 'spamhaus':
                row = json.loads(text)
                if 'cidr' not in row:
                    continue
                text = row['cidr']
            else:
                require(len(text.split()) == 1, 'extra fields in IP list')
            try:
                addresses.add(network(text, prefixes=spec['format'] != 'addresses'))
            except ValueError:
                # Invalid syntax rejects the complete feed; special-use addresses are deliberately filtered.
                try:
                    candidate = ipaddress.ip_network(text, strict=True)
                except ValueError:
                    raise ValueError('malformed IP list') from None
                if candidate.version == 6:
                    rejected += 1
                    continue  # A valid IPv6 record is outside this explicitly IPv4-only profile.
                require(spec['format'] != 'addresses' or candidate.prefixlen == 32,
                        'network prefix in host-only IP list')
                require(candidate.prefixlen >= 8 or any(candidate.subnet_of(special) for special in SPECIAL),
                        'overbroad public prefix refused')
                rejected += 1
    elif spec['format'] == 'threatfox':
        data = json.loads(raw)
        require(data.get('query_status') in {'ok', 'no_result'}, 'ThreatFox query failed')
        rows = data.get('data', []) if data.get('query_status') == 'ok' else []
        require(isinstance(rows, list) and len(rows) <= 100000, 'ThreatFox response bound')
        for row in rows:
            confidence = row.get('confidence_level')
            if type(confidence) is not int or confidence < 75:
                continue
            try:
                stamp = row.get('last_seen') or row['first_seen']
                seen = int(dt.datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S UTC').replace(tzinfo=dt.timezone.utc).timestamp())
                require(0 <= now - seen <= 7 * 86400, 'stale IOC')
                if row['ioc_type'] == 'domain':
                    domains.add(domain(row['ioc']))
                elif row['ioc_type'] == 'ip:port':
                    host, port = row['ioc'].rsplit(':', 1)
                    addr = network(host)
                    require(port.isascii() and port.isdigit() and 1 <= int(port) <= 65535, 'invalid IOC port')
                    addresses.add(addr)
                    if confidence >= 90 and row.get('threat_type') == 'botnet_cc':
                        endpoints.add((addr, int(port)))
            except (ValueError, KeyError, TypeError):
                rejected += 1
    elif spec['format'] == 'otx':
        data = json.loads(raw)
        require(isinstance(data.get('results'), list) and len(data['results']) <= 50, 'OTX response bound')
        # A partial pulse page is detection context only; never an allowlist or exhaustive inventory.
        for pulse in data['results']:
            for row in pulse.get('indicators', [])[:100000]:
                try:
                    if row.get('type') == 'IPv4':
                        addresses.add(network(row['indicator']))
                    elif row.get('type') in {'domain', 'hostname'}:
                        domains.add(domain(row['indicator']))
                except (ValueError, KeyError):
                    rejected += 1
    require(len(addresses) <= MAX_ENTRIES and len(domains) <= 100000 and len(endpoints) <= 65536,
            'indicator count exceeds bound')
    require(bool(addresses or domains) or spec['format'] in {'threatfox', 'otx'}, 'empty IP feed refused')
    return {'addresses': sorted(addresses), 'domains': sorted(domains),
            'endpoints': sorted(endpoints), 'filtered': rejected}


def fetch_source(name, now, credentials):
    spec, url = SOURCES[name], SOURCES[name]['url']
    key, data, published = None, None, None
    if name in {'threatfox', 'otx'}:
        path = Path(credentials) / ('abuse-ch' if name == 'threatfox' else 'otx')
        require(path.is_file(), 'credential not configured')
        key = path.read_text().splitlines()[0].strip()
        require(re.fullmatch(r'[A-Za-z0-9._~+=/-]{16,512}', key) is not None, 'invalid credential')
        if name == 'threatfox':
            data = encoded({'query': 'get_iocs', 'days': 7})
    if spec.get('github'):
        repository, filename = spec['github']
        api = 'https://api.github.com/repos/' + repository + '/commits?' + urllib.parse.urlencode({'path': filename, 'per_page': 1})
        meta = json.loads(retrieve(api, limit=1024 * 1024)[0])
        require(isinstance(meta, list) and len(meta) == 1 and re.fullmatch('[a-f0-9]{40}', meta[0]['sha']), 'source commit unknown')
        published = int(dt.datetime.fromisoformat(meta[0]['commit']['committer']['date'].replace('Z', '+00:00')).timestamp())
        url = 'https://raw.githubusercontent.com/' + repository + '/' + meta[0]['sha'] + '/' + filename
    raw, modified = retrieve(url, key=key, data=data)
    completed = int(time.time())
    published = published if published is not None else modified
    if name == 'threatfox' or name == 'otx':
        published = now  # API snapshot time; individual ThreatFox IOCs additionally have a seven-day bound.
    require(published is not None and 0 <= completed - published <= spec['age'], 'source publication stale, unknown or from future')
    parsed = parse(name, raw, completed)
    return {**parsed, 'fetched_unix': completed, 'published_unix': published,
            'expires_unix': min(completed + spec['age'], published + spec['age']), 'sha256': sha(raw), 'url': url}


def protected_config(values):
    require(isinstance(values, list) and 1 <= len(values) <= 256, 'explicit owned networks required')
    result = []
    for value in values:
        net = ipaddress.ip_network(value, strict=True)
        require(net.version == 4 and net.prefixlen >= 8, 'invalid protected network')
        result.append(net)
    return result


def admitted(entries, protected):
    result = []
    for value in entries:
        net = ipaddress.ip_network(value)
        if not any(net.overlaps(own) for own in protected):
            result.append(net)
    return result


def policy(feeds, protected, now):
    result = {'incoming': [], 'outgoing': [], 'c2_ports': []}
    for name, data in feeds.items():
        if name not in SOURCES or not data['fetched_unix'] <= now < data['expires_unix'] - 60:
            continue
        mode = SOURCES[name]['mode']
        nets = admitted(data['addresses'], protected)
        if mode in {'inbound_drop', 'both_drop'}:
            result['incoming'].extend(nets)
        if mode in {'outbound_drop', 'both_drop'}:
            result['outgoing'].extend(nets)
        if mode == 'c2_port_drop':
            result['c2_ports'].extend((str(ipaddress.ip_network(addr).network_address), port)
                                      for addr, port in data['endpoints'] if admitted([addr], protected))
    for name in ('incoming', 'outgoing'):
        result[name] = [str(x) for x in ipaddress.collapse_addresses(result[name])]
    result['c2_ports'] = sorted(set(result['c2_ports']))
    return result


def nft_batch(candidate, *, create, ttl):
    require(type(ttl) is int and 60 <= ttl <= 86400, 'bounded kernel timeout required')
    for name in ('incoming', 'outgoing'):
        require(len(candidate[name]) <= MAX_ENTRIES, 'kernel element count exceeds bound')
        for text in candidate[name]:
            require(str(ipaddress.IPv4Network(text, strict=True)) == text, 'noncanonical kernel address')
    for address, port in candidate['c2_ports']:
        require(str(ipaddress.IPv4Address(address)) == address and type(port) is int and 1 <= port <= 65535,
                'invalid kernel endpoint')
    out = []
    if create:
        out += [f'table bridge {TABLE} {{ comment "{OWNER}"; }}',
                f'add set bridge {TABLE} incoming {{ type ipv4_addr; flags interval,timeout; timeout {ttl}s; auto-merge; }}',
                f'add set bridge {TABLE} outgoing {{ type ipv4_addr; flags interval,timeout; timeout {ttl}s; auto-merge; }}',
                f'add set bridge {TABLE} c2_ports {{ type ipv4_addr . inet_service; flags timeout; timeout {ttl}s; }}',
                f'add counter bridge {TABLE} incoming_dropped', f'add counter bridge {TABLE} outgoing_dropped',
                f'add counter bridge {TABLE} c2_dropped',
                f'add chain bridge {TABLE} public0_forward {{ type filter hook forward priority -250; policy accept; }}']
        prefix = f'add rule bridge {TABLE} public0_forward meta ibrname "public0" meta obrname "public0" ether type ip '
        out += [prefix + f'ip saddr @incoming counter name incoming_dropped drop comment "{OWNER}:incoming"',
                prefix + f'ip daddr @outgoing counter name outgoing_dropped drop comment "{OWNER}:outgoing"',
                prefix + f'meta l4proto {{ tcp, udp }} ip daddr . th dport @c2_ports counter name c2_dropped drop comment "{OWNER}:c2"']
    else:
        out += [f'flush set bridge {TABLE} {name}' for name in ('incoming', 'outgoing', 'c2_ports')]
    for name in ('incoming', 'outgoing'):
        values = candidate[name]
        # Batches remain one nft transaction; chunks bound the individual parser expression.
        for start in range(0, len(values), 2048):
            out.append(f'add element bridge {TABLE} {name} {{ ' + ', '.join(x + f' timeout {ttl}s' for x in values[start:start + 2048]) + ' }')
    for start in range(0, len(candidate['c2_ports']), 2048):
        values = [f'{addr} . {port} timeout {ttl}s' for addr, port in candidate['c2_ports'][start:start + 2048]]
        out.append(f'add element bridge {TABLE} c2_ports {{ ' + ', '.join(values) + ' }')
    return ('\n'.join(out) + '\n').encode()


def nft(*args, payload=None, check=True):
    result = subprocess.run(['nft', *args], input=payload, capture_output=True, timeout=90)
    if check:
        require(result.returncode == 0, 'nft operation failed: ' + result.stderr.decode(errors='replace')[:300])
    return result


def owned_table(*, terse=False):
    result = nft('-j', *(['--terse'] if terse else []), 'list', 'table', 'bridge', TABLE, check=False)
    if result.returncode:
        # Missing table is accepted only after a successful listing of all table names.
        tables = json.loads(nft('-j', 'list', 'tables').stdout)['nftables']
        require(not any(x.get('table', {}).get('family') == 'bridge' and x.get('table', {}).get('name') == TABLE
                        for x in tables), 'cannot read existing IOC table')
        return None
    require(len(result.stdout) <= 128 * 1024 * 1024, 'kernel readback exceeds bound')
    rows = json.loads(result.stdout)['nftables']
    table = [x['table'] for x in rows if 'table' in x]
    require(len(table) == 1 and table[0].get('comment') == OWNER, 'IOC table is not owned')
    require({x['set']['name'] for x in rows if 'set' in x} == {'incoming', 'outgoing', 'c2_ports'}, 'IOC sets changed')
    for row in (x['set'] for x in rows if 'set' in x):
        require(row['type'] == (['ipv4_addr', 'inet_service'] if row['name'] == 'c2_ports' else 'ipv4_addr')
                and set(row.get('flags', [])) == ({'timeout'} if row['name'] == 'c2_ports' else {'interval', 'timeout'})
                and 0 < row.get('timeout', 0) <= 3600, 'IOC set type or expiry changed')
    chains = [x['chain'] for x in rows if 'chain' in x]
    require(len(chains) == 1 and chains[0]['name'] == 'public0_forward' and chains[0]['hook'] == 'forward'
            and chains[0]['prio'] == -250 and chains[0]['policy'] == 'accept', 'IOC chain changed')
    rules = [x['rule'] for x in rows if 'rule' in x]
    require(len(rules) == 3 and [x.get('comment') for x in rules] == [OWNER + ':incoming', OWNER + ':outgoing', OWNER + ':c2'],
            'IOC rules changed')
    common = [{'match': {'op': '==', 'left': {'meta': {'key': name}}, 'right': 'public0'}}
              for name in ('ibrname', 'obrname')]
    expected = [common + [{'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': field}},
                                    'right': '@' + name}}, {'counter': name + '_dropped'}, {'drop': None}]
                for field, name in [('saddr', 'incoming'), ('daddr', 'outgoing')]]
    expected.append(common + [{'match': {'op': '==', 'left': {'meta': {'key': 'l4proto'}}, 'right': {'set': ['tcp', 'udp']}}},
                             {'match': {'op': '==', 'left': {'concat': [{'payload': {'protocol': 'ip', 'field': 'daddr'}},
                                                                     {'payload': {'protocol': 'th', 'field': 'dport'}}]},
                                        'right': '@c2_ports'}}, {'counter': 'c2_dropped'}, {'drop': None}])
    require([r['expr'] for r in rules] == expected, 'IOC rule expressions changed')
    require({x['counter']['name'] for x in rows if 'counter' in x} ==
            {'incoming_dropped', 'outgoing_dropped', 'c2_dropped'}, 'IOC counters changed')
    return rows


def intervals(values):
    result = []
    for start, finish in sorted(values):
        if result and start <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(finish, result[-1][1]))
        else:
            result.append((start, finish))
    return result


def network_interval(value):
    net = ipaddress.IPv4Network(value, strict=True)
    return int(net.network_address), int(net.broadcast_address)


def verify_members(rows, candidate):
    """Compare actual kernel members, including nft's automatic interval merging."""
    actual = {}
    for row in (x['set'] for x in rows if 'set' in x):
        values = []
        for elem in row.get('elem', []):
            val = elem['elem']['val'] if isinstance(elem, dict) and 'elem' in elem else elem
            if row['name'] == 'c2_ports':
                require(isinstance(val, dict) and isinstance(val.get('concat'), list) and len(val['concat']) == 2,
                        'unknown kernel endpoint representation')
                address, port = val['concat']
                values.append((str(ipaddress.IPv4Address(address)), port))
            elif isinstance(val, str):
                values.append(network_interval(val))
            elif isinstance(val, dict) and 'prefix' in val:
                values.append(network_interval(val['prefix']['addr'] + '/' + str(val['prefix']['len'])))
            elif isinstance(val, dict) and 'range' in val:
                start, finish = val['range']
                values.append((int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(finish))))
            else:
                raise ValueError('unknown kernel interval representation')
        actual[row['name']] = sorted(values) if row['name'] == 'c2_ports' else intervals(values)
    for name in ('incoming', 'outgoing'):
        require(actual.get(name) == intervals(network_interval(x) for x in candidate[name]), 'kernel members differ: ' + name)
    require(actual.get('c2_ports') == sorted(tuple(x) for x in candidate['c2_ports']), 'kernel endpoints differ')


def metrics(state, now):
    from policy_inventory import sample
    out = sample('ip_last_tick_unix_seconds', now)
    out += sample('ip_last_apply_unix_seconds', state.get('last_apply_unix', 0))
    out += sample('ip_apply_success', int(state.get('apply_success', False)))
    for name, spec in SOURCES.items():
        status = state.get('status', {}).get(name, {})
        feed = state.get('feeds', {}).get(name, {})
        labels = {'source': name, 'mode': spec['mode']}
        installed = state.get('applied_source_versions', {}).get(name) == feed.get('sha256') and bool(feed)
        deployment = 'DETECTION_ONLY' if spec['mode'] == 'detect' else 'INSTALLED' if installed else 'NOT_INSTALLED'
        out += sample('ip_source_info', 1, **labels, status=status.get('result', 'NOT_CONFIGURED'),
                      deployment=deployment, sha256=feed.get('sha256', 'unknown'))
        out += sample('ip_source_download_success', int(status.get('result') == 'OK'), **labels)
        out += sample('ip_source_fresh', int(feed.get('fetched_unix', now + 1) <= now < feed.get('expires_unix', 0)), **labels)
        for field in ('fetched_unix', 'published_unix', 'expires_unix'):
            out += sample('ip_source_' + field + '_seconds', feed.get(field, 0), **labels)
        out += sample('ip_source_entries', len(feed.get('addresses', [])), **labels)
        out += sample('ip_source_domains', len(feed.get('domains', [])), **labels)
        out += sample('ip_source_filtered', feed.get('filtered', 0), **labels)
    for name, count in state.get('counts', {}).items():
        out += sample('ip_installed_entries', count, set=name)
    for name, count in state.get('counters', {}).items():
        out += sample('ip_blocked_packets_total', count, rule=name)
    return out


def ioc_snapshot(feeds, protected, now):
    """A generated IP snapshot for the existing EVE observer; no domain-coverage claim."""
    hosts, prefixes, expirations = set(), set(), []
    for name, feed in feeds.items():
        # Scanner-only IPInsights is enforced inbound; it is not a C2 feed.
        if name == 'ipinsights' or name not in SOURCES or not feed['fetched_unix'] <= now < feed['expires_unix']:
            continue
        expirations.append(feed['expires_unix'])
        for net in admitted(feed['addresses'], protected):
            if net.prefixlen == 32:
                hosts.add(str(net.network_address))
            else:
                prefixes.add(str(net))
    require(len(hosts) <= 65536 and len(prefixes) <= 65536, 'observer IOC bound exceeded')
    content = {'addresses': sorted(hosts), 'networks': sorted(prefixes)}
    digest = sha(json.dumps(content, sort_keys=True, separators=(',', ':')).encode())
    return {'schema': 'cs-public0-egress-ioc-v2', 'source': 'cs-public0 IP intelligence generated snapshot',
            'version': digest, 'content_sha256': digest, 'published_unix': now, 'fetched_unix': now,
            'expires_unix': min([now + 86400, *expirations]), **content}


def active_versions(feeds, now):
    return {n: x['sha256'] for n, x in feeds.items() if n in SOURCES and SOURCES[n]['mode'] != 'detect'
            and x['fetched_unix'] <= now < x['expires_unix'] - 60}


def refresh_required(state, now):
    """Keep last-transaction semantics; renew well before kernel expiry."""
    return (not state.get('apply_success') or state.get('applied_source_versions') != active_versions(state['feeds'], now)
            or not 0 <= now - state.get('last_apply_unix', 0) < 1800
            or state.get('kernel_expires_unix', 0) - now < 600)


def main():
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--preview', action='store_true', help='download/validate only; no nft operations')
    args = parser.parse_args()
    from policy_inventory import read
    require(os.geteuid() == 0, 'root required')
    raw = read(args.config, 65536)
    require(sha(raw) == args.config_sha256, 'IP configuration pin differs')
    config = json.loads(raw)
    require(config['schema'] == 'cs-public0-ip-intelligence-v1' and config['bridge'] == 'public0', 'installed contract differs')
    require(config['mode'] in {'observe', 'apply'}, 'unknown mode')
    require(config['sources'] == sorted(set(config['sources'])) and set(config['sources']) <= SOURCES.keys(), 'unknown source')
    protected = protected_config(config['protected_networks'])
    root = Path(config['state_directory'])
    require(str(root) == '/var/lib/cs-public0-ip-intelligence', 'fixed private state directory required')
    lock = os.open(root / 'tick.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = root / 'state.json'
        state = json.loads(read(path, 64 * 1024 * 1024)) if path.exists() else {'feeds': {}, 'status': {}}
        require(state.get('config_sha256', args.config_sha256) == args.config_sha256, 'state belongs to another installed policy')
        state['config_sha256'] = args.config_sha256
        state.setdefault('apply_success', False)
        now = int(time.time())
        due = [n for n in config['sources'] if args.refresh or now - max(
            state['feeds'].get(n, {}).get('fetched_unix', 0),
            state['status'].get(n, {}).get('attempted_unix', 0)) >= SOURCES[n]['interval']]
        credentials = os.environ.get('CREDENTIALS_DIRECTORY', '/run/credentials/cs-public0-ip-intelligence.service')
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            pending = {pool.submit(fetch_source, name, now, credentials): name for name in due}
            for future in concurrent.futures.as_completed(pending):
                name = pending[future]
                try:
                    fetched = future.result()
                    previous = state['feeds'].get(name)
                    require(not previous or len(fetched['addresses']) <= max(100, len(previous['addresses']) * 1.5),
                            'unexpected source growth; previous policy retained')
                    state['feeds'][name] = fetched
                    state['status'][name] = {'result': 'OK', 'attempted_unix': now}
                except Exception as error:
                    state['status'][name] = {'result': 'UNAVAILABLE_LAST_GOOD_RETAINED', 'attempted_unix': now,
                                             'reason': str(error)[:256]}
        now = int(time.time())  # Admission uses the clock after potentially slow retrieval and parsing.
        needs_refresh = refresh_required(state, now)
        # Retrieval receipts survive process/cgroup failure during the expensive
        # policy build or nft readback. Provider retry intervals include errors.
        atomic(path, encoded(state))
        try:
            # The short read still verifies ownership, exact expressions and expiry policy.
            # A no-op does not claim a new kernel-member verification or deployment time.
            rows = None if args.preview else owned_table(terse=True)
            if rows is None:
                needs_refresh = True
            if config['mode'] == 'apply' and not args.preview and needs_refresh:
                state['apply_success'] = False
                state['apply_attempt_unix'] = now
                atomic(path, encoded(state))
                if not state.get('last_apply_unix'):
                    require(all(n in state['feeds'] and state['feeds'][n]['fetched_unix'] <= now < state['feeds'][n]['expires_unix']
                                for n in config['required_sources']), 'required initial sources are not fresh')
                candidate = policy(state['feeds'], protected, now)
                expirations = [x['expires_unix'] - now for name, x in state['feeds'].items()
                               if name in SOURCES and SOURCES[name]['mode'] != 'detect'
                               and x['fetched_unix'] <= now < x['expires_unix'] - 60]
                ttl = min([3600, *expirations])
                batch = nft_batch(candidate, create=rows is None, ttl=ttl)
                atomic(root / 'pending.nft', batch)
                nft('--check', '--file', str(root / 'pending.nft'))
                nft('--file', str(root / 'pending.nft'))
                rows = owned_table()
                require(rows is not None, 'IOC table absent after apply')
                verify_members(rows, candidate)
                state.update(apply_success=True, last_apply_unix=int(time.time()), policy_sha256=sha(encoded(candidate)))
                state.pop('apply_error', None)
                state['applied_source_versions'] = active_versions(state['feeds'], now)
                state['kernel_expires_unix'] = int(time.time()) + ttl
                state['counts'] = {x['set']['name']: len(x['set'].get('elem', [])) for x in rows if 'set' in x}
            if rows is not None:
                state['counters'] = {x['counter']['name']: x['counter']['packets'] for x in rows if 'counter' in x}
        except Exception as error:
            state['apply_success'] = False
            state['apply_error'] = str(error)[:512]
        state['last_tick_unix'] = int(time.time())
        atomic(path, encoded(state))
        if config.get('ioc_file'):
            require(config['ioc_file'] == str(root / 'ioc.json'), 'fixed observer IOC path required')
            atomic(config['ioc_file'], encoded(ioc_snapshot(state['feeds'], protected, state['last_tick_unix'])), 0o644)
        atomic(config['metrics_file'], metrics(state, state['last_tick_unix']).encode(), 0o644)
        print(json.dumps({'mode': config['mode'], 'apply_success': state['apply_success'],
                          'counts': state.get('counts'), 'status': state['status']}))
        require(args.preview or config['mode'] != 'apply' or state['apply_success'], 'IP policy apply not confirmed')
    finally:
        os.close(lock)


if __name__ == '__main__':
    main()
