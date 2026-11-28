"""Local inbound scan detector for the public0 bridge (ADR-067), OBSERVE only.

Reads Suricata EVE flow records, counts distinct failed (target, port) pairs per
external source in a sliding window and, when a source crosses the threshold,
records one decision: a kernel set element with a TTL in an own nft table and
one JSON line for the SIEM.

Version 1 implements no verdict. The own table only counts the initial inbound
SYNs that a future ENFORCE mode would drop; it never drops, rejects, queues or
redirects a packet. ENFORCE is refused by the configuration contract and needs a
separate, reviewed version (ADR-067 E3).

Two verdicts are recorded side by side:
  behavior_only        -- behaviour threshold crossed, source on no IOC list;
  behavior_reputation  -- behaviour threshold crossed AND the source is on an
                          IOC list of the IP updater (variant B, the selected
                          one). Reputation is necessary, never sufficient.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import gzip
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

_HERE = str(pathlib.Path(__file__).resolve().parent)
if _HERE not in sys.path:
    # Run as `python3 -I`: the script directory is not on sys.path.
    sys.path.insert(0, _HERE)

from egress_model import IOC, MAX_RECORD, strict_json, timestamp  # noqa: E402

SCHEMA = 'cs-public0-scan-v1'
EVENT_SCHEMA = 'cs-public0-scan-decision-v1'
STATE_SCHEMA = 'cs-public0-scan-state-v1'
VERSION = '1'
TABLE = 'cs_public0_scan'
OWNER = 'cs-public0-scan-v1-observe'
CHAIN = 'public0_forward'
# Between IP intelligence (-250, IPsum/Spamhaus DROP) and the NFQUEUE (-240).
PRIORITY = -245
# Set -> counter. scan_behavior holds every decision (variant A, comparison),
# scan_block only behaviour AND reputation (variant B, the selected policy).
SETS = {'scan_behavior': 'observed_behavior', 'scan_block': 'observed_block'}
VERDICTS = ('behavior_only', 'behavior_reputation')
SPECIAL = tuple(ipaddress.ip_network(x) for x in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'))
FLOW_CLASSES = ('failed', 'handshake', 'no_syn', 'excluded', 'unprotected', 'late',
                'from_active', 'held', 'invalid')
GAP_REASONS = ('rotated', 'truncated', 'oversize', 'partial', 'missing')
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10
MAX_READ = 8 * 1024 * 1024
MAX_SOURCES = 20000
MAX_TOTAL_PAIRS = 400000
MAX_HISTORY_SOURCES = 8192
MAX_HISTORY_PER_SOURCE = 16
MAX_DECISION_LOG = 8 * 1024 * 1024
SWEEP_SECONDS = 15
METRICS_SECONDS = 15
IOC_CHECK_SECONDS = 30
DATE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}\Z')
NAME = re.compile(r'[A-Za-z0-9_.-]{1,15}\Z')
# Cheap byte prefilter, independent of JSON spacing; the parser decides.
PREFILTER = (b'"flow"', b'"TCP"')


def require(value, message):
    if not value:
        raise ValueError(message)


def bounded_text(value, limit):
    require(isinstance(value, str) and 0 < len(value.encode()) <= limit, 'text outside contract')
    require(not any(ord(c) < 32 or ord(c) == 127 for c in value), 'control character')
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'integer outside contract')
    return value


def absolute(value):
    bounded_text(value, 256)
    require(value.startswith('/') and '/../' not in value + '/' and '//' not in value, 'absolute path required')
    return value


def network_list(values, *, minimum, maximum, min_prefix):
    require(isinstance(values, list) and minimum <= len(values) <= maximum, 'network list bound')
    out = []
    for value in values:
        bounded_text(value, 18)
        net = ipaddress.ip_network(value, strict=True)
        require(net.version == 4 and net.prefixlen >= min_prefix and str(net) == value, 'canonical IPv4 network')
        out.append(net)
    return tuple(out)


def day_end(value):
    """Unix time of the end of a YYYY-MM-DD day (UTC): the entry is valid through that day."""
    require(isinstance(value, str) and DATE.fullmatch(value), 'date YYYY-MM-DD')
    day = datetime.datetime.strptime(value, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
    return (day + datetime.timedelta(days=1)).timestamp()


WHITELIST_KEYS = {'network', 'kind', 'reporter', 'reason', 'added', 'expires'}


def whitelist_entries(values):
    require(isinstance(values, list) and len(values) <= 1024, 'whitelist bound')
    out = []
    for entry in values:
        require(isinstance(entry, dict) and set(entry) == WHITELIST_KEYS, 'whitelist entry fields')
        # Reported exceptions are narrow: one address or at most a /24.
        net = network_list([entry['network']], minimum=1, maximum=1, min_prefix=24)[0]
        require(entry['kind'] in ('reported', 'own_probe'), 'whitelist kind')
        bounded_text(entry['reporter'], 128)
        bounded_text(entry['reason'], 512)
        added = day_end(entry['added'])
        if entry['expires'] is None:
            # Only own permanent probes may stay without an expiry date.
            require(entry['kind'] == 'own_probe', 'reported whitelist entry requires an expiry date')
            until = None
        else:
            until = day_end(entry['expires'])
            require(until >= added, 'whitelist expiry before addition')
        out.append((net, until))
    return tuple(out)


CONFIG_KEYS = {'schema', 'mode', 'bridge', 'sensor_id', 'protected_networks', 'own_networks',
               'eve_file', 'ioc_file', 'state_directory', 'metrics_file', 'decision_log',
               'window_seconds', 'min_pairs', 'min_ports', 'ttl_seconds', 'repeat_window_seconds',
               'set_size', 'max_decisions_per_minute', 'whitelist'}


def load_config(raw):
    """Validate the complete operator contract before any input is read."""
    config = json.loads(raw) if isinstance(raw, (bytes, str)) else raw
    require(isinstance(config, dict) and set(config) == CONFIG_KEYS, 'configuration fields')
    require(config['schema'] == SCHEMA, 'configuration schema')
    # ADR-067: only OBSERVE is approved. Refuse anything that could drop.
    require(config['mode'] in ('observe', 'off'), 'mode must be observe or off; enforce is not implemented in v1')
    require(isinstance(config['bridge'], str) and NAME.fullmatch(config['bridge']), 'bridge name')
    require(isinstance(config['sensor_id'], str) and re.fullmatch(r'[a-z0-9-]{1,32}', config['sensor_id']),
            'sensor id')
    network_list(config['protected_networks'], minimum=1, maximum=64, min_prefix=16)
    network_list(config['own_networks'], minimum=0, maximum=64, min_prefix=8)
    for key in ('eve_file', 'ioc_file', 'state_directory', 'metrics_file', 'decision_log'):
        absolute(config[key])
    require(config['metrics_file'].endswith('/cs_public0_scan.prom'), 'metrics file name')
    integer(config['window_seconds'], 60, 3600)
    integer(config['min_pairs'], 10, 10000)
    integer(config['min_ports'], 2, config['min_pairs'])
    ttl = config['ttl_seconds']
    require(isinstance(ttl, list) and 1 <= len(ttl) <= 6, 'TTL ladder bound')
    previous = 0
    for value in ttl:
        # Maximum 6 h per decision (ADR-067).
        integer(value, 60, 21600)
        require(value > previous, 'TTL ladder must increase')
        previous = value
    integer(config['repeat_window_seconds'], 3600, 7 * 86400)
    integer(config['set_size'], 64, 65536)
    integer(config['max_decisions_per_minute'], 1, 600)
    whitelist_entries(config['whitelist'])
    return config


def flags(value):
    if isinstance(value, str) and re.fullmatch(r'[0-9a-fA-F]{1,2}', value):
        return int(value, 16)
    return None


class Scope:
    def __init__(self, config):
        self.protected = network_list(config['protected_networks'], minimum=1, maximum=64, min_prefix=16)
        own = network_list(config['own_networks'], minimum=0, maximum=64, min_prefix=8)
        self.excluded = self.protected + own + SPECIAL

    @staticmethod
    def inside(address, nets):
        return any(address in net for net in nets)


def classify(raw, scope):
    """Return (class, src, dst, port, start) for an inbound TCP EVE flow, or None.

    failed    -- client SYN, handshake not completed (no reply, RST, or a scanner
                 that answers SYN-ACK with RST);
    handshake -- client SYN, server SYN-ACK and a client ACK.
    The classification matches the ADR-067 calibration on sda/sdd EVE."""
    if not all(token in raw for token in PREFILTER):
        return None
    try:
        row = strict_json(raw.rstrip(b'\r\n'))
        if row.get('event_type') != 'flow' or row.get('proto') != 'TCP':
            return None
        if ':' in str(row.get('dest_ip', '')) or ':' in str(row.get('src_ip', '')):
            # IPv6 never reaches the IPv4-only protected networks.
            return ('unprotected', None, None, None, None)
        src = ipaddress.IPv4Address(row['src_ip'])
        dst = ipaddress.IPv4Address(row['dest_ip'])
        port = integer(row['dest_port'], 1, 65535)
        start = timestamp(row['flow']['start'])
        tcp = row.get('tcp') or {}
        require(isinstance(tcp, dict), 'tcp object')
    except (KeyError, TypeError, ValueError, ipaddress.AddressValueError):
        return ('invalid', None, None, None, None)
    if not Scope.inside(dst, scope.protected):
        return ('unprotected', None, None, None, None)
    if Scope.inside(src, scope.excluded):
        return ('excluded', None, None, None, None)
    client = flags(tcp.get('tcp_flags_ts'))
    server = flags(tcp.get('tcp_flags_tc')) or 0
    if client is None or not client & TCP_SYN or tcp.get('midstream'):
        return ('no_syn', None, None, None, None)
    if client & TCP_ACK and server & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK):
        return ('handshake', str(src), str(dst), port, start)
    return ('failed', str(src), str(dst), port, start)


class Track:
    __slots__ = ('pairs', 'ports', 'last', 'handshakes', 'hold_until')

    def __init__(self):
        self.pairs = {}
        self.ports = {}
        self.last = 0.0
        self.handshakes = 0
        self.hold_until = 0.0


class Detector:
    """Bounded sliding-window state; time of evidence = EVE flow start.

    Memory is bounded independently of the input rate: per-source pair and port
    maps are capped, the number of sources and the total number of pairs are
    capped with least-recently-updated eviction. A flood of spoofed sources
    evicts state (fail-open, counted), it never grows memory."""

    def __init__(self, config, *, max_sources=MAX_SOURCES, max_pairs=MAX_TOTAL_PAIRS):
        self.window = config['window_seconds']
        self.min_pairs = config['min_pairs']
        self.min_ports = config['min_ports']
        self.ladder = list(config['ttl_seconds'])
        self.repeat_window = config['repeat_window_seconds']
        self.rate = config['max_decisions_per_minute']
        self.whitelist = whitelist_entries(config['whitelist'])
        self.pair_cap = max(4 * self.min_pairs, 256)
        self.port_cap = max(4 * self.min_ports, 64)
        self.max_sources = max_sources
        self.max_pairs = max_pairs
        self.tracks = collections.OrderedDict()
        self.total_pairs = 0
        self.clock = 0.0
        self.active = {}
        self.history = {}
        self.recent = collections.deque()
        self.ioc = None
        # Replay evaluates a stored IOC snapshot at its own time, not at the evidence clock.
        self.reputation_time = None
        self.flows = collections.Counter()
        self.counts = collections.Counter()
        self.detection_sum = 0.0

    def whitelisted(self, src, now):
        address = ipaddress.IPv4Address(src)
        return any(address in net and (until is None or now < until) for net, until in self.whitelist)

    def whitelist_state(self, now):
        active = sum(1 for _, until in self.whitelist if until is None or now < until)
        return active, len(self.whitelist) - active

    def reputation(self, src, now):
        if self.reputation_time is not None:
            now = self.reputation_time
        if self.ioc is None or not self.ioc.fresh(now):
            return 'unavailable', []
        match = self.ioc.match(src, now)
        if not match:
            return 'none', []
        return 'match', sorted({x['name'] for x in match['matched_sources']})

    def _drop_track(self, src):
        track = self.tracks.pop(src, None)
        if track is not None:
            self.total_pairs -= len(track.pairs)

    def _evict(self):
        while self.tracks and (len(self.tracks) > self.max_sources or self.total_pairs > self.max_pairs):
            src, track = self.tracks.popitem(last=False)
            self.total_pairs -= len(track.pairs)
            self.counts['source_evictions'] += 1

    @staticmethod
    def _trim(mapping, cap):
        while len(mapping) > cap:
            del mapping[min(mapping, key=mapping.get)]

    def _prune(self, track, cutoff):
        before = len(track.pairs)
        track.pairs = {k: t for k, t in track.pairs.items() if t >= cutoff}
        track.ports = {k: t for k, t in track.ports.items() if t >= cutoff}
        self.total_pairs -= before - len(track.pairs)

    def observe(self, kind, src, dst, port, start, now):
        """Account one classified flow. Returns a decision dict or None."""
        if kind not in ('failed', 'handshake'):
            self.flows[kind] += 1
            return None
        expires = self.active.get(src)
        if expires is not None and expires > now:
            self.flows['from_active'] += 1
            return None
        self.clock = max(self.clock, start)
        cutoff = self.clock - self.window
        if start < cutoff:
            self.flows['late'] += 1
            return None
        track = self.tracks.get(src)
        if track is None:
            track = self.tracks[src] = Track()
        else:
            self.tracks.move_to_end(src)
        track.last = max(track.last, start)
        self.flows[kind] += 1
        if kind == 'handshake':
            track.handshakes += 1
            return None
        if track.hold_until > now:
            self.flows['held'] += 1
            return None
        pair = (dst, port)
        if pair not in track.pairs:
            self.total_pairs += 1
        track.pairs[pair] = max(track.pairs.get(pair, start), start)
        track.ports[port] = max(track.ports.get(port, start), start)
        if len(track.pairs) > self.pair_cap:
            self._trim(track.pairs, self.pair_cap)
            self.total_pairs -= 1
        if len(track.ports) > self.port_cap:
            self._trim(track.ports, self.port_cap)
        decision = None
        if len(track.pairs) >= self.min_pairs and len(track.ports) >= self.min_ports:
            self._prune(track, cutoff)
            if len(track.pairs) >= self.min_pairs and len(track.ports) >= self.min_ports:
                decision = self._decide(src, track, start, now)
        self._evict()
        return decision

    def _decide(self, src, track, reached, now):
        if self.whitelisted(src, now):
            self.counts['whitelist_hits'] += 1
            track.hold_until = now + self.window
            return None
        while self.recent and self.recent[0] <= now - 60:
            self.recent.popleft()
        if len(self.recent) >= self.rate:
            # Safety fuse: a burst of decisions means a flood or spoofing, not scanners.
            self.counts['rate_limited'] += 1
            track.hold_until = now + self.window
            return None
        self.recent.append(now)
        status, sources = self.reputation(src, now)
        verdict = 'behavior_reputation' if status == 'match' else 'behavior_only'
        previous = [t for t in self.history.get(src, []) if t > now - self.repeat_window]
        ttl = self.ladder[min(len(previous), len(self.ladder) - 1)]
        first = min(track.pairs.values())
        decision = {
            'src_ip': src, 'verdict': verdict,
            'reputation': {'status': status, 'sources': sources},
            'failed_pairs': len(track.pairs), 'ports': len(track.ports),
            'targets': len({d for d, _ in track.pairs}), 'handshakes': track.handshakes,
            'first_attempt_unix': first, 'threshold_unix': reached,
            'detection_seconds': round(max(0.0, reached - first), 3),
            'decided_unix': now, 'ttl_seconds': ttl, 'repeat': len(previous),
            'expires_unix': now + ttl,
            'sets': ['scan_behavior', 'scan_block'] if verdict == 'behavior_reputation' else ['scan_behavior'],
        }
        self._drop_track(src)
        self.history[src] = (previous + [now])[-MAX_HISTORY_PER_SOURCE:]
        if len(self.history) > MAX_HISTORY_SOURCES:
            oldest = sorted(self.history, key=lambda k: self.history[k][-1])
            for key in oldest[:len(self.history) - MAX_HISTORY_SOURCES]:
                del self.history[key]
        self.active[src] = now + ttl
        self.counts['decisions:' + verdict] += 1
        self.detection_sum += decision['detection_seconds']
        return decision

    def sweep(self, now):
        cutoff = self.clock - self.window
        for src in list(self.tracks):
            track = self.tracks[src]
            self._prune(track, cutoff)
            if not track.pairs and track.last < cutoff and track.hold_until <= now:
                self._drop_track(src)
        for src in [k for k, v in self.active.items() if v <= now]:
            del self.active[src]
        for src in list(self.history):
            kept = [t for t in self.history[src] if t > now - self.repeat_window]
            if kept:
                self.history[src] = kept
            else:
                del self.history[src]


class Follower:
    """Follow the live EVE file without replaying history.

    Starts at the end of the file. A rename rotation (new inode) drains the old
    descriptor to its end before switching; copytruncate (size below the read
    offset) restarts at offset 0. Lost or partial lines are counted, never
    guessed. Line length is bounded by the EVE record bound."""

    def __init__(self, path, gaps):
        self.path = path
        self.gaps = gaps
        self.f = None
        self.inode = None
        self.buf = b''
        self.discarding = False
        self.started = False

    def _open(self, at_end):
        fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise ValueError('EVE is not a regular file')
        self.f = os.fdopen(fd, 'rb', buffering=0)
        self.inode = (info.st_dev, info.st_ino)
        if at_end:
            self.f.seek(0, os.SEEK_END)
        self.buf = b''
        self.discarding = False

    def close(self):
        if self.f is not None:
            self.f.close()
            self.f = None

    def read(self, limit=MAX_READ):
        if self.f is None:
            try:
                self._open(at_end=not self.started)
                self.started = True
            except FileNotFoundError:
                self.gaps['missing'] += 1
                return []
        chunk = self.f.read(limit)
        if not chunk:
            self._check_rotation()
            return []
        data = self.buf + chunk
        lines = data.split(b'\n')
        self.buf = lines.pop()
        if self.discarding and lines:
            lines.pop(0)
            self.discarding = False
        if len(self.buf) > MAX_RECORD:
            if not self.discarding:
                self.gaps['oversize'] += 1
            self.buf = b''
            self.discarding = True
        out = []
        for line in lines:
            if len(line) > MAX_RECORD:
                self.gaps['oversize'] += 1
            elif line:
                out.append(line)
        return out

    def _check_rotation(self):
        try:
            info = os.stat(self.path)
        except FileNotFoundError:
            return
        if (info.st_dev, info.st_ino) != self.inode:
            # Old descriptor already read to its end: switch to the new file.
            if self.buf:
                self.gaps['partial'] += 1
            self.gaps['rotated'] += 1
            self.close()
            try:
                self._open(at_end=False)
            except FileNotFoundError:
                self.gaps['missing'] += 1
        elif os.fstat(self.f.fileno()).st_size < self.f.tell():
            if self.buf:
                self.gaps['partial'] += 1
            self.gaps['truncated'] += 1
            self.f.seek(0)
            self.buf = b''
            self.discarding = False


class Kernel:
    """Own nft table: one forward chain, two timeout sets, counters, no verdicts."""

    def __init__(self, bridge, *, runner=None):
        self.bridge = bridge
        self.runner = runner or self._run

    @staticmethod
    def _run(args, payload=None):
        return subprocess.run(['nft', *args], input=payload, capture_output=True, timeout=30)

    def nft(self, *args, payload=None, check=True):
        result = self.runner(list(args), payload)
        if check:
            require(result.returncode == 0,
                    'nft operation failed: ' + result.stderr.decode(errors='replace')[:300])
        return result

    def create_batch(self, protected, size, replace=False):
        out = []
        if replace:
            out.append(f'delete table bridge {TABLE}')
        out += [f'table bridge {TABLE} {{ comment "{OWNER}"; }}',
                f'add set bridge {TABLE} protected {{ type ipv4_addr; flags interval; auto-merge; }}']
        for name in SETS:
            out.append(f'add set bridge {TABLE} {name} {{ type ipv4_addr; flags timeout; size {size}; }}')
        for counter in SETS.values():
            out.append(f'add counter bridge {TABLE} {counter}')
        out.append(f'add chain bridge {TABLE} {CHAIN} {{ type filter hook forward priority {PRIORITY}; '
                   'policy accept; }')
        prefix = (f'add rule bridge {TABLE} {CHAIN} meta ibrname "{self.bridge}" '
                  f'meta obrname "{self.bridge}" ether type ip ip daddr @protected ')
        for name, counter in SETS.items():
            # Counter only: OBSERVE measures what ENFORCE would drop.
            out.append(prefix + f'ip saddr @{name} tcp flags & (fin | syn | rst | ack) == syn '
                       f'counter name {counter} comment "{OWNER}:{name}"')
        out.append(f'add element bridge {TABLE} protected {{ ' + ', '.join(str(x) for x in protected) + ' }')
        return ('\n'.join(out) + '\n').encode()

    def table(self):
        result = self.nft('-j', 'list', 'table', 'bridge', TABLE, check=False)
        if result.returncode:
            tables = json.loads(self.nft('-j', 'list', 'tables').stdout)['nftables']
            require(not any(x.get('table', {}).get('family') == 'bridge' and
                            x.get('table', {}).get('name') == TABLE for x in tables),
                    'cannot read existing scan table')
            return None
        require(len(result.stdout) <= 16 * 1024 * 1024, 'kernel readback exceeds bound')
        return json.loads(result.stdout)['nftables']

    def conforms(self, rows, protected, size):
        """Exact structural contract. Returns a list of differences (empty = owned and exact)."""
        problems = []
        table = [x['table'] for x in rows if 'table' in x]
        if len(table) != 1 or table[0].get('comment') != OWNER:
            return ['foreign']
        sets = {x['set']['name']: x['set'] for x in rows if 'set' in x}
        if set(sets) != {'protected', *SETS}:
            problems.append('sets')
        else:
            if sets['protected'].get('type') != 'ipv4_addr' or set(sets['protected'].get('flags', [])) != {'interval'}:
                problems.append('protected set type')
            for name in SETS:
                row = sets[name]
                if (row.get('type') != 'ipv4_addr' or set(row.get('flags', [])) != {'timeout'}
                        or row.get('size') != size):
                    problems.append(name + ' set type')
            members = []
            for elem in sets['protected'].get('elem', []):
                if isinstance(elem, dict) and 'prefix' in elem:
                    members.append(f"{elem['prefix']['addr']}/{elem['prefix']['len']}")
                elif isinstance(elem, str):
                    members.append(elem + '/32')
                else:
                    members.append(repr(elem))
            if sorted(members) != sorted(str(x) for x in protected):
                problems.append('protected members')
        chains = [x['chain'] for x in rows if 'chain' in x]
        if (len(chains) != 1 or chains[0].get('name') != CHAIN or chains[0].get('hook') != 'forward'
                or chains[0].get('prio') != PRIORITY or chains[0].get('policy') != 'accept'):
            problems.append('chain')
        rules = [x['rule'] for x in rows if 'rule' in x]
        common = [{'match': {'op': '==', 'left': {'meta': {'key': name}}, 'right': self.bridge}}
                  for name in ('ibrname', 'obrname')]
        expected = [(f'{OWNER}:{name}', common + [
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}}, 'right': '@protected'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '@' + name}},
            {'match': {'op': '==', 'left': {'&': [{'payload': {'protocol': 'tcp', 'field': 'flags'}},
                                                ['fin', 'syn', 'rst', 'ack']]}, 'right': 'syn'}},
            {'counter': counter}]) for name, counter in SETS.items()]
        if [(r.get('comment'), r.get('expr')) for r in rules] != expected:
            problems.append('rules')
        if {x['counter']['name'] for x in rows if 'counter' in x} != set(SETS.values()):
            problems.append('counters')
        return problems

    def ensure(self, protected, size):
        rows = self.table()
        if rows is None:
            batch = self.create_batch(protected, size)
            self.nft('--check', '-f', '-', payload=batch)
            self.nft('-f', '-', payload=batch)
            return 'created'
        problems = self.conforms(rows, protected, size)
        if problems == ['foreign']:
            raise ValueError('scan table exists with a foreign owner; refusing to change it')
        if not problems:
            return 'kept'
        # Own table with another structure (upgrade or config change): replace atomically.
        # It holds no verdicts, so the replacement never changes forwarding.
        batch = self.create_batch(protected, size, replace=True)
        self.nft('--check', '-f', '-', payload=batch)
        self.nft('-f', '-', payload=batch)
        return 'replaced:' + ','.join(problems)

    def withdraw(self):
        rows = self.table()
        if rows is None:
            return 'absent'
        table = [x['table'] for x in rows if 'table' in x]
        require(len(table) == 1 and table[0].get('comment') == OWNER, 'refusing to delete a foreign scan table')
        self.nft('delete', 'table', 'bridge', TABLE)
        return 'deleted'

    def add(self, name, address, ttl):
        require(name in SETS, 'unknown set')
        require(str(ipaddress.IPv4Address(address)) == address, 'canonical address')
        integer(ttl, 60, 21600)
        result = self.nft('add', 'element', 'bridge', TABLE, name, '{ ' + address + f' timeout {ttl}s' + ' }',
                          check=False)
        return result.returncode == 0

    def elements(self, name):
        """Address -> remaining seconds, from the kernel (restart recovery)."""
        result = self.nft('-j', 'list', 'set', 'bridge', TABLE, name, check=False)
        if result.returncode:
            return {}
        out = {}
        for row in json.loads(result.stdout)['nftables']:
            for elem in row.get('set', {}).get('elem', []):
                if isinstance(elem, dict) and isinstance(elem.get('elem'), dict):
                    value = elem['elem']
                    address, expires = value.get('val'), value.get('expires', value.get('timeout', 0))
                    if isinstance(address, str) and type(expires) is int:
                        out[address] = expires
        return out

    def counters(self):
        result = self.nft('-j', 'list', 'counters', 'table', 'bridge', TABLE, check=False)
        if result.returncode:
            return None
        out = {}
        for row in json.loads(result.stdout)['nftables']:
            counter = row.get('counter')
            if isinstance(counter, dict) and counter.get('name') in SETS.values():
                out[counter['name']] = counter.get('packets', 0)
        return out


def atomic(path, raw, mode=0o644):
    path = pathlib.Path(path)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError('unsafe publication target')
    fd, temporary = tempfile.mkstemp(prefix='.scan-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def iso(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def event(decision, config, kernel_status):
    """One SIEM line per decision, never one per flow.

    The common fields (observed_unix, remote_ip, direction, category,
    evidence_kind, enforcement, ioc.matched_sources) follow the record shape the
    sensor's Wazuh adapter already normalises for the IP and DNS channels."""
    ident = hashlib.sha256('|'.join((config['sensor_id'], decision['src_ip'],
                                     repr(decision['decided_unix']))).encode()).hexdigest()
    sources = decision['reputation']['sources']
    return {
        'schema': EVENT_SCHEMA, 'event_id': ident, 'component': 'cs-public0-scan',
        'sensor_id': config['sensor_id'], 'mode': config['mode'], 'action': 'observe',
        'observed_unix': decision['decided_unix'], 'remote_ip': decision['src_ip'],
        'direction': 'ingress', 'direction_basis': 'EVE_FLOW_CLIENT_SYN', 'category': 'scan',
        'evidence_kind': 'scan_decision', 'enforcement': 'none', 'connection_evidence': 'attempted',
        'severity': 'medium' if decision['verdict'] == 'behavior_reputation' else 'low',
        'ioc': {'matched_sources': [{'name': name} for name in sources], 'enforcement': 'none'},
        'src_ip': decision['src_ip'], 'verdict': decision['verdict'], 'reputation': decision['reputation'],
        'window_seconds': config['window_seconds'], 'failed_pairs': decision['failed_pairs'],
        'ports': decision['ports'], 'targets': decision['targets'], 'handshakes': decision['handshakes'],
        'first_attempt': iso(decision['first_attempt_unix']), 'threshold_at': iso(decision['threshold_unix']),
        'detection_seconds': decision['detection_seconds'], 'decided_at': iso(decision['decided_unix']),
        'ttl_seconds': decision['ttl_seconds'], 'repeat': decision['repeat'],
        'expires_at': iso(decision['expires_unix']), 'sets': decision['sets'], 'kernel': kernel_status,
    }


def append_event(path, row):
    path = pathlib.Path(path)
    raw = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
    try:
        if path.stat().st_size + len(raw) > MAX_DECISION_LOG:
            os.replace(path, str(path) + '.1')
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o640)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def load_history(path, now, repeat_window):
    try:
        raw = pathlib.Path(path).read_bytes()
        data = json.loads(raw)
        require(isinstance(data, dict) and data.get('schema') == STATE_SCHEMA, 'state schema')
        history = data['history']
        require(isinstance(history, dict) and len(history) <= MAX_HISTORY_SOURCES, 'state bound')
        out = {}
        for address, times in history.items():
            require(str(ipaddress.IPv4Address(address)) == address, 'state address')
            require(isinstance(times, list) and len(times) <= MAX_HISTORY_PER_SOURCE, 'state times')
            kept = [float(t) for t in times if isinstance(t, (int, float)) and now - repeat_window < t <= now + 60]
            if kept:
                out[address] = kept
        return out, 'loaded'
    except FileNotFoundError:
        return {}, 'empty'
    except (ValueError, KeyError, TypeError):
        return {}, 'reset'


def save_history(path, history):
    raw = json.dumps({'schema': STATE_SCHEMA, 'history': history}, sort_keys=True, separators=(',', ':'))
    atomic(path, raw.encode(), 0o600)


def metrics_text(det, config, gaps, now, *, lines, last_event, kernel_counters, kernel_errors,
                 set_full, active_sets, decisions_logged, started, eve_available=True, up=True):
    out = ['# HELP cs_public0_scan_info Scan detector (ADR-067); action is always observe in v1.',
           '# TYPE cs_public0_scan_info gauge',
           'cs_public0_scan_info{mode="%s",version="%s"} 1' % (config['mode'], VERSION),
           'cs_public0_scan_up %d' % int(up),
           'cs_public0_scan_eve_available %d' % int(eve_available),
           'cs_public0_scan_last_write_timestamp_seconds %.3f' % now,
           'cs_public0_scan_start_timestamp_seconds %.3f' % started,
           'cs_public0_scan_eve_last_flow_start_timestamp_seconds %.3f' % last_event,
           'cs_public0_scan_eve_lines_total %d' % lines]
    for reason in GAP_REASONS:
        out.append('cs_public0_scan_eve_gaps_total{reason="%s"} %d' % (reason, gaps[reason]))
    for kind in FLOW_CLASSES:
        out.append('cs_public0_scan_flows_total{class="%s"} %d' % (kind, det.flows[kind]))
    for verdict in VERDICTS:
        out.append('cs_public0_scan_decisions_total{verdict="%s"} %d' % (verdict, det.counts['decisions:' + verdict]))
    out.append('cs_public0_scan_decision_events_total %d' % decisions_logged)
    for key in ('whitelist_hits', 'rate_limited', 'source_evictions'):
        out.append('cs_public0_scan_%s_total %d' % (key, det.counts[key]))
    out.append('cs_public0_scan_set_full_total %d' % set_full)
    out.append('cs_public0_scan_kernel_errors_total %d' % kernel_errors)
    out.append('cs_public0_scan_tracked_sources %d' % len(det.tracks))
    out.append('cs_public0_scan_tracked_pairs %d' % det.total_pairs)
    for name in SETS:
        out.append('cs_public0_scan_active_decisions{set="%s"} %d' % (name, active_sets.get(name, 0)))
    if kernel_counters is not None:
        for name, counter in SETS.items():
            out.append('cs_public0_scan_observed_syn_packets_total{set="%s"} %d' % (name, kernel_counters.get(counter, 0)))
    out.append('cs_public0_scan_kernel_table_present %d' % int(kernel_counters is not None))
    fresh = det.ioc is not None and det.ioc.fresh(now)
    out.append('cs_public0_scan_reputation_fresh %d' % int(fresh))
    out.append('cs_public0_scan_reputation_expires_timestamp_seconds %d' % (det.ioc.expires if det.ioc else 0))
    total = sum(det.counts['decisions:' + v] for v in VERDICTS)
    out.append('cs_public0_scan_detection_seconds_sum %.3f' % det.detection_sum)
    out.append('cs_public0_scan_detection_seconds_count %d' % total)
    active, expired = det.whitelist_state(now)
    out.append('cs_public0_scan_whitelist_entries{state="active"} %d' % active)
    out.append('cs_public0_scan_whitelist_entries{state="expired"} %d' % expired)
    return ('\n'.join(out) + '\n').encode()


def load_ioc(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        return None, None
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            return None, None
        key = (info.st_ino, info.st_size, info.st_mtime_ns)
        try:
            return IOC(json.loads(f.read())), key
        except (ValueError, KeyError, TypeError):
            return None, key


class Service:
    def __init__(self, config, *, kernel=None, clock=time.time):
        self.config = config
        self.clock = clock
        self.kernel = kernel or Kernel(config['bridge'])
        self.scope = Scope(config)
        self.det = Detector(config)
        self.gaps = collections.Counter()
        self.follower = Follower(config['eve_file'], self.gaps)
        self.state_file = str(pathlib.Path(config['state_directory']) / 'history.json')
        self.lines = 0
        self.last_event = 0.0
        self.kernel_errors = 0
        self.set_full = 0
        self.decisions_logged = 0
        self.ioc_key = None
        self.stop = False
        self.started = clock()

    def prepare(self):
        protected = network_list(self.config['protected_networks'], minimum=1, maximum=64, min_prefix=16)
        result = self.kernel.ensure(protected, self.config['set_size'])
        now = self.clock()
        for address, remaining in self.kernel.elements('scan_behavior').items():
            if remaining > 0:
                self.det.active[address] = now + remaining
        self.det.history, _ = load_history(self.state_file, now, self.config['repeat_window_seconds'])
        return result

    def refresh_ioc(self):
        try:
            info = os.stat(self.config['ioc_file'])
            key = (info.st_ino, info.st_size, info.st_mtime_ns)
        except FileNotFoundError:
            self.det.ioc, self.ioc_key = None, None
            return
        if key != self.ioc_key:
            self.det.ioc, self.ioc_key = load_ioc(self.config['ioc_file'])

    def apply(self, decision, now):
        active = sum(1 for v in self.det.active.values() if v > now)
        if active > self.config['set_size']:
            # Fail open: no new elements, the decision is still reported.
            self.set_full += 1
            status = 'set_full'
        else:
            status = 'added'
            for name in decision['sets']:
                if not self.kernel.add(name, decision['src_ip'], decision['ttl_seconds']):
                    self.kernel_errors += 1
                    status = 'error'
        append_event(self.config['decision_log'], event(decision, self.config, status))
        self.decisions_logged += 1
        save_history(self.state_file, self.det.history)

    def process(self, raw, now):
        self.lines += 1
        parsed = classify(raw, self.scope)
        if parsed is None:
            return None
        kind, src, dst, port, start = parsed
        if start is not None:
            self.last_event = max(self.last_event, start)
        decision = self.det.observe(kind, src, dst, port, start, now)
        if decision is not None:
            self.apply(decision, now)
        return decision

    def active_sets(self, now):
        behavior = sum(1 for v in self.det.active.values() if v > now)
        return {'scan_behavior': behavior}

    def write_metrics(self, now, *, up=True):
        counters = self.kernel.counters()
        sets = {name: len([1 for r in self.kernel.elements(name).values() if r > 0]) for name in SETS} \
            if counters is not None else self.active_sets(now)
        atomic(self.config['metrics_file'],
               metrics_text(self.det, self.config, self.gaps, now, lines=self.lines, last_event=self.last_event,
                            kernel_counters=counters, kernel_errors=self.kernel_errors, set_full=self.set_full,
                            active_sets=sets, decisions_logged=self.decisions_logged, started=self.started,
                            eve_available=self.follower.f is not None, up=up))

    def run(self, *, iterations=None):
        last_sweep = last_metrics = last_ioc = 0.0
        loops = 0
        while not self.stop and (iterations is None or loops < iterations):
            loops += 1
            now = self.clock()
            if now - last_ioc >= IOC_CHECK_SECONDS:
                self.refresh_ioc()
                last_ioc = now
            batch = self.follower.read()
            for raw in batch:
                self.process(raw, self.clock())
            now = self.clock()
            if now - last_sweep >= SWEEP_SECONDS:
                self.det.sweep(now)
                last_sweep = now
            if now - last_metrics >= METRICS_SECONDS:
                self.write_metrics(now)
                last_metrics = now
            if not batch and iterations is None:
                time.sleep(0.5)
        # A stopped detector says so; the kernel elements expire by their own TTL.
        self.write_metrics(self.clock(), up=iterations is not None)


def replay(config, paths, *, ioc_path=None):
    """Offline evaluation on EVE files with the evidence clock; no kernel, no log."""
    scope = Scope(config)
    det = Detector(config)
    if ioc_path:
        det.ioc, _ = load_ioc(ioc_path)
        if det.ioc is not None:
            det.reputation_time = det.ioc.fetched
    decisions = []
    last_sweep = 0.0
    for path in paths:
        opener = gzip.open if str(path).endswith('.gz') else open
        with opener(path, 'rb') as f:
            for raw in f:
                if len(raw) > MAX_RECORD:
                    continue
                parsed = classify(raw, scope)
                if parsed is None:
                    continue
                kind, src, dst, port, start = parsed
                # Evidence clock: the decision time is the flow start of the crossing flow.
                now = start if start is not None else det.clock
                decision = det.observe(kind, src, dst, port, start, now)
                if decision:
                    decisions.append({k: decision[k] for k in (
                        'src_ip', 'verdict', 'failed_pairs', 'ports', 'targets', 'handshakes',
                        'detection_seconds', 'ttl_seconds', 'repeat')} | {
                        'threshold_at': iso(decision['threshold_unix'])})
                if det.clock - last_sweep >= SWEEP_SECONDS:
                    det.sweep(det.clock)
                    last_sweep = det.clock
    return {'decisions': decisions, 'flows': dict(det.flows), 'counts': dict(det.counts)}


def read_config(path):
    with open(path, 'rb') as f:
        info = os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024 * 1024, 'configuration file bound')
        return load_config(f.read())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('command', choices=('check', 'prepare', 'run', 'withdraw', 'replay'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--eve', action='append', default=[], help='replay: EVE file (plain or .gz)')
    parser.add_argument('--ioc', help='replay: IOC snapshot (ioc.json)')
    args = parser.parse_args(argv)
    config = read_config(args.config)
    if args.command == 'check':
        print(json.dumps({'schema': config['schema'], 'mode': config['mode'], 'sensor_id': config['sensor_id'],
                          'whitelist': len(config['whitelist'])}))
        return 0
    if args.command == 'replay':
        print(json.dumps(replay(config, args.eve, ioc_path=args.ioc), sort_keys=True))
        return 0
    kernel = Kernel(config['bridge'])
    if args.command == 'withdraw' or (args.command == 'prepare' and config['mode'] == 'off'):
        print(json.dumps({'table': kernel.withdraw()}))
        return 0
    if args.command == 'prepare':
        service = Service(config, kernel=kernel)
        print(json.dumps({'table': service.prepare()}))
        return 0
    if config['mode'] == 'off':
        print(json.dumps({'mode': 'off'}))
        return 0
    service = Service(config, kernel=kernel)
    service.prepare()

    def stop(_signum, _frame):
        service.stop = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    service.run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
