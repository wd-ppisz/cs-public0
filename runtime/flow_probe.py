"""Read-only first-packet observation on guest taps and the public uplink.

The kernel object (bpf/flow_probe.c) is loaded by bpftool and pinned. This
daemon attaches the pinned programs with TCX (never clsact: libvirt bandwidth
limits own the ingress qdisc on guest taps), drains the bounded record queue,
maps taps to libvirt domains and writes bounded JSONL records, observe-only
behaviour events and aggregate Prometheus metrics.

It never drops, redirects or modifies packets, never calls a cloud API and
never blocks traffic. Detach removes only the programs it owns, identified by
their pinned file descriptors, preserving other TCX attachments.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

# --- bpf(2) -----------------------------------------------------------------
SYS_BPF = 321  # x86_64
CMD_MAP_LOOKUP = 1
CMD_MAP_GET_NEXT_KEY = 4
CMD_OBJ_GET = 7
CMD_PROG_ATTACH = 8
CMD_PROG_DETACH = 9
CMD_OBJ_GET_INFO_BY_FD = 15
CMD_PROG_QUERY = 16
CMD_MAP_LOOKUP_AND_DELETE = 21
TCX_INGRESS = 46
TCX_EGRESS = 47

PROGRAMS = ('flow_guest_out', 'flow_guest_in', 'flow_uplink')
MAPS = ('flow_records', 'flow_counters', 'flow_stats', 'flow_dns')

RECORD = struct.Struct('<QIIIIHHHBBII')  # struct flow_record, 40 bytes, no padding
COUNTER_FIELDS = ('packets_out', 'bytes_out', 'syn_out', 'udp_out', 'synack_in', 'rst_in')
SVC_NAMES = ('other', 'ssh', 'telnet', 'smtp', 'smb', 'rdp', 'vnc')
COUNTERS = struct.Struct('<' + 'Q' * (len(COUNTER_FIELDS) + len(SVC_NAMES)))
SIDES = {1: 'guest', 2: 'uplink'}
DNS_RECORD = struct.Struct('<QIIIHHHH128sI')  # struct dns_record, 160 bytes

_libc = None


def _sys():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    return _libc


def bpf(cmd, attr):
    buf = ctypes.create_string_buffer(bytes(attr), len(attr))
    ret = _sys().syscall(SYS_BPF, cmd, buf, len(attr))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, f'bpf cmd {cmd}: {os.strerror(err)}')
    return ret, buf.raw


def obj_get(path):
    p = ctypes.create_string_buffer(os.fsencode(path))
    attr = struct.pack('<QIIi4x', ctypes.addressof(p), 0, 0, 0)
    fd, _ = bpf(CMD_OBJ_GET, attr)
    return fd


def prog_id(fd):
    info = ctypes.create_string_buffer(256)
    attr = struct.pack('<IIQ', fd, len(info), ctypes.addressof(info))
    bpf(CMD_OBJ_GET_INFO_BY_FD, attr)
    return struct.unpack_from('<I', info.raw, 4)[0]


def prog_attach_attr(ifindex, prog_fd, attach_type):
    # target_ifindex, attach_bpf_fd, attach_type, attach_flags, replace_bpf_fd,
    # relative_fd, expected_revision (u64)
    return struct.pack('<IIIIIIQ', ifindex, prog_fd, attach_type, 0, 0, 0, 0)


def tcx_attach(ifindex, prog_fd, attach_type):
    bpf(CMD_PROG_ATTACH, prog_attach_attr(ifindex, prog_fd, attach_type))


def tcx_detach(ifindex, prog_fd, attach_type):
    bpf(CMD_PROG_DETACH, prog_attach_attr(ifindex, prog_fd, attach_type))


def tcx_query(ifindex, attach_type, cap=64):
    ids = (ctypes.c_uint32 * cap)()
    attr = struct.pack('<IIIIQI4xQQQQ', ifindex, attach_type, 0, 0,
                       ctypes.addressof(ids), cap, 0, 0, 0, 0)
    _, out = bpf(CMD_PROG_QUERY, attr)
    count = struct.unpack_from('<I', out, 24)[0]
    return list(ids[:min(count, cap)])


def map_pop(fd, size):
    val = ctypes.create_string_buffer(size)
    attr = struct.pack('<I4xQQQ', fd, 0, ctypes.addressof(val), 0)
    try:
        bpf(CMD_MAP_LOOKUP_AND_DELETE, attr)
    except OSError as e:
        if e.errno == 2:  # ENOENT: queue empty
            return None
        raise
    return val.raw


def map_items(fd, key_size, val_size, limit=100000):
    key = ctypes.create_string_buffer(key_size)
    nxt = ctypes.create_string_buffer(key_size)
    val = ctypes.create_string_buffer(val_size)
    first = True
    out = []
    while len(out) < limit:
        attr = struct.pack('<I4xQQQ', fd, 0 if first else ctypes.addressof(key),
                           ctypes.addressof(nxt), 0)
        try:
            bpf(CMD_MAP_GET_NEXT_KEY, attr)
        except OSError as e:
            if e.errno == 2:
                break
            raise
        first = False
        ctypes.memmove(key, nxt, key_size)
        attr = struct.pack('<I4xQQQ', fd, ctypes.addressof(key), ctypes.addressof(val), 0)
        try:
            bpf(CMD_MAP_LOOKUP, attr)
        except OSError as e:
            if e.errno == 2:
                continue
            raise
        out.append((key.raw, val.raw))
    return out


# --- pure helpers (unit-tested) ----------------------------------------------
def ip4(value):
    return socket.inet_ntoa(struct.pack('<I', value))


def tai_offset_ns():
    return time.clock_gettime_ns(time.CLOCK_TAI) - time.clock_gettime_ns(time.CLOCK_REALTIME)


def decode_record(raw, offset_ns):
    ts, ifindex, saddr, daddr, seq, sport, dport, ip_id, ttl, side, _, _ = RECORD.unpack(raw)
    return {
        'ts_ns': ts - offset_ns, 'ifindex': ifindex, 'side': SIDES.get(side, 'unknown'),
        'src_ip': ip4(saddr), 'src_port': sport, 'dst_ip': ip4(daddr), 'dst_port': dport,
        'isn': seq, 'ttl': ttl, 'ip_id': ip_id,
    }


def decode_counters(raw):
    vals = COUNTERS.unpack(raw[:COUNTERS.size])
    out = dict(zip(COUNTER_FIELDS, vals))
    out['svc_syn'] = dict(zip(SVC_NAMES, vals[len(COUNTER_FIELDS):]))
    return out


def parse_qname(payload):
    """First question name of an ordinary DNS query, lower-case, no trailing dot.

    Returns None for responses, non-QUERY opcodes, compression in the question,
    truncated or oversized names. The name is used only for an in-memory
    catalog comparison and is never written unless it matches."""
    if len(payload) < 13:
        return None
    flags = int.from_bytes(payload[2:4], 'big')
    qdcount = int.from_bytes(payload[4:6], 'big')
    if flags & 0x8000 or (flags >> 11) & 0xF or qdcount < 1:
        return None
    labels, i = [], 12
    while True:
        if i >= len(payload):
            return None
        n = payload[i]
        if n == 0:
            break
        if n & 0xC0 or n > 63 or i + 1 + n > len(payload):
            return None
        label = payload[i + 1:i + 1 + n]
        try:
            labels.append(label.decode('ascii').lower())
        except UnicodeDecodeError:
            return None
        i += 1 + n
    name = '.'.join(labels)
    return name if 0 < len(name) <= 253 else None


def decode_dns(raw, offset_ns):
    ts, ifindex, saddr, daddr, sport, dport, length, _, payload, _ = DNS_RECORD.unpack(raw)
    return {'ts_ns': ts - offset_ns, 'ifindex': ifindex, 'src_ip': ip4(saddr), 'dst_ip': ip4(daddr),
            'src_port': sport, 'dst_port': dport, 'qname': parse_qname(payload[:min(length, 128)])}


def load_domain_catalog(path):
    """Qualified ThreatFox domain catalog shared with the DNS IOC module.

    Accepts the DNS IOC cache wrapper ({"catalog": {...}}) or a bare catalog and
    validates it with the same DomainCatalog contract (freshness, expiry, form)."""
    from dns_ioc import DomainCatalog
    value = json.loads(Path(path).read_text(encoding='utf-8'))
    if isinstance(value, dict) and 'catalog' in value:
        value = value['catalog']
    return DomainCatalog(value)


# --- clock (G7) --------------------------------------------------------------
TIME_ERROR = 5
STA_UNSYNC = 0x0040


def decode_timex(ret, raw):
    """(synced, maxerror_seconds, esterror_seconds) from adjtimex(2) output."""
    _modes, _offset, _freq, maxerror, esterror, status = struct.unpack_from('<I4xqqqqi', raw, 0)
    synced = ret != TIME_ERROR and not status & STA_UNSYNC
    return synced, maxerror / 1e6, esterror / 1e6


def clock_state():
    buf = ctypes.create_string_buffer(256)  # struct timex, modes=0: read only
    ret = _sys().adjtimex(buf)
    if ret < 0:
        return False, float('inf'), float('inf')
    return decode_timex(ret, buf.raw)


# --- reference correlation (input to the central correlator) -----------------
def correlate(guest, uplink, window_s=2.0, max_dt_s=0.05):
    """Join guest SYN records with uplink records of the same SYN.

    Key: (dst_ip, dst_port, isn) with TTL decremented by exactly one hop and a
    time window. SYN retransmissions share the ISN, so a key can carry several
    records on both sides. The constant clock offset between hosts is first
    estimated as the median delay of keys with exactly one record per side; then
    records are assigned one-to-one, nearest to the skew-corrected time first,
    so an uplink record is never used twice. A key whose uplink records name
    more than one public source, or guest records of more than one connection,
    is ambiguous and never confident."""
    def key(r):
        return (r['dst_ip'], r['dst_port'], r['isn'])

    gk, uk = {}, {}
    for i, g in enumerate(guest):
        gk.setdefault(key(g), []).append(i)
    for j, u in enumerate(uplink):
        uk.setdefault(key(u), []).append(j)

    def ok(g, u):
        return u['ttl'] == g['ttl'] - 1 and abs(u['ts_ns'] - g['ts_ns']) <= window_s * 1e9

    unique = sorted((uplink[uk[k][0]]['ts_ns'] - guest[gi[0]]['ts_ns']) / 1e9
                    for k, gi in gk.items() if len(gi) == 1 and len(uk.get(k, [])) == 1
                    and ok(guest[gi[0]], uplink[uk[k][0]]))
    skew = unique[len(unique) // 2] if unique else 0.0

    edges = []
    for k, gi in gk.items():
        for i in gi:
            for j in uk.get(k, []):
                if ok(guest[i], uplink[j]):
                    dt = (uplink[j]['ts_ns'] - guest[i]['ts_ns']) / 1e9
                    edges.append((abs(dt - skew), i, j, dt))
    edges.sort()
    used_g, used_u, best = set(), set(), {}
    for cost, i, j, dt in edges:
        if i in used_g or j in used_u:
            continue
        used_g.add(i)
        used_u.add(j)
        best[i] = (j, dt)
    pairs = []
    for i, g in enumerate(guest):
        if i not in best:
            pairs.append({'guest': g, 'uplink': None, 'ambiguous': False, 'confident': False})
            continue
        j, dt = best[i]
        sources = {(uplink[x]['src_ip'], uplink[x]['src_port']) for x in uk[key(g)] if ok(g, uplink[x])}
        # Competing guests: different connections (source tuple or tap) under the
        # same key within the window. Retransmissions of one connection share it.
        rivals = {(guest[y]['src_ip'], guest[y]['src_port'], guest[y].get('iface'), guest[y].get('vm_uuid'))
                  for y in gk[key(g)] if abs(guest[y]['ts_ns'] - g['ts_ns']) <= 2 * window_s * 1e9}
        amb = len(sources) > 1 or len(rivals) > 1
        pairs.append({'guest': g, 'uplink': uplink[j], 'ambiguous': amb, 'dt_s': dt,
                      'confident': not amb and bool(unique) and abs(dt - skew) <= max_dt_s})
    return pairs, skew


SYSTEM_VM = re.compile(r'^[rsv]-\d+-VM$')


def parse_domain_xml(text):
    """Return (uuid, name, [(target_dev, mac)]) from a libvirt domain XML."""
    root = ET.fromstring(text)
    if root.tag == 'domstatus':
        root = root.find('domain')
    if root is None:
        raise ValueError('no domain element')
    uuid = (root.findtext('uuid') or '').strip()
    name = (root.findtext('name') or '').strip()
    nics = []
    for iface in root.findall('./devices/interface'):
        t = iface.find('target')
        m = iface.find('mac')
        if t is not None and t.get('dev'):
            nics.append((t.get('dev'), m.get('address') if m is not None else None))
    return uuid, name, nics


def tap_map(state_dir='/run/libvirt/qemu'):
    out = {}
    for p in sorted(Path(state_dir).glob('*.xml')):
        try:
            uuid, name, nics = parse_domain_xml(p.read_text(encoding='utf-8'))
        except (OSError, ET.ParseError, ValueError):
            continue
        for dev, mac in nics:
            out[dev] = {'vm_uuid': uuid, 'vm_name': name, 'mac': mac,
                        'system_vm': bool(SYSTEM_VM.match(name))}
    return out


class _Recent:
    """Distinct keys last seen within a window, bounded to `cap` entries.

    Insertion order follows the last sighting, so the oldest entry is evicted
    first. A full structure means "at least cap distinct keys" - enough for a
    threshold comparison - while memory stays constant under a flood."""
    __slots__ = ('cap', 'seen')

    def __init__(self, cap):
        self.cap = cap
        self.seen = {}

    def add(self, key, ts):
        seen = self.seen
        if key in seen:
            del seen[key]
        elif len(seen) >= self.cap:
            del seen[next(iter(seen))]
        seen[key] = ts

    def prune(self, cutoff):
        seen = self.seen
        for key in [k for k, ts in seen.items() if ts < cutoff]:
            del seen[key]
        return len(seen)


class _VmState:
    __slots__ = ('per_second', 'dsts', 'fanout')

    def __init__(self, cap):
        self.per_second = {}
        self.dsts = _Recent(cap)
        self.fanout = {}


class Window:
    """Per-VM sliding behaviour state (observe-only detectors D1-D3).

    Memory per VM is bounded independently of the record rate: per-second
    counters for D1 and capped recent-destination sets for D2 and D3, so a SYN
    flood costs constant memory and constant evaluation time."""
    def __init__(self, seconds=60, cap=4096, service_ports=None):
        self.seconds = seconds
        self.cap = cap
        self.service_ports = frozenset(service_ports if service_ports is not None
                                       else DEFAULTS['thresholds']['service_ports'])
        self.rows = {}

    def add(self, vm, ts_s, dst, dport):
        st = self.rows.get(vm)
        if st is None:
            st = self.rows[vm] = _VmState(self.cap)
        sec = int(ts_s)
        st.per_second[sec] = st.per_second.get(sec, 0) + 1
        st.dsts.add(dst, ts_s)
        if dport in self.service_ports:
            fan = st.fanout.get(dport)
            if fan is None:
                fan = st.fanout[dport] = _Recent(self.cap)
            fan.add(dst, ts_s)

    def evaluate(self, now_s, thresholds):
        events = []
        cutoff = now_s - self.seconds
        ports = set(thresholds.get('service_ports', ()))
        for vm, st in list(self.rows.items()):
            for sec in [s for s in st.per_second if s < int(cutoff)]:
                del st.per_second[sec]
            count = sum(st.per_second.values())
            distinct = st.dsts.prune(cutoff)
            fan = 0
            for port, recent in list(st.fanout.items()):
                n = recent.prune(cutoff)
                if not n:
                    del st.fanout[port]
                elif port in ports:
                    fan = max(fan, n)
            if not st.per_second and not distinct:
                del self.rows[vm]
                continue
            checks = {
                'D1_new_conn_rate': count / self.seconds,
                'D2_distinct_dst': distinct,
                'D3_service_fanout': fan,
            }
            for name, value in checks.items():
                limit = thresholds.get(name)
                if limit is not None and value >= limit:
                    events.append({'detector': name, 'vm_uuid': vm, 'value': round(value, 3),
                                   'threshold': limit, 'window_s': self.seconds})
        return events


DEFAULTS = {
    'schema': 'cs-public0-flow-v1',
    'pin_dir': '/sys/fs/bpf/cs-public0-flow',
    'object': '/usr/local/lib/cs-public0/flow_probe.o',
    'guest_prefix': 'vnet',
    'uplink': '',
    'state_dir': '/run/libvirt/qemu',
    'spool_dir': '/var/lib/cs-public0-flow',
    'metrics_file': '/var/lib/prometheus/node-exporter/cs_public0_flow.prom',
    'sensor_id': '',
    'record_budget_per_cycle': 20000,
    'spool_max_files': 48,
    'spool_max_bytes': 2 * 1024 ** 3,
    'file_max_bytes': 256 * 1024 ** 2,
    'events_max_bytes': 16 * 1024 ** 2,
    'event_cooldown_seconds': 300,
    'dns_catalog_file': '',
    'dns_budget_per_cycle': 5000,
    'clock_max_error_ms': 500,
    'thresholds': {'D1_new_conn_rate': 50, 'D2_distinct_dst': 500, 'D3_service_fanout': 100,
                   'service_ports': [22, 23, 25, 445, 3389, 5900]},
}
POSITIVE = ('record_budget_per_cycle', 'spool_max_files', 'spool_max_bytes', 'file_max_bytes',
            'events_max_bytes', 'event_cooldown_seconds', 'dns_budget_per_cycle', 'clock_max_error_ms')


def load_config(path):
    cfg = json.loads(Path(path).read_text(encoding='utf-8')) if path else {}
    out = dict(DEFAULTS)
    unknown = set(cfg) - set(DEFAULTS)
    if unknown:
        raise ValueError(f'unknown config keys: {sorted(unknown)}')
    out.update(cfg)
    if out['schema'] != DEFAULTS['schema']:
        raise ValueError('schema')
    if not re.fullmatch(r'[a-z][a-z0-9]{0,14}', out['guest_prefix']):
        raise ValueError('guest_prefix')
    if out['uplink'] and not re.fullmatch(r'[A-Za-z0-9._-]{1,15}', out['uplink']):
        raise ValueError('uplink')
    if not str(out['pin_dir']).startswith('/sys/fs/bpf/'):
        raise ValueError('pin_dir must be under /sys/fs/bpf')
    for k in POSITIVE:
        if not isinstance(out[k], int) or isinstance(out[k], bool) or out[k] <= 0:
            raise ValueError(k)
    if not isinstance(out['dns_catalog_file'], str) or (out['dns_catalog_file']
                                                       and not out['dns_catalog_file'].startswith('/')):
        raise ValueError('dns_catalog_file must be empty or absolute')
    if out['file_max_bytes'] > out['spool_max_bytes']:
        raise ValueError('file_max_bytes exceeds spool_max_bytes')
    return out


def metrics_text(m):
    lines = []
    for name, (kind, help_, value) in sorted(m.items()):
        lines += [f'# HELP cs_public0_flow_{name} {help_}', f'# TYPE cs_public0_flow_{name} {kind}']
        if isinstance(value, dict):
            for label, v in sorted(value.items()):
                lines.append(f'cs_public0_flow_{name}{{detector="{label}"}} {v}')
        else:
            lines.append(f'cs_public0_flow_{name} {value}')
    return '\n'.join(lines) + '\n'


def write_atomic(path, data):
    path = Path(path)
    tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    tmp.write_text(data, encoding='utf-8')
    os.replace(tmp, path)


# --- private spool -----------------------------------------------------------
def secure_dir(path):
    """Create or tighten a root-private directory; refuse links and foreign owners."""
    p = Path(path)
    try:
        os.mkdir(p, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ValueError(f'{p} is not a real directory')
    if st.st_uid != os.geteuid():
        raise ValueError(f'{p} owned by another user')
    if stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(p, 0o700)
    return p


def open_private(path):
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f'{path} is not a regular file')
        if st.st_uid != os.geteuid() or st.st_nlink != 1:
            raise ValueError(f'{path} has a foreign owner or extra hard links')
        if stat.S_IMODE(st.st_mode) & 0o077:
            os.fchmod(fd, 0o600)
        return os.fdopen(fd, 'a', encoding='utf-8')
    except Exception:
        os.close(fd)
        raise


def prune_spool(directory, current, max_files, max_bytes):
    """Delete oldest record files beyond the count/byte budget; never the current one."""
    files = sorted(Path(directory).glob('records-*.jsonl'))
    sizes = {f: f.stat().st_size for f in files}
    removed = 0
    total = sum(sizes.values())
    for f in files:
        if f == current:
            continue
        if len(files) - removed <= max_files and total <= max_bytes:
            break
        total -= sizes[f]
        f.unlink(missing_ok=True)
        removed += 1
    return removed


class Cooldown:
    """Emit at most one event per (vm, detector) per window."""
    def __init__(self, seconds):
        self.seconds = seconds
        self.last = {}

    def allow(self, key, now):
        if now - self.last.get(key, -1e18) < self.seconds:
            return False
        self.last[key] = now
        for k in [k for k, t in self.last.items() if now - t > 4 * self.seconds]:
            del self.last[k]
        return True


# --- runtime -----------------------------------------------------------------
ALL_ATTACH = (('flow_guest_out', TCX_INGRESS), ('flow_guest_in', TCX_EGRESS),
              ('flow_uplink', TCX_EGRESS))


def interfaces():
    out = {}
    for d in Path('/sys/class/net').iterdir():
        try:
            out[d.name] = int((d / 'ifindex').read_text())
        except (OSError, ValueError):
            continue
    return out


class Probe:
    def __init__(self, cfg, maps=True):
        self.cfg = cfg
        self._fds = []
        try:
            pin = Path(cfg['pin_dir'])
            # Programs of an older object stay detachable: unload opens only the
            # programs that are actually pinned and never needs the maps.
            names = PROGRAMS if maps else tuple(p for p in PROGRAMS if (pin / 'progs' / p).exists())
            self.prog_fd = {p: self._open(pin / 'progs' / p) for p in names}
            self.prog_ids = {p: prog_id(fd) for p, fd in self.prog_fd.items()}
            self.map_fd = {m: self._open(pin / 'maps' / m) for m in MAPS} if maps else {}
        except Exception:
            self.close()
            raise
        self.offset = tai_offset_ns()
        th = cfg['thresholds']
        # Sets only need to prove "threshold reached"; a margin keeps the exact value visible.
        cap = 2 * max(int(th.get('D2_distinct_dst', 500)), int(th.get('D3_service_fanout', 100)), 1)
        self.window = Window(cap=cap, service_ports=th.get('service_ports', ()))
        self.cooldown = Cooldown(cfg['event_cooldown_seconds'])
        self.records_total = 0
        self.spool_dropped = 0
        self.stale_detached = 0
        self.events_total = {}
        self.taps = {}
        self.taps_at = 0.0
        self.dns_total = 0
        self.dns_matches = 0
        self.dns_cooldown = Cooldown(cfg['event_cooldown_seconds'])
        self.catalog = None
        self.catalog_key = None
        self.prev_lost = None

    def _open(self, path):
        fd = obj_get(path)
        self._fds.append(fd)
        return fd

    def close(self):
        while self._fds:
            try:
                os.close(self._fds.pop())
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def owned(self, ifaces=None, strict=False):
        """Actual attachments of our programs: {(ifindex, prog, attach_type)}.

        A vanished interface (ENODEV/ENOENT) is skipped. Other query errors are
        skipped in the periodic cycle but raised when strict (unload), so an
        unverifiable state never leads to removing the pins."""
        found = set()
        for _, idx in (ifaces or interfaces()).items():
            for prog, at in ALL_ATTACH:
                if prog not in self.prog_ids:
                    continue
                try:
                    if self.prog_ids[prog] in tcx_query(idx, at):
                        found.add((idx, prog, at))
                except OSError as e:
                    if strict and e.errno not in (2, 19):
                        raise
        return found

    def wanted(self, ifaces=None):
        out = set()
        for name, idx in (ifaces or interfaces()).items():
            if name.startswith(self.cfg['guest_prefix']):
                meta = self.taps.get(name)
                if meta and meta['system_vm']:
                    continue
                out.add((idx, 'flow_guest_out', TCX_INGRESS))
                out.add((idx, 'flow_guest_in', TCX_EGRESS))
            elif self.cfg['uplink'] and name == self.cfg['uplink']:
                out.add((idx, 'flow_uplink', TCX_EGRESS))
        return out

    def reconcile(self):
        """Attach missing, detach stale; returns (attached, missing, errors)."""
        ifaces = interfaces()
        want = self.wanted(ifaces)
        have = self.owned(ifaces)
        errors = missing = 0
        for idx, prog, at in have - want:
            try:
                tcx_detach(idx, self.prog_fd[prog], at)
                self.stale_detached += 1
            except OSError as e:
                if e.errno != 19:
                    errors += 1
        attached = len(have & want)
        for idx, prog, at in want - have:
            try:
                tcx_attach(idx, self.prog_fd[prog], at)
                attached += 1
            except OSError as e:
                if e.errno == 19:  # interface vanished between listing and attach
                    continue
                if e.errno == 17:  # attached concurrently
                    attached += 1
                    continue
                errors += 1
                missing += 1
        return attached, missing, errors

    def detach_all(self):
        """Detach every own attachment; returns (detached, failures)."""
        detached, failures = 0, []
        for idx, prog, at in self.owned(strict=True):
            try:
                tcx_detach(idx, self.prog_fd[prog], at)
                detached += 1
            except OSError as e:
                if e.errno != 19:
                    failures.append((idx, prog, at, e.errno))
        return detached, failures

    def refresh_taps(self, now):
        if now - self.taps_at > 30:
            self.taps = tap_map(self.cfg['state_dir'])
            self.taps_at = now

    def drain(self, out, path):
        names = {idx: name for name, idx in interfaces().items()}
        try:
            size = path.stat().st_size if out is not None else 0
        except OSError:
            out, size = None, 0
        n = 0
        while n < self.cfg['record_budget_per_cycle']:
            raw = map_pop(self.map_fd['flow_records'], RECORD.size)
            if raw is None:
                break
            n += 1
            rec = decode_record(raw, self.offset)
            iface = names.get(rec['ifindex'], '')
            meta = self.taps.get(iface, {})
            rec.update(iface=iface, vm_uuid=meta.get('vm_uuid'), sensor=self.cfg['sensor_id'])
            if rec['side'] == 'guest' and rec['vm_uuid']:
                self.window.add(rec['vm_uuid'], rec['ts_ns'] / 1e9, rec['dst_ip'], rec['dst_port'])
            line = json.dumps(rec, separators=(',', ':')) + '\n'
            if out is None or size + len(line) > self.cfg['file_max_bytes']:
                self.spool_dropped += 1
                continue
            try:
                out.write(line)
                size += len(line)
            except OSError:
                self.spool_dropped += 1
                out = None
        return n

    def stats(self):
        out = []
        for i in (0, 1, 2):
            key = ctypes.create_string_buffer(struct.pack('<I', i), 4)
            val = ctypes.create_string_buffer(8)
            attr = struct.pack('<I4xQQQ', self.map_fd['flow_stats'], ctypes.addressof(key),
                               ctypes.addressof(val), 0)
            bpf(CMD_MAP_LOOKUP, attr)
            out.append(struct.unpack('<Q', val.raw)[0])
        return out

    def refresh_catalog(self):
        path = self.cfg['dns_catalog_file']
        if not path:
            self.catalog = None
            return
        try:
            st = os.stat(path)
            key = (st.st_ino, st.st_size, st.st_mtime_ns)
            if key != self.catalog_key:
                self.catalog = load_domain_catalog(path)
                self.catalog_key = key
        except (OSError, ValueError, KeyError, TypeError):
            self.catalog, self.catalog_key = None, None

    def drain_dns(self, now):
        """Compare guest DNS questions with the catalog; keep only matches."""
        names = {idx: name for name, idx in interfaces().items()}
        events, n = [], 0
        fresh = self.catalog is not None and self.catalog.fresh(now)
        while n < self.cfg['dns_budget_per_cycle']:
            raw = map_pop(self.map_fd['flow_dns'], DNS_RECORD.size)
            if raw is None:
                break
            n += 1
            q = decode_dns(raw, self.offset)
            name = q.pop('qname')
            if not fresh or not name or name not in self.catalog.names:
                continue
            iface = names.get(q['ifindex'], '')
            meta = self.taps.get(iface, {})
            vm = meta.get('vm_uuid')
            if meta.get('system_vm') or not self.dns_cooldown.allow((vm, iface, name), now):
                continue
            self.dns_matches += 1
            events.append({'detector': 'D7_dns_ioc', 'vm_uuid': vm, 'domain': name,
                           'iface': iface, 'src_ip': q['src_ip'],
                           'resolver_ip': q['dst_ip'], 'observed_ns': q['ts_ns'],
                           'ioc': {**self.catalog.receipt, 'match': 'exact'}})
        self.dns_total += n
        return events, n

    def write_events(self, d, events, now):
        ev = d / 'events.jsonl'
        try:
            if ev.exists() and ev.stat().st_size > self.cfg['events_max_bytes']:
                os.replace(ev, d / 'events.jsonl.1')
            with open_private(ev) as f:
                for e in events:
                    f.write(json.dumps(e, separators=(',', ':')) + '\n')
        except OSError:
            self.spool_dropped += len(events)

    def cycle(self):
        now = time.time()
        self.refresh_taps(now)
        attached, missing, errors = self.reconcile()
        d = secure_dir(self.cfg['spool_dir'])
        path = d / time.strftime('records-%Y%m%dT%H.jsonl', time.gmtime(now))
        dropped_before = self.spool_dropped
        try:
            out = open_private(path)
        except (OSError, ValueError):
            out = None
        try:
            n = self.drain(out, path) if out else self.drain(None, path)
        finally:
            if out:
                try:
                    out.close()
                except OSError:
                    self.spool_dropped += 1
        prune_spool(d, path, self.cfg['spool_max_files'], self.cfg['spool_max_bytes'])
        self.records_total += n
        self.refresh_catalog()
        events, dns_n = self.drain_dns(now)
        for e in events:
            e.update(ts=int(now), mode='observe', sensor=self.cfg['sensor_id'])
            self.events_total[e['detector']] = self.events_total.get(e['detector'], 0) + 1
        for e in self.window.evaluate(now, self.cfg['thresholds']):
            if self.cooldown.allow((e['vm_uuid'], e['detector']), now):
                e.update(ts=int(now), mode='observe', sensor=self.cfg['sensor_id'])
                events.append(e)
                self.events_total[e['detector']] = self.events_total.get(e['detector'], 0) + 1
        if events:
            self.write_events(d, events, now)
        lost, skipped, dns_lost = self.stats()
        loss_free = self.prev_lost is not None and (lost, dns_lost) == self.prev_lost
        self.prev_lost = (lost, dns_lost)
        guests = sum(1 for name in interfaces() if name.startswith(self.cfg['guest_prefix']))
        synced, maxerr, _esterr = clock_state()
        clock_ok = synced and maxerr * 1000 <= self.cfg['clock_max_error_ms']
        catalog_fresh = int(self.catalog is not None and self.catalog.fresh(now))
        continuity = int(missing == 0 and errors == 0 and self.spool_dropped == dropped_before
                         and n < self.cfg['record_budget_per_cycle']
                         and dns_n < self.cfg['dns_budget_per_cycle'] and clock_ok and loss_free)
        m = {
            'up': ('gauge', 'Last cycle completed', 1),
            'last_cycle_unix_seconds': ('gauge', 'Last completed cycle', int(now)),
            'attachments': ('gauge', 'TCX attachments owned by the probe', attached),
            'attachments_missing': ('gauge', 'Wanted attachments that failed', missing),
            'attach_errors': ('gauge', 'Attach/detach errors in the last cycle', errors),
            'stale_detached_total': ('counter', 'Own attachments removed as no longer wanted', self.stale_detached),
            'guest_interfaces': ('gauge', 'Guest tap interfaces present', guests),
            'records_total': ('counter', 'Records drained since start', self.records_total),
            'records_lost_total': ('counter', 'Records lost on a full kernel queue', lost),
            'spool_dropped_total': ('counter', 'Records or events not written (budget or I/O)', self.spool_dropped),
            'parse_skipped_total': ('counter', 'Packets not parsed (non-IPv4 or short)', skipped),
            'continuity_known': ('gauge', 'No known loss in the last cycle', continuity),
            'events_total': ('counter', 'Observe-only detector events', self.events_total or {'none': 0}),
            'dns_queries_total': ('counter', 'Guest DNS questions compared with the catalog', self.dns_total),
            'dns_ioc_matches_total': ('counter', 'Guest DNS questions matching the catalog', self.dns_matches),
            'dns_records_lost_total': ('counter', 'DNS records lost on a full kernel queue', dns_lost),
            'dns_catalog_fresh': ('gauge', 'Qualified domain catalog loaded and current (D7 active)', catalog_fresh),
            'clock_synced': ('gauge', 'Kernel clock reports NTP synchronisation', int(synced)),
            'clock_maxerror_seconds': ('gauge', 'Kernel clock maximum error estimate',
                                       round(maxerr, 6) if maxerr != float('inf') else -1),
        }
        write_atomic(self.cfg['metrics_file'], metrics_text(m))
        return m


def load_object(cfg):
    pin = Path(cfg['pin_dir'])
    if (pin / 'progs' / PROGRAMS[0]).exists():
        missing = [m for m in MAPS if not (pin / 'maps' / m).exists()] + \
                  [p for p in PROGRAMS if not (pin / 'progs' / p).exists()]
        if missing:
            raise RuntimeError(f'pinned object is an older or partial ABI (missing {missing}); '
                               'run unload, then load')
        return 'already-loaded'
    (pin / 'maps').mkdir(parents=True, exist_ok=True)
    subprocess.run(['bpftool', 'prog', 'loadall', cfg['object'], str(pin / 'progs'),
                    'type', 'tc', 'pinmaps', str(pin / 'maps')], check=True)
    return 'loaded'


def unload(cfg):
    """Detach own programs, verify, then remove only the probe's own pins."""
    pin = Path(cfg['pin_dir'])
    expected = {'progs': set(PROGRAMS), 'maps': set(MAPS)}
    for sub, names in expected.items():
        present = {p.name for p in (pin / sub).iterdir()} if (pin / sub).exists() else set()
        foreign = present - names
        if foreign:
            raise RuntimeError(f'foreign objects in {pin / sub}: {sorted(foreign)}; nothing removed')
    with Probe(cfg, maps=False) as probe:
        detached, failures = probe.detach_all()
        remaining = probe.owned(strict=True)
    if failures or remaining:
        raise RuntimeError(f'detach incomplete (failures={failures}, remaining={sorted(remaining)}); '
                           'pins kept for retry')
    for sub, names in expected.items():
        for name in names:
            (pin / sub / name).unlink(missing_ok=True)
        if (pin / sub).exists():
            (pin / sub).rmdir()
    if pin.exists():
        pin.rmdir()
    return detached


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('command', choices=('load', 'run', 'once', 'status', 'unload'))
    ap.add_argument('--config', default='/etc/cs-public0/flow.json')
    a = ap.parse_args(argv)
    cfg = load_config(a.config if Path(a.config).exists() else None)
    if a.command == 'load':
        print(load_object(cfg))
    elif a.command == 'unload':
        print(json.dumps({'detached': unload(cfg)}))
    elif a.command == 'status':
        print(json.dumps({'pinned': Path(cfg['pin_dir']).exists()}))
    elif a.command == 'once':
        with Probe(cfg) as probe:
            m = probe.cycle()
        print(json.dumps({k: v[2] for k, v in m.items()}))
    else:
        with Probe(cfg) as probe:
            while True:
                t0 = time.monotonic()
                probe.cycle()
                time.sleep(max(0.0, 1.0 - (time.monotonic() - t0)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
