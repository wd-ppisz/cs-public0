#!/usr/bin/env python3
"""Ship flow probe spool records to ClickHouse over HTTPS (ADR-066 E1).

Reads `records-*.jsonl` written by flow_probe.py from a saved byte offset, sends
complete lines in batches with INSERT ... FORMAT JSONEachRow and advances the
offset only after the server confirmed the insert. Every batch carries a
deterministic `insert_deduplication_token` derived from (sensor, file, byte
range, table); the range is written to the state file *before* sending, so a
crash between insert and state update resends exactly the same range and the
server drops the duplicate. Spool files removed by the probe's retention before
they were shipped are counted, never silently skipped.

Standard library only. The password is read from a root-only file; TLS always
verifies the server certificate against the configured name (SNI), also when
connecting by IP address.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import time

ZERO_UUID = '00000000-0000-0000-0000-000000000000'
DEFAULTS = {
    'schema': 'cs-public0-flow-ship-v1',
    'spool_dir': '/var/lib/cs-public0-flow',
    'state_file': '/var/lib/cs-public0-flow-ship/state.json',
    'endpoints': [],            # ["192.0.2.10:8443", ...] (host:port), tried in order
    'server_name': '',          # TLS name verified on every endpoint
    'user': 'probe_writer',
    'password_file': '/etc/cs-public0/clickhouse-probe-writer',
    'database': 'flow',
    'batch_lines': 50000,
    'timeout_seconds': 30,
    'interval_seconds': 5,
    'metrics_file': '',
}
TABLES = {'guest': 'syn_vnet', 'uplink': 'syn_public0'}
EVENTS_FILE = 'events.jsonl'
EVENTS_TABLE = 'public0_events'
# Wazuh SIDs from the event contract (behaviour detectors of the flow probe).
DETECTOR_SID = {'D1_new_conn_rate': 100321, 'D2_distinct_dst': 100322, 'D3_service_fanout': 100323,
                'D4': 100324, 'D5': 100325, 'D6': 100326, 'D7_dns_ioc': 100327}
ZERO_IP = '0.0.0.0'


def load_config(path):
    cfg = dict(DEFAULTS)
    if path:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        unknown = set(data) - set(DEFAULTS)
        if unknown:
            raise ValueError(f'unknown config keys: {sorted(unknown)}')
        cfg.update(data)
    if cfg['schema'] != DEFAULTS['schema']:
        raise ValueError('unsupported config schema')
    if not cfg['endpoints'] or not cfg['server_name']:
        raise ValueError('endpoints and server_name are required')
    for key in ('batch_lines', 'timeout_seconds', 'interval_seconds'):
        if not isinstance(cfg[key], int) or cfg[key] <= 0:
            raise ValueError(f'{key} must be a positive integer')
    return cfg


def to_row(rec):
    """Spool record -> (table, ClickHouse row) or None for unknown sides."""
    table = TABLES.get(rec.get('side'))
    if table is None:
        return None
    ts = rec['ts_ns']
    row = {
        'ts': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts // 1_000_000_000))
              + '.%06d' % (ts % 1_000_000_000 // 1000),
        'host': rec.get('sensor') or '',
        'iface': rec.get('iface') or '',
        'src_ip': rec['src_ip'], 'src_port': rec['src_port'],
        'dst_ip': rec['dst_ip'], 'dst_port': rec['dst_port'],
        'isn': rec['isn'], 'ttl': rec['ttl'], 'ip_id': rec['ip_id'],
    }
    if table == 'syn_vnet':
        row['vm_uuid'] = rec.get('vm_uuid') or ZERO_UUID
    return table, row


def _ts_ns(ns):
    """Integer nanoseconds -> 'YYYY-MM-DD hh:mm:ss.ffffff' (truncated to µs, no float)."""
    ns = int(ns)
    return (time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ns // 1_000_000_000))
            + '.%06d' % (ns % 1_000_000_000 // 1000))


def event_row(raw, sensor_hint=''):
    """Probe detector event (one events.jsonl line) -> flow.public0_events row.

    event_id is the SHA-256 of the canonical event, so a resent or re-read event
    collapses in the ReplacingMergeTree; record_sha256 is the hash of the exact
    spool line (evidence reference). The probe knows the VM from the tap
    interface, so attribution needs no NAT correlation."""
    ev = json.loads(raw)
    detector = ev.get('detector', '')
    sid = DETECTOR_SID.get(detector)
    if sid is None:
        return None
    observed_ns = int(ev['observed_ns']) if 'observed_ns' in ev else int(ev['ts']) * 1_000_000_000
    vm = ev.get('vm_uuid') or None
    src_ip, dst_ip, dst_port = ZERO_IP, ZERO_IP, 0
    if detector == 'D7_dns_ioc':
        src_ip, dst_ip, dst_port = ev.get('src_ip') or ZERO_IP, ev.get('resolver_ip') or ZERO_IP, 53
    canon = json.dumps(ev, sort_keys=True, separators=(',', ':')).encode()
    return {
        'event_id': hashlib.sha256(canon).hexdigest(),
        'observed_at': _ts_ns(observed_ns),
        'host': ev.get('sensor') or sensor_hint,
        'source': 'flow',
        'category': detector,
        'direction': 'egress',
        'src_ip': src_ip, 'src_port': 0,
        'dst_ip': dst_ip, 'dst_port': dst_port,
        'sid': sid,
        'record_sha256': hashlib.sha256(raw).hexdigest(),
        'vm_uuid': vm,
        'attribution': 'vm' if vm else 'unresolved',
    }


def read_batch(path, offset, max_lines):
    """Complete lines from `offset`; returns (lines, end_offset)."""
    with open(path, 'rb') as f:
        return _batch_from(f, offset, max_lines)


def _batch_from(f, offset, max_lines):
    lines = []
    f.seek(offset)
    end = offset
    for raw in f:
        if not raw.endswith(b'\n'):
            break  # line still being written by the probe
        lines.append(raw)
        end += len(raw)
        if len(lines) >= max_lines:
            break
    return lines, end


def token(sensor, name, start, end, table):
    return hashlib.sha256(f'{sensor}|{name}|{start}|{end}|{table}'.encode()).hexdigest()


class ClickHouse:
    def __init__(self, cfg):
        self.cfg = cfg
        password = Path(cfg['password_file']).read_text(encoding='utf-8').strip()
        cred = f"{cfg['user']}:{password}".encode()
        self.auth = 'Basic ' + base64.b64encode(cred).decode()
        self.ctx = ssl.create_default_context()
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def _conn(self, endpoint):
        host, port = endpoint.rsplit(':', 1)
        timeout = self.cfg['timeout_seconds']
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        tls = self.ctx.wrap_socket(sock, server_hostname=self.cfg['server_name'])
        conn = http.client.HTTPSConnection(self.cfg['server_name'], int(port), timeout=timeout)
        conn.sock = tls
        return conn

    def insert(self, table, rows, dedup_token):
        query = f"INSERT INTO {self.cfg['database']}.{table} FORMAT JSONEachRow"
        params = ('query=' + _quote(query) + '&insert_deduplication_token=' + dedup_token
                  + '&date_time_input_format=basic')
        body = b''.join(json.dumps(r, separators=(',', ':')).encode() + b'\n' for r in rows)
        last = None
        for endpoint in self.cfg['endpoints']:
            try:
                conn = self._conn(endpoint)
                try:
                    conn.request('POST', '/?' + params, body=body,
                                 headers={'Authorization': self.auth,
                                          'Content-Type': 'application/x-ndjson'})
                    resp = conn.getresponse()
                    text = resp.read(2048).decode(errors='replace')
                finally:
                    conn.close()
            except (OSError, ssl.SSLError, http.client.HTTPException) as e:
                last = f'{endpoint}: {type(e).__name__}'
                continue
            if resp.status == 200:
                return endpoint
            # An authenticated server refused the data: do not try another node.
            raise RuntimeError(f'{endpoint}: HTTP {resp.status}: {text.strip()[:300]}')
        raise ConnectionError(last or 'no endpoint')


def _quote(s):
    from urllib.parse import quote
    return quote(s, safe='')


def load_state(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {'offsets': {}, 'pending': None, 'shipped_rows': 0, 'unshipped_files': 0}


def save_state(path, state):
    p = Path(path)
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = p.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)


def ship_once(cfg, client, state, sensor_hint=''):
    """Ship every complete line available now. Returns rows sent in this call."""
    spool = Path(cfg['spool_dir'])
    names = sorted(p.name for p in spool.glob('records-*.jsonl'))
    offsets = state.setdefault('offsets', {})
    sizes = state.setdefault('sizes', {})
    for gone in [n for n in offsets if n not in names]:
        # Retention removed a file; data past the shipped offset is lost.
        if sizes.pop(gone, 0) > offsets.pop(gone):
            state['unshipped_files'] = state.get('unshipped_files', 0) + 1
    sent = 0
    for name in names:
        path = spool / name
        try:
            sizes[name] = path.stat().st_size
        except FileNotFoundError:
            continue
        offsets.setdefault(name, 0)
        while True:
            pending = state.get('pending')
            if pending and pending['file'] == name:
                start, end = pending['start'], pending['end']
                lines = read_range(path, start, end)
            else:
                start = offsets.get(name, 0)
                lines, end = read_batch(path, start, cfg['batch_lines'])
                if not lines:
                    offsets[name] = start
                    break
                state['pending'] = {'file': name, 'start': start, 'end': end}
                save_state(cfg['state_file'], state)
            by_table = {}
            sensor = sensor_hint
            for raw in lines:
                rec = json.loads(raw)
                sensor = sensor or rec.get('sensor', '')
                out = to_row(rec)
                if out:
                    by_table.setdefault(out[0], []).append(out[1])
            for table, rows in sorted(by_table.items()):
                client.insert(table, rows, token(sensor, name, start, end, table))
                sent += len(rows)
            offsets[name] = end
            state['pending'] = None
            state['shipped_rows'] = state.get('shipped_rows', 0) + sum(map(len, by_table.values()))
            save_state(cfg['state_file'], state)
    return sent


def _ino(path):
    try:
        return path.stat().st_ino
    except FileNotFoundError:
        return None


def ship_events(cfg, client, state, sensor_hint=''):
    """Ship probe detector events (events.jsonl) to flow.public0_events.

    The probe rotates events.jsonl to events.jsonl.1 by rename, so the offset is
    bound to the file's inode: after a rotation the remainder of the old inode
    is read from events.jsonl.1 before the new file starts at 0. The same
    pending-range rule as for records makes a crash resend an identical batch
    with an identical deduplication token."""
    spool = Path(cfg['spool_dir'])
    cur, old = spool / EVENTS_FILE, spool / (EVENTS_FILE + '.1')
    if 'events' not in state:
        # First run (also: upgrade of a running probe): an existing rotated file is
        # shipped in full before the current one, so nothing waits to be overwritten.
        state['events'] = {'ino': _ino(old), 'offset': 0}
    es = state['events']
    sent = 0
    cur_ino = _ino(cur)
    if es['ino'] is not None and cur_ino != es['ino']:
        old_ino = _ino(old)
        if old_ino == es['ino']:
            sent += _ship_events_file(cfg, client, state, old, es['ino'], sensor_hint)
        else:
            # Rotated twice (or removed) before the remainder was shipped: counted, not skipped.
            state['unshipped_files'] = state.get('unshipped_files', 0) + 1
            state['events_pending'] = None
            if old_ino is not None and old_ino != cur_ino:
                # The newer rotated file is still on disk: ship it whole before it goes too.
                es.update(ino=old_ino, offset=0)
                save_state(cfg['state_file'], state)
                sent += _ship_events_file(cfg, client, state, old, old_ino, sensor_hint)
        es.update(ino=None, offset=0)
        state['events_pending'] = None
        save_state(cfg['state_file'], state)
    if cur_ino is None:
        return sent
    if es['ino'] is None:
        es.update(ino=cur_ino, offset=0)
    sent += _ship_events_file(cfg, client, state, cur, cur_ino, sensor_hint)
    return sent


def _ship_events_file(cfg, client, state, path, ino, sensor_hint):
    """Ship from one open descriptor whose inode was verified: a rename by the
    probe during the inserts cannot switch the file under the saved offset."""
    try:
        f = open(path, 'rb')
    except FileNotFoundError:
        return 0
    with f:
        if os.fstat(f.fileno()).st_ino != ino:
            return 0  # rotated between stat and open; the next pass ships it from .1
        return _ship_events_fd(cfg, client, state, f, ino, sensor_hint)


def _ship_events_fd(cfg, client, state, f, ino, sensor_hint):
    es = state['events']
    sent = 0
    while True:
        pending = state.get('events_pending')
        if pending and pending['ino'] == ino:
            start, end = pending['start'], pending['end']
            f.seek(start)
            data = f.read(end - start)
            if len(data) != end - start or not data.endswith(b'\n'):
                raise RuntimeError('events: pending range no longer readable')
            lines = data.splitlines(keepends=True)
        else:
            start = es['offset']
            lines, end = _batch_from(f, start, cfg['batch_lines'])
            if not lines:
                return sent
            state['events_pending'] = {'ino': ino, 'start': start, 'end': end}
            save_state(cfg['state_file'], state)
        rows = [r for r in (event_row(raw, sensor_hint) for raw in lines) if r]
        if rows:
            # Inode numbers can be reused after a rotation was deleted: the batch
            # content hash keeps a token unique to these bytes (and identical on resend).
            body = hashlib.sha256(b''.join(lines)).hexdigest()
            client.insert(EVENTS_TABLE, rows,
                          token(rows[0]['host'], f'events:{ino}:{body}', start, end, EVENTS_TABLE))
            sent += len(rows)
        es['offset'] = end
        state['events_pending'] = None
        state['shipped_events'] = state.get('shipped_events', 0) + len(rows)
        save_state(cfg['state_file'], state)


def read_range(path, start, end):
    """Exactly the bytes [start, end) as lines; the range was complete when recorded."""
    with open(path, 'rb') as f:
        f.seek(start)
        data = f.read(end - start)
    if len(data) != end - start or not data.endswith(b'\n'):
        raise RuntimeError(f'{Path(path).name}: pending range no longer readable')
    return data.splitlines(keepends=True)


def write_metrics(cfg, state, ok, last_error):
    if not cfg['metrics_file']:
        return
    lines = [
        '# TYPE cs_public0_flow_ship_rows_total counter',
        f"cs_public0_flow_ship_rows_total {state.get('shipped_rows', 0)}",
        '# TYPE cs_public0_flow_ship_events_total counter',
        f"cs_public0_flow_ship_events_total {state.get('shipped_events', 0)}",
        '# TYPE cs_public0_flow_ship_unshipped_files_total counter',
        f"cs_public0_flow_ship_unshipped_files_total {state.get('unshipped_files', 0)}",
        '# TYPE cs_public0_flow_ship_up gauge',
        f'cs_public0_flow_ship_up {1 if ok else 0}',
        '# TYPE cs_public0_flow_ship_last_success_unix_seconds gauge',
        f"cs_public0_flow_ship_last_success_unix_seconds {state.get('last_success', 0)}",
    ]
    p = Path(cfg['metrics_file'])
    tmp = p.with_suffix('.tmp')
    tmp.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    os.replace(tmp, p)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('command', choices=('once', 'run'))
    ap.add_argument('--config', default='/etc/cs-public0/flow-ship.json')
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    client = ClickHouse(cfg)
    state = load_state(cfg['state_file'])
    while True:
        ok, err = True, ''
        try:
            n = ship_once(cfg, client, state)
            n += ship_events(cfg, client, state)
            state['last_success'] = int(time.time())
            save_state(cfg['state_file'], state)
            if a.command == 'once':
                print(json.dumps({'sent': n, 'shipped_rows': state['shipped_rows'],
                                  'unshipped_files': state.get('unshipped_files', 0)}))
        except (OSError, RuntimeError, ValueError) as e:
            ok, err = False, f'{type(e).__name__}: {e}'
            print(json.dumps({'error': err}), file=sys.stderr, flush=True)
        write_metrics(cfg, state, ok, err)
        if a.command == 'once':
            return 0 if ok else 1
        time.sleep(cfg['interval_seconds'])


if __name__ == '__main__':
    sys.exit(main())
