import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import flow_ship as fs  # noqa: E402

REC = {'ts_ns': 1794946521473991673, 'ifindex': 129, 'side': 'guest', 'src_ip': '198.51.100.11',
       'src_port': 49548, 'dst_ip': '192.0.2.7', 'dst_port': 443, 'isn': 669044664, 'ttl': 64,
       'ip_id': 33181, 'iface': 'vnet7', 'vm_uuid': '11111111-2222-4333-8444-555555555555',
       'sensor': 'lab'}


class FakeClient:
    def __init__(self, fail_after=None):
        self.calls = []
        self.fail_after = fail_after

    def insert(self, table, rows, dedup_token):
        if self.fail_after is not None and len(self.calls) >= self.fail_after:
            raise ConnectionError('down')
        self.calls.append((table, len(rows), dedup_token))


def line(**kw):
    return json.dumps(dict(REC, **kw)) + '\n'


class Ship(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        root = Path(self.d.name)
        (root / 'spool').mkdir()
        self.spool = root / 'spool'
        self.cfg = dict(
            fs.DEFAULTS, spool_dir=str(self.spool), state_file=str(root / 'st' / 'state.json'),
            endpoints=['127.0.0.1:1'], server_name='x.example', batch_lines=2)

    def tearDown(self):
        self.d.cleanup()

    def test_row_mapping(self):
        table, row = fs.to_row(REC)
        self.assertEqual(table, 'syn_vnet')
        self.assertEqual(row['ts'], '2026-11-17 20:15:21.473991')
        self.assertEqual(row['host'], 'lab')
        table, row = fs.to_row(dict(REC, side='uplink'))
        self.assertEqual(table, 'syn_public0')
        self.assertNotIn('vm_uuid', row)
        self.assertEqual(fs.to_row(dict(REC, vm_uuid=None))[1]['vm_uuid'], fs.ZERO_UUID)
        self.assertIsNone(fs.to_row(dict(REC, side='unknown')))

    def test_incremental_batches_and_partial_line(self):
        f = self.spool / 'records-20261117T20.jsonl'
        tail = line(isn=9)
        f.write_text(line() + line(side='uplink') + line(isn=1) + tail[:20], encoding='utf-8')
        c = FakeClient()
        st = fs.load_state(self.cfg['state_file'])
        self.assertEqual(fs.ship_once(self.cfg, c, st), 3)
        self.assertEqual(sorted(t for t, _, _ in c.calls), ['syn_public0', 'syn_vnet', 'syn_vnet'])
        self.assertLess(st['offsets'][f.name], f.stat().st_size)  # partial line not consumed
        self.assertIsNone(st['pending'])
        self.assertEqual(fs.ship_once(self.cfg, FakeClient(), st), 0)  # nothing complete yet
        with f.open('a', encoding='utf-8') as h:
            h.write(tail[20:])
        self.assertEqual(fs.ship_once(self.cfg, FakeClient(), st), 1)
        self.assertEqual(st['offsets'][f.name], f.stat().st_size)

    def test_crash_resends_identical_range_and_token(self):
        f = self.spool / 'records-20261117T20.jsonl'
        f.write_text(line() + line(isn=2), encoding='utf-8')
        st = fs.load_state(self.cfg['state_file'])
        with self.assertRaises(ConnectionError):
            fs.ship_once(self.cfg, FakeClient(fail_after=0), st)
        pending = fs.load_state(self.cfg['state_file'])['pending']
        self.assertEqual((pending['start'], pending['end']), (0, f.stat().st_size))
        # More data arrives before the retry: the retry still sends the recorded range only.
        with f.open('a', encoding='utf-8') as h:
            h.write(line(isn=3))
        st = fs.load_state(self.cfg['state_file'])
        c = FakeClient()
        fs.ship_once(self.cfg, c, st)
        first = c.calls[0]
        self.assertEqual(first[1], 2)
        self.assertEqual(first[2], fs.token('lab', f.name, 0, pending['end'], 'syn_vnet'))
        self.assertEqual(sum(n for _, n, _ in c.calls), 3)

    def test_removed_unshipped_file_is_counted(self):
        f = self.spool / 'records-20261117T19.jsonl'
        f.write_text(line() + line(isn=2) + line(isn=3), encoding='utf-8')
        st = fs.load_state(self.cfg['state_file'])
        with self.assertRaises(ConnectionError):
            fs.ship_once(self.cfg, FakeClient(fail_after=0), st)
        st['pending'] = None
        f.unlink()
        fs.ship_once(self.cfg, FakeClient(), st)
        self.assertEqual(st['unshipped_files'], 1)

    # --- detector events -> flow.public0_events ---------------------------------
    D1 = {'detector': 'D1_new_conn_rate', 'vm_uuid': REC['vm_uuid'], 'value': 61.2, 'threshold': 50,
          'window_s': 60, 'ts': 1794946521, 'mode': 'observe', 'sensor': 'lab'}
    D7 = {'detector': 'D7_dns_ioc', 'vm_uuid': None, 'domain': 'bad.example', 'iface': 'vnet9',
          'src_ip': '198.51.100.12', 'resolver_ip': '192.0.2.53', 'observed_ns': 1794946521500000000,
          'ioc': {'source': 'threatfox', 'match': 'exact'}, 'ts': 1794946522, 'mode': 'observe',
          'sensor': 'lab'}

    def ev(self, *events):
        return ''.join(json.dumps(e) + '\n' for e in events).encode()  # bytes: no CRLF on Windows

    def test_event_row_mapping(self):
        raw = json.dumps(self.D1).encode() + b'\n'
        row = fs.event_row(raw)
        self.assertEqual((row['source'], row['category'], row['sid']), ('flow', 'D1_new_conn_rate', 100321))
        self.assertEqual((row['vm_uuid'], row['attribution'], row['host']), (REC['vm_uuid'], 'vm', 'lab'))
        self.assertEqual(row['observed_at'], '2026-11-17 20:15:21.000000')
        self.assertEqual((row['src_ip'], row['dst_ip'], row['dst_port']), ('0.0.0.0', '0.0.0.0', 0))
        self.assertEqual(len(row['event_id']), 64)
        self.assertEqual(row['record_sha256'], __import__('hashlib').sha256(raw).hexdigest())
        # Same event, different key order -> same event_id (canonical form).
        reordered = json.dumps(dict(reversed(list(self.D1.items())))).encode() + b'\n'
        self.assertEqual(fs.event_row(reordered)['event_id'], row['event_id'])
        d7 = fs.event_row(json.dumps(self.D7).encode() + b'\n')
        self.assertEqual((d7['sid'], d7['attribution'], d7['vm_uuid']), (100327, 'unresolved', None))
        self.assertEqual((d7['src_ip'], d7['dst_ip'], d7['dst_port']), ('198.51.100.12', '192.0.2.53', 53))
        self.assertEqual(d7['observed_at'], '2026-11-17 20:15:21.500000')
        self.assertIsNone(fs.event_row(json.dumps({'detector': 'X', 'ts': 1}).encode()))

    def test_events_ship_incrementally_with_token(self):
        f = self.spool / fs.EVENTS_FILE
        f.write_bytes(self.ev(self.D1, self.D7, dict(self.D1, value=70)))
        st = fs.load_state(self.cfg['state_file'])
        c = FakeClient()
        self.assertEqual(fs.ship_events(self.cfg, c, st), 3)  # batch_lines=2 -> two inserts
        self.assertEqual([(t, n) for t, n, _ in c.calls], [('public0_events', 2), ('public0_events', 1)])
        ino = f.stat().st_ino
        body = __import__('hashlib').sha256(self.ev(self.D1, self.D7)).hexdigest()
        self.assertEqual(c.calls[0][2], fs.token('lab', f'events:{ino}:{body}', 0, len(self.ev(self.D1, self.D7)),
                                                 'public0_events'))
        self.assertEqual(fs.ship_events(self.cfg, FakeClient(), st), 0)
        self.assertEqual(st['shipped_events'], 3)

    def test_events_crash_resends_identical_range(self):
        f = self.spool / fs.EVENTS_FILE
        f.write_bytes(self.ev(self.D1))
        st = fs.load_state(self.cfg['state_file'])
        with self.assertRaises(ConnectionError):
            fs.ship_events(self.cfg, FakeClient(fail_after=0), st)
        with f.open('ab') as h:
            h.write(self.ev(self.D7))
        st = fs.load_state(self.cfg['state_file'])
        c = FakeClient()
        fs.ship_events(self.cfg, c, st)
        end = len(self.ev(self.D1))
        self.assertEqual(c.calls[0][1], 1)
        body = __import__('hashlib').sha256(self.ev(self.D1)).hexdigest()
        self.assertEqual(c.calls[0][2], fs.token('lab', f'events:{f.stat().st_ino}:{body}', 0, end,
                                                 'public0_events'))
        self.assertEqual(sum(n for _, n, _ in c.calls), 2)

    def test_events_rotation_ships_remainder_then_new_file(self):
        f = self.spool / fs.EVENTS_FILE
        f.write_bytes(self.ev(self.D1))
        st = fs.load_state(self.cfg['state_file'])
        fs.ship_events(self.cfg, FakeClient(), st)
        with f.open('ab') as h:
            h.write(self.ev(dict(self.D1, value=80)))
        f.replace(self.spool / (fs.EVENTS_FILE + '.1'))  # probe rotation by rename
        f.write_bytes(self.ev(self.D7))
        c = FakeClient()
        self.assertEqual(fs.ship_events(self.cfg, c, st), 2)
        self.assertEqual(st.get('unshipped_files', 0), 0)
        self.assertEqual(st['events']['ino'], f.stat().st_ino)

    def test_events_lost_rotation_is_counted(self):
        f = self.spool / fs.EVENTS_FILE
        f.write_bytes(self.ev(self.D1))
        st = fs.load_state(self.cfg['state_file'])
        fs.ship_events(self.cfg, FakeClient(), st)
        f.unlink()
        f.write_bytes(self.ev(self.D7))
        if f.stat().st_ino == st['events']['ino']:
            self.skipTest('filesystem reused the inode')
        self.assertEqual(fs.ship_events(self.cfg, FakeClient(), st), 1)
        self.assertEqual(st['unshipped_files'], 1)

    def test_event_time_is_integer_truncated(self):
        row = fs.event_row(json.dumps(dict(self.D7, observed_ns=1794946521999999600)).encode())
        self.assertEqual(row['observed_at'], '2026-11-17 20:15:21.999999')

    def test_first_run_ships_existing_rotated_file(self):
        (self.spool / (fs.EVENTS_FILE + '.1')).write_bytes(self.ev(self.D1, dict(self.D1, value=90)))
        (self.spool / fs.EVENTS_FILE).write_bytes(self.ev(self.D7))
        st = fs.load_state(self.cfg['state_file'])
        self.assertEqual(fs.ship_events(self.cfg, FakeClient(), st), 3)
        self.assertEqual(st.get('unshipped_files', 0), 0)
        self.assertEqual(st['events']['ino'], (self.spool / fs.EVENTS_FILE).stat().st_ino)

    def test_events_file_switched_under_name_is_not_read(self):
        f = self.spool / fs.EVENTS_FILE
        f.write_bytes(self.ev(self.D1))
        st = fs.load_state(self.cfg['state_file'])
        st['events'] = {'ino': f.stat().st_ino + 12345, 'offset': 0}
        c = FakeClient()
        # Verified-inode read: a different file behind the same name yields nothing.
        self.assertEqual(fs._ship_events_file(self.cfg, c, st, f, st['events']['ino'], ''), 0)
        self.assertEqual(c.calls, [])

    def test_double_rotation_ships_surviving_rotated_file(self):
        f, old = self.spool / fs.EVENTS_FILE, self.spool / (fs.EVENTS_FILE + '.1')
        f.write_bytes(self.ev(self.D1))
        st = fs.load_state(self.cfg['state_file'])
        fs.ship_events(self.cfg, FakeClient(), st)
        a_ino = st['events']['ino']
        f.write_bytes(self.ev(self.D1, dict(self.D1, value=81)))  # A grows; then two rotations
        keep = self.spool / 'keep-A'
        f.replace(keep)                                        # A leaves (kept so the inode is not reused)
        f.write_bytes(self.ev(dict(self.D1, value=82), dict(self.D1, value=83)))  # B
        f.replace(old)                                         # B -> .1
        f.write_bytes(self.ev(self.D7))                        # C
        if a_ino in (old.stat().st_ino, f.stat().st_ino):
            self.skipTest('filesystem reused the inode')
        c = FakeClient()
        self.assertEqual(fs.ship_events(self.cfg, c, st), 3)  # all of B + C
        self.assertEqual(st['unshipped_files'], 1)            # the rest of A is counted

    def test_config_requires_endpoint_and_name(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'c.json')
            p.write_text('{}', encoding='utf-8')
            with self.assertRaises(ValueError):
                fs.load_config(p)
            p.write_text(json.dumps({'endpoints': ['h:1'], 'server_name': 'n', 'extra': 1}),
                         encoding='utf-8')
            with self.assertRaises(ValueError):
                fs.load_config(p)


if __name__ == '__main__':
    unittest.main()
