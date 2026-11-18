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
