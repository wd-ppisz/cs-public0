"""Offline checks of the flow probe: kernel ABI layouts, decoding, libvirt
mapping, observe-only detectors and configuration bounds."""
from pathlib import Path
import os
import re
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import flow_probe as fp

SRC = (Path(__file__).resolve().parents[1] / 'bpf' / 'flow_probe.c').read_text(encoding='utf-8')

DOMSTATUS = """<domstatus state='running'>
  <domain type='kvm'>
    <name>i-2-77-VM</name>
    <uuid>3f1c2d4e-0000-4000-8000-000000000001</uuid>
    <devices>
      <interface type='bridge'><mac address='02:01:00:aa:00:01'/><target dev='vnet7'/></interface>
      <interface type='bridge'><mac address='02:01:00:bb:00:02'/></interface>
    </devices>
  </domain>
</domstatus>"""


class Layout(unittest.TestCase):
    def test_record_matches_c_struct(self):
        # u64 + 4*u32 + 3*u16 + 2*u8 + u32 = 36, padded to 8-byte alignment.
        self.assertEqual(fp.RECORD.size, 40)
        self.assertIn('__u32 pad[2];', SRC)
        self.assertIn('_Static_assert(sizeof(struct flow_record) == 40', SRC)
        self.assertIn('__builtin_memset(&rec, 0, sizeof(rec));', SRC)

    def test_counters_match_c_struct(self):
        self.assertEqual(fp.COUNTERS.size, 8 * (6 + 7))
        self.assertIn('#define SVC_MAX 7', SRC)

    def test_programs_never_terminate_or_drop(self):
        returns = re.findall(r'return\s+([^;]+);', SRC)
        verdicts = {r for r in returns if r.startswith('TC') or r.lstrip('-').isdigit()}
        self.assertEqual(verdicts, {'TCX_NEXT'})
        self.assertNotIn('bpf_redirect', SRC)
        self.assertNotIn('bpf_skb_store_bytes', SRC)

    def test_program_and_map_names_match(self):
        for name in fp.PROGRAMS:
            self.assertIn(f'int {name}(', SRC)
        for name in fp.MAPS:
            self.assertIn(f'}} {name} SEC(".maps")', SRC)

    def test_attach_attr_sizes(self):
        self.assertEqual(len(fp.prog_attach_attr(5, 9, fp.TCX_INGRESS)), 32)
        self.assertEqual(struct.unpack('<III', fp.prog_attach_attr(5, 9, 46)[:12]), (5, 9, 46))


class Decode(unittest.TestCase):
    def test_record(self):
        saddr = struct.unpack('<I', bytes([10, 1, 2, 3]))[0]
        daddr = struct.unpack('<I', bytes([198, 51, 100, 7]))[0]
        raw = fp.RECORD.pack(5_000_000_000, 12, saddr, daddr, 0xDEADBEEF, 40000, 22, 777, 64, 1, 0, 0)
        rec = fp.decode_record(raw, 1_000_000_000)
        self.assertEqual(rec, {'ts_ns': 4_000_000_000, 'ifindex': 12, 'side': 'guest',
                               'src_ip': '10.1.2.3', 'src_port': 40000, 'dst_ip': '198.51.100.7',
                               'dst_port': 22, 'isn': 0xDEADBEEF, 'ttl': 64, 'ip_id': 777})

    def test_counters(self):
        raw = fp.COUNTERS.pack(*range(1, 14))
        c = fp.decode_counters(raw)
        self.assertEqual(c['packets_out'], 1)
        self.assertEqual(c['rst_in'], 6)
        self.assertEqual(c['svc_syn']['ssh'], 8)


class Libvirt(unittest.TestCase):
    def test_domstatus(self):
        uuid, name, nics = fp.parse_domain_xml(DOMSTATUS)
        self.assertEqual((uuid, name), ('3f1c2d4e-0000-4000-8000-000000000001', 'i-2-77-VM'))
        self.assertEqual(nics, [('vnet7', '02:01:00:aa:00:01')])

    def test_tap_map_and_system_vm(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'i-2-77-VM.xml').write_text(DOMSTATUS, encoding='utf-8')
            Path(d, 'r-9-VM.xml').write_text(DOMSTATUS.replace('i-2-77-VM', 'r-9-VM')
                                             .replace('vnet7', 'vnet8'), encoding='utf-8')
            Path(d, 'broken.xml').write_text('<domstatus>', encoding='utf-8')
            m = fp.tap_map(d)
        self.assertFalse(m['vnet7']['system_vm'])
        self.assertTrue(m['vnet8']['system_vm'])


class Detectors(unittest.TestCase):
    T = {'D1_new_conn_rate': 5, 'D2_distinct_dst': 50, 'D3_service_fanout': 20, 'service_ports': [22]}

    def test_ssh_fanout_triggers_d3_not_d2(self):
        w = fp.Window(60)
        for i in range(30):
            w.add('vm-a', 100 + i, f'203.0.113.{i}', 22)
        ev = {e['detector'] for e in w.evaluate(130, self.T)}
        self.assertIn('D3_service_fanout', ev)
        self.assertNotIn('D2_distinct_dst', ev)

    def test_quiet_vm_and_window_expiry(self):
        w = fp.Window(60)
        w.add('vm-b', 10, '203.0.113.1', 443)
        self.assertEqual(w.evaluate(20, self.T), [])
        self.assertEqual(w.evaluate(200, self.T), [])
        self.assertNotIn('vm-b', w.rows)


class Config(unittest.TestCase):
    def test_defaults_and_rejections(self):
        self.assertEqual(fp.load_config(None)['guest_prefix'], 'vnet')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'c.json')
            for bad in ('{"nope": 1}', '{"pin_dir": "/tmp/x"}', '{"uplink": "eth0; rm"}',
                        '{"guest_prefix": "../x"}'):
                p.write_text(bad, encoding='utf-8')
                with self.assertRaises(ValueError, msg=bad):
                    fp.load_config(p)

    def test_metrics_have_no_address_or_vm_labels(self):
        text = fp.metrics_text({'up': ('gauge', 'x', 1),
                                'events_total': ('counter', 'x', {'D1_new_conn_rate': 2})})
        self.assertIn('cs_public0_flow_events_total{detector="D1_new_conn_rate"} 2', text)
        self.assertNotRegex(text, r'vm_uuid|ip=|src=|dst=')


class Spool(unittest.TestCase):
    @unittest.skipUnless(hasattr(fp.os, 'geteuid'), 'POSIX permissions')
    def test_private_dir_and_files(self):
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d, 'spool')
            sp.mkdir(mode=0o755)
            fp.secure_dir(sp)
            self.assertEqual(sp.stat().st_mode & 0o777, 0o700)
            f = sp / 'records-x.jsonl'
            f.write_text('', encoding='utf-8')
            f.chmod(0o644)
            with fp.open_private(f) as h:
                h.write('{}' + chr(10))
            self.assertEqual(f.stat().st_mode & 0o777, 0o600)
            link = sp / 'link.jsonl'
            link.symlink_to(f)
            with self.assertRaises(OSError):
                fp.open_private(link)
            hard = sp / 'hard.jsonl'
            os.link(f, hard)
            with self.assertRaises(ValueError):
                fp.open_private(hard)
            hard.unlink()
            other = Path(d, 'dirlink')
            other.symlink_to(sp)
            with self.assertRaises(ValueError):
                fp.secure_dir(other)

    def test_prune_by_count_and_bytes_keeps_current(self):
        with tempfile.TemporaryDirectory() as d:
            files = [Path(d, f'records-2026111{i}T00.jsonl') for i in range(5)]
            for f in files:
                f.write_bytes(b'x' * 100)
            self.assertEqual(fp.prune_spool(d, files[-1], max_files=3, max_bytes=10**6), 2)
            self.assertEqual(fp.prune_spool(d, files[-1], max_files=10, max_bytes=150), 2)
            self.assertEqual(sorted(Path(d).glob('*.jsonl')), [files[-1]])

    def test_cooldown(self):
        c = fp.Cooldown(300)
        self.assertTrue(c.allow(('vm', 'D1'), 0))
        self.assertFalse(c.allow(('vm', 'D1'), 299))
        self.assertTrue(c.allow(('vm', 'D2'), 299))
        self.assertTrue(c.allow(('vm', 'D1'), 301))

    def test_unload_refuses_foreign_pins_before_touching_kernel(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = dict(fp.DEFAULTS, pin_dir=d)
            Path(d, 'progs').mkdir()
            Path(d, 'progs', 'someone_else').write_text('', encoding='utf-8')
            with self.assertRaises(RuntimeError):
                fp.unload(cfg)
            self.assertTrue(Path(d, 'progs', 'someone_else').exists())

    def test_budget_config_validation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'c.json')
            for bad in ('{"spool_max_bytes": 0}', '{"file_max_bytes": true}',
                        '{"file_max_bytes": 3000000000}'):
                p.write_text(bad, encoding='utf-8')
                with self.assertRaises(ValueError, msg=bad):
                    fp.load_config(p)


if __name__ == '__main__':
    unittest.main()
