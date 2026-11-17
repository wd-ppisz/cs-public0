"""Offline checks of the flow probe: kernel ABI layouts, decoding, libvirt
mapping, observe-only detectors and configuration bounds."""
from pathlib import Path
import json
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


def dns_query(name, flags=0x0100, qd=1):
    body = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\x00\x00\x01\x00\x01'
    return b'\x12\x34' + flags.to_bytes(2, 'big') + qd.to_bytes(2, 'big') + b'\x00' * 6 + body


def catalog_value(now, domains=('bad.example',), expires_in=3600):
    return {'schema': 'cs-public0-domain-catalog-v1', 'source': 'threatfox', 'domains': sorted(domains),
            'sha256': 'a' * 64, 'fetched_unix': now - 60, 'published_unix': now - 120,
            'expires_unix': now + expires_in}


class Dns(unittest.TestCase):
    def test_dns_record_layout(self):
        self.assertEqual(fp.DNS_RECORD.size, 160)
        self.assertIn('_Static_assert(sizeof(struct dns_record) == 160', SRC)
        self.assertIn('flow_dns', fp.MAPS)
        self.assertIn('emit_dns(skb, ip, l4)', SRC)

    def test_parse_query_name(self):
        self.assertEqual(fp.parse_qname(dns_query('Bad.Example')), 'bad.example')
        self.assertEqual(fp.parse_qname(dns_query('a.b.c.example')), 'a.b.c.example')

    def test_reject_response_opcode_compression_and_garbage(self):
        self.assertIsNone(fp.parse_qname(dns_query('bad.example', flags=0x8180)))  # response
        self.assertIsNone(fp.parse_qname(dns_query('bad.example', flags=0x2800)))  # UPDATE opcode
        self.assertIsNone(fp.parse_qname(dns_query('bad.example', qd=0)))
        compressed = dns_query('x.example')[:12] + b'\xc0\x0c\x00\x01\x00\x01'
        self.assertIsNone(fp.parse_qname(compressed))
        self.assertIsNone(fp.parse_qname(dns_query('a' * 64 + '.example')))
        self.assertIsNone(fp.parse_qname(dns_query('bad.example')[:20]))  # truncated
        self.assertIsNone(fp.parse_qname(b'\x00' * 5))

    def test_decode_dns_record(self):
        payload = dns_query('bad.example')
        saddr = struct.unpack('<I', bytes([10, 0, 0, 5]))[0]
        daddr = struct.unpack('<I', bytes([10, 0, 0, 1]))[0]
        raw = fp.DNS_RECORD.pack(2_000_000_000, 7, saddr, daddr, 53000, 53, len(payload), 0,
                                 payload.ljust(128, b'\x00'), 0)
        q = fp.decode_dns(raw, 1_000_000_000)
        self.assertEqual((q['ts_ns'], q['src_ip'], q['dst_ip'], q['qname']),
                         (1_000_000_000, '10.0.0.5', '10.0.0.1', 'bad.example'))

    def test_catalog_shared_contract(self):
        now = int(fp.time.time())
        with tempfile.TemporaryDirectory() as d:
            wrapped = Path(d, 'domain-catalog.json')
            wrapped.write_text(json.dumps({'identity': [1], 'policy': 'x', 'catalog': catalog_value(now)}),
                               encoding='utf-8')
            cat = fp.load_domain_catalog(wrapped)
            self.assertTrue(cat.fresh(now))
            self.assertIn('bad.example', cat.names)
            bare = Path(d, 'bare.json')
            bare.write_text(json.dumps(catalog_value(now, expires_in=-1)), encoding='utf-8')
            expired = fp.load_domain_catalog(bare)  # well-formed but past expiry: D7 pauses
            self.assertFalse(expired.fresh(now))
            bad = Path(d, 'bad.json')
            bad.write_text(json.dumps(catalog_value(now, domains=('Bad.Example',))), encoding='utf-8')
            with self.assertRaises(ValueError):
                fp.load_domain_catalog(bad)

    def test_config_catalog_path(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'c.json')
            p.write_text('{"dns_catalog_file": "relative.json"}', encoding='utf-8')
            with self.assertRaises(ValueError):
                fp.load_config(p)
            p.write_text('{"dns_catalog_file": "/var/lib/cs-public0-dns/domain-catalog.json"}', encoding='utf-8')
            self.assertTrue(fp.load_config(p)['dns_catalog_file'].endswith('domain-catalog.json'))


class Clock(unittest.TestCase):
    @staticmethod
    def timex(maxerror_us, status):
        return struct.pack('<I4xqqqqi', 0, 0, 0, maxerror_us, 100, status).ljust(256, b'\x00')

    def test_synced(self):
        self.assertEqual(fp.decode_timex(0, self.timex(12_000, 0x2001)), (True, 0.012, 0.0001))

    def test_unsynced_by_state_or_flag(self):
        self.assertFalse(fp.decode_timex(fp.TIME_ERROR, self.timex(16_000_000, 0x0041))[0])
        self.assertFalse(fp.decode_timex(0, self.timex(5_000, fp.STA_UNSYNC))[0])


class Correlation(unittest.TestCase):
    @staticmethod
    def rec(side, ts, isn, src='10.0.0.5', sport=40000, dst='198.51.100.9', ttl=None):
        return {'side': side, 'ts_ns': int(ts * 1e9), 'isn': isn, 'src_ip': src, 'src_port': sport,
                'dst_ip': dst, 'dst_port': 443, 'ttl': ttl if ttl is not None else (64 if side == 'g' else 63)}

    def test_constant_clock_skew_is_tolerated(self):
        guest = [self.rec('g', 100 + i, 1000 + i) for i in range(10)]
        uplink = [self.rec('u', 100 + i + 1.2, 1000 + i, src='203.0.113.1') for i in range(10)]
        pairs, skew = fp.correlate(guest, uplink, window_s=2.0, max_dt_s=0.05)
        self.assertAlmostEqual(skew, 1.2, places=3)
        self.assertTrue(all(p['confident'] for p in pairs))

    def test_retransmission_pairs_with_nearest_record(self):
        guest = [self.rec('g', 100.0, 7), self.rec('g', 101.0, 7), self.rec('g', 50.0, 99)]
        uplink = [self.rec('u', 100.0003, 7, src='203.0.113.1'), self.rec('u', 101.0004, 7, src='203.0.113.1'),
                  self.rec('u', 50.0003, 99, src='203.0.113.1')]
        pairs, _ = fp.correlate(guest, uplink)
        self.assertEqual([round(p['dt_s'], 4) for p in pairs], [0.0003, 0.0004, 0.0003])
        self.assertTrue(all(p['confident'] and not p['ambiguous'] for p in pairs))

    def test_skew_with_retransmissions_assigns_one_to_one(self):
        # reviewer scenario: true skew 1.2 s, three transmissions of one SYN
        guest = [self.rec('g', t, 7) for t in (100, 101, 102)] + [self.rec('g', 50 + i, 500 + i) for i in range(3)]
        uplink = [self.rec('u', t + 1.2, 7, src='203.0.113.1') for t in (100, 101, 102)] +                  [self.rec('u', 50 + i + 1.2, 500 + i, src='203.0.113.1') for i in range(3)]
        pairs, skew = fp.correlate(guest, uplink)
        self.assertAlmostEqual(skew, 1.2, places=3)
        self.assertEqual([round(p['dt_s'], 3) for p in pairs[:3]], [1.2, 1.2, 1.2])
        used = [id(p['uplink']) for p in pairs if p['uplink']]
        self.assertEqual(len(used), len(set(used)))
        self.assertTrue(all(p['confident'] for p in pairs))

    def test_competing_guests_under_one_key_are_ambiguous(self):
        # reviewer scenario: two VMs, same (dst, port, isn); router passes only one
        anchor_g = [self.rec('g', 50.0, 1)]
        anchor_u = [self.rec('u', 50.0001, 1, src='203.0.113.1')]
        guest = anchor_g + [self.rec('g', 100.0, 7, src='10.0.0.5'), self.rec('g', 100.001, 7, src='10.0.0.6')]
        uplink = anchor_u + [self.rec('u', 100.002, 7, src='203.0.113.1')]
        pairs, _ = fp.correlate(guest, uplink)
        hits = [p for p in pairs[1:] if p['uplink']]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]['ambiguous'] and not hits[0]['confident'])
        self.assertTrue(pairs[0]['confident'])

    def test_no_unambiguous_anchor_means_no_confidence(self):
        guest = [self.rec('g', 100.0, 7), self.rec('g', 101.0, 7)]
        uplink = [self.rec('u', 100.0003, 7, src='203.0.113.1'), self.rec('u', 101.0004, 7, src='203.0.113.1')]
        pairs, _ = fp.correlate(guest, uplink)
        self.assertTrue(all(p['uplink'] is not None and not p['confident'] for p in pairs))

    def test_older_pins_refused_and_unload_needs_no_maps(self):
        with tempfile.TemporaryDirectory() as d:
            for sub, names in (('progs', fp.PROGRAMS), ('maps', ('flow_records', 'flow_counters', 'flow_stats'))):
                Path(d, sub).mkdir()
                for n in names:
                    Path(d, sub, n).write_text('', encoding='utf-8')
            with self.assertRaises(RuntimeError):
                fp.load_object(dict(fp.DEFAULTS, pin_dir=d))

    def test_ambiguous_collision_is_never_confident(self):
        guest = [self.rec('g', 100.0, 5)]
        uplink = [self.rec('u', 100.0002, 5, src='203.0.113.1'), self.rec('u', 100.0003, 5, src='203.0.113.2')]
        pairs, _ = fp.correlate(guest, uplink)
        self.assertTrue(pairs[0]['ambiguous'])
        self.assertFalse(pairs[0]['confident'])

    def test_wrong_hop_or_outside_window_is_unmatched(self):
        guest = [self.rec('g', 100.0, 9), self.rec('g', 200.0, 10)]
        uplink = [self.rec('u', 100.0001, 9, src='203.0.113.1', ttl=64),
                  self.rec('u', 205.0, 10, src='203.0.113.1')]
        pairs, _ = fp.correlate(guest, uplink, window_s=2.0)
        self.assertEqual([p['uplink'] for p in pairs], [None, None])


if __name__ == '__main__':
    unittest.main()
