"""Regression cases for truthful DNS direction and source-qualified IOC matches."""
import copy
from pathlib import Path
import sys
import unittest
import hashlib
import json
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
from dns_ioc import DomainCatalog, domain_name, observe_dns
import dns_ioc

NOW = 1794254000
CATALOG = {'schema': 'cs-public0-domain-catalog-v1', 'source': 'threatfox',
    'domains': ['bad.example'], 'sha256': 'a' * 64, 'fetched_unix': NOW - 100,
    'published_unix': NOW - 110, 'expires_unix': NOW + 100}
CONFIG = {'sensor_id': 'fixture', 'owned_ipv4_networks': ['192.0.2.0/24']}
REF = {'device': 1, 'inode': 2, 'offset': 0, 'length': 400, 'record_sha256': 'b' * 64}


def event():
    return {'timestamp': '2026-11-09T19:53:20Z', 'event_type': 'dns', 'host': '1' * 32,
        'flow_id': 42, 'src_ip': '192.0.2.20', 'dest_ip': '198.51.100.53',
        'src_port': 53001, 'dest_port': 53, 'proto': 'UDP',
        'dns': {'version': 3, 'type': 'request', 'opcode': 0, 'id': 123, 'tx_id': 0,
                'queries': [{'rrname': 'Bad.Example.', 'rrtype': 'A'}]}}


class DNSIOCTests(unittest.TestCase):
    def observe(self, row):
        return observe_dns(row, CONFIG, DomainCatalog(CATALOG), REF, NOW)

    def test_actual_query_direction_and_separate_resolver(self):
        row = self.observe(event())[0]
        self.assertEqual((row['direction'], row['client_ip'], row['resolver_ip']),
                         ('egress', '192.0.2.20', '198.51.100.53'))
        self.assertEqual(row['enforcement'], 'none')
        self.assertEqual(row['queried_name'], 'bad.example')
        self.assertEqual(row['ioc']['minimum_confidence'], 75)

    def test_resolver_response_never_becomes_guest_abuse(self):
        row = event(); row['dns']['type'] = 'response'
        row['src_ip'], row['dest_ip'] = row['dest_ip'], row['src_ip']
        row['src_port'], row['dest_port'] = 53, 53001
        self.assertEqual(self.observe(row), [])

    def test_exact_name_does_not_match_suffix_or_shared_parent(self):
        for name in ['notbad.example', 'sub.bad.example', 'bad.example.attacker.invalid', 'example']:
            row = event(); row['dns']['queries'][0]['rrname'] = name
            self.assertEqual(self.observe(row), [])

    def test_non_ioc_dns_names_are_not_claimed_as_capture_failures(self):
        for name in ['_dmarc.example.com','_sip._tcp.example.com','localhost','1.1.1.1']:
            row=event();row['dns']['queries'][0]['rrname']=name
            with self.subTest(name=name):self.assertEqual(self.observe(row),[])

    def test_stale_future_and_low_integrity_catalogs_are_refused(self):
        catalog = DomainCatalog(CATALOG)
        self.assertFalse(catalog.match('bad.example', CATALOG['expires_unix']))
        self.assertFalse(catalog.match('bad.example', CATALOG['fetched_unix'] - 1))
        for key, value in [('source', 'ipinsights'), ('domains', ['com']),
                           ('domains', ['bad.example', 'bad.example']), ('expires_unix', NOW + 90000),
                           ('sha256', 'not-a-sha')]:
            bad = dict(CATALOG, **{key: value})
            with self.subTest(key=key,value=value), self.assertRaises(ValueError): DomainCatalog(bad)

    def test_v2_truncation_missing_epoch_and_ambiguous_request_are_rejected(self):
        for field,value in [('version', 2), ('qr', True), ('opcode', 5), ('rrname_truncated', True)]:
            row=event();row['dns'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.observe(row)
        row=event();row.pop('host')
        with self.assertRaises(ValueError):self.observe(row)

    def test_duplicate_questions_and_transport_retries_have_stable_identity(self):
        row=event();row['dns']['queries']*=2
        first=self.observe(row)
        self.assertEqual(len(first),1)
        self.assertEqual(first,self.observe(row))
        row['host']='2'*32
        self.assertNotEqual(first[0]['event_id'],self.observe(row)[0]['event_id'])

    def test_ordinary_lookup_without_ioc_is_not_reported(self):
        row=event();row['dns']['queries'][0]['rrname']='ip-api.com'
        self.assertEqual(self.observe(row),[])

    def test_non_egress_is_not_relabelled_and_vm_is_not_invented(self):
        row=event();row['src_ip'],row['dest_ip']=row['dest_ip'],row['src_ip']
        result=self.observe(row)[0]
        self.assertEqual(result['direction'],'ingress')
        self.assertNotIn('vm_ref',result['attribution'])
        row['src_ip']='198.51.100.55';row['dest_ip']='198.51.100.53'
        self.assertEqual(self.observe(row)[0]['direction'],'unknown')

    def test_name_normalization_rejects_addresses_urls_wildcards_and_escapes(self):
        self.assertEqual(domain_name('XN--EXAMPLE-9D0B.Example.'),'xn--example-9d0b.example')
        for name in ['1.1.1.1','https://bad.example','*.bad.example','bad..example',
                     'bad.example..','bad\\046example',' bad.example','bäd.example','-bad.example']:
            with self.subTest(name=name),self.assertRaises(ValueError):domain_name(name)

    def test_inputs_are_preserved_and_expired_ioc_publishes_nothing(self):
        row=event();before=copy.deepcopy(row);self.observe(row)
        self.assertEqual(row,before)
        old=dict(CATALOG,expires_unix=NOW-1)
        self.assertEqual(observe_dns(row,CONFIG,DomainCatalog(old),REF,NOW),[])


@unittest.skipUnless(sys.platform == 'linux', 'Linux flock and filesystem integration')
class DNSReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.state=self.root/'state';self.state.mkdir()
        self.updater=self.root/'updater.py';self.updater.write_bytes(b'accepted parser fixture\n')
        self.source=self.root/'updater-state.json'
        self.eve=self.root/'eve.json';self.eve.write_bytes(b'')
        self.config={'schema':'cs-public0-dns-config-v1',**CONFIG,'state_directory':str(self.state),
            'eve_file':str(self.eve),'updater_state_file':str(self.source),
            'updater_module_file':str(self.updater),
            'updater_module_sha256':hashlib.sha256(self.updater.read_bytes()).hexdigest(),
            'initial_position':'begin','details_file':str(self.root/'observations.jsonl'),
            'metrics_file':str(self.root/'metrics.prom')}
        self.feed()

    def feed(self, **changes):
        value=dict(CATALOG,**changes)
        self.source.write_text(json.dumps({'feeds':{'threatfox':value}}))

    def append(self, *rows):
        with self.eve.open('ab') as out:
            for row in rows:out.write(json.dumps(row).encode()+b'\n')

    def stats(self, drops=0, epoch='1'*32):
        return {'event_type':'stats','host':epoch,'timestamp':event()['timestamp'],
                'stats':{'capture':{'kernel_drops':drops}}}

    def rows(self):
        path=Path(self.config['details_file'])
        return [json.loads(x) for x in path.read_bytes().splitlines()] if path.exists() else []

    def metrics(self):
        return dict(line.rsplit(' ',1) for line in Path(self.config['metrics_file']).read_text().splitlines())

    def test_restart_preserves_cursor_database_and_one_observation(self):
        self.append(event(),self.stats())
        self.assertTrue(dns_ioc.run(self.config,NOW)['success'])
        identity=(self.state/'state.sqlite3').stat().st_ino
        original=self.rows()
        self.assertEqual(len(original),1)
        self.assertEqual(self.metrics()['cs_public0_dns_source_fresh'],'1')
        self.assertTrue(dns_ioc.run(self.config,NOW+5)['success'])
        self.assertEqual(self.rows(),original)
        self.assertEqual((self.state/'state.sqlite3').stat().st_ino,identity)

    def test_continuity_recovers_after_the_mandatory_initial_boundary(self):
        import datetime as dt
        self.append(self.stats());self.assertTrue(dns_ioc.run(self.config,NOW)['success'])
        self.assertEqual(self.metrics()['cs_public0_dns_collection_continuity_known'],'0')
        row=self.stats();row['timestamp']=dt.datetime.fromtimestamp(NOW+61,dt.timezone.utc).isoformat()
        self.append(row);self.assertTrue(dns_ioc.run(self.config,NOW+61)['success'])
        self.assertEqual(self.metrics()['cs_public0_dns_collection_continuity_known'],'1')
        self.assertEqual(self.metrics()['cs_public0_dns_collection_gaps_total{reason="initial_boundary"}'],'1')

    def test_same_inode_rewritten_content_is_detected_and_references_are_true(self):
        self.append(event(),self.stats());dns_ioc.run(self.config,NOW)
        inode=self.eve.stat().st_ino
        row=event();row['flow_id']=43
        self.eve.write_bytes(json.dumps(row).encode()+b'\n')
        self.assertEqual(self.eve.stat().st_ino,inode)
        dns_ioc.run(self.config,NOW+1)
        output=self.rows();self.assertEqual(len(output),2)
        self.assertEqual(output[-1]['source_ref']['record_sha256'],hashlib.sha256(self.eve.read_bytes()).hexdigest())

    def test_partial_record_is_held_until_newline(self):
        raw=json.dumps(event()).encode()
        self.eve.write_bytes(raw[:40]);dns_ioc.run(self.config,NOW)
        self.assertEqual(self.rows(),[])
        with self.eve.open('ab') as out:out.write(raw[40:]+b'\n')
        dns_ioc.run(self.config,NOW+1)
        self.assertEqual(len(self.rows()),1)

    def test_expired_catalog_holds_input_then_resumes_without_fake_clean(self):
        self.feed(expires_unix=NOW-1);self.append(event(),self.stats())
        self.assertFalse(dns_ioc.run(self.config,NOW)['success'])
        self.assertEqual(self.rows(),[])
        self.assertEqual(self.metrics()['cs_public0_dns_ioc_fresh'],'0')
        self.feed();self.assertTrue(dns_ioc.run(self.config,NOW+1)['success'])
        self.assertEqual(len(self.rows()),1)

    def test_outbox_survives_delivery_failure_after_cursor_commit(self):
        self.append(event(),self.stats());calls=[]
        def failure(*args):
            calls.append(1)
            if len(calls)==2:raise OSError('synthetic interrupted delivery')
        with patch('egress_collector.deliver',side_effect=failure):
            self.assertFalse(dns_ioc.run(self.config,NOW)['success'])
        self.assertTrue(dns_ioc.run(self.config,NOW+1)['success'])
        self.assertEqual(len(self.rows()),1)
        self.assertEqual(self.metrics()['cs_public0_dns_ioc_observations_total{source="threatfox",direction="egress"}'],'1')

    def test_capture_loss_history_survives_new_producer_epoch(self):
        self.append(self.stats(5));dns_ioc.run(self.config,NOW)
        self.append(self.stats(5));dns_ioc.run(self.config,NOW+1)
        self.assertEqual(self.metrics()['cs_public0_dns_capture_drops_seen_total'],'5')
        self.append(self.stats(2,'2'*32));dns_ioc.run(self.config,NOW+2)
        self.assertEqual(self.metrics()['cs_public0_dns_capture_drops_seen_total'],'7')

    def test_parser_policy_change_holds_collection(self):
        self.append(event());self.updater.write_bytes(b'changed parser\n')
        self.assertFalse(dns_ioc.run(self.config,NOW)['success'])
        self.assertEqual(self.rows(),[])
        self.assertEqual(self.metrics()['cs_public0_dns_collector_up'],'0')

    def test_invalid_producer_record_marks_health_unknown(self):
        self.append(self.stats(),{'event_type':'dns','dns':{'version':2,'type':'query'}})
        dns_ioc.run(self.config,NOW)
        self.assertEqual(self.metrics()['cs_public0_dns_source_fresh'],'0')
        self.assertEqual(self.metrics()['cs_public0_dns_capture_loss_known'],'0')


if __name__ == '__main__':unittest.main()
