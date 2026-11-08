import datetime as dt
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import ip_intelligence as ipi
import policy_inventory as inv
from egress_model import IOC

NOW = 1794168000


class IntelligenceTests(unittest.TestCase):
    def test_invalid_line_rejects_complete_feed(self):
        for bad in (b'1.2.3.4\n<script>\n', b'1.2.3.4 999\n', b'0.0.0.0/0\n', b'1.2.3.4;flush ruleset\n'):
            with self.subTest(raw=bad), self.assertRaises(ValueError):
                ipi.parse('ipinsights', bad, NOW)

    def test_nonpublic_addresses_are_filtered(self):
        result = ipi.parse('ipinsights', b'# list\n1.2.3.4\n10.0.0.1\n127.0.0.1\n224.0.0.1\n', NOW)
        self.assertEqual(result['addresses'], ['1.2.3.4/32'])
        self.assertEqual(result['filtered'], 3)

    def test_mixed_feed_filters_ipv6_without_losing_valid_ipv4(self):
        parsed = ipi.parse('ipinsights', b'1.2.3.4\n2001:db8::1\n2001:4860:4860::8888\n', NOW)
        self.assertEqual(parsed['addresses'], ['1.2.3.4/32'])
        self.assertEqual(parsed['filtered'], 2)

    def test_firehol_bogons_are_filtered_but_public_overbroad_prefix_is_refused(self):
        parsed = ipi.parse('firehol1', b'1.2.3.0/24\n224.0.0.0/3\n10.0.0.0/8\n', NOW)
        self.assertEqual(parsed['addresses'], ['1.2.3.0/24'])
        self.assertEqual(parsed['filtered'], 2)
        with self.assertRaises(ValueError):
            ipi.parse('firehol1', b'0.0.0.0/1\n', NOW)

    def test_spamhaus_ndjson_retains_networks_and_skips_metadata(self):
        raw = b'{"cidr":"5.6.7.0/24","sblid":"x"}\n{"type":"metadata","copyright":"Spamhaus"}\n'
        self.assertEqual(ipi.parse('spamhaus', raw, NOW)['addresses'], ['5.6.7.0/24'])

    def test_empty_ip_feed_refused(self):
        with self.assertRaises(ValueError):
            ipi.parse('ipinsights', b'# no entries\n', NOW)

    def fox(self, **kwargs):
        row = {'ioc_type': 'ip:port', 'ioc': '5.6.7.8:443', 'confidence_level': 100,
               'first_seen': dt.datetime.fromtimestamp(NOW - 60, dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
               'last_seen': None, 'threat_type': 'botnet_cc'}
        row.update(kwargs)
        return json.dumps({'query_status': 'ok', 'data': [row]}).encode()

    def test_threatfox_drop_retains_port_and_requires_c2_confidence(self):
        self.assertEqual(ipi.parse('threatfox', self.fox(), NOW)['endpoints'], [('5.6.7.8/32', 443)])
        for kwargs in ({'confidence_level': 75}, {'threat_type': 'payload_delivery'}, {'ioc': '5.6.7.8:0'}):
            self.assertEqual(ipi.parse('threatfox', self.fox(**kwargs), NOW)['endpoints'], [])

    def test_old_threatfox_ioc_refused(self):
        parsed = ipi.parse('threatfox', self.fox(first_seen='2020-01-01 00:00:00 UTC'), NOW)
        self.assertEqual(parsed['addresses'], [])
        self.assertEqual(parsed['filtered'], 1)

    def test_otx_decodes_its_own_json_without_threatfox_branch(self):
        raw = json.dumps({'results': [{'indicators': [
            {'type': 'IPv4', 'indicator': '5.6.7.8'},
            {'type': 'domain', 'indicator': 'C2.Example.com.'},
            {'type': 'IPv4', 'indicator': '10.1.2.3'}]}]}).encode()
        parsed = ipi.parse('otx', raw, NOW)
        self.assertEqual(parsed['addresses'], ['5.6.7.8/32'])
        self.assertEqual(parsed['domains'], ['c2.example.com'])
        self.assertEqual(parsed['filtered'], 1)
        self.assertEqual(parsed['endpoints'], [])

    def test_otx_invalid_response_is_not_accepted(self):
        for raw in (b'{"error":"unauthorized"}', b'broken json', b'{"results":{}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ipi.parse('otx', raw, NOW)

    def test_domain_is_detection_context_and_never_ip_drop(self):
        parsed = ipi.parse('threatfox', self.fox(ioc_type='domain', ioc='C2.Example.COM.'), NOW)
        self.assertEqual(parsed['domains'], ['c2.example.com'])
        self.assertEqual(parsed['endpoints'], [])
        self.assertEqual(parsed['addresses'], [])

    def feed(self, addresses, **kwargs):
        return dict(addresses=addresses, endpoints=[], domains=[], fetched_unix=NOW - 30,
                    expires_unix=NOW + 120, **kwargs)

    def test_direction_and_protected_overlap(self):
        feeds = {'ipinsights': self.feed(['1.2.3.4/32', '83.168.93.5/32']),
                 'spamhaus': self.feed(['5.6.7.0/24']), 'firehol1': self.feed(['9.10.11.12/32'])}
        result = ipi.policy(feeds, ipi.protected_config(['83.168.92.0/22']), NOW)
        self.assertEqual(result['incoming'], ['1.2.3.4/32', '5.6.7.0/24'])
        self.assertEqual(result['outgoing'], ['5.6.7.0/24'])

    def test_expired_last_good_is_not_reapplied(self):
        feed = self.feed(['1.2.3.4/32'])
        feed['expires_unix'] = NOW
        self.assertEqual(ipi.policy({'ipinsights': feed}, [], NOW)['incoming'], [])

    def test_nft_transaction_is_scoped_and_keeps_counters_on_refresh(self):
        candidate = {'incoming': ['1.2.3.4/32'], 'outgoing': [], 'c2_ports': [('5.6.7.8', 443)]}
        first = ipi.nft_batch(candidate, create=True, ttl=3600).decode()
        self.assertIn('meta ibrname "public0" meta obrname "public0"', first)
        self.assertIn('priority -250', first)
        self.assertNotIn('flush ruleset', first)
        self.assertIn('timeout 3600s', first)
        self.assertIn('5.6.7.8 . 443', first)
        refresh = ipi.nft_batch(candidate, create=False, ttl=3600).decode()
        self.assertNotIn('add chain', refresh)
        self.assertNotIn('add counter', refresh)
        self.assertNotIn('delete table', refresh)

    def test_redirect_and_credential_host_rejected(self):
        for url in ('http://ipinsights.io/x', 'https://evil.example/feed', 'https://user@www.ipinsights.io/x'):
            with self.assertRaises(ValueError):
                ipi.retrieve(url)
        with self.assertRaises(ValueError):
            ipi.retrieve(ipi.SOURCES['ipinsights']['url'], key='synthetic')

    def test_inventory_parses_exact_drop_list(self):
        raw = b'drop http any any -> any any (msg:"Example"; reference:cve,2021-1234; sid:42; rev:3;)\n'
        self.assertEqual(inv.rules(raw), [{'sid': 42, 'rev': 3, 'message': 'Example', 'cve': '2021-1234'}])
        with self.assertRaises(ValueError):
            inv.rules(raw + raw)

    def test_inventory_hash_mismatch_never_reports_success(self):
        with self.assertRaises(ValueError):
            inv.inventory({'baseline': {}}, {'expected_rules_sha256': 'a' * 64},
                          {'rules_sha256': 'b' * 64}, b'', True, NOW)

    def test_source_time_is_not_invented_from_mtime(self):
        state = {'last_transaction': '/var/lib/x/batch-1794167900-abc123'}
        with patch.object(inv, 'read', return_value=json.dumps({'sources': [
                {'url': 'https://api.first.org/data/v1/epss?x', 'sha256': 'a' * 64}]}).encode()):
            result = inv.decision_inventory(state)[0]
        self.assertEqual(result['decision_unix'], 1794167900)
        self.assertEqual(result['retrieved_timestamp_known'], 0)
        self.assertEqual(result['retrieved_unix'], 0)

    def test_observer_snapshot_matches_prefixes_without_expansion(self):
        feeds = {'spamhaus': self.feed(['5.6.7.0/24']), 'threatfox': self.feed(['9.10.11.12/32']),
                 'ipinsights': self.feed(['1.2.3.4/32'])}
        result = ipi.ioc_snapshot(feeds, [], NOW)
        ioc = IOC(result)
        self.assertEqual(ioc.match('5.6.7.99', NOW)['matched_prefix'], '5.6.7.0/24')
        self.assertIsNotNone(ioc.match('9.10.11.12', NOW))
        self.assertIsNone(ioc.match('5.6.8.1', NOW))
        self.assertIsNone(ioc.match('1.2.3.4', NOW))
        self.assertIsNone(ioc.match('5.6.7.99', NOW + 120))

    def test_observer_snapshot_content_hash_and_own_exemptions(self):
        result = ipi.ioc_snapshot({'spamhaus': self.feed(['5.6.7.0/24'])},
                                  ipi.protected_config(['5.6.7.4/32']), NOW)
        self.assertEqual(result['networks'], [])
        result['networks'] = ['5.6.7.0/24']
        with self.assertRaises(ValueError):
            IOC(result)

    def test_noop_does_not_rebuild_unchanged_sets_but_renews_before_expiry(self):
        feed = self.feed(['1.2.3.4/32'], sha256='a' * 64)
        feed['expires_unix'] = NOW + 7200
        state = {'feeds': {'ipinsights': feed}, 'apply_success': True, 'last_apply_unix': NOW - 100,
                 'kernel_expires_unix': NOW + 3500, 'applied_source_versions': {'ipinsights': 'a' * 64}}
        self.assertFalse(ipi.refresh_required(state, NOW))
        self.assertTrue(ipi.refresh_required(state, NOW + 1701))
        state['kernel_expires_unix'] = NOW + 500
        self.assertTrue(ipi.refresh_required(state, NOW))
        state['kernel_expires_unix'] = NOW + 3500
        state['feeds']['ipinsights']['sha256'] = 'b' * 64
        self.assertTrue(ipi.refresh_required(state, NOW))

    def test_failed_apply_or_clock_reversal_never_takes_noop_path(self):
        state = {'feeds': {}, 'apply_success': False, 'last_apply_unix': NOW,
                 'kernel_expires_unix': NOW + 3600, 'applied_source_versions': {}}
        self.assertTrue(ipi.refresh_required(state, NOW))
        state['apply_success'] = True
        self.assertTrue(ipi.refresh_required(state, NOW - 1))


if __name__ == '__main__':
    unittest.main()
