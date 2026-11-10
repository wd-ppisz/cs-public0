"""Execute the exact installer writer and render the real passive profile."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[1]


class DNSInstall(unittest.TestCase):
    def test_safe_ancestor_without_syslog_group(self):
        import ast
        import pathlib
        import stat
        from types import SimpleNamespace
        plays=yaml.safe_load((ROOT/'ansible/dns-ioc.yml').read_text())
        task=next(t for t in plays[0]['tasks'] if t['name']=='Refuse drift, unsafe ancestors or changed source pins')
        tree=ast.parse(task['ansible.builtin.command']['argv'][4])
        function=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='safe_directory')
        space={'pathlib':pathlib,'stat':stat}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual installer directory guard>','exec'),space)
        guard=space['safe_directory'];info=lambda mode,gid:SimpleNamespace(st_mode=stat.S_IFDIR|mode,st_uid=0,st_gid=gid)
        self.assertTrue(guard(Path('/var/log'),info(0o755,0),None))
        self.assertFalse(guard(Path('/var/log'),info(0o775,104),None))
        self.assertTrue(guard(Path('/var/log'),info(0o775,104),104))
        self.assertFalse(guard(Path('/var/log'),info(0o775,105),104))
        self.assertFalse(guard(Path('/var/log/cs-public0-dns'),info(0o775,104),104))

    def test_passive_profile_has_no_inline_or_detection_action(self):
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT / 'config'),
                                 undefined=jinja2.StrictUndefined)
        env.filters['to_json'] = json.dumps
        values = {'cs_public0_dns_interface': 'public0', 'cs_public0_dns_cluster_id': 97,
                  'cs_public0_dns_log_directory': '/var/log/cs-public0-dns',
                  'cs_public0_dns_binary': '/opt/suricata/bin/suricata'}
        profile = yaml.safe_load(env.get_template('suricata-dns.yaml.j2').render(values))
        self.assertNotIn('nfq', profile)
        self.assertNotIn('rule-files', profile)
        self.assertNotIn('copy-mode', profile['af-packet'][0])
        dns = profile['outputs'][0]['eve-log']['types'][0]['dns']
        self.assertEqual(dns['version'], 3)
        self.assertTrue(dns['requests']); self.assertTrue(dns['responses'])
        unit = env.get_template('cs-public0-dns.service.j2').render(values)
        self.assertIn('--disable-detection', unit)
        self.assertIn('sensor-name=${INVOCATION_ID}', unit)
        self.assertIn('CapabilityBoundingSet=CAP_NET_RAW', unit)
        self.assertNotIn('wd-public0-inline', unit)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root file ownership contract')
    def test_exact_json_writer_is_idempotent_and_refuses_drift_or_symlink(self):
        plays = yaml.safe_load((ROOT / 'ansible/dns-ioc.yml').read_text())
        task = next(t for t in plays[0]['tasks'] if t['name'] == 'Install exact owned configuration and service artifacts')
        code = task['ansible.builtin.command']['argv'][4]
        raw = b'{"z": 1, "a": [2,3]}\n'
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'config.json'
            args = [sys.executable, '-I', '-B', '-c', code, str(target),
                    base64.b64encode(raw).decode(), hashlib.sha256(raw).hexdigest(), '0600']
            first = subprocess.run(args, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(target.read_bytes(), raw)
            inode = target.stat().st_ino
            self.assertEqual(subprocess.check_output(args).strip(), b'UNCHANGED')
            self.assertEqual(target.stat().st_ino, inode)
            target.write_bytes(b'{}')
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            target.unlink(); target.symlink_to(Path(td) / 'outside')
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertFalse((Path(td) / 'outside').exists())


if __name__ == '__main__': unittest.main()
