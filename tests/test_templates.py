"""Validate the deployed configuration, not just the template source text."""
import importlib.util
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import stat
from unittest.mock import patch
import re
import unittest

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[1]


def defaults():
    value = yaml.safe_load((ROOT / 'ansible/roles/cs_public0/defaults/main.yml').read_text())
    return value


def environment():
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROOT / 'config'),
                             undefined=jinja2.StrictUndefined)
    env.filters['to_json'] = json.dumps
    env.filters['dirname'] = lambda value: str(Path(value).parent)
    env.filters['basename'] = lambda value: Path(value).name
    return env


class Templates(unittest.TestCase):
    def test_installer_allows_system_log_group_but_rejects_unsafe_leaf(self):
        tasks = yaml.safe_load((ROOT / 'ansible/roles/cs_public0/tasks/main.yml').read_text())
        task = next(t for t in tasks if t['name'].startswith('Reject unsafe existing directories'))
        code = task['ansible.builtin.command']['argv'][2]
        class FakePath(PurePosixPath):
            unsafe = None
            def lstat(self):
                mode = stat.S_IFDIR | (0o775 if str(self) == '/var/log' or str(self) == self.unsafe else 0o755)
                return SimpleNamespace(st_mode=mode, st_uid=0)
        with patch('pathlib.Path', FakePath):
            with patch('sys.argv', ['check', '/var/log/cs-public0']):
                exec(compile(code, '<directory validation>', 'exec'), {})
                FakePath.unsafe = '/var/log/cs-public0'
                with self.assertRaises(SystemExit):
                    exec(compile(code, '<directory validation>', 'exec'), {})
            FakePath.unsafe = '/var/lib'
            with patch('sys.argv', ['check', '/var/lib/cs-public0']), self.assertRaises(SystemExit):
                exec(compile(code, '<directory validation>', 'exec'), {})

    def test_suricata_availability_and_rules(self):
        data = yaml.safe_load(environment().get_template('suricata.yaml.j2').render(defaults()))
        self.assertEqual(data['nfq']['mode'], 'accept')
        self.assertTrue(data['nfq']['fail-open'])
        self.assertEqual(data['nfq']['batchcount'], 1)
        self.assertEqual(data['rule-files'], ['local.rules'])
        self.assertEqual(data['threshold-file'], '/dev/null')
        self.assertEqual(data['flow']['memcap-policy'], 'pass-packet')
        self.assertEqual(data['stream']['memcap-policy'], 'pass-flow')
        self.assertEqual(data['stream']['midstream-policy'], 'pass-flow')
        self.assertFalse(data['stream']['drop-invalid'])
        self.assertEqual(data['stream']['reassembly']['memcap-policy'], 'pass-flow')
        self.assertEqual(data['app-layer']['error-policy'], 'pass-flow')
        self.assertEqual(data['unix-command']['filename'], '/run/cs-public0/suricata.socket')
        self.assertNotIn('af-packet', data)

    def test_systemd_lifecycle_and_read_only_monitor(self):
        env = environment()
        service = env.get_template('cs-public0.service.j2').render(defaults())
        self.assertIn('ExecStartPost=/usr/local/libexec/cs-public0 arm', service)
        self.assertIn('ExecStopPost=/usr/local/libexec/cs-public0 disarm', service)
        self.assertIn('RuntimeDirectoryPreserve=yes', service)
        self.assertIn('Conflicts=suricata.service', service)
        self.assertNotIn('flush ruleset', service)
        monitor = env.get_template('cs-public0-monitor.service.j2').render(defaults())
        self.assertIn('ExecStart=/usr/local/libexec/cs-public0 monitor', monitor)
        self.assertNotIn(' disarm', monitor)

    def test_passive_install_default_and_example(self):
        self.assertIs(defaults()['cs_public0_enabled'], False)
        example = yaml.safe_load((ROOT / 'examples/apache-cloudstack-kvm/settings.yml').read_text())
        self.assertIs(example['cs_public0_enabled'], False)
        tasks = yaml.safe_load((ROOT / 'ansible/roles/cs_public0/tasks/main.yml').read_text())
        activation = next(task for task in tasks if task['name'] == 'Apply the explicit activation choice')
        self.assertEqual(activation['when'], 'not ansible_check_mode')
        planned = next(task for task in tasks if task['name'] == 'Report the planned activation choice in check mode')
        self.assertEqual(planned['when'], 'ansible_check_mode')

    def test_alert_rules_and_documentation_inventory(self):
        rules = (ROOT / 'config/local.rules').read_text().splitlines()
        active = [line for line in rules if line.strip() and not line.startswith('#')]
        self.assertTrue(active)
        self.assertTrue(all(line.startswith('alert ') for line in active))
        inventory = (ROOT / 'examples/apache-cloudstack-kvm/inventory.ini').read_text()
        self.assertIn('hypervisor.example.invalid', inventory)

    def test_alerts_do_not_hide_unknown_state(self):
        groups = yaml.safe_load((ROOT / 'monitoring/prometheus/alerts.yml').read_text())['groups']
        expr = '\n'.join(rule['expr'] for group in groups for rule in group['rules'])
        self.assertNotIn('or vector(0)', expr)
        self.assertIn('unless on(job, instance, bridge, queue)', expr)
        self.assertIn('time() - cs_public0_last_publish_unix_seconds', expr)


if __name__ == '__main__':
    unittest.main()
