"""Exercise deployment preconditions before any timer or pinned-source change."""
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import yaml


ROOT = Path(__file__).resolve().parents[1]


class Day2Guards(unittest.TestCase):
    def test_monitor_refuses_any_existing_release_before_service_commands(self):
        tasks = yaml.safe_load((ROOT / 'ansible/monitor.yml').read_text())[0]['tasks']
        task = next(t for t in tasks if t['name'].startswith('Verify the existing service'))
        code = task['ansible.builtin.command']['argv'][2]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / 'release.json').write_text('{}')
            functions = {'load_config': lambda _: {'rules_file': str(path / 'local.rules'), 'service': 'fixture'},
                         'previous_state': lambda _: {'latched': False}, 'sensor': lambda _: {},
                         'secure_path': Mock()}
            with patch('runpy.run_path', return_value=functions), patch('subprocess.run') as run, \
                    patch('subprocess.check_output') as output, self.assertRaises(SystemExit):
                exec(compile(code, '<monitor preflight>', 'exec'), {})
            run.assert_not_called()
            output.assert_not_called()
        guard_index = tasks.index(task)
        block_index = next(i for i, t in enumerate(tasks) if 'block' in t)
        self.assertLess(guard_index, block_index)
        copies = next(t for t in tasks[block_index]['block'] if 'ansible.builtin.copy' in t)['loop']
        self.assertEqual({x['target'] for x in copies}, {'/usr/local/libexec/cs-public0',
            '/usr/local/libexec/cs-public0-lib/cs_public0.py',
            '/usr/local/libexec/cs-public0-lib/rule_release.py',
            '/usr/local/libexec/cs-public0-lib/rule_update_journal.py'})

    def test_pinned_generated_dropin_must_be_present_safe_and_exact_before_writes(self):
        tasks = yaml.safe_load((ROOT / 'ansible/rule-controller.yml').read_text())[0]['tasks']
        task = next(t for t in tasks if t['name'].startswith('Verify an explicitly pinned generated drop-in'))
        code = task['ansible.builtin.command']['argv'][2]
        expected = b'[Service]\nExecStartPre=/usr/bin/python3 /controller/rule_release.py verify --directory /rules\n'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'public0-release.conf'
            def execute(pinned=True):
                with patch.object(sys, 'argv', ['guard', str(path), '/controller', '/rules',
                                               json.dumps([str(path)] if pinned else [])]):
                    exec(compile(code, '<bootstrap preflight>', 'exec'), {})
            with self.assertRaises(SystemExit): execute()
            execute(False)
            for payload, mode, owner, valid in [(expected, stat.S_IFREG | 0o644, 0, True),
                    (b'foreign', stat.S_IFREG | 0o644, 0, False),
                    (expected, stat.S_IFREG | 0o664, 0, False),
                    (expected, stat.S_IFREG | 0o644, 1000, False),
                    (expected, stat.S_IFLNK | 0o777, 0, False)]:
                path.write_bytes(payload)
                info = SimpleNamespace(st_mode=mode, st_uid=owner, st_size=len(payload))
                with self.subTest(mode=mode, owner=owner, payload=payload), \
                        patch.object(Path, 'lstat', return_value=info):
                    if valid: execute()
                    else:
                        with self.assertRaises(SystemExit): execute()
        self.assertLess(tasks.index(task), next(i for i,t in enumerate(tasks)
                                              if t['name'].startswith('Copy the pinned modules')))


if __name__ == '__main__':
    unittest.main()
