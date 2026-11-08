#!/usr/bin/env python3
"""Read-only DROP/feed inventory; timestamps describe evidence, never file mtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

RULE = re.compile(r'^drop\s+.*?\(.*?\bmsg:\s*"((?:\\.|[^"\\])*)";.*?\bsid:\s*(\d+);.*?\brev:\s*(\d+);', re.M)
CONFIG = re.compile(r'--config (/etc/[a-zA-Z0-9_./-]+\.json) --config-sha256 ([a-f0-9]{64})(?:\s|\}|$)')


def read(path, limit=1024 * 1024):
    path = Path(path)
    for parent in path.parents:
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('unsafe ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or s.st_mode & 0o022 or s.st_size > limit:
            raise ValueError('unsafe or excessive inventory input')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            return source.read(limit + 1)
    finally:
        os.close(fd)


def quote(value):
    return str(value).replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"')


def sample(name, value, **labels):
    suffix = '{' + ','.join(k + '="' + quote(v) + '"' for k, v in sorted(labels.items())) + '}' if labels else ''
    return 'cs_public0_policy_' + name + suffix + ' ' + str(value) + '\n'


def rules(raw):
    text = raw.decode('utf-8')
    rows = [{'sid': int(sid), 'rev': int(rev), 'message': message, 'cve': ','.join(sorted(set(
        re.findall(r'reference:cve,(\d{4}-\d+)', line))))}
        for line in text.splitlines() if line.startswith('drop ')
        for message, sid, rev in RULE.findall(line)]
    count = sum(line.startswith('drop ') for line in text.splitlines())
    if len(rows) != count or len({r['sid'] for r in rows}) != count or count > 128:
        raise ValueError('DROP inventory cannot be parsed exactly')
    return sorted(rows, key=lambda r: r['sid'])


def decision_inventory(state):
    path = state.get('last_transaction')
    if not path:
        return []
    decision = json.loads(read(Path(path) / 'decision.json', 1024 * 1024))
    result = []
    for item in decision.get('sources', []):
        url = item.get('url', '')
        name = 'cisa_kev' if 'cisagov/kev-data/' in url else 'first_epss' if url.startswith('https://api.first.org/') else 'unknown'
        # Original controllers persist retrieval receipts without a timestamp.
        # batch-<unix>-<nonce> is the decision time after both fetches, not an HTTP publication date.
        match = re.fullmatch(r'batch-(\d+)-[a-f0-9]+', Path(path).name)
        result.append({'source': name, 'sha256': item['sha256'],
                       'decision_unix': int(match[1]) if match else 0,
                       'retrieved_unix': item.get('retrieved_unix', 0),
                       'retrieved_timestamp_known': int(type(item.get('retrieved_unix')) is int)})
    return result


def inventory(config, state, release, raw, sensor_active, now):
    digest = hashlib.sha256(raw).hexdigest()
    if digest != release['rules_sha256'] or digest != state.get('expected_rules_sha256'):
        raise ValueError('ruleset, release and controller state differ')
    rows = rules(raw)
    if [r['sid'] for r in rows] != release.get('drop_sids'):
        raise ValueError('release DROP list differs')
    out = sample('inventory_up', 1) + sample('inventory_unix_seconds', now)
    out += sample('sensor_active', int(sensor_active)) + sample('drop_count', len(rows))
    out += sample('controller_info', 1, phase=state.get('phase', 'UNKNOWN'), result=state.get('result', 'UNKNOWN'),
                  accounting_policy=config['baseline'].get('accounting_gap_policy', 'fixed'))
    out += sample('ruleset_info', 1, sha256=digest, evidence='VERIFIED_MANAGED_RULESET')
    for row in rows:
        out += sample('drop_rule_info', 1, **row)
    for row in decision_inventory(state):
        labels = {k: row[k] for k in ('source', 'sha256')}
        for field in ('decision_unix', 'retrieved_unix', 'retrieved_timestamp_known'):
            out += sample('source_' + field + ('_seconds' if field.endswith('_unix') else ''), row[field], **labels)
    deferred = state.get('result') in {'SOURCES_UNAVAILABLE_CURRENT_POLICY_RETAINED', 'GATES_NOT_MET', 'EVIDENCE_STORE_FULL'}
    out += sample('last_decision_success', int(state.get('phase') == 'STABLE' and not deferred))
    out += sample('last_tick_unix_seconds', state.get('last_tick_unix', 0))
    return out


def atomic(path, raw):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + str(os.getpid()))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metrics', default='/var/lib/node_exporter/cs_public0_policy_inventory.prom')
    args = parser.parse_args()
    try:
        output = subprocess.run(['systemctl', 'show', 'cs-public0-exploit-policy.service', '-p', 'ExecStart', '--value'],
                                capture_output=True, text=True, check=True, timeout=10).stdout
        match = CONFIG.search(output)
        if not match:
            raise ValueError('cannot identify pinned policy')
        raw_config = read(match[1], 65536)
        if hashlib.sha256(raw_config).hexdigest() != match[2]:
            raise ValueError('configuration pin differs')
        config = json.loads(raw_config)
        state = json.loads(read(Path(config['state_directory']) / 'state.json', 65536))
        if state.get('config_sha256') != match[2]:
            raise ValueError('state belongs to another configuration')
        release = json.loads(read(Path(config['target']) / 'release.json'))
        raw = read(config['cfg']['rules_file'], 64 * 1024 * 1024)
        active = subprocess.run(['systemctl', 'is-active', config['cfg']['service']], capture_output=True,
                                text=True, timeout=10).stdout.strip() == 'active'
        result = inventory(config, state, release, raw, active, int(time.time()))
    except Exception as error:
        result = sample('inventory_up', 0) + sample('inventory_error_info', 1, reason=type(error).__name__)
    atomic(args.metrics, result.encode())


if __name__ == '__main__':
    main()
