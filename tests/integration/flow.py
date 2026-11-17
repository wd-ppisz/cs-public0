"""Root-only dataplane smoke for the flow probe in disposable namespaces.

Two private network namespaces are created: "host" holds a veth end named like
a guest tap and runs the probe; "guest" holds the peer. Nothing listens in the
host namespace, so every guest connection receives RST regardless of services
on the runner. The test checks TCX attach, records with the right tuple and
ISN, RST counters, idempotent reconcile, stale-attachment removal, private
spool permissions, no addresses in metrics and detach of own programs only.
Exit 77 = prerequisites unavailable (not a pass).

Usage: sudo FLOW_OBJECT=/path/flow_probe.o python3 tests/integration/flow.py
"""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / 'runtime'))
import flow_probe as fp

NS_HOST, NS_GUEST = 'csp0flowhost', 'csp0flowguest'
TAP, PEER = 'vnettest0', 'gethtest0'
PIN = '/sys/fs/bpf/cs-public0-flow-test'
HOST_IP, GUEST_IP = '192.0.2.1', '192.0.2.2'
PORTS = (22, 25, 2222)


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def cleanup():
    for ns in (NS_HOST, NS_GUEST):
        sh('ip', 'netns', 'del', ns, check=False)
    shutil.rmtree(PIN, ignore_errors=True)


def inner(tmp):
    """Runs inside NS_HOST (own /sys/class/net view)."""
    # `ip netns exec` mounts a fresh sysfs in a private mount namespace, without
    # the bpffs that hosts normally have at /sys/fs/bpf. Mount it for the test.
    if not os.path.ismount('/sys/fs/bpf'):
        sh('mount', '-t', 'bpf', 'bpf', '/sys/fs/bpf')
    cfg = fp.load_config(tmp / 'flow.json')
    assert fp.load_object(cfg) == 'loaded'
    idx = int(Path(f'/sys/class/net/{TAP}/ifindex').read_text())
    with fp.Probe(cfg) as probe:
        probe.cycle()
        assert probe.prog_ids['flow_guest_out'] in fp.tcx_query(idx, fp.TCX_INGRESS), 'ingress'
        assert probe.prog_ids['flow_guest_in'] in fp.tcx_query(idx, fp.TCX_EGRESS), 'egress'
        assert probe.reconcile() == (2, 0, 0), 'idempotent reconcile'

        for port in PORTS:
            r = sh('ip', 'netns', 'exec', NS_GUEST, sys.executable, '-c',
                   'import socket,sys\ns=socket.socket();s.settimeout(2)\n'
                   f'try: s.connect(("{HOST_IP}",{port}))\n'
                   'except OSError as e: print(e.errno)', check=False)
            assert r.stdout.strip() == '111', f'expected ECONNREFUSED to {port}: {r.stdout} {r.stderr}'
        time.sleep(0.2)
        probe.cycle()

        spool = Path(cfg['spool_dir'])
        assert stat.S_IMODE(spool.stat().st_mode) == 0o700, oct(spool.stat().st_mode)
        files = sorted(spool.glob('records-*.jsonl'))
        assert files and all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
        rows = [json.loads(x) for f in files for x in f.read_text(encoding='utf-8').splitlines()]
        seen = sorted({(r['src_ip'], r['dst_ip'], r['dst_port'], r['side']) for r in rows})
        want = sorted((GUEST_IP, HOST_IP, p, 'guest') for p in PORTS)
        assert seen == want, f'records {seen} != {want}'
        assert all(r['iface'] == TAP and r['ttl'] == 64 and r['isn'] for r in rows), rows
        assert abs(rows[0]['ts_ns'] / 1e9 - time.time()) < 60, 'wall clock conversion'

        items = fp.map_items(probe.map_fd['flow_counters'], 4, fp.COUNTERS.size)
        ctr = {int.from_bytes(k, 'little'): fp.decode_counters(v) for k, v in items}[idx]
        assert ctr['syn_out'] >= 3 and ctr['rst_in'] >= 3, ctr
        assert ctr['svc_syn']['ssh'] >= 1 and ctr['svc_syn']['smtp'] >= 1, ctr
        prom = Path(cfg['metrics_file']).read_text(encoding='utf-8')
        assert 'cs_public0_flow_attachments 2' in prom and GUEST_IP not in prom, prom

        # Stale removal: once the tap no longer matches the prefix, reconcile detaches it.
        probe.cfg = dict(cfg, guest_prefix='nomatch')
        probe.cycle()
        assert not fp.tcx_query(idx, fp.TCX_INGRESS) and not fp.tcx_query(idx, fp.TCX_EGRESS)
        assert probe.stale_detached == 2, probe.stale_detached
        probe.cfg = cfg
        probe.cycle()
        assert probe.prog_ids['flow_guest_out'] in fp.tcx_query(idx, fp.TCX_INGRESS)

    assert fp.unload(cfg) == 2
    assert not fp.tcx_query(idx, fp.TCX_INGRESS) and not fp.tcx_query(idx, fp.TCX_EGRESS)
    assert not Path(PIN).exists()
    print(json.dumps({'records': len(rows), 'counters': ctr, 'result': 'PASS'}))
    return 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--inner':
        return inner(Path(sys.argv[2]))
    obj = os.environ.get('FLOW_OBJECT', '')
    if os.geteuid() != 0 or not obj or not Path(obj).exists() or not shutil.which('bpftool'):
        print('prerequisites unavailable (root, FLOW_OBJECT, bpftool)')
        return 77
    cleanup()
    tmp = Path(tempfile.mkdtemp(prefix='flow-test-'))
    (tmp / 'libvirt').mkdir()
    (tmp / 'flow.json').write_text(json.dumps({
        'pin_dir': PIN, 'object': str(Path(obj).resolve()), 'guest_prefix': 'vnettest',
        'uplink': '', 'state_dir': str(tmp / 'libvirt'), 'spool_dir': str(tmp / 'spool'),
        'metrics_file': str(tmp / 'flow.prom'), 'sensor_id': 'ci',
    }), encoding='utf-8')
    try:
        sh('ip', 'netns', 'add', NS_HOST)
        sh('ip', 'netns', 'add', NS_GUEST)
        sh('ip', '-n', NS_HOST, 'link', 'add', TAP, 'type', 'veth', 'peer', 'name', PEER,
           'netns', NS_GUEST)
        sh('ip', '-n', NS_HOST, 'addr', 'add', f'{HOST_IP}/24', 'dev', TAP)
        sh('ip', '-n', NS_GUEST, 'addr', 'add', f'{GUEST_IP}/24', 'dev', PEER)
        for ns, dev in ((NS_HOST, TAP), (NS_GUEST, PEER), (NS_HOST, 'lo'), (NS_GUEST, 'lo')):
            sh('ip', '-n', ns, 'link', 'set', dev, 'up')
        r = subprocess.run(['ip', 'netns', 'exec', NS_HOST, sys.executable, '-B', str(HERE),
                            '--inner', str(tmp)], text=True)
        return r.returncode
    finally:
        cleanup()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
