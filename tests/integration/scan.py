"""Root-only kernel smoke for the scan detector table (ADR-067, OBSERVE).

Runs inside an empty private network namespace (refuses the host namespace):
a bridge named like the sensor bridge, two veth pairs, raw Ethernet frames sent
into one port and captured on the other. Checks that the own table never
changes forwarding, counts only the initial inbound SYN from listed sources to
protected targets, honours element timeouts and the set size, keeps working
during an atomic replacement, refuses a foreign table, coexists with the IP
intelligence DROP table (-250 runs first) and withdraws cleanly. A real Service
run turns synthetic EVE flows into one decision, one event and kernel elements.
Exit 77 = prerequisites unavailable (not a pass).

Usage: sudo unshare --net python3 -B tests/integration/scan.py
       (on a sensor: systemd-run --wait --pipe --property=PrivateNetwork=yes ...)
"""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / 'runtime'))
import scan_detector as sd  # noqa: E402
import ip_intelligence as ipi  # noqa: E402

PROTECTED = '203.0.113.0/24'
TARGET = '203.0.113.10'
LISTED = '198.51.100.2'
ONLY_BEHAVIOR = '198.51.100.3'
CLEAN = '198.51.100.1'
IOC_LISTED = '198.51.100.4'
FIXTURE = b'public0-scan-isolated-fixture'


def run(*args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if r.returncode:
        raise RuntimeError(' '.join(args[:4]) + ': ' + r.stderr[:500])
    return r.stdout


def checksum(raw):
    if len(raw) % 2:
        raw += b'\0'
    total = sum(struct.unpack('!' + str(len(raw) // 2) + 'H', raw))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(source, destination, port, mac, flags=2):
    src, dst = ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed
    transport = struct.pack('!HHIIBBHHH', 40000, port, 1, 1 if flags & 16 else 0, 0x50, flags, 8192, 0, 0) + FIXTURE
    value = checksum(src + dst + struct.pack('!BBH', 0, 6, len(transport)) + transport)
    transport = transport[:16] + struct.pack('!H', value) + transport[18:]
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 1, 0, 64, 6, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return bytes.fromhex(mac.replace(':', '')) + bytes.fromhex('020000000001') + b'\x08\x00' + header + transport


def forwarded(source, destination, port=22, flags=2):
    """Send one frame into scan_a1 and report whether it left the bridge on scan_b1."""
    mac = json.loads(run('ip', '-j', 'link', 'show', 'scan_b1'))[0]['address']
    expected = ipaddress.IPv4Address(source).packed + ipaddress.IPv4Address(destination).packed
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as receiver, \
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
        receiver.bind(('scan_b1', 0))
        sender.bind(('scan_a1', 0))
        sender.send(frame(source, destination, port, mac, flags))
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            receiver.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                data = receiver.recv(4096)
            except TimeoutError:
                return False
            if data[26:34] == expected and data.endswith(FIXTURE):
                return True
    return False


def counters(kernel):
    return kernel.counters()


def require(condition, message, **details):
    if not condition:
        raise RuntimeError(message + (' ' + json.dumps(details, default=str) if details else ''))


def main():
    if os.geteuid() != 0 or Path('/proc/self/ns/net').stat().st_ino == Path('/proc/1/ns/net').stat().st_ino:
        print('root in a separate network namespace required', file=sys.stderr)
        return 77
    if not shutil.which('nft') or not shutil.which('ip'):
        print('nft and ip are required', file=sys.stderr)
        return 77
    if {x['ifname'] for x in json.loads(run('ip', '-j', 'link', 'show'))} != {'lo'}:
        print('the namespace must be empty', file=sys.stderr)
        return 77
    probe = subprocess.run(['nft', '--check', 'add', 'table', 'bridge', 'cs_public0_scan_probe'],
                           capture_output=True, text=True, timeout=30)
    if probe.returncode:
        # Some kernels (WSL2) lack the nf_tables bridge family.
        print('nf_tables bridge family unavailable: ' + probe.stderr.strip()[:200], file=sys.stderr)
        return 77
    tests = []
    run('ip', 'link', 'add', 'public0', 'type', 'bridge')
    run('ip', 'link', 'set', 'public0', 'up')
    for name in ('a', 'b'):
        run('ip', 'link', 'add', f'scan_{name}0', 'type', 'veth', 'peer', 'name', f'scan_{name}1')
        run('ip', 'link', 'set', f'scan_{name}0', 'master', 'public0')
        for suffix in '01':
            run('ip', 'link', 'set', f'scan_{name}{suffix}', 'up')
    require(forwarded(CLEAN, TARGET), 'baseline forwarding')
    tests.append('BASELINE_FORWARD')

    protected = (ipaddress.ip_network(PROTECTED),)
    kernel = sd.Kernel('public0')
    require(kernel.ensure(protected, 4096) == 'created', 'create')
    require(kernel.conforms(kernel.table(), protected, 4096) == [], 'exact readback',
            rows=kernel.table())
    require(kernel.ensure(protected, 4096) == 'kept', 'idempotent ensure')
    tests += ['TABLE_CREATED_EXACT', 'ENSURE_IDEMPOTENT']

    require(forwarded(LISTED, TARGET), 'unlisted SYN forwarded')
    require(counters(kernel) == {'observed_behavior': 0, 'observed_block': 0}, 'no count before listing')
    require(kernel.add('scan_behavior', LISTED, 60) and kernel.add('scan_block', LISTED, 60), 'add elements')
    require(kernel.add('scan_behavior', ONLY_BEHAVIOR, 60), 'add behaviour-only element')
    require(forwarded(LISTED, TARGET), 'OBSERVE never drops a listed SYN')
    require(counters(kernel) == {'observed_behavior': 1, 'observed_block': 1}, 'listed SYN counted once per set',
            counters=counters(kernel))
    require(forwarded(ONLY_BEHAVIOR, TARGET), 'behaviour-only SYN forwarded')
    require(counters(kernel) == {'observed_behavior': 2, 'observed_block': 1}, 'variant A counted apart from B')
    tests += ['OBSERVE_SYN_FORWARDED_AND_COUNTED', 'VARIANT_A_B_COUNTERS']
    for flags, label in ((18, 'SYNACK'), (16, 'ACK'), (24, 'DATA'), (4, 'RST'), (3, 'SYNFIN')):
        require(forwarded(LISTED, TARGET, flags=flags), label + ' forwarded')
    require(forwarded(LISTED, '192.0.2.50'), 'unprotected destination forwarded')
    require(counters(kernel) == {'observed_behavior': 2, 'observed_block': 1}, 'only initial SYN to protected counted',
            counters=counters(kernel))
    tests += ['NON_SYN_NOT_COUNTED', 'UNPROTECTED_NOT_COUNTED']

    remaining = kernel.elements('scan_block')
    require(LISTED in remaining and 0 < remaining[LISTED] <= 60, 'element TTL readback', elements=remaining)
    run('nft', 'add', 'element', 'bridge', sd.TABLE, 'scan_behavior', '{ 198.51.100.9 timeout 2s }')
    require('198.51.100.9' in kernel.elements('scan_behavior'), 'short element present')
    time.sleep(3.2)
    require('198.51.100.9' not in kernel.elements('scan_behavior'), 'element expired in the kernel')
    tests += ['ELEMENT_TTL_READBACK', 'KERNEL_EXPIRY_WITHOUT_CONTROLLER']

    # Atomic replacement (another size) keeps forwarding and starts empty.
    result = kernel.ensure(protected, 64)
    require(result.startswith('replaced:'), 'replacement', result=result)
    require(forwarded(LISTED, TARGET), 'forwarding after replacement')
    added = sum(kernel.add('scan_behavior', f'198.18.0.{n}', 60) for n in range(1, 66))
    require(added == 64, 'set size bound enforced by the kernel', added=added)
    require(forwarded(CLEAN, TARGET), 'full set does not affect forwarding')
    tests += ['ATOMIC_REPLACEMENT', 'SET_SIZE_BOUND']
    kernel.ensure(protected, 4096)

    # Coexistence: IP intelligence (-250) drops first, the scan table never sees the packet.
    batch = ipi.nft_batch({'incoming': [IOC_LISTED + '/32'], 'outgoing': [], 'c2_ports': []},
                          create=True, ttl=3600, protected=[PROTECTED])
    ipi.nft('--file', '-', payload=batch)
    kernel.add('scan_behavior', IOC_LISTED, 60)
    before = counters(kernel)
    require(not forwarded(IOC_LISTED, TARGET), 'IP intelligence still drops')
    require(counters(kernel) == before, 'scan table after the -250 DROP sees nothing', counters=counters(kernel))
    run('nft', 'delete', 'table', 'bridge', ipi.TABLE)
    tests.append('COEXISTS_WITH_IP_INTELLIGENCE')

    # Service end to end with the real kernel.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        eve = root / 'eve.json'
        eve.write_bytes(b'')
        config = sd.load_config({
            'schema': sd.SCHEMA, 'mode': 'observe', 'bridge': 'public0', 'sensor_id': 'lab',
            'protected_networks': [PROTECTED], 'own_networks': [],
            'eve_file': str(eve), 'ioc_file': str(root / 'ioc.json'), 'state_directory': str(root),
            'metrics_file': str(root / 'cs_public0_scan.prom'), 'decision_log': str(root / 'events.jsonl'),
            'window_seconds': 600, 'min_pairs': 100, 'min_ports': 30, 'ttl_seconds': [900, 3600, 21600],
            'repeat_window_seconds': 86400, 'set_size': 4096, 'max_decisions_per_minute': 60, 'whitelist': []})
        service = sd.Service(config, kernel=kernel)
        service.prepare()
        service.run(iterations=1)
        now = time.time()
        rows = []
        for i in range(150):
            start = sd.iso(now - 60 + i * 0.1).replace('Z', '+0000')
            rows.append(json.dumps({'event_type': 'flow', 'proto': 'TCP', 'src_ip': '45.67.89.10', 'src_port': 40000,
                                    'dest_ip': '203.0.113.%d' % (10 + i % 5), 'dest_port': 1000 + i,
                                    'flow': {'start': start}, 'tcp': {'tcp_flags_ts': '02', 'tcp_flags_tc': '14'}}))
        with open(eve, 'a', encoding='ascii') as f:
            f.write('\n'.join(rows) + '\n')
        service.run(iterations=2)
        service.follower.close()
        events = [json.loads(x) for x in (root / 'events.jsonl').read_text().splitlines()]
        require([(e['remote_ip'], e['kernel'], e['action']) for e in events] == [('45.67.89.10', 'added', 'observe')],
                'one decision event', events=events)
        require('45.67.89.10' in kernel.elements('scan_behavior'), 'decision element in the kernel')
        require(forwarded('45.67.89.10', TARGET), 'decided source still forwarded in OBSERVE')
        metrics = (root / 'cs_public0_scan.prom').read_text()
        require('45.67.89.10' not in metrics and 'cs_public0_scan_kernel_table_present 1' in metrics, 'metrics')
        restarted = sd.Service(config, kernel=kernel)
        restarted.prepare()
        require('45.67.89.10' in restarted.det.active, 'restart restores active decisions from the kernel')
    tests += ['SERVICE_DECISION_EVENT', 'SERVICE_RESTART_RECOVERY']  # source outside special ranges

    # Foreign table refused; withdraw removes only the own table.
    require(kernel.withdraw() == 'deleted' and kernel.table() is None, 'withdraw')
    require(forwarded(LISTED, TARGET), 'forwarding after withdraw')
    run('nft', 'add', 'table', 'bridge', sd.TABLE, '{ comment "foreign-owner"; }')
    for action in (lambda: kernel.ensure(protected, 4096), kernel.withdraw):
        try:
            action()
        except ValueError:
            continue
        raise RuntimeError('foreign table accepted')
    run('nft', 'delete', 'table', 'bridge', sd.TABLE)
    tests += ['WITHDRAW', 'FOREIGN_TABLE_REFUSED']

    print(json.dumps({'status': 'PASS_ISOLATED_ONLY', 'kernel': os.uname().release,
                      'nft': run('nft', '--version').strip(), 'tests': tests}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
