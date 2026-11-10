"""Synthetic DNS packets for offline/private-namespace replay; no network calls."""
import ipaddress
import struct
import time

from exploit_corpus import checksum, frame


def message(name, txid, response=False):
    labels = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', txid, 0x8180 if response else 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)


def udp_frame(source, destination, sport, dport, body):
    src, dst = ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed
    size = len(body) + 8
    udp = struct.pack('!HHHH', sport, dport, size, 0)
    check = checksum(src + dst + struct.pack('!BBH', 0, 17, size) + udp + body) or 65535
    udp = struct.pack('!HHHH', sport, dport, size, check)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + size, 1, 0x4000, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('0200000000020200000000010800') + ip + udp + body


def pcap(now=None):
    now = int(time.time()) if now is None else int(now)
    packets = []
    for index, name in enumerate(('bad.example', 'ip-api.com', 'bad.example.attacker.invalid')):
        sport = 53001 + index
        packets.append(udp_frame('192.0.2.20', '198.51.100.53', sport, 53, message(name, index + 1)))
        packets.append(udp_frame('198.51.100.53', '192.0.2.20', 53, sport, message(name, index + 1, True)))
    body = message('bad.example', 99)
    tcp_body = struct.pack('!H', len(body)) + body
    packets.extend((frame('192.0.2.20', '198.51.100.53', 54001, 53, 1000, 0, 0x02),
        frame('198.51.100.53', '192.0.2.20', 53, 54001, 9000, 1001, 0x12),
        frame('192.0.2.20', '198.51.100.53', 54001, 53, 1001, 9001, 0x10),
        frame('192.0.2.20', '198.51.100.53', 54001, 53, 1001, 9001, 0x18, tcp_body),
        frame('198.51.100.53', '192.0.2.20', 53, 54001, 9001, 1001 + len(tcp_body), 0x10)))
    answer = message('bad.example', 99, True)
    reply = struct.pack('!H', len(answer)) + answer
    packets.append(frame('198.51.100.53', '192.0.2.20', 53, 54001, 9001, 1001 + len(tcp_body), 0x18, reply))
    out = [struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    for i, packet in enumerate(packets):
        out += [struct.pack('<IIII', now, i * 1000, len(packet), len(packet)), packet]
    return b''.join(out), len(packets)
