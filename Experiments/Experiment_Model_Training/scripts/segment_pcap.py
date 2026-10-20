#!/usr/bin/env python3
"""Build a replay PCAP of one time window of a capture, with one ICEFE flow per
(original flow x segment). Standard library only (classic pcap in/out; convert
pcapng first with `editcap -F pcap`).

python3 segment_pcap.py IN.pcap OUT.pcap MAP.csv --cls AR --capture ar \
        --window 0.0 0.7 --segment-s 5 --used USED.json

Per packet (IPv4 UDP/TCP; with --ipv6, IPv6 UDP/TCP without extension headers
is converted to IPv4 with the same payload; other packets are skipped):
  * original flow = directional 5-tuple (src, sport, dst, dport, proto). ICEFE
    itself keys on (dst, dport, proto); sessions that share a destination would
    merge on the switch, so every original 5-tuple gets its own new port;
  * --keep-major F (AR/CG captures): keep only UDP 5-tuples carrying >= F of
    the capture's bytes (the media streams), dropping background traffic;
  * segment = floor((t - window start) / segment_s);
  * every (flow, segment) gets a new destination port such that its CRC16 flow
    ID (CRC-16/ARC of 172.16.0.5 | port | proto, as on the switch) is unique and
    its low 13 bits (the LPF slot) are unique among all ports in USED.json;
  * src/dst IP -> 172.16.0.4 / 172.16.0.5, MACs superpeach -> superluigi,
    DSCP/ECN cleared, IPv4 checksum recomputed, UDP checksum 0; TCP checksum is
    left stale (the switch does not check it; superluigi drops those segments);
  * timestamps shifted so the window starts at t = 0 (original spacing kept).
MAP.csv: port, flow_id, slot13, class, capture, split window, original flow,
segment, packets, bytes, first/last packet time.
"""
import argparse
import csv
import json
import struct
from pathlib import Path

DST_IP, SRC_IP = bytes([172, 16, 0, 5]), bytes([172, 16, 0, 4])
DST_MAC, SRC_MAC = bytes.fromhex('00154d135cb8'), bytes.fromhex('00154d135ca6')
RESERVED = set(range(5201, 5215)) | {22, 53, 80, 443, 4789, 9999}


def crc16_arc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def flow_id(port, proto):
    return crc16_arc(DST_IP + port.to_bytes(2, 'big') + bytes([proto]))


def ip_checksum(header):
    s = sum(struct.unpack('!%dH' % (len(header) // 2), header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class Ports:
    """Destination ports per protocol (TCP and UDP flows with the same port have
    different flow IDs), with flow IDs and LPF slots unique across both."""

    def __init__(self, path):
        self.path = Path(path)
        d = json.loads(self.path.read_text()) if self.path.exists() else {}
        self.ports = {int(k): set(v) for k, v in d.get('ports_by_proto', {}).items()}
        self.ids, self.slots = set(d.get('ids', [])), set(d.get('slots', []))
        self.next = {}

    def take(self, proto):
        used = self.ports.setdefault(proto, set())
        port = self.next.get(proto, 10000)
        while port <= 65535:
            if port not in RESERVED and port not in used:
                fid = flow_id(port, proto)
                if fid and fid not in self.ids and (fid & 0x1FFF) not in self.slots:
                    used.add(port)
                    self.ids.add(fid)
                    self.slots.add(fid & 0x1FFF)
                    self.next[proto] = port + 1
                    return port, fid
            port += 1
        raise RuntimeError('out of ports: %d LPF slots in use' % len(self.slots))

    def save(self):
        self.path.write_text(json.dumps({'ports_by_proto': {str(k): sorted(v) for k, v in self.ports.items()},
                                         'ids': sorted(self.ids), 'slots': sorted(self.slots)}))


def packets(path):
    with open(path, 'rb') as f:
        head = f.read(24)
        magic = struct.unpack('<I', head[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            endian = '<'
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
            endian = '>'
        else:
            raise ValueError('not a classic pcap (convert pcapng with editcap -F pcap)')
        nano = magic in (0xa1b23c4d, 0x4d3cb2a1)
        linktype = struct.unpack(endian + 'I', head[20:24])[0]
        if linktype not in (1, 101):
            raise ValueError('linktype %d: only Ethernet (1) and raw IP (101) are supported' % linktype)
        yield head
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, frac, incl, orig = struct.unpack(endian + 'IIII', rec)
            data = f.read(incl)
            if linktype == 101:                       # raw IP: add a synthetic Ethernet header
                if not data:
                    continue
                eth = b'\x86\xdd' if data[0] >> 4 == 6 else b'\x08\x00'
                data, orig = bytes(12) + eth + data, orig + 14
            yield (sec + frac / (1e9 if nano else 1e6), data, orig)


def parse(data, orig, ipv6):
    """Return (ipv4_frame, orig_len, five_tuple) or None."""
    eth_type = struct.unpack('!H', data[12:14])[0]
    if eth_type == 0x8100:
        eth_type = struct.unpack('!H', data[16:18])[0]
        data = data[:12] + data[16:]
        orig -= 4
    off = 14
    if eth_type == 0x0800 and len(data) >= off + 20:
        ihl = (data[off] & 0x0F) * 4
        proto = data[off + 9]
        if proto not in (6, 17) or len(data) < off + ihl + 4:
            return None
        l4 = off + ihl
        five = (bytes(data[off + 12:off + 16]), data[l4:l4 + 2], bytes(data[off + 16:off + 20]),
                struct.unpack('!H', data[l4 + 2:l4 + 4])[0], proto)
        return bytearray(data), orig, five, ihl
    if ipv6 and eth_type == 0x86DD and len(data) >= off + 40:
        nxt = data[off + 6]
        if nxt not in (6, 17):
            return None
        plen = struct.unpack('!H', data[off + 4:off + 6])[0]
        l4 = off + 40
        if len(data) < l4 + 4:
            return None
        five = (bytes(data[off + 8:off + 24]), data[l4:l4 + 2], bytes(data[off + 24:off + 40]),
                struct.unpack('!H', data[l4 + 2:l4 + 4])[0], nxt)
        v4 = bytearray(20)
        v4[0], v4[1] = 0x45, 0
        v4[2:4] = struct.pack('!H', min(plen + 20, 65535))
        v4[8], v4[9] = data[off + 7], nxt               # TTL = hop limit
        frame = bytearray(data[:12]) + b'\x08\x00' + v4 + bytearray(data[l4:])
        return frame, orig - 20, five, 20
    return None


def first_pass(path, ipv6):
    first = last = None
    volume = {}
    total = 0
    for item in packets(path):
        if isinstance(item, bytes):
            continue
        t, data, orig = item
        first = t if first is None else first
        last = t
        p = parse(data, orig, ipv6)
        if p:
            volume[p[2]] = volume.get(p[2], 0) + p[1]
            total += p[1]
    return first, last, volume, total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('inp')
    ap.add_argument('out')
    ap.add_argument('mapcsv')
    ap.add_argument('--cls', required=True, choices=('AR', 'CG', 'Other'))
    ap.add_argument('--capture', required=True)
    ap.add_argument('--window', nargs=2, type=float, required=True)
    ap.add_argument('--segment-s', type=float, required=True)
    ap.add_argument('--used', required=True)
    ap.add_argument('--ipv6', action='store_true')
    ap.add_argument('--keep-major', type=float, default=0.0)
    ap.add_argument('--max-flows', type=int, default=0,
                    help='keep a seeded random sample of at most N (5-tuple, segment) flows')
    ap.add_argument('--seed', type=int, default=7)
    a = ap.parse_args()

    t_first, t_last, volume, total = first_pass(a.inp, a.ipv6)
    keep = None
    if a.keep_major:
        keep = {k for k, v in volume.items() if k[4] == 17 and v >= a.keep_major * total}
    span = t_last - t_first
    w0, w1 = t_first + a.window[0] * span, t_first + a.window[1] * span
    selected = None
    if a.max_flows:
        keys = set()
        for item in packets(a.inp):
            if isinstance(item, bytes) or not (w0 <= item[0] < w1):
                continue
            p = parse(item[1], item[2], a.ipv6)
            if p and (keep is None or p[2] in keep):
                keys.add(p[2] + (int((item[0] - w0) // a.segment_s),))
        if len(keys) > a.max_flows:
            import random
            selected = set(random.Random(a.seed).sample(sorted(keys), a.max_flows))
    ports = Ports(a.used)
    flows = {}
    out = open(a.out, 'wb')
    out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    skipped = 0
    for item in packets(a.inp):
        if isinstance(item, bytes):
            continue
        t, data, orig = item
        if not (w0 <= t < w1):
            continue
        p = parse(data, orig, a.ipv6)
        if p is None or (keep is not None and p[2] not in keep):
            skipped += 1
            continue
        data, orig, five, ihl = p
        off = 14
        proto = five[4]
        l4 = off + ihl
        key = five + (int((t - w0) // a.segment_s),)
        if selected is not None and key not in selected:
            skipped += 1
            continue
        if key not in flows:
            port, fid = ports.take(proto)
            flows[key] = {'port': port, 'flow_id': fid, 'packets': 0, 'bytes': 0, 'first': t, 'last': t}
        rec = flows[key]
        rec['packets'] += 1
        rec['bytes'] += orig - 14
        rec['last'] = t
        b = data
        b[0:6], b[6:12] = DST_MAC, SRC_MAC
        b[off + 1] = 0                                # DSCP 0, Not-ECT
        b[off + 12:off + 16], b[off + 16:off + 20] = SRC_IP, DST_IP
        b[off + 10:off + 12] = b'\x00\x00'
        b[off + 10:off + 12] = struct.pack('!H', ip_checksum(bytes(b[off:off + ihl])))
        b[l4 + 2:l4 + 4] = struct.pack('!H', rec['port'])
        if proto == 17 and len(b) >= l4 + 8:
            b[l4 + 6:l4 + 8] = b'\x00\x00'            # UDP checksum optional on IPv4
        tt = t - w0
        sec = int(tt)
        out.write(struct.pack('<IIII', sec, int(round((tt - sec) * 1e6)) % 1000000, len(b), orig))
        out.write(bytes(b))
    out.close()
    ports.save()
    with open(a.mapcsv, 'a', newline='') as fh:
        w = csv.writer(fh)
        if fh.tell() == 0:
            w.writerow(['port', 'flow_id', 'slot13', 'class', 'capture', 'window', 'orig_src', 'orig_sport',
                        'orig_dst', 'orig_dport', 'proto', 'segment', 'packets', 'bytes', 'first_s', 'last_s'])
        def ip(b):
            return '.'.join(map(str, b)) if len(b) == 4 else ':'.join('%02x%02x' % (b[i], b[i + 1]) for i in range(0, 16, 2))
        for (src, sport, dst, dport, proto, seg), r in sorted(flows.items(), key=lambda kv: kv[1]['first']):
            w.writerow([r['port'], r['flow_id'], r['flow_id'] & 0x1FFF, a.cls, a.capture,
                        '%g-%g' % tuple(a.window), ip(src), int.from_bytes(sport, 'big'), ip(dst), dport, proto, seg,
                        r['packets'], r['bytes'], round(r['first'] - w0, 6), round(r['last'] - w0, 6)])
    print('%s %s window %s: %d flows, %d packets, %.1f s, skipped %d non-IPv4/UDP/TCP' % (
        a.capture, a.cls, a.window, len(flows), sum(r['packets'] for r in flows.values()),
        w1 - w0, skipped))


if __name__ == '__main__':
    main()
