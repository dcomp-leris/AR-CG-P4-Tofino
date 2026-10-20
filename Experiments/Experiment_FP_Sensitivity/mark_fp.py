#!/usr/bin/env python3
"""Controlled false positives: pre-mark a seeded set of Other flows with DSCP 46 (AR) or
34 (CG) so that they carry TARGET of all Other packets; ICEFE's DSCP override then treats
them as AR/CG (ECT(1), Q1) regardless of the classifier.

python3 mark_fp.py IN.pcap OUT.pcap MAP.csv TARGET SEED SELECTED.json

Flows are picked in seeded random order and added while the running packet share stays
<= TARGET; the last pick is the flow that brings the share closest to TARGET. Each picked
flow is assigned DSCP 46 or 34 at random (seeded). ECN stays Not-ECT; the IPv4 header
checksum is recomputed.
"""
import csv
import json
import random
import struct
import sys


def ip_checksum(h):
    s = sum(struct.unpack('!%dH' % (len(h) // 2), h))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


inp, out, mapcsv, target, seed, selpath = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
rows = [r for r in csv.DictReader(open(mapcsv)) if r['class'] == 'Other']
total = sum(int(r['packets']) for r in rows)
rng = random.Random(seed)
order = rows[:]
rng.shuffle(order)
picked, acc = [], 0
for r in order:
    p = int(r['packets'])
    if acc + p <= target * total:
        picked.append(r)
        acc += p
    if acc >= target * total * 0.995:
        break
if acc < target * total * 0.995:                     # top up with the flow closest to the gap
    rest = [r for r in order if r not in picked]
    gap = target * total - acc
    best = min(rest, key=lambda r: abs(int(r['packets']) - gap))
    picked.append(best)
    acc += int(best['packets'])
dscp = {(int(r['port']), int(r['proto'])): rng.choice((46, 34)) for r in picked}
json.dump({'target': target, 'seed': seed, 'other_packets': total, 'marked_packets': acc,
           'marked_share': acc / total, 'flows': [{'flow_id': int(r['flow_id']), 'port': int(r['port']),
                                                    'proto': int(r['proto']), 'packets': int(r['packets']),
                                                    'dscp': dscp[(int(r['port']), int(r['proto']))]} for r in picked]},
          open(selpath, 'w'), indent=1)
marked = 0
with open(inp, 'rb') as f, open(out, 'wb') as o:
    o.write(f.read(24))
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            break
        incl = struct.unpack('<IIII', rec)[2]
        d = bytearray(f.read(incl))
        if len(d) >= 38 and d[12:14] == b'\x08\x00' and d[23] in (6, 17):
            ihl = (d[14] & 15) * 4
            port = struct.unpack('!H', d[14 + ihl + 2:14 + ihl + 4])[0]
            v = dscp.get((port, d[23]))
            if v is not None:
                d[15] = v << 2                        # DSCP v, ECN Not-ECT
                d[24:26] = b'\x00\x00'
                d[24:26] = struct.pack('!H', ip_checksum(bytes(d[14:14 + ihl])))
                marked += 1
        o.write(rec)
        o.write(bytes(d))
print('target %.3f: %d flows, %d of %d Other packets (%.4f), %d packets rewritten' % (
    target, len(picked), acc, total, acc / total, marked))
