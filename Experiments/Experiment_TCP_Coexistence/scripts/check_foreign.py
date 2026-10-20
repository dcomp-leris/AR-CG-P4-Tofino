#!/usr/bin/env python3
"""python3 check_foreign.py RUN_DIR...: ring samples from flows not in the run's plan (e.g. P4TG)."""
import collections, json, sys
def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c
for d in sys.argv[1:]:
    sw = json.load(open(d + '/switch.json')); plan = json.load(open(d + '/plan.json'))
    ids = {crc(bytes([172, 16, 0, 5]) + f['port'].to_bytes(2, 'big') + bytes([6])) for f in plan['flows']}
    ring = collections.Counter(r['flow_id'] for r in sw['ring'])
    foreign = {k: v for k, v in ring.items() if k not in ids}
    print('%-24s ring %6d  foreign %s' % (d.rstrip('/').split('/')[-1], sum(ring.values()), foreign or 'none'))
