#!/usr/bin/env python3
"""Compare switch LPF features with PCAP references (first N packets).
python3 check_features.py SAMPLES.csv TRUTH.csv MAP.csv"""
import csv, statistics, sys
samples = {int(r['flow_id']): r for r in csv.DictReader(open(sys.argv[1]))}
port_of = {int(r['flow_id']): (r['capture'], int(r['port'])) for r in csv.DictReader(open(sys.argv[3]))}
truth = {(r['pcap'].rsplit('.', 1)[0], int(r['port'])): r for r in csv.DictReader(open(sys.argv[2]))}
rows = {}
for fid, s in samples.items():
    t = truth.get(port_of.get(fid))
    if not t or int(s['clones']) == 0:
        continue
    ps_ratio = int(s['PS']) / float(t['ps_mean']) if float(t['ps_mean']) else None
    ipg_us = int(s['IPG20']) * 4.096
    ipg_ratio = ipg_us / float(t['ipg_mean_us']) if t['ipg_mean_us'] and float(t['ipg_mean_us']) > 0 else None
    rows.setdefault(s['class'], []).append((ps_ratio, ipg_ratio, int(s['clones'])))
for cls, v in sorted(rows.items()):
    ps = [x[0] for x in v if x[0] is not None]
    ip = [x[1] for x in v if x[1] is not None and x[2] >= 10]
    q = lambda a: ' / '.join('%.2f' % x for x in statistics.quantiles(a, n=10)[::4]) if len(a) > 10 else str(a[:5])
    print('%-6s flows %5d   PS/true p10/p50/p90 %s   IPG/true (>=10 clones) p10/p50/p90 %s' % (cls, len(v), q(ps), q(ip)))
