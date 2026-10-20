#!/usr/bin/env python3
"""Join a replay's ground-truth map with the switch's per-flow registers.

python3 make_samples.py MAP.csv FEATURES.json OUT.csv [--budget DL|UL]

One row per replayed flow: flow_id, class, capture, packets, bytes (from the map),
switch_pkts (ingress packets to 137), clones (clones that returned to ingress),
PS / FS (LPF values the tables match on), IPG20 / IFG20 (LPF value [31:12]),
T1..T5 votes and the decision stored with the weights loaded during the replay.
"""
import argparse
import csv
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mapcsv')
    ap.add_argument('features')
    ap.add_argument('out')
    ap.add_argument('--budget', default='DL')
    a = ap.parse_args()
    feat = {k: {int(i): v for i, v in d.items()} for k, d in json.loads(open(a.features).read()).items()}
    rows = list(csv.DictReader(open(a.mapcsv)))
    cols = ['flow_id', 'class', 'capture', 'window', 'proto', 'segment', 'packets', 'bytes', 'budget',
            'switch_pkts', 'clones', 'PS', 'FS', 'IPG20', 'IFG20', 'T1', 'T2', 'T3', 'T4', 'T5',
            'decision_loaded_weights']
    missing = 0
    with open(a.out, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            i = int(r['flow_id'])
            g = lambda name: feat.get(name, {}).get(i, 0)
            if not g('c7_ingress_flow'):
                missing += 1
            w.writerow({'flow_id': i, 'class': r['class'], 'capture': r['capture'], 'window': r['window'],
                        'proto': r['proto'], 'segment': r['segment'], 'packets': r['packets'],
                        'bytes': r['bytes'], 'budget': a.budget,
                        'switch_pkts': g('c7_ingress_flow'), 'clones': g('drop_cloned_pkt'),
                        'PS': g('packet_size_reg'), 'FS': g('frame_size_reg'),
                        'IPG20': (g('ipg_cloned_packets_reg') >> 12) & 0xFFFFF,
                        'IFG20': (g('ifg_reg') >> 12) & 0xFFFFF,
                        'T1': g('metadata_classT1'), 'T2': g('metadata_classT2'),
                        'T3': g('metadata_classT3'), 'T4': g('metadata_classT4'),
                        'T5': g('metadata_classT5'), 'decision_loaded_weights': g('shared_register')})
    print('%d flows written, %d not seen by the switch' % (len(rows), missing))


if __name__ == '__main__':
    main()
