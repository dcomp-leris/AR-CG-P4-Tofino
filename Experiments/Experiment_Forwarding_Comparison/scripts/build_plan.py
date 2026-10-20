#!/usr/bin/env python3
"""Session characteristics + replay schedule.

Inputs: raw/pcap_sessions/<session>.timeline.csv (tshark: epoch,len,src,dst,sport,dport)
Outputs:
  results/flow_characteristics.csv  per-session packets, bytes, duration, rates
  raw/plan_<DL|UL>.json             session order, durations, sampling masks, gap
  start.json (with --t0)            absolute schedule shared by switch and hosts

Packet timing inside a session is untouched (tcpreplay uses PCAP timestamps).
Only the idle time between independent sessions is set to GAP_S.
"""
import argparse
import csv
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RING = 65536
GAP_S = 45.0   # drain (2 s) + snapshot/ring read + reset + arm margin; validated in the trial run
LINK_BPS = 10e9
ORDER = {'DL': ['AR_5000', 'AR_5001', 'AR_5002', 'AR_5003',
                'CGDL_4000', 'CGDL_4001', 'CGDL_4002', 'CGDL_4003', 'CGDL_4004', 'CGDL_4005'],
         'UL': ['CGUL_3000', 'CGUL_3005']}
TRACE = {'AR': 'DL-AR (dl/myar_p00.pcap)', 'CGDL': 'DL-CG (dl/mycgdl_p00.pcap)',
         'CGUL': 'UL-CG (ul/mycgull_p00.pcap)'}


def characterise(name):
    times, sizes, tuples = [], [], set()
    with (ROOT / 'raw' / 'pcap_sessions' / (name + '.timeline.csv')).open() as f:
        for row in csv.reader(f):
            times.append(float(row[0]))
            sizes.append(int(row[1]))
            tuples.add(tuple(row[2:6]))
    assert len(tuples) == 1, (name, tuples)
    duration = times[-1] - times[0]

    def peak(window):
        best, j, acc = 0, 0, 0
        for i in range(len(times)):
            acc += sizes[i]
            while times[i] - times[j] >= window:
                acc -= sizes[j]
                j += 1
            best = max(best, acc)
        return best * 8 / window

    k = max(0, math.ceil(math.log2(max(1, len(times)) / RING)))
    src, dst, sport, dport = next(iter(tuples))
    return {'session': name, 'trace': TRACE[name.split('_')[0]],
            'src_ip': src, 'dst_ip': dst, 'src_port': sport, 'dst_port': dport,
            'packets': len(times), 'bytes_l2': sum(sizes), 'duration_s': round(duration, 6),
            'mean_rate_mbps': round(sum(sizes) * 8 / duration / 1e6, 3) if duration else None,
            'peak_1ms_mbps': round(peak(0.001) / 1e6, 3),
            'peak_100ms_mbps': round(peak(0.1) / 1e6, 3),
            'max_peak_fraction_of_10G': round(peak(0.001) / LINK_BPS, 5),
            'sampling_mask': (1 << k) - 1, 'expected_samples': math.ceil(len(times) / (1 << k))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--t0', type=float, help='epoch of the first session start')
    parser.add_argument('--direction', choices=['DL', 'UL'])
    parser.add_argument('--run-id')
    parser.add_argument('--program', choices=['ICEFE_r2c1', 'FWD_r2c1'])
    parser.add_argument('--sessions', help='comma list overriding the direction order (validation)')
    args = parser.parse_args()
    rows = {n: characterise(n) for d in ORDER for n in ORDER[d]}
    if args.t0 is None:
        out = ROOT / 'results' / 'flow_characteristics.csv'
        out.parent.mkdir(exist_ok=True)
        with out.open('w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(next(iter(rows.values()))))
            w.writeheader()
            w.writerows(rows.values())
        for d, names in ORDER.items():
            plan = {'direction': d, 'gap_s': GAP_S, 'sessions': [rows[n] for n in names]}
            (ROOT / 'raw' / ('plan_%s.json' % d)).write_text(json.dumps(plan, indent=2))
        print(out)
        return
    names = args.sessions.split(',') if args.sessions else ORDER[args.direction]
    t, schedule = args.t0, []
    for n in names:
        r = rows[n]
        schedule.append({'session': n, 'start_epoch': t, 'duration_s': r['duration_s'],
                         'packets': r['packets'], 'mask': r['sampling_mask'], 'gap_s': GAP_S})
        t += r['duration_s'] + GAP_S
    start = {'run_id': args.run_id, 'program': args.program, 'direction': args.direction,
             't0_epoch': args.t0, 'gap_s': GAP_S, 'schedule': schedule,
             'expected_end_epoch': t - GAP_S}
    print(json.dumps(start, indent=2))


if __name__ == '__main__':
    main()
