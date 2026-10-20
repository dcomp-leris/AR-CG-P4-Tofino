#!/usr/bin/env python3
"""Extra metrics for E1.3-E1.5: python3 e1x_extra.py   (all finished E13/E14/E15 runs)

E1.3: the replayed held-out AR / CG-DL flows (merged_ARCG.pcap, ground truth from
config/map_test_DL.csv): ICEFE's stored decision per flow, admitted share (flows,
packets), switch TM queueing delay of their packets by queue used (per-packet ring),
loss (switch ingress vs egress per flow).
E1.4/E1.5: ICEFE's decision for the SCReAM flow (172.16.0.5:30120/UDP) and the ECN /
queue its packets actually had (ring samples).
Writes results/e1x_extra_runs.csv and results/e1x_extra_cells.csv (mean, SD, 95 % CI).
"""
import csv
import json
import statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / 'raw' / 'e1'
OUT = ROOT / 'results'
NAMES = {0: 'none', 1: 'AR', 2: 'CG', 3: 'Other'}
T975 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776}


def crc16_arc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def pct(v, p):
    if not v:
        return None
    v = sorted(v)
    k = (len(v) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


truth = {int(r['flow_id']): r['class'] for r in csv.DictReader(open(ROOT / 'config' / 'map_test_DL.csv'))
         if r['capture'] in ('ar', 'DLF', 'DL_K')}
SCREAM_ID = crc16_arc(bytes([172, 16, 0, 5]) + (30120).to_bytes(2, 'big') + bytes([17]))
rows = []
for plan_path in sorted(RUNS.glob('E1[345]_*/plan.json')):
    rd = plan_path.parent
    if not (rd / 'switch_done.json').exists():
        continue
    plan = json.loads(plan_path.read_text())
    fs = {k: {int(i): v for i, v in d.items()} for k, d in json.loads((rd / 'flow_state.json').read_text()).items()}
    ring = json.loads((rd / 'switch.json').read_text())['ring']
    row = {'run_id': plan['run_id'], 'cell': plan['cell'], 'config': plan['config'], 'rep': plan['rep']}
    if plan['cell'] == 'E13':
        seen = [i for i in truth if fs['ingress_pkts'].get(i, 0) > 0]
        adm = [i for i in seen if NAMES.get(fs['decision'].get(i, 0)) in ('AR', 'CG')]
        pk = lambda ids: sum(fs['ingress_pkts'].get(i, 0) for i in ids)
        row.update({'replay_flows': len(seen), 'replay_admitted_flow_frac': len(adm) / len(seen) if seen else None,
                    'replay_admitted_pkt_frac': pk(adm) / pk(seen) if seen else None,
                    'replay_loss': 1 - sum(fs['egress_pkts'].get(i, 0) for i in seen) / pk(seen) if seen else None,
                    'replay_admitted_loss': 1 - sum(fs['egress_pkts'].get(i, 0) for i in adm) / pk(adm) if adm else None})
        for q in (0, 1):
            v = [x['queue_raw'] / 1000 for x in ring if x['flow_id'] in truth and x['queue'] == q]
            row['replay_q%d_samples' % q] = len(v)
            for p in (50, 95, 99):
                row['replay_q%d_qdelay_p%d_us' % (q, p)] = pct(v, p)
    else:
        dec = NAMES.get(fs['decision'].get(SCREAM_ID, 0))
        smp = [x for x in ring if x['flow_id'] == SCREAM_ID]
        row.update({'scream_decision': dec, 'scream_samples': len(smp),
                    'scream_q1_frac': sum(x['queue'] == 1 for x in smp) / len(smp) if smp else None,
                    'scream_ect1_or_ce_frac': sum(x['ecn_out'] in (1, 3) for x in smp) / len(smp) if smp else None,
                    'scream_ce_frac_ring': sum(x['ecn_out'] == 3 for x in smp) / len(smp) if smp else None,
                    'scream_loss': 1 - fs['egress_pkts'].get(SCREAM_ID, 0) / fs['ingress_pkts'][SCREAM_ID]
                    if fs['ingress_pkts'].get(SCREAM_ID) else None})
        for p in (50, 95, 99):
            row['scream_qdelay_p%d_us' % p] = pct([x['queue_raw'] / 1000 for x in smp], p)
    rows.append(row)
OUT.mkdir(exist_ok=True)
keys = []
for r in rows:
    keys += [k for k in r if k not in keys]
with (OUT / 'e1x_extra_runs.csv').open('w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=keys)
    w.writeheader()
    w.writerows(rows)
cells = []
for key in sorted({(r['cell'], r['config']) for r in rows}):
    rs = [r for r in rows if (r['cell'], r['config']) == key]
    out = {'cell': key[0], 'config': key[1], 'runs': len(rs)}
    for k in keys:
        vals = [r[k] for r in rs if isinstance(r.get(k), (int, float)) and k != 'rep']
        if vals and len(vals) == len(rs):
            m = st.mean(vals)
            sd = st.stdev(vals) if len(vals) > 1 else 0.0
            out[k + '_mean'], out[k + '_ci95'] = m, (T975.get(len(vals), 1.96) * sd / len(vals) ** 0.5 if len(vals) > 1 else None)
        elif rs and isinstance(rs[0].get(k), str) and k not in ('run_id', 'cell', 'config'):
            out[k] = ';'.join(sorted({r[k] for r in rs}))
    cells.append(out)
keys2 = []
for c in cells:
    keys2 += [k for k in c if k not in keys2]
with (OUT / 'e1x_extra_cells.csv').open('w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=keys2)
    w.writeheader()
    w.writerows(cells)
for c in cells:
    print({k: (round(v, 4) if isinstance(v, float) else v) for k, v in c.items()})
