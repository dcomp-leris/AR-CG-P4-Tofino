#!/usr/bin/env python3
"""Analyse the FP mixture runs: python3 fp_analyze.py [RUN_ID ...]  (default: all finished)
Writes results/fp_runs.csv (per run), results/fp_flows.csv (per flow), results/fp_sets.csv
(per set: mean, SD, 95% t-CI across repetitions) and prints a summary.

Ground truth: data/map_test_<set>.csv (class of the capture each flow came from).
Applied decision: the switch's stored decision per flow (shared_register) at the end of the
run. A decision can change only while the flow's first 52 (DL) / 32 (UL) packets are
cloned, so packet-level rates assume the final decision for all of a flow's packets; the
error of that assumption is at most budget-packets per flow (reported as fp_pkt_bound).
Throughput/loss: per-flow packets at ingress (c7_ingress_flow) and leaving port 137
(c7_eg_flow); bytes scale the map's bytes by switch/map packets.
Delay variation (genuine AR/CG): superluigi RX packets matched to their original PCAP send
times (data/send_ref_test.csv.gz) by (dst port, IP ID, IP length); D = rx - t_pcap
(unknown constant offset: replay start, clocks), valid because the replay is not stretched
(checked per run, replay_stretch.json):
PDV_i = D_i - min_flow(D) after removing each flow's linear drift, and IPDV_i = |D_i - D_{i-1}| over consecutive matched packets.
superluigi's NIC drops part of the RX capture under the 10G P4TG load (capture coverage
is reported); IPDV uses only consecutive pairs present on both sides.
"""
import csv
import gzip
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / 'raw' / 'fp'
OUT = ROOT / 'results'
NAMES = {0: 'none', 1: 'AR', 2: 'CG', 3: 'Other'}
BUDGET = {'DL': 52, 'UL': 32}
T975 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776}


def pct(v, p):
    if not v:
        return None
    v = sorted(v)
    k = (len(v) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


_REF = None


def send_ref():
    global _REF
    if _REF is None:
        _REF = {}
        with gzip.open(ROOT / 'data' / 'send_ref_test.csv.gz', 'rt') as fh:
            next(fh)
            for line in fh:
                n, port, ipid, ln, t = line.strip().split(',')
                _REF.setdefault(int(port), []).append((float(t), int(ipid), int(ln)))
    return _REF


def load_caps(rd):
    caps = {'peach': send_ref()}
    for role in ('luigi',):
        rows = {}
        with gzip.open(rd / 'hosts' / ('%s_pkts.csv.gz' % role), 'rt') as fh:
            next(fh)
            for line in fh:
                p = line.strip().split(',')
                if len(p) < 4 or not p[1] or not p[2]:
                    continue
                rows.setdefault(int(p[1]), []).append((float(p[0]), int(p[2], 16) if p[2].startswith('0x') else int(p[2]), int(p[3])))
        caps[role] = rows
    return caps


def delay_stats(tx, rx):
    """Per flow: matched (tx order) delays -> PDV list, IPDV list, coverage."""
    rx_index = {}
    for t, ipid, ln in rx:
        rx_index.setdefault((ipid, ln), []).append(t)
    seq = []
    for t, ipid, ln in tx:
        lst = rx_index.get((ipid, ln))
        if lst:
            r = lst.pop(0)
            seq.append(r - t)
        else:
            seq.append(None)
    d = [x for x in seq if x is not None]
    if not d:
        return [], [], 0.0
    # Remove the flow's linear drift (tcpreplay timing drift, clock skew) before PDV:
    # least-squares D = a + b * t_send over the flow's matched packets.
    ts = [t for (t, _, _), x in zip(tx, seq) if x is not None]
    if len(d) > 2:
        mt, md = st.mean(ts), st.mean(d)
        var = sum((t - mt) ** 2 for t in ts)
        b = sum((t - mt) * (x - md) for t, x in zip(ts, d)) / var if var else 0.0
        d = [x - b * (t - mt) for t, x in zip(ts, d)]
    m = min(d)
    pdv = [(x - m) * 1e6 for x in d]
    ipdv = [abs(b - a) * 1e6 for a, b in zip(seq, seq[1:]) if a is not None and b is not None]
    return pdv, ipdv, len(d) / len(tx)


def analyse(run_id):
    rd = RUNS / run_id
    plan = json.loads((rd / 'plan.json').read_text())
    fs = {k: {int(i): v for i, v in d.items()} for k, d in json.loads((rd / 'flow_state.json').read_text()).items()}
    sw = json.loads((rd / 'switch.json').read_text())
    mp = list(csv.DictReader(open(ROOT / 'data' / ('map_test_%s.csv' % plan['set']))))
    dur = plan['max_duration_s']
    injected = {}
    if plan.get('injected'):
        sel = json.loads((ROOT / 'data' / plan['injected']).read_text())
        injected = {f['flow_id']: ('AR' if f['dscp'] == 46 else 'CG') for f in sel['flows']}
    caps = load_caps(rd)
    # P4TG has no map entry; a map flow whose switch packets exceed its replayed packets by
    # far shares P4TG's flow index (CRC16 collision) and is excluded from all statistics.
    collided = {int(r['flow_id']) for r in mp
                if fs['ingress_pkts'].get(int(r['flow_id']), 0) > max(10 ** 6, 100 * int(r['packets']))}
    flows = []
    for r in mp:
        fid, port = int(r['flow_id']), int(r['port'])
        if fid in collided:
            continue
        ing = fs['ingress_pkts'].get(fid, 0)
        eg = fs['egress_pkts'].get(fid, 0)
        mpk, mby = int(r['packets']), int(r['bytes'])
        cls_dec = NAMES.get(fs['decision'].get(fid, 0), 'none')
        # Applied treatment: pre-marked (injected) flows are AR/CG via ICEFE's DSCP override.
        dec = injected.get(fid, cls_dec)
        f = {'run_id': run_id, 'set': plan['set'], 'variant': plan.get('variant', plan['set']), 'flow_id': fid,
             'port': port, 'capture': r['capture'], 'true': r['class'], 'decision': dec,
             'classifier_decision': cls_dec, 'injected': fid in injected, 'pkts_in': ing, 'pkts_out': eg,
             'bytes_in': mby * ing / mpk if mpk else 0, 'loss': (1 - eg / ing) if ing else None,
             'clones': fs['clone_rx'].get(fid, 0)}
        if r['class'] in ('AR', 'CG') and port in caps['peach']:
            pdv, ipdv, cov = delay_stats(caps['peach'][port], caps['luigi'].get(port, []))
            f.update({'cap_coverage': cov, 'pdv_p50_us': pct(pdv, 50), 'pdv_p95_us': pct(pdv, 95),
                      'pdv_p99_us': pct(pdv, 99), 'ipdv_p50_us': pct(ipdv, 50), 'ipdv_p95_us': pct(ipdv, 95),
                      'ipdv_p99_us': pct(ipdv, 99), '_pdv': pdv, '_ipdv': ipdv})
        flows.append(f)
    seen = [f for f in flows if f['pkts_in'] > 0]
    def frac(sel, num, w=None):
        tot = sum((x[w] if w else 1) for x in sel)
        return sum((x[w] if w else 1) for x in sel if num(x)) / tot if tot else None
    other = [f for f in seen if f['true'] == 'Other']
    arcg = [f for f in seen if f['true'] in ('AR', 'CG')]
    admit = lambda x: x['decision'] in ('AR', 'CG')
    row = {'run_id': run_id, 'set': plan.get('variant', plan['set']), 'rep': int(run_id.rsplit('rep', 1)[1]),
           'excluded_p4tg_collision': ';'.join(str(c) for c in sorted(collided)),
           'flows_seen': len(seen), 'flows_other': len(other), 'flows_arcg': len(arcg)}
    for unit, w in (('flow', None), ('pkt', 'pkts_in'), ('byte', 'bytes_in')):
        row['FP_%s' % unit] = frac(other, admit, w)
        row['FN_%s' % unit] = frac(arcg, lambda x: not admit(x), w)
        row['ARCG_swap_%s' % unit] = frac(arcg, lambda x: admit(x) and x['decision'] != x['true'], w)
        row['acc_%s' % unit] = frac(seen, lambda x: x['decision'] == x['true'], w)
    fp_flows = [f for f in other if admit(f)]
    inj = [f for f in other if f['injected']]
    row['injected_flows'] = len(inj)
    row['injected_pkt_share'] = sum(f['pkts_in'] for f in inj) / sum(f['pkts_in'] for f in other) if other else None
    row['classifier_FP_pkt'] = frac(other, lambda x: x['classifier_decision'] in ('AR', 'CG'), 'pkts_in')
    row['fp_pkt_bound'] = (BUDGET[plan['set']] * len(fp_flows) / sum(f['pkts_in'] for f in other)) if other else None
    for name, sel in (('genuine_AR', [f for f in arcg if f['true'] == 'AR']), ('genuine_CG', [f for f in arcg if f['true'] == 'CG']),
                      ('genuine_ARCG', arcg), ('other_admitted', fp_flows), ('other_correct', [f for f in other if not admit(f)])):
        row['%s_mbps' % name] = sum(f['bytes_in'] for f in sel) * 8 / dur / 1e6
        pin, pout = sum(f['pkts_in'] for f in sel), sum(f['pkts_out'] for f in sel)
        row['%s_loss' % name] = (1 - pout / pin) if pin else None
    for name, sel in (('AR', [f for f in arcg if f['true'] == 'AR' and f.get('_pdv')]), ('CG', [f for f in arcg if f['true'] == 'CG' and f.get('_pdv')])):
        pdv = [x for f in sel for x in f['_pdv']]
        ipdv = [x for f in sel for x in f['_ipdv']]
        for p in (50, 95, 99):
            row['%s_pdv_p%d_us' % (name, p)] = pct(pdv, p)
            row['%s_ipdv_p%d_us' % (name, p)] = pct(ipdv, p)
        row['%s_cap_coverage' % name] = st.mean([f['cap_coverage'] for f in sel]) if sel else None
    ev = {}
    for r in sw['counters']['egress_event']:
        ev.setdefault((r['queue'], r['class']), {})[r['event']] = r['packets']
    for (q, cls), d in ev.items():
        if cls in ('AR', 'CG'):
            tot = sum(d.values())
            row['q%d_%s_ce_frac' % (q, cls)] = sum(v for e, v in d.items() if e.startswith('ce_')) / tot if tot else None
    ig = {r['queue']: 0 for r in sw['counters']['ingress_class']}
    for r in sw['counters']['ingress_class']:
        ig[r['queue']] += r['packets']
    for q in ig:
        row['q%d_tm_drops' % q] = ig[q] - sum(v for (qq, c), d in ev.items() if qq == q for v in d.values())
    # Switch-side queueing delay (TM deq_timedelta) of genuine AR/CG packets from the ring,
    # by ground-truth class and by the queue actually used (Q1 admitted, Q0 not admitted).
    truth = {int(r['flow_id']): r['class'] for r in mp if int(r['flow_id']) not in collided}
    for cls in ('AR', 'CG'):
        for qname, qsel in (('all', (0, 1)), ('q1', (1,)), ('q0', (0,))):
            v = [x['queue_raw'] / 1000 for x in sw['ring'] if truth.get(x['flow_id']) == cls and x['queue'] in qsel]
            row['%s_%s_qdelay_n' % (cls, qname)] = len(v)
            for p in (50, 95, 99):
                row['%s_%s_qdelay_p%d_us' % (cls, qname, p)] = pct(v, p)
    p4tg = sorted(collided) or [f for f in fs['ingress_pkts'] if f not in {x['flow_id'] for x in flows} and fs['ingress_pkts'][f] > 10 ** 6]
    row['p4tg_flow'] = ';'.join('%d:%s:%d' % (f, NAMES.get(fs['decision'].get(f, 0)), fs['ingress_pkts'][f]) for f in p4tg)
    for f in flows:
        f.pop('_pdv', None)
        f.pop('_ipdv', None)
    return row, flows


def main():
    names = sys.argv[1:] or sorted(p.name for p in RUNS.iterdir() if (p / 'switch_done.json').exists() and (p / 'hosts' / 'luigi_pkts.csv.gz').exists())
    rows, flows = [], []
    for n in names:
        r, f = analyse(n)
        rows.append(r)
        flows.extend(f)
    OUT.mkdir(exist_ok=True)
    for path, data in ((OUT / 'fp_runs.csv', rows), (OUT / 'fp_flows.csv', flows)):
        keys = []
        for d in data:
            keys += [k for k in d if k not in keys]
        with path.open('w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            w.writerows(data)
    sets = []
    for s in ('DL', 'UL', 'DLfp10', 'DLfp18'):
        rs = [r for r in rows if r['set'] == s]
        if not rs:
            continue
        out = {'set': s, 'runs': len(rs)}
        for k in rs[0]:
            vals = [r[k] for r in rs if isinstance(r.get(k), (int, float)) and k != 'rep']
            if len(vals) == len(rs) and vals:
                m = st.mean(vals)
                sd = st.stdev(vals) if len(vals) > 1 else 0.0
                out[k + '_mean'], out[k + '_sd'] = m, sd
                out[k + '_ci95'] = T975.get(len(vals), 1.96) * sd / len(vals) ** 0.5 if len(vals) > 1 else None
        sets.append(out)
    if sets:
        keys = []
        for d in sets:
            keys += [k for k in d if k not in keys]
        with (OUT / 'fp_sets.csv').open('w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            w.writerows(sets)
    for r in rows:
        print({k: (round(v, 5) if isinstance(v, float) else v) for k, v in r.items()})


if __name__ == '__main__':
    main()
