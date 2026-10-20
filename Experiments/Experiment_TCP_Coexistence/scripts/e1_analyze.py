#!/usr/bin/env python3
"""Summarise E1 runs: python3 e1_analyze.py [RUN_ID ...]  (default: all finished runs)

Writes results/e1_runs.csv (one row per run), results/e1_flows.csv (one row per flow),
results/e1_pbase/<run>.csv (p_base time series, ~1 s) and results/e1_cells.csv
(per cell: mean, SD and 95% t-CI across repetitions of the per-run values; packets
are never pooled across runs).
Window: [warmup_s, duration_s] of each iperf3 flow (1 s intervals, sender side).
Queue-delay percentiles come from the switch ring (1-in-2^k systematic sample of
packets leaving port 137). The ring has no timestamps; the warm-up is removed by
dropping the first warmup_s/duration_s fraction of samples (packet order at a
saturated 1 Gbit/s bottleneck is close to time order). This is an approximation.
"""
import csv
import json
import re
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent
RUNS = ROOT / 'raw' / 'e1'
OUT = ROOT / 'results'


def pct(values, p):
    if not values:
        return None
    values = sorted(values)
    k = (len(values) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def jain(x):
    return sum(x) ** 2 / (len(x) * sum(v * v for v in x)) if x and any(x) else None


def flow_metrics(path, warmup, duration):
    d = json.loads(path.read_text())
    if 'error' in d and not d.get('intervals'):
        raise RuntimeError('%s: %s' % (path, d['error']))
    rows = [i['streams'][0] for i in d['intervals']]
    win = [r for r in rows if r['start'] >= warmup - 1e-6 and r['end'] <= duration + 0.5]
    mbps = [r['bits_per_second'] / 1e6 for r in win]
    rtt = [r['rtt'] / 1000 for r in win if r.get('rtt')]
    end = d['end']['streams'][0]['sender']
    return {'goodput_mbps': st.mean(mbps) if mbps else 0.0,
            'goodput_cv': st.pstdev(mbps) / st.mean(mbps) if mbps and st.mean(mbps) else None,
            'rtt_mean_ms': st.mean(rtt) if rtt else None, 'rtt_p50_ms': pct(rtt, 50),
            'rtt_p95_ms': pct(rtt, 95), 'rtt_p99_ms': pct(rtt, 99),
            'retransmits': end.get('retransmits'),
            'cc': d['start'].get('tcp_congestion') or d['start'].get('test_start', {}).get('congestion')}


KERNEL = ('Tcp:RetransSegs', 'TcpExt:TCPLossProbes', 'TcpExt:TCPTimeouts',
          'TcpExt:TCPSackRecovery', 'TcpExt:TCPDeliveredCE', 'TcpExt:TCPLostRetransmit',
          'IpExt:InCEPkts', 'IpExt:InECT1Pkts', 'IpExt:InECT0Pkts', 'IpExt:InNoECTPkts')


def proc_counters(text):
    out, lines = {}, text.splitlines()
    for head, vals in zip(lines[::2], lines[1::2]):
        names, values = head.split(), vals.split()
        if names and names[0] == values[0]:
            for n, v in zip(names[1:], values[1:]):
                out[names[0] + n] = int(v)
    return out


def kernel_deltas(hosts_dir):
    out = {}
    for before in hosts_dir.glob('proc_*_before.txt'):
        role = before.name[5:-11]
        after = hosts_dir / ('proc_%s_after.txt' % role)
        if not after.exists():
            continue
        b, a = proc_counters(before.read_text()), proc_counters(after.read_text())
        for k in KERNEL:
            if k in a and k in b:
                out['%s_%s' % (role, k.split(':')[1])] = a[k] - b[k]
    return out


def crc16_arc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def scream_metrics(summary_path, log_path, warmup, duration):
    """SCReAM BW test tool sender: 2 s summaries (rate, PLR, CE, RTT, queue delay) and the
    per-ACK log (col 1 time [s], col 2 estimated queue delay [s], col 3 RTT [s])."""
    import re as _re
    rates, rtts, qds, ce, plr = [], [], [], None, None
    for line in summary_path.read_text(errors='replace').splitlines():
        m = _re.search(r'summary\s+([0-9.]+)\s+Transmit rate =\s*([0-9]+)kbps, PLR =\s*([0-9.]+)%\(\s*([0-9.]+)%\), '
                       r'CE =\s*([0-9.]+)%\(\s*([0-9.]+)%\).*RTT =\s*([0-9.]+)s, Queue delay =\s*([0-9.]+)s', line)
        if not m:
            continue
        t = float(m.group(1))
        plr, ce = float(m.group(4)), float(m.group(6))          # cumulative values (in parentheses)
        if warmup <= t <= duration:
            rates.append(float(m.group(2)) / 1000)
            rtts.append(float(m.group(7)) * 1000)
            qds.append(float(m.group(8)) * 1000)
    q_ack, rtt_ack = [], []
    for line in log_path.read_text(errors='replace').splitlines():
        p = line.split(',')
        try:
            t = float(p[0])
        except (ValueError, IndexError):
            continue
        if warmup <= t <= duration:
            q_ack.append(float(p[1]) * 1000)
            rtt_ack.append(float(p[2]) * 1000)
    return {'goodput_mbps': st.mean(rates) if rates else 0.0,
            'goodput_cv': st.pstdev(rates) / st.mean(rates) if rates and st.mean(rates) else None,
            'rtt_mean_ms': st.mean(rtt_ack) if rtt_ack else None, 'rtt_p50_ms': pct(rtt_ack, 50),
            'rtt_p95_ms': pct(rtt_ack, 95), 'rtt_p99_ms': pct(rtt_ack, 99),
            'scream_qdelay_p50_ms': pct(q_ack, 50), 'scream_qdelay_p95_ms': pct(q_ack, 95),
            'scream_qdelay_p99_ms': pct(q_ack, 99), 'scream_ce_pct': ce, 'scream_plr_pct': plr,
            'retransmits': None, 'cc': 'scream'}


def p_base_series(log_text):
    out = []
    for m in re.finditer(r"137: \{'state': '([a-z-]+)', 'p_base': ([0-9.e-]+)", log_text):
        out.append(float(m.group(2)))
    return out


def analyze(run_dir):
    plan = json.loads((run_dir / 'plan.json').read_text())
    sw = json.loads((run_dir / 'switch.json').read_text())
    warm, dur = plan['warmup_s'], plan['duration_s']
    fs_path = run_dir / 'flow_state.json'
    fstate = json.loads(fs_path.read_text()) if fs_path.exists() else {}
    flows = []
    for f in plan['flows']:
        if f.get('type') == 'scream':
            m = scream_metrics(run_dir / 'hosts' / ('scream_summary_%d.txt' % f['port']),
                               run_dir / 'hosts' / ('scream_tx_%d.log' % f['port']), warm, dur)
            proto = 17
        else:
            m = flow_metrics(run_dir / 'hosts' / ('iperf_%d.json' % f['port']), warm, dur)
            proto = 6
        fid = crc16_arc(bytes([172, 16, 0, 5]) + f['port'].to_bytes(2, 'big') + bytes([proto]))
        dec = fstate.get('decision', {}).get(str(fid), 0)
        flows.append(dict(run_id=plan['run_id'], group=f['group'], port=f['port'], flow_id=fid,
                          decision={0: 'none', 1: 'AR', 2: 'CG', 3: 'Other'}.get(dec, dec), **m))
    l4s = [f['goodput_mbps'] for f in flows if f['group'] in ('L4S', 'SCReAM-NotECT')]
    classic = [f['goodput_mbps'] for f in flows if f['group'] not in ('L4S', 'SCReAM-NotECT')]
    ring = sw.get('ring', [])
    ring = ring[int(len(ring) * warm / dur):]
    q = {k: [r['queue_raw'] / 1e6 for r in ring if r['queue'] == k] for k in (0, 1)}
    c = sw['counters']
    ev = {}
    for r in c['egress_event']:
        ev[(r['queue'], r['event'])] = ev.get((r['queue'], r['event']), 0) + r['packets']
    eg_q = {k: sum(v for (qq, _), v in ev.items() if qq == k) for k in (0, 1)}
    ig_q = {k: sum(r['packets'] for r in c['ingress_class'] if r['queue'] == k) for k in (0, 1)}
    dec = {}
    for r in c['ingress_decision']:
        dec[r['decision']] = dec.get(r['decision'], 0) + r['packets']
    pb = p_base_series((run_dir / 'bfshell.log').read_text(errors='replace'))
    row = {'run_id': plan['run_id'], 'cell': plan['cell'], 'config': plan['config'], 'n': plan['n'],
           'rtt_ms': plan['rtt_ms'], 'rep': plan['rep'],
           'l4s_mbps': sum(l4s), 'classic_mbps': sum(classic), 'total_mbps': sum(l4s) + sum(classic),
           'ratio_l4s_classic_perflow': (st.mean(l4s) / st.mean(classic)) if l4s and classic and st.mean(classic) else None,
           'jain_all': jain([f['goodput_mbps'] for f in flows]),
           'l4s_rtt_ms': st.mean([f['rtt_mean_ms'] for f in flows if f['group'] == 'L4S' and f['rtt_mean_ms']] or [0]),
           'classic_rtt_ms': st.mean([f['rtt_mean_ms'] for f in flows if f['group'] != 'L4S' and f['rtt_mean_ms']] or [0]),
           'retrans_l4s': sum(f['retransmits'] or 0 for f in flows if f['group'] == 'L4S'),
           'retrans_classic': sum(f['retransmits'] or 0 for f in flows if f['group'] != 'L4S')}
    for grp, key in (('L4S', 'l4s'), ('Classic', 'classic')):
        sel = [f for f in flows if (f['group'] == 'L4S') == (grp == 'L4S')]
        for p in (50, 95, 99):
            v = [f['rtt_p%d_ms' % p] for f in sel if f['rtt_p%d_ms' % p] is not None]
            row['%s_rtt_p%d_ms' % (key, p)] = st.mean(v) if v else None
    for k in (0, 1):
        for p in (50, 90, 95, 99, 99.9):
            row['q%d_p%s_ms' % (k, p)] = pct(q[k], p)
        row['q%d_samples' % k] = len(q[k])
        row['q%d_tm_drops' % k] = ig_q[k] - eg_q[k]
    for (k, name) in ((1, 'ce_tm'), (1, 'ce_step'), (1, 'ce_coupled'), (0, 'ce_classic'), (0, 'drop_classic')):
        row['q%d_%s_frac' % (k, name)] = ev.get((k, name), 0) / eg_q[k] if eg_q[k] else None
    ce = sum(v for (qq, e), v in ev.items() if e.startswith('ce_'))
    row['ce_total_frac'] = ce / (eg_q[0] + eg_q[1]) if eg_q[0] + eg_q[1] else None
    for name in ('none', 'AR', 'CG', 'Other'):
        row['decision_%s_pkts' % name] = dec.get(name, 0)
    row['flow_decisions'] = ';'.join('%d:%s' % (f['port'], f['decision']) for f in flows)
    row.update(kernel_deltas(run_dir / 'hosts'))
    row['p_base_mean'] = st.mean(pb) if pb else None
    row['p_base_max'] = max(pb) if pb else None
    (OUT / 'e1_pbase').mkdir(parents=True, exist_ok=True)
    (OUT / 'e1_pbase' / (plan['run_id'] + '.csv')).write_text(
        'second,p_base\n' + ''.join('%d,%.6f\n' % (i, v) for i, v in enumerate(pb)))
    return row, flows


def main():
    names = sys.argv[1:] or sorted(p.name for p in RUNS.iterdir()
                                   if (p / 'switch_done.json').exists())
    rows, flows = [], []
    for name in names:
        try:
            r, f = analyze(RUNS / name)
        except Exception as exc:
            print('skip', name, exc)
            continue
        rows.append(r)
        flows.extend(f)
    OUT.mkdir(exist_ok=True)
    for path, data in ((OUT / 'e1_runs.csv', rows), (OUT / 'e1_flows.csv', flows)):
        if data:
            keys = []
            for d in data:
                keys += [k for k in d if k not in keys]
            with path.open('w', newline='') as fh:
                w = csv.DictWriter(fh, fieldnames=keys)
                w.writeheader()
                w.writerows(data)
    T975 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262}
    cells = {}
    for r in rows:
        if r['rep']:
            cells.setdefault((r['cell'], r['config'], r['n'], r['rtt_ms']), []).append(r)
    cell_rows = []
    for (cell, config, n, rtt), rs in sorted(cells.items()):
        out = {'cell': cell, 'config': config, 'n': n, 'rtt_ms': rtt, 'runs': len(rs)}
        allkeys = []
        for x in rs:
            allkeys += [k for k in x if k not in allkeys]
        for k in allkeys:
            v = next((x[k] for x in rs if k in x), None)
            if isinstance(v, (int, float)) and k not in ('n', 'rtt_ms', 'rep'):
                vals = [x[k] for x in rs if isinstance(x.get(k), (int, float))]
                if not vals:
                    continue
                m = st.mean(vals)
                sd = st.stdev(vals) if len(vals) > 1 else 0.0
                half = T975.get(len(vals), 1.96) * sd / len(vals) ** 0.5 if len(vals) > 1 else None
                out[k + '_mean'], out[k + '_sd'], out[k + '_ci95'] = m, sd, half
        cell_rows.append(out)
    if cell_rows:
        keys = []
        for c in cell_rows:
            keys += [k for k in c if k not in keys]
        with (OUT / 'e1_cells.csv').open('w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            w.writerows(cell_rows)
    for r in rows:
        print(json.dumps({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()}))
    for f in flows:
        print('  ', {k: (round(v, 3) if isinstance(v, float) else v) for k, v in f.items()})


if __name__ == '__main__':
    main()
