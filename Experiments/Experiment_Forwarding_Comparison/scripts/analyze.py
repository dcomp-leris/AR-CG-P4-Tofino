#!/usr/bin/env python3
"""R2-C1 analysis. python3 analyze.py  (reads raw/runs/*, writes results/ and raw/samples/)

Definitions
  residence      egress-parser global_tstamp - ingress-parser global_tstamp (ns),
                 same 48-bit switch clock, low 32 bits, modular subtraction.
  mean           exact: sum over ALL evaluated packets / packet count (sums polled
                 every 0.25 s and unwrapped in software).
  median/p95     from per-packet samples (systematic 1-in-(mask+1)); pooled
                 percentiles weight each sample by (mask+1).
  decision lat.  decision_store stamp (clone ingress-parser time of the first
                 non-zero stored class) - first_eligible stamp (ingress-parser time
                 of the entry's first original UDP/TCP packet from port 136),
                 modular 32-bit, valid < 4.29 s.
Validation runs (VAL_*) are excluded from the results.
"""
import csv
import gzip
import json
import re
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / 'raw' / 'runs'
OUT = ROOT / 'results'
SAMPLES = ROOT / 'raw' / 'samples'
WRAP = 1 << 32
BUDGET = {'DL': (52, 13), 'UL': (32, 8)}
GROUP = {'AR': 'DL-AR', 'CGDL': 'DL-CG', 'CGUL': 'UL-CG'}


def crc8(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xff if c & 0x80 else (c << 1) & 0xff
    return c


def session_entry(port):
    return crc8(bytes([172, 16, 0, 5]) + port.to_bytes(2, 'big') + bytes([17]))


def wpercentile(pairs, q):
    """pairs: (value, weight); lower weighted percentile."""
    pairs = sorted(pairs)
    total = sum(w for _, w in pairs)
    acc = 0
    for v, w in pairs:
        acc += w
        if acc >= q * total:
            return v
    return pairs[-1][0] if pairs else None


def received_by_port(run_dir):
    cache = run_dir / 'hosts' / 'luigi' / 'received_by_port.json'
    if cache.exists():
        return json.loads(cache.read_text())
    pcap = run_dir / 'hosts' / 'luigi' / 'luigi_capture.pcap'
    out = subprocess.run(['tshark', '-r', str(pcap), '-Y', 'ip.src==172.16.0.4 && ip.dst==172.16.0.5',
                          '-T', 'fields', '-e', 'udp.dstport'], capture_output=True, text=True).stdout
    counts = defaultdict(int)
    for line in out.split():
        counts[line] += 1
    cache.write_text(json.dumps(counts))
    return counts


def tcpreplay_stats(path):
    text = path.read_text() if path.exists() else ''
    found = re.findall(r'Actual: (\d+) packets \((\d+) bytes\) sent in ([\d.]+) seconds', text)
    m = found[-1] if found else None  # --stats prints interim lines; the last is final
    f = re.search(r'Failed packets:\s+(\d+)', text)
    return (int(m[0]), int(m[1]), float(m[2]), int(f.group(1))) if m else (None,) * 4


def main():
    OUT.mkdir(exist_ok=True)
    SAMPLES.mkdir(exist_ok=True)
    flows = {r['session']: r for r in csv.DictReader((OUT / 'flow_characteristics.csv').open())}
    session_rows, entry_rows, other_rows = [], [], []
    pooled = defaultdict(list)          # (group, impl) -> [(residence, weight)]
    pooled_q = defaultdict(list)
    superseded = json.loads((RUNS / 'SUPERSEDED.json').read_text())['superseded_runs']
    for line in (RUNS / 'sequence.txt').read_text().splitlines():
        if not line.strip() or line.startswith('VAL_'):
            continue
        run_id, program = line.split()[:2]
        if run_id in superseded:
            continue
        rd = RUNS / run_id
        if not (rd / 'switch_done.json').exists():
            print('missing/incomplete run', run_id)
            continue
        impl = 'ICEFE' if program.startswith('ICEFE') else 'FWD'
        direction = 'UL' if '_UL_' in run_id else 'DL'
        rep = int(re.search(r'rep(\d+)', run_id).group(1))
        start = json.loads((rd / 'start.json').read_text())
        received = received_by_port(rd)
        for item in start['schedule']:
            name = item['session']
            snap = json.loads((rd / ('switch_%s.json' % name)).read_text())
            port = int(flows[name]['dst_port'])
            group = GROUP[name.split('_')[0]]
            weight = item['mask'] + 1
            samples = snap['samples']
            with gzip.open(SAMPLES / ('%s_%s.csv.gz' % (run_id, name)), 'wt', newline='') as f:
                w = csv.writer(f)
                w.writerow(['sample_index', 'packet_seq', 'residence_ns', 'queue_delay_raw'])
                for i, (res, q) in enumerate(samples):
                    w.writerow([i, i * weight, res, q])
            for res, q in samples:
                pooled[(group, impl)].append((res, weight))
                pooled_q[(group, impl)].append((q, weight))
            for g in ([group] + (['DL-combined'] if direction == 'DL' else [])):
                if g != group:
                    pooled[(g, impl)].extend((r, weight) for r, _ in samples)
                    pooled_q[(g, impl)].extend((q, weight) for _, q in samples)
            sent, sent_bytes, elapsed, failed = tcpreplay_stats(rd / 'hosts' / 'peach' / ('tcpreplay_%s.log' % name))
            n = snap['eval']['packets']
            rres = sorted(r for r, _ in samples)
            rq = sorted(q for _, q in samples)
            rec = int(received.get(str(port), 0))
            session_rows.append({
                'impl': impl, 'direction': direction, 'group': group, 'rep': rep, 'run_id': run_id,
                'session': name, 'pcap_packets': int(flows[name]['packets']),
                'tcpreplay_sent': sent, 'tcpreplay_failed': failed, 'replay_elapsed_s': elapsed,
                'trace_duration_s': float(flows[name]['duration_s']),
                'switch_in_port136_all': snap['ingress_port_pkts']['136'],
                'switch_evaluated_pkts': n, 'switch_evaluated_bytes': snap['eval']['bytes'],
                'luigi_received': rec, 'loss_sent_minus_received': (sent - rec) if sent is not None else None,
                'residence_sum_ns': snap['residence_sum_ns'],
                'mean_residence_ns': snap['residence_sum_ns'] / n if n else None,
                'sampling_mask': item['mask'], 'samples': len(samples),
                'sample_mean_ns': statistics.fmean(rres) if rres else None,
                'median_residence_ns': rres[len(rres) // 2] if rres else None,
                'p95_residence_ns': rres[min(len(rres) - 1, int(0.95 * len(rres)))] if rres else None,
                'max_residence_ns': snap['residence_max_ns'],
                'mean_queue_delay_raw': snap['queue_sum_raw'] / n if n else None,
                'median_queue_delay_raw': rq[len(rq) // 2] if rq else None,
                'p95_queue_delay_raw': rq[min(len(rq) - 1, int(0.95 * len(rq)))] if rq else None,
                'sum_unwrap_ok': max(snap['sum_max_poll_delta'].values()) < (1 << 31),
                'samples_complete': len(samples) == -(-n // weight),
                'arm_status': snap['status'],
            })
            if impl != 'ICEFE':
                continue
            target = session_entry(port)
            p_budget, f_budget = BUDGET[direction]
            for e in snap['entries']:
                if e['entry'] != target:
                    other_rows.append({'run_id': run_id, 'session': name, **e})
                    continue
                complete = bool(e['first_seen'] and e['decision_seen'])
                latency = (e['decision_stamp'] - e['first_stamp']) % WRAP if complete else None
                entry_rows.append({
                    'impl': impl, 'direction': direction, 'group': group, 'rep': rep,
                    'run_id': run_id, 'session': name, 'entry': e['entry'],
                    'first_eligible_stamp_ns_mod2^32': e['first_stamp'] if e['first_seen'] else None,
                    'decision_store_stamp_ns_mod2^32': e['decision_stamp'] if e['decision_seen'] else None,
                    'decision_latency_ns': latency, 'decision_incomplete': not complete,
                    'final_decision': e['final_decision'],
                    'budget_packets': p_budget, 'budget_frames': f_budget,
                    'clones_emitted': e['clone_tx'], 'clones_received_ingress': e['clone_rx'],
                    'rf_executions': e['rf_exec'], 'clones_after_decision': e['clone_after_decision'],
                    'original_pkts': e['orig_pkts'], 'original_pkts_with_decision': e['orig_with_decision'],
                    'egress_pkt_count': e['egress_pkt_count'], 'egress_frames_counted': e['egress_frame_count'],
                })
    write(OUT / 'sessions.csv', session_rows)
    write(OUT / 'entries_icefe.csv', entry_rows)
    write(OUT / 'non_session_entries_icefe.csv', other_rows)
    summary = summarize(session_rows, entry_rows, pooled, pooled_q)
    write(OUT / 'summary.csv', summary)
    print_table(summary)


def write(path, rows):
    if not rows:
        path.write_text('')
        return
    keys = list(rows[0])
    for r in rows:
        keys += [k for k in r if k not in keys]
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def summarize(sessions, entries, pooled, pooled_q):
    groups = {'DL-AR': ['DL-AR'], 'DL-CG': ['DL-CG'], 'DL-combined': ['DL-AR', 'DL-CG'], 'UL-CG': ['UL-CG']}
    rows = []
    means = {}
    for g, members in groups.items():
        for impl in ('ICEFE', 'FWD'):
            sel = [s for s in sessions if s['group'] in members and s['impl'] == impl]
            if not sel:
                continue
            reps = sorted({s['rep'] for s in sel})
            per_rep = {}
            for r in reps:
                rs = [s for s in sel if s['rep'] == r]
                per_rep[r] = sum(s['residence_sum_ns'] for s in rs) / sum(s['switch_evaluated_pkts'] for s in rs)
            n = sum(s['switch_evaluated_pkts'] for s in sel)
            mean = sum(s['residence_sum_ns'] for s in sel) / n
            means[(g, impl)] = (mean, per_rep)
            ent = [e for e in entries if e['group'] in members and e['impl'] == impl]
            lat = sorted(e['decision_latency_ns'] for e in ent if e['decision_latency_ns'] is not None)
            row = {
                'group': g, 'impl': impl, 'repetitions': len(reps),
                'sessions_per_rep': len(sel) // len(reps), 'evaluated_pkts_total': n,
                'mean_residence_ns': round(mean, 2),
                'per_rep_mean_residence_ns': ';'.join('%.2f' % per_rep[r] for r in reps),
                'sd_across_reps_ns': round(statistics.stdev(per_rep.values()), 2) if len(reps) > 1 else None,
                'median_residence_ns': wpercentile(pooled[(g, impl)], 0.5),
                'p95_residence_ns': wpercentile(pooled[(g, impl)], 0.95),
                'mean_queue_delay_raw': round(sum(s['mean_queue_delay_raw'] * s['switch_evaluated_pkts'] for s in sel) / n, 2),
                'p95_queue_delay_raw': wpercentile(pooled_q[(g, impl)], 0.95),
                'sent': sum(s['tcpreplay_sent'] or 0 for s in sel),
                'received': sum(s['luigi_received'] for s in sel),
                'loss': sum(s['loss_sent_minus_received'] or 0 for s in sel),
                'all_sums_unwrap_ok': all(s['sum_unwrap_ok'] for s in sel),
                'all_samples_complete': all(s['samples_complete'] for s in sel),
            }
            if impl == 'ICEFE':
                row.update({
                    'decision_entries': len(ent),
                    'decision_incomplete': sum(e['decision_incomplete'] for e in ent),
                    'decision_latency_median_ns': lat[len(lat) // 2] if lat else None,
                    'decision_latency_p95_ns': lat[min(len(lat) - 1, int(0.95 * len(lat)))] if lat else None,
                    'decision_latency_max_ns': lat[-1] if lat else None,
                    'budget_packets_frames_per_entry': '%d/%d' % BUDGET['UL' if g.startswith('UL') else 'DL'],
                    'clones_emitted_total': sum(e['clones_emitted'] for e in ent),
                    'clones_received_total': sum(e['clones_received_ingress'] for e in ent),
                    'rf_executions_total': sum(e['rf_executions'] for e in ent),
                    'clones_after_decision_total': sum(e['clones_after_decision'] for e in ent),
                    'clones_emitted_per_entry_min_max': '%d-%d' % (min(e['clones_emitted'] for e in ent),
                                                                     max(e['clones_emitted'] for e in ent)) if ent else None,
                })
            rows.append(row)
    for row in rows:
        if row['impl'] != 'ICEFE' or (row['group'], 'FWD') not in means:
            continue
        mi, ri = means[(row['group'], 'ICEFE')]
        mf, rf = means[(row['group'], 'FWD')]
        row['incremental_residence_ns'] = round(mi - mf, 2)
        paired = [ri[r] - rf[r] for r in ri if r in rf]
        row['incremental_per_rep_ns'] = ';'.join('%.2f' % d for d in paired)
        row['incremental_sd_across_reps_ns'] = round(statistics.stdev(paired), 2) if len(paired) > 1 else None
    return rows


def print_table(rows):
    for r in rows:
        print({k: r.get(k) for k in ('group', 'impl', 'repetitions', 'evaluated_pkts_total',
                                     'mean_residence_ns', 'sd_across_reps_ns', 'median_residence_ns',
                                     'p95_residence_ns', 'incremental_residence_ns',
                                     'decision_latency_median_ns', 'decision_latency_p95_ns', 'loss')})


if __name__ == '__main__':
    main()
