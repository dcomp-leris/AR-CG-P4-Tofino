#!/usr/bin/env python3
"""Observation-window completion latency (DERIVED, not a direct switch stamp).

The clone condition (pkt index <= P and frames-before < F) is monotone, so the
clones of an entry are exactly its first k packets, k = clones emitted.
  window_offset   = t(packet k) - t(packet 1), from luigi capture timestamps of
                    the same session in the same ICEFE run (receiver clock;
                    per-packet residence varies by < 1 us, see sessions.csv).
  window_latency  = window_offset + measured first-decision latency
                    (first packet ingress -> its clone's decision store), i.e.
                    assumes the k-th clone's feedback takes as long as the first.
Also reports the trace-time offset (PCAP timestamps) for comparison.
Writes results/decision_window.csv and prints per-group median / p95.
"""
import csv
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
flows = {r['session']: r for r in csv.DictReader((ROOT / 'results' / 'flow_characteristics.csv').open())}
entries = list(csv.DictReader((ROOT / 'results' / 'entries_icefe.csv').open()))


def capture_times(run_id, port, k):
    pcap = ROOT / 'raw' / 'runs' / run_id / 'hosts' / 'luigi' / 'luigi_capture.pcap'
    out = subprocess.run(['tshark', '-r', str(pcap), '-c', '2000000', '-Y',
                          'ip.src==172.16.0.4 && udp.dstport==%d' % port,
                          '-T', 'fields', '-e', 'frame.time_epoch'],
                         capture_output=True, text=True).stdout.split()
    return [float(x) for x in out[:k]]


def trace_times(session, k):
    with (ROOT / 'raw' / 'pcap_sessions' / (session + '.timeline.csv')).open() as f:
        return [float(row[0]) for _, row in zip(range(k), csv.reader(f))]


rows = []
for e in entries:
    k = int(e['clones_emitted'])
    port = int(flows[e['session']]['dst_port'])
    cap = capture_times(e['run_id'], port, k)
    tr = trace_times(e['session'], k)
    first = int(e['decision_latency_ns'])
    cap_off = (cap[-1] - cap[0]) * 1e9 if len(cap) == k else None
    rows.append({
        'run_id': e['run_id'], 'group': e['group'], 'rep': e['rep'], 'session': e['session'],
        'entry': e['entry'], 'window_packets_k': k,
        'first_decision_latency_ns_measured': first,
        'window_offset_ns_capture': round(cap_off) if cap_off is not None else None,
        'window_offset_ns_trace': round((tr[-1] - tr[0]) * 1e9),
        'window_completion_latency_ns_derived': round(cap_off + first) if cap_off is not None else None,
        'final_decision': e['final_decision'],
    })

out = ROOT / 'results' / 'decision_window.csv'
with out.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)


def pct(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(q * len(v)))] if q < 1 else v[-1]


groups = {'DL-AR': ['DL-AR'], 'DL-CG': ['DL-CG'], 'DL-combined': ['DL-AR', 'DL-CG'], 'UL-CG': ['UL-CG']}
for g, members in groups.items():
    sel = [r for r in rows if r['group'] in members and r['window_completion_latency_ns_derived'] is not None]
    v = [r['window_completion_latency_ns_derived'] / 1e6 for r in sel]
    t = [r['window_offset_ns_trace'] / 1e6 for r in sel]
    print('%-12s n=%2d  window completion (derived) median %.3f ms  p95 %.3f ms  max %.3f ms | trace offset median %.3f ms'
          % (g, len(v), pct(v, .5), pct(v, .95), pct(v, 1), pct(t, .5)))
print(out)
