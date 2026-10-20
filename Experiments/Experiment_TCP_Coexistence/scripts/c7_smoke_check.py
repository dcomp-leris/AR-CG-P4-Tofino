#!/usr/bin/env python3
"""Mandatory smoke test before the E1 batch: python3 c7_smoke_check.py RUN_ID

Uses raw/e1/RUN_ID/{plan.json, flow_state.json, switch.json}. For each TCP flow
(dst 172.16.0.5, its dst port, proto 6) the expected flow ID is CRC-16/ARC of
dst IP(4) | dst port(2) | proto(1), which reproduces the switch (AR_5000 -> 40761).
Conditions:
 1 the egress indices of the flows are distinct and present at egress;
 2 each egress index equals the ingress index (both counters non-zero there);
 3 clones emitted == clones returned > 0 for each flow;
 4 each flow has a non-zero stored decision;
 5 sampled packets' DSCP / ECN / queue agree with ICEFE's rule for that decision.
"""
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent
ARRIVAL_ECN = {'L4S': 1, 'Classic-NotECT': 0, 'Classic-ECT0': 2}
NAMES = {0: 'none', 1: 'AR', 2: 'CG', 3: 'Other'}


def crc16_arc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def flow_id(ip, port, proto):
    return crc16_arc(bytes(map(int, ip.split('.'))) + port.to_bytes(2, 'big') + bytes([proto]))


def expected(decision, ecn):
    """(DSCP, allowed ECN out, queue) after ICEFE ingress (ICEFE.p4 marking block)."""
    if ecn in (1, 3):                       # ECT(1)/CE: classifier bypassed
        return 0, {1, 3}, 1 if ecn == 1 else 0
    if decision in (1, 2):                  # AR / CG -> ECT(1), DSCP 46 / 34, Q1 (may be CE-marked)
        return (46 if decision == 1 else 34), {1, 3}, 1
    if decision == 3:                       # Other -> Not-ECT, DSCP 50, Q0
        return 50, {0}, 0
    return 0, {ecn, 3} if ecn == 2 else {ecn}, 0


def main(run_id):
    rd = ROOT / 'raw' / 'e1' / run_id
    plan = json.loads((rd / 'plan.json').read_text())
    state = {k: {int(i): v for i, v in d.items()}
             for k, d in json.loads((rd / 'flow_state.json').read_text()).items()}
    ring = json.loads((rd / 'switch.json').read_text())['ring']
    by_flow = {}
    for r in ring:
        by_flow.setdefault(r['flow_id'], Counter())[(r['dscp'], r['ecn_out'], r['queue'])] += 1
    flows = [(f['port'], f['group'], flow_id('172.16.0.5', f['port'], 6)) for f in plan['flows']]
    ids = [i for _, _, i in flows]
    results = {}
    results[1] = len(set(ids)) == len(ids) and all(i in state['egress_pkt_cnt'] for i in ids)
    results[2] = all(state['ingress_pkts'].get(i, 0) > 0 and state['egress_pkt_cnt'].get(i, 0) > 0
                     for i in ids)
    results[3] = all(state['clone_tx'].get(i, 0) > 0 and
                     state['clone_tx'].get(i) == state['clone_rx'].get(i) for i in ids)
    results[4] = all(state['decision'].get(i, 0) != 0 for i in ids)
    ok5 = True
    for port, group, i in flows:
        dec = state['decision'].get(i, 0)
        dscp, ecns, queue = expected(dec, ARRIVAL_ECN[group])
        seen = by_flow.get(i, Counter())
        bad = sum(n for (d, e, q), n in seen.items() if not (d == dscp and e in ecns and q == queue))
        ok5 &= bool(seen) and bad == 0
        print('flow :%d %-15s id %5d  ingress %s egress_cnt %s clones tx/rx %s/%s  decision %s'
              '  expected dscp %d ecn %s q%d  ring %s  mismatched %d' % (
                  port, group, i, state['ingress_pkts'].get(i), state['egress_pkt_cnt'].get(i),
                  state['clone_tx'].get(i), state['clone_rx'].get(i), NAMES.get(dec, dec),
                  dscp, sorted(ecns), queue, dict(seen), bad))
    results[5] = ok5
    other = sorted(set(by_flow) - set(ids))
    if other:
        print('ring flow IDs not in the plan:', {i: sum(by_flow[i].values()) for i in other})
    for k in sorted(results):
        print('condition %d: %s' % (k, 'PASS' if results[k] else 'FAIL'))
    (rd / 'smoke_check.json').write_text(json.dumps({str(k): v for k, v in results.items()}))
    return all(results.values())


if __name__ == '__main__':
    sys.exit(0 if main(sys.argv[1]) else 1)
