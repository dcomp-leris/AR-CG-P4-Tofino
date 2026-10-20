#!/usr/bin/env python3
"""Generate raw/e1/sequence.json: the E1 run list (user-approved matrix, 2026-10-17).

python3 e1_plan.py [--test|--smoke]   --test: TEST_E11_a_N1_R10; --smoke: SMOKE2 (5 conditions)

Senders: superpeach (172.16.0.4, port 136) Prague ECT(1) or Cubic ECT(0)
(tcp_ecn = 3); supermario (172.16.0.6, port 138) Cubic Not-ECT (tcp_ecn = 2).
Receiver: superluigi 172.16.0.5 (port 137, shaped). Every flow has its own
destination port, so its own ICEFE flow ID. Run order is shuffled (seed 7).
E1.3-E1.5 (replay, SCReAM) are added once their host steps are built.
"""
import argparse
import json
import os
import random
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent
OUT = ROOT / 'raw' / 'e1' / 'sequence.json'
PEACH = os.environ.get('ICEFE_PEACH_SSH', 'user@peach-host')
MARIO = os.environ.get('ICEFE_MARIO_SSH', 'user@mario-host')
COMMON = {'duration_s': 60, 'warmup_s': 10, 'idle_s': 10, 'bottleneck_kbps': 1000000,
          'step_us': 1000, 'ring_mask_bits': 7}


def flows(cell, n):
    l4s = [{'host': PEACH, 'cc': 'prague', 'port': 5201 + i, 'group': 'L4S'} for i in range(n)]
    if cell == 'E11':
        classic = [{'host': MARIO, 'cc': 'cubic', 'port': 5211 + i, 'group': 'Classic-NotECT'}
                   for i in range(n)]
    elif cell == 'E12':
        classic = [{'host': PEACH, 'cc': 'cubic', 'port': 5211 + i, 'group': 'Classic-ECT0'}
                   for i in range(n)]
    elif cell in ('E13', 'E14', 'E15'):
        classic = [{'host': MARIO, 'cc': 'cubic', 'port': 5211 + i, 'group': 'Classic-NotECT'} for i in range(4)]
        if cell == 'E13':
            l4s = [{'host': PEACH, 'cc': 'prague', 'port': 5201 + i, 'group': 'L4S'} for i in range(4)]
        else:   # SCReAM BW test tool, ECT(1) (E1.4) or Not-ECT (E1.5)
            l4s = [{'host': PEACH, 'type': 'scream', 'ect': 1 if cell == 'E14' else -1, 'port': 30120,
                    'group': 'L4S' if cell == 'E14' else 'SCReAM-NotECT'}]
    else:
        raise ValueError(cell)
    return l4s + classic


def run(cell, config, n, rtt, rep):
    r = dict(COMMON, run_id='%s_%s_N%d_R%d_rep%d' % (cell, config, n, rtt, rep), cell=cell,
             config=config, n=n, rtt_ms=rtt, rep=rep, flows=flows(cell, n))
    if cell == 'E13':   # held-out AR + CG-DL test traffic (Not-ECT; ICEFE classifies it)
        r['replay'] = {'host_role': 'peach', 'pcap': os.environ.get('ICEFE_ARCG_PCAP', '/data/merged_ARCG.pcap'),
                       'duration_s': r['duration_s']}
    return r


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--e1x', action='store_true', help='E1.3-E1.5: 4 flows/side, 10 ms, configs a/b, 5 reps')
    args = parser.parse_args()
    if args.test:
        runs = [dict(run('E11', 'a', 1, 10, 0), run_id='TEST_E11_a_N1_R10')]
    elif args.e1x:
        runs = [run(cell, config, 4, 10, rep) for rep in range(1, 6) for cell in ('E13', 'E14', 'E15')
                for config in ('a', 'b')]
        random.Random(11).shuffle(runs)
    elif args.smoke:   # mandatory 5-condition check: 2 TCP flows, different dst ports
        runs = [dict(run('E11', 'a', 1, 10, 0), run_id='SMOKE2_E11_a_N1_R10', duration_s=30)]
    else:
        runs = []
        for rep in range(1, 6):
            for n in (1, 4):
                for rtt in (10, 50):
                    for config in ('a', 'b'):   # config c (FIFO) needs a program reload: separate batch
                        runs.append(run('E11', config, n, rtt, rep))
                        runs.append(run('E12', config, n, rtt, rep))
        random.Random(7).shuffle(runs)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(runs, indent=1) + '\n')
    print(OUT, len(runs), 'runs')


if __name__ == '__main__':
    main()
