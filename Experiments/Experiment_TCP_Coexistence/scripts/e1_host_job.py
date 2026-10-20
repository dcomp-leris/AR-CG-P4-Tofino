#!/usr/bin/env python3
"""Sender-side sudo job for E1 (superpeach and supermario).

sudo python3 e1_host_job.py <peach|mario> <runs_root>

For each run directory that receives a plan.json (copied by e1_drive.py), apply
the base RTT as netem on the fiber interface, verify it, and write
<role>_ready.json. Runs until <runs_root>/STOP exists, then removes netem.
The delay is applied on the sender egress (data path), so the bottleneck queue
remains at the switch; the reverse (ACK) path is not delayed.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

IFACE = {'peach': 'enp2s0np1', 'mario': 'eno7'}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def set_netem(iface, rtt_ms):
    if rtt_ms:
        out = sh('tc qdisc replace dev %s root netem delay %dms limit 1000000' % (iface, rtt_ms))
    else:
        out = sh('tc qdisc del dev %s root' % iface)
    shown = sh('tc qdisc show dev %s' % iface).stdout.strip()
    return out.returncode, out.stderr.strip(), shown


def main(role, root):
    iface = IFACE[role]
    root.mkdir(parents=True, exist_ok=True)
    print(role, 'watching', root, 'interface', iface, flush=True)
    current = None
    while not (root / 'STOP').exists():
        for run_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            plan_file, ready = run_dir / 'plan.json', run_dir / ('%s_ready.json' % role)
            if not plan_file.exists() or ready.exists():
                continue
            plan = json.loads(plan_file.read_text())
            rtt = int(plan['rtt_ms'])
            status = None
            if rtt != current:
                status = set_netem(iface, rtt)
                current = rtt
            shown = sh('tc qdisc show dev %s' % iface).stdout.strip()
            ok = ('delay %dms' % rtt in shown or 'delay %d.0ms' % rtt in shown) if rtt else 'netem' not in shown
            ready.write_text(json.dumps({'ready': time.time(), 'rtt_ms': rtt, 'netem_ok': ok,
                                         'qdisc': shown, 'set_status': status}))
            print(time.strftime('%H:%M:%S'), run_dir.name, 'rtt', rtt, 'ok' if ok else 'NETEM MISMATCH',
                  flush=True)
            # E1.3: replay a PCAP at t0 for the run duration (root needed for tcpreplay).
            rp = plan.get('replay')
            if rp and role == rp.get('host_role'):
                while not (run_dir / 'start.json').exists():
                    time.sleep(0.1)
                t0 = json.loads((run_dir / 'start.json').read_text())['t0_epoch']
                subprocess.run(['cat', rp['pcap']], stdout=subprocess.DEVNULL)
                while time.time() < t0:
                    time.sleep(0.01)
                out = subprocess.run(['tcpreplay', '-K', '-i', iface, '--duration=%d' % int(rp['duration_s']),
                                      '--stats=30', rp['pcap']], capture_output=True, text=True)
                (run_dir / ('%s_replay.log' % role)).write_text(out.stdout + out.stderr)
                print(time.strftime('%H:%M:%S'), run_dir.name, 'replay done', out.returncode, flush=True)
        time.sleep(0.5)
    print(role, 'STOP: removing netem', set_netem(iface, 0), flush=True)


if __name__ == '__main__':
    main(sys.argv[1], Path(sys.argv[2]))
