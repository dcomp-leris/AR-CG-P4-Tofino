#!/usr/bin/env python3
"""Host side of the false-positive (FP) mixture runs.

sudo python3 fp_host_job.py peach|luigi ROOT        (ROOT: ~/c7/fp)

For each ROOT/<run>/ that receives plan.json and then start.json (from fp_drive.py):
  peach: replays all PCAPs of the plan's dataset set concurrently at original timing
         (-K) at t0. No capture on peach: a TX tcpdump stretched the high-rate replays by
         about 40 % (rerun 2026-10-18).
  luigi: tcpdump on nfp1 (RX, 64 B, AR/CG ports only) from t0-5 s until the driver
         writes stop_capture (after peach's replay ended), at most t0 + 3 x duration.
Each capture is reduced with tshark to <role>_pkts.csv.gz (time, dst port, IP ID,
IP length) and the pcap is deleted, so at most one run's capture exists on disk.
Writes <role>_ready.json and <role>_done.json. ROOT/STOP ends the job.
"""
import gzip
import json
import subprocess
import sys
import time
from pathlib import Path

IFACE = {'peach': 'enp2s0np1', 'luigi': 'nfp1'}


def wait_until(epoch):
    while time.time() < epoch:
        time.sleep(min(0.05, max(0.0, epoch - time.time())))


def reduce_capture(pcap, out_gz):
    cmd = ['tshark', '-r', str(pcap), '-T', 'fields', '-E', 'separator=,',
           '-e', 'frame.time_epoch', '-e', 'udp.dstport', '-e', 'ip.id', '-e', 'ip.len']
    proc = subprocess.run(cmd, capture_output=True, text=True)
    with gzip.open(out_gz, 'wt') as fh:
        fh.write('t,port,ip_id,ip_len\n')
        fh.write(proc.stdout)
    rows = proc.stdout.count('\n')
    pcap.unlink()
    return rows


def run(role, run_dir):
    plan = json.loads((run_dir / 'plan.json').read_text())
    bpf = 'udp and (' + ' or '.join('dst port %d' % p for p in plan['capture_ports']) + ')'
    (run_dir / ('%s_ready.json' % role)).write_text(json.dumps({'ready': time.time()}))
    print(time.strftime('%H:%M:%S'), run_dir.name, 'ready', flush=True)
    while not (run_dir / 'start.json').exists():
        time.sleep(0.2)
    t0 = json.loads((run_dir / 'start.json').read_text())['t0_epoch']
    events = {'t0': t0}
    if role == 'peach':
        for name in plan['pcaps']:                        # warm the page cache
            subprocess.run(['cat', str(Path(plan['dataset_dir']) / (name + '.pcap'))],
                           stdout=subprocess.DEVNULL)
    pcap = run_dir / ('%s_capture.pcap' % role)
    wait_until(t0 - 5)
    if role == 'luigi':
        cap = subprocess.Popen(['tcpdump', '-i', IFACE[role], '-n', '-s', '64', '-B', '262144',
                                '-w', str(pcap), bpf], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        events['capture_start'] = time.time()
    if role == 'peach':
        wait_until(t0)
        procs = []
        for name in plan['pcaps']:
            log = open(run_dir / ('replay_%s.log' % name), 'w')
            procs.append(subprocess.Popen(['tcpreplay', '-K', '-i', IFACE[role], '--stats=60',
                                           str(Path(plan['dataset_dir']) / (name + '.pcap'))],
                                          stdout=log, stderr=subprocess.STDOUT))
        events['replay_start'] = time.time()
        for p in procs:
            p.wait()
        events['replay_end'] = time.time()
    else:
        limit = t0 + 3 * plan['max_duration_s']
        while not (run_dir / 'stop_capture').exists() and time.time() < limit:
            time.sleep(0.5)
        time.sleep(2)
        cap.send_signal(2)
        err = cap.communicate(timeout=30)[1].decode(errors='replace')
        events['capture_end'] = time.time()
        events['tcpdump_stats'] = [l for l in err.splitlines() if 'packets' in l]
        events['rows'] = reduce_capture(pcap, run_dir / ('%s_pkts.csv.gz' % role))
    (run_dir / ('%s_done.json' % role)).write_text(json.dumps(events))
    print(time.strftime('%H:%M:%S'), run_dir.name, 'done', events.get('tcpdump_stats'), flush=True)


def main(role, root):
    root.mkdir(parents=True, exist_ok=True)
    print(role, 'watching', root, flush=True)
    while not (root / 'STOP').exists():
        for run_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            if (run_dir / 'plan.json').exists() and not (run_dir / ('%s_ready.json' % role)).exists():
                run(role, run_dir)
        time.sleep(0.5)
    print(role, 'STOP', flush=True)


if __name__ == '__main__':
    main(sys.argv[1], Path(sys.argv[2]))
