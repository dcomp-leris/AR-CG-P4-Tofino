#!/usr/bin/env python3
"""Host side of the run sequence. sudo python3 host_job.py peach|luigi <runs_root> <sequence.txt>
peach: replays each session PCAP at its scheduled epoch with original timing.
luigi: captures UDP headers on nfp1 for the whole run.
Waits for <run_dir>/start.json (copied by the operator)."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PEACH_IFACE, LUIGI_IFACE = 'enp2s0np1', 'nfp1'
SESSIONS = Path(os.environ.get('ICEFE_R2C1_SESSIONS', '/data/icefe-r2c1/sessions'))


def wait_until(epoch):
    while time.time() < epoch:
        time.sleep(min(0.05, max(0.0, epoch - time.time())))


def main(role, run_dir):
    run_dir.mkdir(parents=True, exist_ok=True)
    events = (run_dir / ('%s_events.jsonl' % role)).open('a', buffering=1)

    def event(name, **kw):
        events.write(json.dumps(dict(event=name, wall=time.time(), **kw)) + '\n')

    (run_dir / ('%s_ready.json' % role)).write_text(json.dumps({'ready': time.time()}))
    print('ready, waiting for', run_dir / 'start.json', flush=True)
    while not (run_dir / 'start.json').exists():
        time.sleep(0.25)
    start = json.loads((run_dir / 'start.json').read_text())
    schedule = start['schedule']
    end_epoch = schedule[-1]['start_epoch'] + schedule[-1]['duration_s']
    event('armed', start=start)
    if role == 'luigi':
        wait_until(start['t0_epoch'] - 10)
        log = (run_dir / 'tcpdump.log').open('w')
        proc = subprocess.Popen(['tcpdump', '-i', LUIGI_IFACE, '-n', '-s', '96', '-B', '262144',
                                 '-w', str(run_dir / 'luigi_capture.pcap'), 'udp'],
                                stdout=log, stderr=subprocess.STDOUT)
        event('tcpdump_started', pid=proc.pid)
        wait_until(end_epoch + 15)
        proc.send_signal(2)
        event('tcpdump_stopped', returncode=proc.wait(timeout=30))
        log.close()
        return
    for item in schedule:
        pcap = SESSIONS / (item['session'] + '.pcap')
        subprocess.run(['cat', str(pcap)], stdout=subprocess.DEVNULL, check=True)  # warm page cache
        wait_until(item['start_epoch'])
        cmd = ['tcpreplay', '-i', PEACH_IFACE, '--stats=5', str(pcap)]
        event('replay_start', session=item['session'], cmd=cmd)
        out = subprocess.run(cmd, capture_output=True, text=True)
        (run_dir / ('tcpreplay_%s.log' % item['session'])).write_text(out.stdout + out.stderr)
        event('replay_end', session=item['session'], returncode=out.returncode)
        late = time.time() - (item['start_epoch'] + item['duration_s'])
        if late > item.get('gap_s', 30) - 10:
            event('overrun', session=item['session'], seconds=late)
    event('done')


if __name__ == '__main__':
    # sudo python3 host_job.py <peach|luigi> <runs_root> <sequence.txt>
    role, root, sequence = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    for line in sequence.read_text().split('\n'):
        if not line.strip():
            continue
        run_dir = root / line.split()[0]
        if (run_dir / ('%s_done.json' % role)).exists():
            continue
        main(role, run_dir)
        (run_dir / ('%s_done.json' % role)).write_text(json.dumps({'done': time.time()}))
