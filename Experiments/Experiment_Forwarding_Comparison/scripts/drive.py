#!/usr/bin/env python3
"""Operator driver (runs as alireza on the Tofino, needs the SSH agent).

python3 drive.py [--until RUN_ID]
For each pending run in raw/runs/sequence.txt: wait for switch_chain.sh to start
switchd, run the BFRT side with `bfshell -b`, wait for links and hosts, issue
one start.json to switch, peach and luigi, wait for completion, fetch host files.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / 'raw' / 'runs'
BFSHELL = os.environ.get('BFSHELL', os.path.join(
    os.environ.get('SDE', '/opt/bf-sde-9.13.4'), 'install/bin/bfshell'))
PEACH = os.environ.get('ICEFE_PEACH_SSH', 'user@peach-host')
LUIGI = os.environ.get('ICEFE_LUIGI_SSH', 'user@luigi-host')
REMOTE = {PEACH: os.environ.get('ICEFE_PEACH_R2C1_DIR', '/tmp/icefe-r2c1'),
          LUIGI: os.environ.get('ICEFE_LUIGI_R2C1_DIR', '/tmp/icefe-r2c1')}
LEAD_S = 30


def log(*args):
    print(time.strftime('%H:%M:%S'), *args, flush=True)


def ssh(host, cmd, check=True):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', host, cmd], capture_output=True,
                          text=True, check=check).stdout


def wait_for(predicate, timeout, what):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(2)
    raise TimeoutError(what)


def listening(port):
    out = subprocess.run(['ss', '-ltn'], capture_output=True, text=True).stdout
    return (':%d ' % port) in out


def run_one(run_id, program, direction, sessions):
    rd = RUNS / run_id
    log(run_id, 'waiting for switchd')
    wait_for(lambda: (rd / 'switchd_started.json').exists(), 3 * 3600, 'switchd start')
    wait_for(lambda: listening(9999), 300, 'bfshell port 9999')
    time.sleep(10)
    Path('/tmp/r2c1').mkdir(exist_ok=True)
    launcher = Path('/tmp/r2c1/%s.py' % run_id)
    launcher.write_text("R2C1_PROGRAM = %r\nR2C1_DIRECTION = %r\nR2C1_RUN_ID = %r\nR2C1_ROOT = %r\n"
                        "exec(open(%r).read())\n" % (program, direction, run_id, str(ROOT),
                                                     str(ROOT / 'scripts' / 'r2c1_switch.py')))
    shell_log = (rd / 'bfshell.log').open('w')
    # bfshell needs a pseudo-terminal; `script` provides one.
    shell = subprocess.Popen(['script', '-qfc', '%s -b %s' % (BFSHELL, launcher), '/dev/null'], stdout=shell_log,
                             stderr=subprocess.STDOUT, cwd='/tmp/r2c1')
    log(run_id, 'bfshell pid', shell.pid)
    wait_for(lambda: (rd / 'switch_ready.json').exists() or shell.poll() is not None, 600,
             'switch_ready')
    if not (rd / 'switch_ready.json').exists():
        raise RuntimeError('bfshell exited before ready; see %s' % (rd / 'bfshell.log'))
    ready = json.loads((rd / 'switch_ready.json').read_text())
    ports = ready['ports']
    if not all(ports[p].get('PORT_UP') == 'True' for p in ('136', '137')):
        raise RuntimeError('links not up: %s' % ports)
    for host in (PEACH, LUIGI):
        role = 'peach' if host == PEACH else 'luigi'
        wait_for(lambda: ssh(host, 'test -e %s/%s/%s_ready.json && echo y' %
                             (REMOTE[host], run_id, role), check=False).strip() == 'y',
                 4 * 3600, '%s ready' % role)
    t0 = time.time() + LEAD_S
    cmd = [sys.executable, str(ROOT / 'scripts' / 'build_plan.py'), '--t0', repr(t0),
           '--direction', direction, '--run-id', run_id, '--program', program]
    if sessions:
        cmd += ['--sessions', sessions]
    start = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    for host in (PEACH, LUIGI):
        subprocess.run(['ssh', '-o', 'BatchMode=yes', host, 'cat > %s/%s/start.json' %
                        (REMOTE[host], run_id)], input=start, text=True, check=True)
    (rd / 'start.json').write_text(start)
    end = json.loads(start)['expected_end_epoch']
    log(run_id, 'started; expected end in %.0f s' % (end - time.time()))
    wait_for(lambda: (rd / 'switch_done.json').exists() or shell.poll() is not None,
             end - time.time() + 900, 'switch_done')
    if not (rd / 'switch_done.json').exists():
        raise RuntimeError('bfshell exited before switch_done; see bfshell.log')
    shell.wait(timeout=120)
    shell_log.close()
    for host in (PEACH, LUIGI):
        role = 'peach' if host == PEACH else 'luigi'
        wait_for(lambda: ssh(host, 'test -e %s/%s/%s_done.json && echo y' %
                             (REMOTE[host], run_id, role), check=False).strip() == 'y',
                 300, '%s done' % role)
        dest = rd / 'hosts' / role
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(['scp', '-q', '-r', '%s:%s/%s/*' % (host, REMOTE[host], run_id),
                        str(dest)], check=True)
    log(run_id, 'complete')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--until', help='stop after this run id')
    args = parser.parse_args()
    for line in (RUNS / 'sequence.txt').read_text().splitlines():
        if not line.strip():
            continue
        run_id, program = line.split()[:2]
        if (RUNS / run_id / 'hosts' / 'luigi').exists() and (RUNS / run_id / 'switch_done.json').exists():
            continue
        direction = 'UL' if '_UL_' in run_id else 'DL'
        sessions = 'AR_5000,AR_5001' if run_id.startswith('VAL_') else None
        run_one(run_id, program, direction, sessions)
        if run_id == args.until:
            log('stopping after', run_id)
            return


if __name__ == '__main__':
    main()
