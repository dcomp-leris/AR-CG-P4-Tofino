#!/usr/bin/env python3
"""E1 operator driver (run on the Tofino host with an active SSH agent).

python3 e1_drive.py [--only RUN_ID] [--max N]
Needs: bf_switchd running ICEFE, no interactive bfrt_python open,
e1_host_job.py running with sudo on superpeach and supermario.
Per run: plan.json -> bfshell -b (c7_switch.py) -> hosts ready (netem) ->
start.json -> iperf3 clients at t0 -> switch_done -> fetch iperf JSON.
Finished runs (switch_done.json + all iperf files) are skipped.
"""
import argparse
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent
RUNS = ROOT / 'raw' / 'e1'
BFSHELL = os.environ.get('BFSHELL', os.path.join(
    os.environ.get('SDE', '/opt/bf-sde-9.13.4'), 'install/bin/bfshell'))
PEACH = os.environ.get('ICEFE_PEACH_SSH', 'user@peach-host')
MARIO = os.environ.get('ICEFE_MARIO_SSH', 'user@mario-host')
LUIGI = os.environ.get('ICEFE_LUIGI_SSH', 'user@luigi-host')
REMOTE = {PEACH: ('peach', os.environ.get('ICEFE_PEACH_E1_DIR', '/tmp/icefe-e1')),
          MARIO: ('mario', os.environ.get('ICEFE_MARIO_E1_DIR', '/tmp/icefe-e1'))}
RECEIVER = '172.16.0.5'
LEAD_S = 8
SCREAM_TX = os.environ.get('SCREAM_TX', '/opt/scream/scream_bw_test_tx')
SCREAM_RX = os.environ.get('SCREAM_RX', '/opt/scream/scream_bw_test_rx')


def log(*args):
    print(time.strftime('%H:%M:%S'), *args, flush=True)


def ssh(host, cmd, check=True, **kw):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', host, cmd], capture_output=True,
                          text=True, check=check, **kw).stdout


def wait_for(predicate, timeout, what, poll=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(poll)
    raise TimeoutError(what)


def ensure_servers(ports):
    running = ssh(LUIGI, 'pgrep -a iperf3 || true')
    for port in ports:
        if ' -p %d ' % port not in running + ' ':
            ssh(LUIGI, 'nohup iperf3 -s -p %d -D >/dev/null 2>&1' % port)
    time.sleep(1)
    running = ssh(LUIGI, 'pgrep -a iperf3 || true')
    missing = [p for p in ports if '-p %d' % p not in running]
    if missing:
        raise RuntimeError('iperf3 servers missing on luigi: %s' % missing)


def result_file(f):
    return 'scream_tx_%d.log' % f['port'] if f.get('type') == 'scream' else 'iperf_%d.json' % f['port']


def done(plan):
    rd = RUNS / plan['run_id']
    return (rd / 'switch_done.json').exists() and all(
        (rd / 'hosts' / result_file(f)).exists() for f in plan['flows'])


def run_one(plan):
    run_id = plan['run_id']
    rd = RUNS / run_id
    rd.mkdir(parents=True, exist_ok=True)
    for name in ('switch_ready.json', 'start.json', 'switch_done.json', 'switch.json'):
        (rd / name).unlink(missing_ok=True)
    (rd / 'plan.json').write_text(json.dumps(plan, indent=1))
    hosts = sorted({f['host'] for f in plan['flows']})
    ensure_servers([f['port'] for f in plan['flows'] if f.get('type') != 'scream'])
    for host in hosts:
        role, base = REMOTE[host]
        ssh(host, 'rm -rf %s/%s && mkdir -p %s/%s && cat > %s/%s/plan.json' %
            (base, run_id, base, run_id, base, run_id), input=json.dumps(plan))

    Path('/tmp/c7').mkdir(exist_ok=True)
    launcher = Path('/tmp/c7/%s.py' % run_id)
    launcher.write_text('C7_RUN_ID = %r\nC7_ROOT = %r\nexec(open(%r).read())\n' %
                        (run_id, str(ROOT), str(ROOT / 'scripts' / 'c7_switch.py')))
    shell_log = (rd / 'bfshell.log').open('w')
    shell = subprocess.Popen(['script', '-qfc', '%s -b %s' % (BFSHELL, launcher), '/dev/null'],
                             stdout=shell_log, stderr=subprocess.STDOUT, cwd='/tmp/c7')
    log(run_id, 'bfshell pid', shell.pid)
    wait_for(lambda: (rd / 'switch_ready.json').exists() or shell.poll() is not None, 900,
             'switch_ready')
    if not (rd / 'switch_ready.json').exists():
        raise RuntimeError('bfshell exited before ready; see %s' % (rd / 'bfshell.log'))
    ready = json.loads((rd / 'switch_ready.json').read_text())
    if not all(ready['ports_up'].values()):
        raise RuntimeError('ports not up: %s' % ready['ports_up'])
    for host in hosts:
        role, base = REMOTE[host]
        path = '%s/%s/%s_ready.json' % (base, run_id, role)
        wait_for(lambda: ssh(host, 'test -e %s && echo y' % path, check=False).strip() == 'y',
                 600, '%s ready' % role, poll=2)
        info = json.loads(ssh(host, 'cat %s' % path))
        if not info['netem_ok']:
            raise RuntimeError('%s netem not applied: %s' % (role, info))

    # Kernel TCP/IP counters per host: /proc snapshots before t0 and after the flows
    # (nstat is broken on luigi); e1_analyze.py computes the deltas.
    snap_hosts = {h: REMOTE[h][0] for h in hosts}
    snap_hosts[LUIGI] = 'luigi'
    snap_cmd = 'cat /proc/net/snmp /proc/net/netstat'
    snap_before = {h: ssh(h, snap_cmd, check=False) for h in snap_hosts}
    lead = 20 if plan.get('replay') else LEAD_S       # replay host preloads the PCAP first
    t0 = time.time() + lead
    start = json.dumps({'run_id': run_id, 't0_epoch': t0})
    (rd / 'start.json').write_text(start)
    for host in hosts:
        role, base = REMOTE[host]
        ssh(host, 'cat > %s/%s/start.json' % (base, run_id), input=start)
    clients = []
    receivers = []
    for f in plan['flows']:
        if f.get('type') != 'scream':
            continue
        ssh(LUIGI, 'pkill -f scream_bw_test_rx || true', check=False)
        receivers.append(subprocess.Popen(['ssh', '-o', 'BatchMode=yes', LUIGI,
            'mkdir -p ~/c7/e1x && %s 172.16.0.4 %d > ~/c7/e1x/scream_rx_%s.log 2>&1' % (SCREAM_RX, f['port'], run_id)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for f in plan['flows']:
        role, base = REMOTE[f['host']]
        if f.get('type') == 'scream':
            # Not-ECT is the tool's default; it rejects '-ect -1' ("ect must be -1, 0, 1 or 3").
            ect = '' if f['ect'] < 0 else '-ect %d ' % f['ect']
            cmd = ("python3 -c 'import time; time.sleep(max(0, %r - time.time()))' && "
                   "%s %s-time %d -log %s/%s/scream_tx_%d.log 172.16.0.5 %d > %s/%s/scream_summary_%d.txt 2>&1"
                   % (t0, SCREAM_TX, ect, plan['duration_s'], base, run_id, f['port'], f['port'],
                      base, run_id, f['port']))
            clients.append(subprocess.Popen(['ssh', '-o', 'BatchMode=yes', f['host'], cmd],
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
            continue
        role, base = REMOTE[f['host']]
        cmd = ("python3 -c 'import time; time.sleep(max(0, %r - time.time()))' && "
               "iperf3 -c %s -p %d -C %s -t %d -i 1 -J --logfile %s/%s/iperf_%d.json"
               % (t0, RECEIVER, f['port'], f['cc'], plan['duration_s'], base, run_id, f['port']))
        clients.append(subprocess.Popen(['ssh', '-o', 'BatchMode=yes', f['host'], cmd],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))
    log(run_id, 'started %d flows; t0 in %.1f s' % (len(clients), t0 - time.time()))
    for c in clients:
        c.wait(timeout=plan['duration_s'] + lead + 120)
    if receivers:
        ssh(LUIGI, 'pkill -f scream_bw_test_rx || true', check=False)
        for r in receivers:
            r.wait(timeout=30)
    dest = rd / 'hosts'
    dest.mkdir(exist_ok=True)
    for host, role in snap_hosts.items():
        (dest / ('proc_%s_before.txt' % role)).write_text(snap_before[host])
        (dest / ('proc_%s_after.txt' % role)).write_text(ssh(host, snap_cmd, check=False))
    wait_for(lambda: (rd / 'switch_done.json').exists() or shell.poll() is not None, 300,
             'switch_done')
    if not (rd / 'switch_done.json').exists():
        raise RuntimeError('bfshell exited before switch_done; see bfshell.log')
    shell.wait(timeout=120)
    shell_log.close()
    for host in hosts:
        role, base = REMOTE[host]
        subprocess.run(['scp', '-q', '%s:%s/%s/*' % (host, base, run_id), str(dest)], check=True)
    errors = [c.stdout.read() for c in clients if c.returncode]
    if errors:
        (rd / 'client_errors.txt').write_text('\n'.join(errors))
        raise RuntimeError('iperf3 client errors: %s' % errors[:2])
    missing = [result_file(f) for f in plan['flows'] if not (dest / result_file(f)).exists()]
    if missing:
        rd.rename(rd.with_name('INVALID_' + run_id + '_missing_results'))
        raise RuntimeError('%s: missing result files %s' % (run_id, missing))
    log(run_id, 'complete')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--only')
    parser.add_argument('--max', type=int, default=0)
    args = parser.parse_args()
    plans = json.loads((RUNS / 'sequence.json').read_text())
    count = 0
    for plan in plans:
        if args.only and plan['run_id'] != args.only:
            continue
        if done(plan):
            continue
        run_one(plan)
        count += 1
        if args.max and count >= args.max:
            break
    log('driver finished', count, 'runs')


if __name__ == '__main__':
    main()
