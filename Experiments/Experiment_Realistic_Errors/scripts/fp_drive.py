#!/usr/bin/env python3
"""FP mixture runs: python3 fp_drive.py [--only RUN_ID]
Needs: switchd with ICEFE + port 152 up, P4TG streaming, fp_host_job.py (sudo) on
superpeach and superluigi, no interactive bfrt_python. Runs FP_DL_rep1, FP_UL_rep1, ...
Each run: plan -> bfshell (fp_switch.py) -> hosts ready -> start.json -> wait -> fetch."""
import argparse, csv, json, os, subprocess, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / 'raw' / 'fp'
BFSHELL = os.environ.get('BFSHELL', os.path.join(
    os.environ.get('SDE', '/opt/bf-sde-9.13.4'), 'install/bin/bfshell'))
HOSTS = {
    'peach': (os.environ.get('ICEFE_PEACH_SSH', 'user@peach-host'),
              os.environ.get('ICEFE_PEACH_FP_DIR', '/tmp/icefe-fp')),
    'luigi': (os.environ.get('ICEFE_LUIGI_SSH', 'user@luigi-host'),
              os.environ.get('ICEFE_LUIGI_FP_DIR', '/tmp/icefe-fp')),
}
DATASET_DIR = os.environ.get('ICEFE_DATASET_DIR', '/data/icefe/test')
# One merged PCAP per set (mergecap of the test-window PCAPs, ordered by time), replayed by
# a single tcpreplay: 10-11 concurrent tcpreplay processes stretched replays by up to 43 %.
SETS = {'DL': ['merged_DL'], 'UL': ['merged_UL'],
        # controlled FP sensitivity: DL set with 10 % / 18 % of Other packets pre-marked AR/CG
        'DLfp10': ['merged_DL_fp10'], 'DLfp18': ['merged_DL_fp18']}
MAPSET = {'DL': 'DL', 'UL': 'UL', 'DLfp10': 'DL', 'DLfp18': 'DL'}
INJECTED = {'DLfp10': 'fp10_selected.json', 'DLfp18': 'fp18_selected.json'}


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def ssh(host, cmd, check=True, **kw):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', host, cmd], capture_output=True, text=True, check=check, **kw).stdout


def wait_for(pred, timeout, what, poll=2):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(poll)
    raise TimeoutError(what)


def plan_for(run_id, s):
    rows = [r for r in csv.DictReader(open(ROOT / 'data' / ('map_test_%s.csv' % MAPSET[s])))]
    return {'run_id': run_id, 'set': MAPSET[s], 'variant': s, 'injected': INJECTED.get(s), 'budget': MAPSET[s],
            'pcaps': SETS[s], 'dataset_dir': DATASET_DIR,
            'capture_ports': sorted(int(r['port']) for r in rows if r['class'] in ('AR', 'CG')),
            'max_duration_s': max(float(r['last_s']) for r in rows), 'ring_mask_bits': 12}


def run_one(run_id, s):
    rd = RUNS / run_id
    rd.mkdir(parents=True, exist_ok=True)
    for n in ('switch_ready.json', 'start.json', 'switch_done.json'):
        (rd / n).unlink(missing_ok=True)
    plan = plan_for(run_id, s)
    (rd / 'plan.json').write_text(json.dumps(plan, indent=1))
    for role, (host, base) in HOSTS.items():
        ssh(host, 'rm -rf %s/%s && mkdir -p %s/%s && cat > %s/%s/plan.json' % (base, run_id, base, run_id, base, run_id), input=json.dumps(plan))
    Path('/tmp/c7').mkdir(exist_ok=True)
    launcher = Path('/tmp/c7/%s.py' % run_id)
    launcher.write_text('C7_RUN_ID = %r\nC7_ROOT = %r\nexec(open(%r).read())\n' %
                        (run_id, str(ROOT), str(ROOT / 'scripts' / 'fp_switch.py')))
    shell_log = (rd / 'bfshell.log').open('w')
    shell = subprocess.Popen(['script', '-qfc', '%s -b %s' % (BFSHELL, launcher), '/dev/null'], stdout=shell_log, stderr=subprocess.STDOUT, cwd='/tmp/c7')
    wait_for(lambda: (rd / 'switch_ready.json').exists() or shell.poll() is not None, 600, 'switch_ready')
    if not (rd / 'switch_ready.json').exists():
        raise RuntimeError('bfshell exited early; see bfshell.log')
    for role, (host, base) in HOSTS.items():
        wait_for(lambda: ssh(host, 'test -e %s/%s/%s_ready.json && echo y' % (base, run_id, role), check=False).strip() == 'y', 600, role + ' ready')
    t0 = time.time() + 20
    start = json.dumps({'run_id': run_id, 't0_epoch': t0})
    (rd / 'start.json').write_text(start)
    for role, (host, base) in HOSTS.items():
        ssh(host, 'cat > %s/%s/start.json' % (base, run_id), input=start)
    log(run_id, 'started; replay at t0 =', time.strftime('%H:%M:%S', time.localtime(t0)), 'for ~%.0f s' % plan['max_duration_s'])
    host, base = HOSTS['peach']
    wait_for(lambda: ssh(host, 'test -e %s/%s/peach_done.json && echo y' % (base, run_id), check=False).strip() == 'y',
             3 * plan['max_duration_s'] + 600, 'peach replay done', poll=5)
    (rd / 'replay_done.json').write_text(json.dumps({'replay_done_seen': time.time()}))
    host, base = HOSTS['luigi']
    ssh(host, 'touch %s/%s/stop_capture' % (base, run_id))
    wait_for(lambda: ssh(host, 'test -e %s/%s/luigi_done.json && echo y' % (base, run_id), check=False).strip() == 'y',
             900, 'luigi done', poll=5)
    wait_for(lambda: (rd / 'switch_done.json').exists() or shell.poll() is not None, 900, 'switch_done')
    if not (rd / 'switch_done.json').exists():
        raise RuntimeError('bfshell exited before switch_done; see bfshell.log')
    shell.wait(timeout=120)
    shell_log.close()
    dest = rd / 'hosts'
    dest.mkdir(exist_ok=True)
    for role, (host, base) in HOSTS.items():
        subprocess.run(['scp', '-q', '%s:%s/%s/*' % (host, base, run_id), str(dest)], check=True)
    # Stress check: P4TG (flow index 53112) must have delivered >= 80 % of its ~900 kpkt/s
    # during the capture window, otherwise the run had no stress (e.g. P4TG link down).
    fs = json.loads((rd / 'flow_state.json').read_text())
    got = fs['ingress_pkts'].get('53112', 0)
    window = json.loads((rd / 'switch_done.json').read_text())['t_read'] - json.loads((rd / 'switch_ready.json').read_text())['ready']
    need = 0.8 * 900000 * window
    if got < need:
        rd.rename(rd.with_name('INVALID_' + run_id + '_low_p4tg'))
        raise RuntimeError('%s: P4TG delivered %d packets (< %d): stress missing, run invalidated' % (run_id, got, need))
    # Replay-timing check: each PCAP's tcpreplay duration vs its window at original timing.
    nominal = {}
    for r in csv.DictReader(open(ROOT / 'data' / ('map_test_%s.csv' % MAPSET[s]))):
        nominal[r['capture']] = max(nominal.get(r['capture'], 0), float(r['last_s']))
    stretch = {}
    for name in plan['pcaps']:
        if name.startswith('merged_'):
            nominal[name] = plan['max_duration_s']
        txt = (rd / 'hosts' / ('replay_%s.log' % name)).read_text()
        secs = [float(l.split('sent in ')[1].split(' ')[0]) for l in txt.splitlines() if l.startswith('Actual') and 'sent in' in l]
        if secs and nominal.get(name, 0) > 20:
            stretch[name] = secs[-1] / nominal[name]
    (rd / 'replay_stretch.json').write_text(json.dumps(stretch))
    bad = {k: round(v, 3) for k, v in stretch.items() if v > 1.05}
    if bad:
        rd.rename(rd.with_name('INVALID_' + run_id + '_stretched'))
        raise RuntimeError('%s: replay stretched > 5 %%: %s' % (run_id, bad))
    log(run_id, 'complete; P4TG packets %d; max replay stretch %.3f' % (got, max(stretch.values()) if stretch else 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only')
    ap.add_argument('--sens', action='store_true', help='controlled 10 %% / 18 %% FP runs')
    a = ap.parse_args()
    order = [('FP_%s_rep%d' % (s, r), s) for r in range(1, 6) for s in ('DL', 'UL')]
    if a.sens:
        order = [('FPS_%s_rep%d' % (s, r), s) for r in range(1, 6) for s in ('DLfp10', 'DLfp18')]
    for run_id, s in order:
        if a.only and run_id != a.only:
            continue
        if (RUNS / run_id / 'switch_done.json').exists() and (RUNS / run_id / 'hosts' / 'luigi_pkts.csv.gz').exists():
            continue
        run_one(run_id, s)
    log('fp driver finished')


if __name__ == '__main__':
    main()
