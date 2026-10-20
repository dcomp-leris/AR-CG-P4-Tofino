"""bfshell -b entry for one FP mixture run (launcher sets C7_RUN_ID). Port 137 unshaped
(10G; P4TG on 152 provides the stress), budget per set, L4S step 1 ms, coupled AQM on
for the replay, then per-flow state, features, counters and ring are saved."""
import ast
import json as _json
import sys as _sys
import time as _time
from pathlib import Path as _Path
C7_ROOT = _Path(globals().get('C7_ROOT', _Path(__file__).absolute().parent.parent))
_rd = C7_ROOT / 'raw' / 'fp' / C7_RUN_ID
_plan = _json.loads((_rd / 'plan.json').read_text())
# Load ICEFE.py (complete on a fresh switch, otherwise only its functions/constants)
# and the c7_* measurement helpers (ICEFE/icefe_tools.py). See ICEFE/load_icefe.py.
ICEFE_DIR = str(C7_ROOT.parent.parent)
exec(open(ICEFE_DIR + '/load_icefe.py').read())
_loaded = ICEFE_LOADED
bfrt.mirror.cfg.mod_with_normal(sid=1, direction='EGRESS', session_enable=True,
                                ucast_egress_port=128, ucast_egress_port_valid=True, max_pkt_len=256)
clear_bottleneck()
set_budget(_plan['budget'])
c7_set_step(1000)
c7_set_mask(_plan['ring_mask_bits'])
set_coupling_base(137, 0)
c7_clear_flows()
c7_clear_features()
c7_reset()
(_rd / 'switch_ready.json').write_text(_json.dumps({'ready': _time.time()}))
print('c7 FP switch ready', C7_RUN_ID, flush=True)
while not (_rd / 'start.json').exists():
    _time.sleep(0.2)
_t0 = _json.loads((_rd / 'start.json').read_text())['t0_epoch']
while _time.time() < _t0 - 2:
    _time.sleep(0.05)
# Coupled AQM until the driver signals that superpeach's replay has ended (replay_done),
# in 20 s chunks; each chunk starts from the current p_base register value.
_aqm = []
_limit = _t0 + 3 * _plan['max_duration_s']
while not (_rd / 'replay_done.json').exists() and _time.time() < _limit:
    try:
        _aqm.append(run_coupling_aqm(duration_s=20))
    except Exception as _exc:
        _aqm.append({'error': repr(_exc)})
_time.sleep(2)
_t_read = _time.time()   # the per-flow ingress counts (incl. P4TG) are read from here
c7_flow_state(str(_rd / 'flow_state.json'))
c7_collect_features(str(_rd / 'features.json'))
c7_save(str(_rd / 'switch.json'))
set_coupling_base(137, 0)
(_rd / 'switch_done.json').write_text(_json.dumps({'done': _time.time(), 't_read': _t_read, 'aqm': _aqm}, default=str))
print('c7 FP switch done', C7_RUN_ID, flush=True)
