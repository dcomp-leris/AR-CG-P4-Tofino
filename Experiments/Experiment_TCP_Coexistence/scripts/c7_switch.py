"""bfshell -b entry point for one E1 run. The launcher sets C7_RUN_ID, then execs this file.

1. Load ICEFE/ICEFE.py fully if the program is not configured yet; otherwise
   re-define only its functions and constants (no table writes).
2. Idempotent run configuration: mirror session (256 B clones), forwarding
   (supermario at 172.16.0.6), bottleneck, budget, L4S step, sampling mask.
3. Reset c7 counters/ring, per-flow classification state and p_base; idle.
4. Write switch_ready.json, wait for start.json, run the AQM loop (config a) or
   wait (config b), then save counters + ring and write switch_done.json.
"""
import ast
import json as _json
import sys as _sys
import time as _time
from pathlib import Path as _Path

C7_ROOT = _Path(globals().get('C7_ROOT', _Path(__file__).absolute().parent.parent))
_run_dir = C7_ROOT / 'raw' / 'e1' / C7_RUN_ID
_run_dir.mkdir(parents=True, exist_ok=True)
_plan = _json.loads((_run_dir / 'plan.json').read_text())
# Load ICEFE.py (complete on a fresh switch, otherwise only its functions/constants)
# and the c7_* measurement helpers (ICEFE/icefe_tools.py). See ICEFE/load_icefe.py.
ICEFE_DIR = str(C7_ROOT.parent.parent)
exec(open(ICEFE_DIR + '/load_icefe.py').read())
_loaded = ICEFE_LOADED

# Idempotent configuration (all mirror fields: mod_with_normal resets omitted ones).
bfrt.mirror.cfg.mod_with_normal(sid=1, direction='EGRESS', session_enable=True,
                                ucast_egress_port=128, ucast_egress_port_valid=True,
                                max_pkt_len=256)
SERVER_INVENTORY["Server2"]["fiber_ip"] = "172.16.0.6"
install_server_topology({"Server1": 137, "Server2": 138, "Server3": 136})
set_bottleneck(_plan['bottleneck_kbps'])
set_budget('DL')
c7_set_step(_plan['step_us'])
c7_set_mask(_plan['ring_mask_bits'])
set_coupling_base(137, 0)
c7_clear_flows()
c7_reset()


def _port_up(port):
    entry = bfrt.port.port.get(DEV_PORT=port, print_ents=False, return_ents=True)
    entry = entry[0] if isinstance(entry, (list, tuple)) else entry
    return str(_c7_fields(entry).get('PORT_UP')) == 'True'


_deadline = _time.time() + 60
while _time.time() < _deadline and not all(_port_up(p) for p in (136, 137, 138)):
    _time.sleep(1)
_ports = {p: _port_up(p) for p in (136, 137, 138)}
_time.sleep(_plan['idle_s'])
(_run_dir / 'switch_ready.json').write_text(_json.dumps(
    {'ready': _time.time(), 'controller': _loaded, 'ports_up': _ports,
     'mirror': 256, 'p_base_137': _c7_reg(C7_EG.coupling_base_probability, 137)}))
print('c7 switch ready', C7_RUN_ID, _loaded, _ports, flush=True)

while not (_run_dir / 'start.json').exists():
    _time.sleep(0.2)
_start = _json.loads((_run_dir / 'start.json').read_text())
while _time.time() < _start['t0_epoch'] - 2:
    _time.sleep(0.05)
_aqm = None
_aqm_t0 = _time.time()
if _plan['config'] == 'a':
    try:
        _aqm = run_coupling_aqm(duration_s=_plan['duration_s'] + 6)
    except Exception as _exc:   # e.g. BFRT polling above 32 ms aborts the loop
        _aqm = {'error': repr(_exc)}
else:
    while _time.time() < _start['t0_epoch'] + _plan['duration_s'] + 4:
        _time.sleep(0.2)
_aqm_t1 = _time.time()
c7_save(str(_run_dir / 'switch.json'))
_time.sleep(1)   # outstanding clones drain
c7_flow_state(str(_run_dir / 'flow_state.json'))
set_coupling_base(137, 0)
(_run_dir / 'switch_done.json').write_text(_json.dumps(
    {'done': _time.time(), 'aqm': _aqm, 'aqm_start': _aqm_t0, 'aqm_end': _aqm_t1}, default=str))
print('c7 switch done', C7_RUN_ID, flush=True)
