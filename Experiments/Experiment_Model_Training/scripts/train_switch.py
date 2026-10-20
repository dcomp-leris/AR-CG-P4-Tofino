"""bfshell -b entry for training/test replays. The launcher sets C7_MODE ('prep' or
'collect'), C7_BUDGET ('DL'/'UL') and C7_TAG (e.g. 'train_DL'), then execs this file.
prep: load controller (full on a fresh switchd), no bottleneck, budget, clear state.
collect: dump per-flow classifier registers to raw/training/features_<tag>.json."""
import ast
import sys as _sys
from pathlib import Path as _Path
C7_ROOT = _Path(globals().get('C7_ROOT', _Path(__file__).absolute().parent.parent))
# Load ICEFE.py (complete on a fresh switch, otherwise only its functions/constants)
# and the c7_* measurement helpers (ICEFE/icefe_tools.py). See ICEFE/load_icefe.py.
ICEFE_DIR = str(C7_ROOT.parent.parent)
exec(open(ICEFE_DIR + '/load_icefe.py').read())
_loaded = ICEFE_LOADED
if C7_MODE == 'prep':
    bfrt.mirror.cfg.mod_with_normal(sid=1, direction='EGRESS', session_enable=True,
                                    ucast_egress_port=128, ucast_egress_port_valid=True, max_pkt_len=256)
    SERVER_INVENTORY["Server2"]["fiber_ip"] = "172.16.0.6"
    install_server_topology({"Server1": 137, "Server2": 138, "Server3": 136})
    clear_bottleneck()
    set_budget(C7_BUDGET)
    set_coupling_base(137, 0)
    c7_clear_flows()
    c7_clear_features()
    c7_reset()
    print('c7 TRAIN PREP DONE', C7_TAG, C7_BUDGET)
else:
    (C7_ROOT / 'raw' / 'training').mkdir(parents=True, exist_ok=True)
    c7_collect_features(str(C7_ROOT / 'raw' / 'training' / ('features_%s.json' % C7_TAG)))
    c7_save(str(C7_ROOT / 'raw' / 'training' / ('switch_%s.json' % C7_TAG)), ring=False)
    print('c7 TRAIN COLLECT DONE', C7_TAG)
