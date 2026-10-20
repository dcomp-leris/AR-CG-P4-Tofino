"""bfrt_python entry point. Set these first, then %run -i this file:
    R2C1_PROGRAM = 'ICEFE_r2c1' or 'FWD_r2c1'
    R2C1_DIRECTION = 'DL' or 'UL'
    R2C1_RUN_ID = e.g. 'ICEFE_DL_rep1'
It configures the freshly loaded program, then follows raw/runs/<id>/start.json.
"""
from pathlib import Path
_root = Path(globals().get('R2C1_ROOT', Path(__file__).absolute().parent.parent))
assert R2C1_PROGRAM in ('ICEFE_r2c1', 'FWD_r2c1') and R2C1_DIRECTION in ('DL', 'UL')
if R2C1_PROGRAM == 'ICEFE_r2c1':
    try:
        _majority = bfrt.ICEFE_r2c1.pipe.Ingress.table_majority.get(regex=True, print_ents=False, return_ents=True)
    except Exception:   # empty table: BFRT raises "Object not found"
        _majority = []
    if _majority in (None, -1, []):
        __file__ = str(_root / 'programs' / 'ICEFE_r2c1.py')   # resolves Model.json/majority.txt
        exec(compile((_root / 'programs' / 'ICEFE_r2c1.py').read_text(), __file__, 'exec'), globals())
    else:
        # Controller already loaded into this switchd (retry after a later failure):
        # define only set_budget, exactly as in build/ICEFE_r2c1.py.
        coupling_program = bfrt.ICEFE_r2c1
        _src = (_root / 'programs' / 'ICEFE_r2c1.py').read_text()
        _a = _src.index("R2C1_BUDGETS = ")
        _b = _src.index("    return budget", _a) + len("    return budget")
        exec(_src[_a:_b], globals())
        print('ICEFE_r2c1 controller already loaded; table_majority entries:', len(_majority))
__file__ = str(_root / 'scripts' / 'r2c1_bfrt.py')
exec(compile((_root / 'scripts' / 'r2c1_bfrt.py').read_text(), __file__, 'exec'), globals())
r2c1 = R2C1(R2C1_PROGRAM)
r2c1.setup_ports()
r2c1.apply_tm()
r2c1_budget = set_budget(R2C1_DIRECTION) if R2C1_PROGRAM == 'ICEFE_r2c1' else None
import json as _j, time as _t
_run_dir = _root / 'raw' / 'runs' / R2C1_RUN_ID
_deadline = _t.time() + 90
while _t.time() < _deadline:   # wait for the peach (136) and luigi (137) links
    _ps = r2c1.port_state()
    if all(_ps[p].get('PORT_UP') == 'True' for p in ('136', '137')):
        break
    _t.sleep(1)
(_run_dir / 'switch_ready.json').write_text(_j.dumps({'epoch': _t.time(), 'program': R2C1_PROGRAM,
    'direction': R2C1_DIRECTION, 'budget': r2c1_budget, 'ports': _ps}, indent=2))
_start = _run_dir / 'start.json'
while not _start.exists():
    _t.sleep(0.5)
r2c1_run(R2C1_RUN_ID, R2C1_PROGRAM, R2C1_DIRECTION, budget=r2c1_budget)
