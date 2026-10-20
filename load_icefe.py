"""Load the ICEFE controller and helpers from a script run by  bfshell -b  (used by the experiments).

The caller must define ICEFE_DIR (path of this folder) before executing this file:
    ICEFE_DIR = '/path/to/ICEFE'
    exec(open(ICEFE_DIR + '/load_icefe.py').read())

* If the switch is NOT configured yet (majority table empty, e.g. right after starting
  bf_switchd), ICEFE.py runs completely (ports, mirror, queues, LPFs, trees, ...).
* If it is already configured, only the functions and constants of ICEFE.py are defined
  (no table writes), so a run can start in seconds without reloading 33,000 entries.
Afterwards icefe_tools.py (c7_* helpers) is loaded. ICEFE_LOADED tells which case happened.
"""
import ast as _ast
import sys as _sys
from pathlib import Path as _Path

_dir = _Path(ICEFE_DIR).resolve()          # folder with ICEFE.py, coupling_aqm.py, Model.json ...
_ctrl = _dir / 'ICEFE.py'
if str(_dir) not in _sys.path:              # coupling_aqm.py must be importable
    _sys.path.insert(0, str(_dir))
try:                                        # is the forest already loaded?
    _majority = bfrt.ICEFE.pipe.Ingress.table_majority.get(regex=True, print_ents=False,
                                                            return_ents=True)
except Exception:                           # an empty table raises "Object not found"
    _majority = []
__file__ = str(_ctrl)                       # ICEFE.py finds its JSON/TXT files next to __file__
if _majority in (None, -1, []):
    exec(compile(_ctrl.read_text(), __file__, 'exec'), globals())       # full configuration
    ICEFE_LOADED = 'full'
else:
    _tree = _ast.parse(_ctrl.read_text())                                 # keep only definitions
    _keep = [n for n in _tree.body if isinstance(
        n, (_ast.Import, _ast.ImportFrom, _ast.FunctionDef, _ast.Assign, _ast.AnnAssign))]
    exec(compile(_ast.Module(body=_keep, type_ignores=[]), __file__, 'exec'), globals())
    ICEFE_LOADED = 'definitions'
__file__ = str(_dir / 'icefe_tools.py')
exec(compile(_Path(__file__).read_text(), __file__, 'exec'), globals())  # c7_* helpers
print('ICEFE loaded:', ICEFE_LOADED, flush=True)
