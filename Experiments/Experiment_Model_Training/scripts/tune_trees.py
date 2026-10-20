#!/usr/bin/env python3
"""Choose fit_trees settings on an internal validation split of the TRAINING samples only
(even 5 s segments -> fit, odd -> validate); the test set is not read.
python3 tune_trees.py samples_train.csv OUT.json"""
import csv, itertools, json, sys
import numpy as np
sys.path.insert(0, __file__.rsplit('/', 1)[0])
import fit_trees as F

rows = [r for r in csv.DictReader(open(sys.argv[1])) if int(r['clones']) > 0]
def arrays(sel):
    X = {f: np.array([int(r[F.COL[f]]) for r in sel], dtype=np.int64) for f in F.COL}
    return X, np.array([F.CLS[r['class']] for r in sel])
fit = [r for r in rows if int(r['segment']) % 2 == 0]
val = [r for r in rows if int(r['segment']) % 2 == 1]
Xf, yf = arrays(fit); Xv, yv = arrays(val)
def balanced_acc(pred, y):
    return float(np.mean([np.mean(pred[y == c] == c) for c in (1, 2, 3)]))
results = []
for cand, passes, seed in itertools.product((16, 24, 40), (4, 8), (1, 2, 3, 4, 5)):
    rng = np.random.default_rng(seed)
    cw = {c: len(yf) / (3 * max(1, (yf == c).sum())) for c in (1, 2, 3)}
    trees = {}
    for name in sorted(F.TOPO):
        boot = rng.integers(0, len(yf), len(yf))
        Xb = {f: v[boot] for f, v in Xf.items()}; yb = yf[boot]
        trees[name] = F.fit_tree(name, Xb, yb, np.array([cw[c] for c in yb]), rng, cand, passes)
    pred, _ = F.forest_predict(trees, Xv)
    ba = balanced_acc(pred, yv)
    fp = float(np.mean(np.isin(pred[yv == 3], (1, 2))))
    results.append({'candidates': cand, 'passes': passes, 'seed': seed, 'val_balanced_acc': ba, 'val_fp_flows': fp})
    print(cand, passes, seed, round(ba, 4), round(fp, 4), flush=True)
best = max(results, key=lambda r: (r['val_balanced_acc'], -r['val_fp_flows']))
json.dump({'best': best, 'all': results, 'fit_flows': len(yf), 'val_flows': len(yv)}, open(sys.argv[2], 'w'), indent=1)
print('BEST', best)
