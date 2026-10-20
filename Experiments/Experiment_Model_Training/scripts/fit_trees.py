#!/usr/bin/env python3
"""Fit ICEFE's 5 range trees to switch-measured features, within the fixed P4 topology.

python3 fit_trees.py train.csv test.csv OUTDIR [--seed 1] [--candidates 24] [--passes 4]

CSV columns: flow_id, class (AR/CG/Other), capture, packets, bytes, clones, PS, FS, IPG20, IFG20
(PS/FS = the LPF values the tables match on; IPG20/IFG20 = LPF value [31:12]).
Only flows with clones > 0 are used (others were never classified).

Topology (ICEFE.p4 apply block; range counts = active controller entries):
  T1  FS(4): leaf 1/3, code 0 -> IPG(2), code 2 -> PS(4)      (PS = packet size)
  T2  IFG(3): leaf, code 0 -> IPG(2)
  T3  FS(2): leaf, code 0 -> IFG(2): leaf, code 0 -> IPG(2)
  T4  IFG(2): leaf, code 5 -> IPG(3), code 6 -> FS(3)
  T5  FS(2): leaf, code 0 -> IPG(3)
Children cover their whole key range, so every route ends in a class 1/2/3.
Method: each tree is fitted on its own bootstrap sample (random forest), with
class-balanced weights. Coordinate descent: each table's cut points (from
feature quantiles) and per-interval labels are optimised exhaustively with the
other tables fixed, scoring the whole tree by emulation. Majority: plurality of
the 5 votes, ties -> lowest class id (as in the original majority.txt).
Outputs OUTDIR/Model.json, OUTDIR/majority.txt, OUTDIR/report.json.
"""
import argparse
import csv
import itertools
import json
from pathlib import Path

import numpy as np

CLS = {'AR': 1, 'CG': 2, 'Other': 3}
NAMES = {1: 'AR', 2: 'CG', 3: 'Other', 0: 'none'}
MAXV = {'PS': 65535, 'FS': 65535, 'IPG': 1048575, 'IFG': 1048575}
COL = {'PS': 'PS', 'FS': 'FS', 'IPG': 'IPG20', 'IFG': 'IFG20'}

# node: (feature, n_ranges, {code: child_node}); leaves are always 1/2/3 except
# where a code equals a leaf class (T1 code 2): then the interval routes.
TOPO = {
    'Tree1': ('FS', 4, {0: ('IPG', 2, {}), 2: ('PS', 4, {})}),
    'Tree2': ('IFG', 3, {0: ('IPG', 2, {})}),
    'Tree3': ('FS', 2, {0: ('IFG', 2, {0: ('IPG', 2, {})})}),
    'Tree4': ('IFG', 2, {5: ('IPG', 3, {}), 6: ('FS', 3, {})}),
    'Tree5': ('FS', 2, {0: ('IPG', 3, {})}),
}


def load(path):
    rows = [r for r in csv.DictReader(open(path)) if int(r['clones']) > 0]
    X = {f: np.array([int(r[COL[f]]) for r in rows], dtype=np.int64) for f in COL}
    y = np.array([CLS[r['class']] for r in rows])
    meta = [{'flow_id': int(r['flow_id']), 'capture': r['capture'], 'packets': int(r['packets']),
             'bytes': int(r['bytes'])} for r in rows]
    return X, y, meta


class Table:
    """A range table: cuts c1 < ... < c_{k-1}; interval i = [c_i, c_{i+1}-1]; label per interval."""

    def __init__(self, feature, k, children):
        self.f, self.k = feature, k
        self.children = {code: Table(*spec) for code, spec in children.items()}
        self.cuts = []
        self.labels = [3] * k

    def options(self):
        leaves = [1, 2, 3]
        if 2 in self.children:            # T1: code 2 routes to PS, no plain CG leaf
            leaves = [1, 3]
        return leaves + list(self.children)

    def interval(self, X):
        return np.searchsorted(np.array(self.cuts, dtype=np.int64), X[self.f], side='right')

    def predict(self, X):
        idx = self.interval(X)
        out = np.array(self.labels)[idx]
        for code, child in self.children.items():
            m = out == code
            if m.any():
                sub = {f: v[m] for f, v in X.items()}
                out = out.copy()
                out[m] = child.predict(sub)
        return out

    def tables(self):
        yield self
        for c in self.children.values():
            yield from c.tables()

    def ranges(self):
        bounds = [0] + list(self.cuts) + [MAXV[self.f] + 1]
        return [(bounds[i], bounds[i + 1] - 1, int(self.labels[i])) for i in range(self.k)]


def init(table, X, rng):
    q = np.quantile(X[table.f], np.linspace(0, 1, table.k + 1)[1:-1]) if len(X[table.f]) else []
    table.cuts = sorted(set(int(v) + 1 for v in q))[:table.k - 1]
    while len(table.cuts) < table.k - 1:
        table.cuts.append((table.cuts[-1] if table.cuts else 0) + 1)
    table.labels = [int(rng.choice(table.options())) for _ in range(table.k)]
    for c in table.children.values():
        init(c, X, rng)


def optimise_table(root, table, X, y, w, n_cand):
    """Exhaustive search of `table`'s cuts and labels with all other tables fixed."""
    vals = X[table.f]
    cand = np.unique(np.quantile(vals, np.linspace(0, 1, n_cand + 2)[1:-1]).astype(np.int64) + 1)
    cand = cand[(cand > 0) & (cand <= MAXV[table.f])]
    combos = list(itertools.combinations(cand.tolist(), table.k - 1)) or [tuple()]
    if tuple(table.cuts) not in combos:
        combos.append(tuple(table.cuts))
    best = (None, None, None)
    saved = (list(table.cuts), list(table.labels))
    opts = table.options()
    # Error of every sample under each option, holding the rest of the tree fixed.
    err = {}
    for o in opts:
        table.labels = [o] * table.k
        err[o] = (root.predict(X) != y) * w
    for cuts in combos:
        table.cuts = list(cuts)
        idx = table.interval(X)
        labels, total = [], 0.0
        for i in range(table.k):
            m = idx == i
            costs = [(err[o][m].sum(), o) for o in opts]
            c, o = min(costs)
            labels.append(o)
            total += c
        if best[0] is None or total < best[0] - 1e-12:
            best = (total, list(cuts), labels)
    table.cuts, table.labels = best[1], best[2]
    if best[0] is None:
        table.cuts, table.labels = saved
    return best[0]


def fit_tree(name, X, y, w, rng, n_cand, passes):
    root = Table(*TOPO[name])
    init(root, X, rng)
    last = None
    for _ in range(passes):
        for t in list(root.tables()):
            cost = optimise_table(root, t, X, y, w, n_cand)
        if last is not None and abs(last - cost) < 1e-12:
            break
        last = cost
    return root


def majority_map():
    out = {}
    for votes in itertools.product((1, 2, 3), repeat=5):
        counts = {c: votes.count(c) for c in (1, 2, 3)}
        top = max(counts.values())
        out[votes] = min(c for c in (1, 2, 3) if counts[c] == top)
    return out


def forest_predict(trees, X):
    votes = np.stack([trees[n].predict(X) for n in sorted(trees)], axis=1)
    mm = majority_map()
    return np.array([mm.get(tuple(int(v) for v in row), 0) for row in votes]), votes


def metrics(pred, y, meta):
    out = {}
    for unit in ('flows', 'packets', 'bytes'):
        wt = np.ones(len(y)) if unit == 'flows' else np.array([m[unit] for m in meta], dtype=float)
        conf = {NAMES[t]: {NAMES[p]: float(wt[(y == t) & (pred == p)].sum()) for p in (1, 2, 3, 0)}
                for t in (1, 2, 3)}
        other = wt[y == 3].sum()
        fp = wt[(y == 3) & ((pred == 1) | (pred == 2))].sum()
        arcg = wt[(y == 1) | (y == 2)].sum()
        fn = wt[((y == 1) | (y == 2)) & ~np.isin(pred, (1, 2))].sum()
        out[unit] = {'confusion': conf,
                     'accuracy': float(wt[pred == y].sum() / wt.sum()),
                     'FP_other_to_ARCG': float(fp / other) if other else None,
                     'FN_ARCG_not_admitted': float(fn / arcg) if arcg else None}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('train')
    ap.add_argument('test')
    ap.add_argument('outdir')
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('--candidates', type=int, default=24)
    ap.add_argument('--passes', type=int, default=4)
    a = ap.parse_args()
    X, y, meta = load(a.train)
    Xt, yt, mt = load(a.test)
    rng = np.random.default_rng(a.seed)
    cw = {c: len(y) / (3 * max(1, (y == c).sum())) for c in (1, 2, 3)}
    trees = {}
    for name in sorted(TOPO):
        boot = rng.integers(0, len(y), len(y))           # bootstrap sample per tree
        Xb = {f: v[boot] for f, v in X.items()}
        yb = y[boot]
        wb = np.array([cw[c] for c in yb])
        trees[name] = fit_tree(name, Xb, yb, wb, rng, a.candidates, a.passes)
    out = Path(a.outdir)
    out.mkdir(parents=True, exist_ok=True)
    weights = {}
    for name, root in trees.items():
        weights[name] = {}
        for t in root.tables():
            weights[name][t.f] = {'r%d' % (i + 1): {'min': lo, 'max': hi, 'class': c}
                                  for i, (lo, hi, c) in enumerate(t.ranges())}
        for f in ('PS', 'IPG', 'FS', 'IFG'):          # unused feature tables, as in the original file
            weights[name].setdefault(f, {'r1': {'min': 0, 'max': MAXV[f], 'class': -1}})
    (out / 'Model.json').write_text(json.dumps(weights, indent=2) + '\n')
    mm = majority_map()
    (out / 'majority.txt').write_text(''.join('t1=%d,t2=%d,t3=%d,t4=%d,t5=%d,m=%d\n' % (k + (v,))
                                              for k, v in sorted(mm.items())))
    ptr, _ = forest_predict(trees, X)
    pte, _ = forest_predict(trees, Xt)
    report = {'train_flows': int(len(y)), 'test_flows': int(len(yt)),
              'train_class_flows': {NAMES[c]: int((y == c).sum()) for c in (1, 2, 3)},
              'test_class_flows': {NAMES[c]: int((yt == c).sum()) for c in (1, 2, 3)},
              'train': metrics(ptr, y, meta), 'test': metrics(pte, yt, mt), 'seed': a.seed}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    with open(out / 'test_predictions.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['flow_id', 'capture', 'class', 'pred', 'packets', 'bytes'])
        for m, t, p in zip(mt, yt, pte):
            w.writerow([m['flow_id'], m['capture'], NAMES[t], NAMES[int(p)], m['packets'], m['bytes']])
    for split in ('train', 'test'):
        r = report[split]
        print(split, {u: {k: (round(v, 4) if isinstance(v, float) else v) for k, v in r[u].items()
                          if k != 'confusion'} for u in r})


if __name__ == '__main__':
    main()
