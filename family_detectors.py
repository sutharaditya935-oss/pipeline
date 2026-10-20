"""Per-family detector results: which families can a simple execution-time monitor actually protect?

For each family with >= 5 damaged samples: how many damaged samples expose each precursor signal (coverage),
and for those, the share with zero damage before the monitor reacts (zero-loss). 'Protected' = the sample
has a key-generation or crypto-context signal and the corresponding monitor (0.5 s reaction) lets no damage
event through. The benign cost of that union rule is computed from the benign baseline.

  .venv/bin/python family_detectors.py --results results_ransomware --labels results/family_labels.csv \
      --benign results_benign_intel --index ~/benign_reports_intel/index_attributable.csv \
      --out results_ransomware/family_detectors.txt
"""
import argparse, gzip, json, math

import numpy as np
import pandas as pd

ap = argparse.ArgumentParser()
for k in ('--results', '--labels', '--benign', '--index', '--out'):
    ap.add_argument(k, required=True)
a = ap.parse_args()
SIG = [('enum', 't_enum', 1.0), ('ctx', 't_crypto_ctx', 0.5), ('key', 't_crypto_key', 0.5)]


def wilson(k, n, z=1.96):
    ph = k / n; d = 1 + z * z / n; c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return ph, max(0, c - h), min(1, c + h)


t = pd.read_csv(f'{a.results}/timelines.csv', dtype={'task': str}); t = t[t.executed & ~t.is_smoketest & t.t_damage.notna()]
t = t.merge(pd.read_csv(a.labels, dtype={'task': str})[['task', 'family']], on='task')
ev = {}
for line in gzip.open(f'{a.results}/damage.jsonl.gz', 'rt'):
    d = json.loads(line); ev[str(d['task'])] = np.array([e[0] for e in d['events']])
for name, col, lat in SIG:
    t[f'has_{name}'] = t[col].notna()
    t[f'zl_{name}'] = [bool(pd.notna(s) and not (ev.get(k, np.array([])) < s + lat).any()) for k, s in zip(t.task, t[col])]
t['protected'] = (t.has_key & t.zl_key) | (t.has_ctx & t.zl_ctx)
L = []
p = lambda s='': (print(s), L.append(s))
fam = t.family.value_counts(); fam = fam[fam >= 5].index
p('family        n   | enum cov zl  | ctx cov  zl (of exposing) | key cov  zl (of exposing) | protected by key-or-ctx')
rows = [(f, t[t.family == f]) for f in fam] + [('ALL', t)]
for f, g in rows:
    n = len(g); parts = []
    for name, _, _ in SIG:
        h = g[g[f'has_{name}']]
        parts.append(f'{100 * len(h) / n:4.0f}% {100 * h[f"zl_{name}"].mean() if len(h) else float("nan"):4.0f}%')
    p(f'{f:12s} {n:3d}  | ' + ' | '.join(parts) + f' | {int(g.protected.sum()):3d}/{n:3d} = {100 * g.protected.mean():4.0f}%')
# benign cost of the union rule
b = pd.read_csv(f'{a.benign}/timelines.csv', dtype={'task': str}).merge(pd.read_csv(a.index, dtype={'task': str}), on='task'); b = b[b.executed]
u = int((b.t_crypto_ctx.notna() | b.t_crypto_key.notna()).sum()); ph, lo, hi = wilson(u, len(b))
p(f'\nbenign cost of "key generation OR crypto context": {u}/{len(b)} = {100 * ph:.0f}% [95% Wilson {100 * lo:.0f}, {100 * hi:.0f}]')
p(f'overall: protects {100 * t.protected.mean():.0f}% of damaged samples ({int(t.protected.sum())}/{len(t)}); families with zero protected samples: ' +
  ', '.join(f for f in fam if t[t.family == f].protected.sum() == 0))
open(a.out, 'w').write('\n'.join(L) + '\n')
