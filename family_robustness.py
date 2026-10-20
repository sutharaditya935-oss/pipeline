"""Robustness of the headline results to family dominance and near-duplicate samples.

Samples from one family (and re-packed builds of one program) are not independent, and a few families are large
(LockBit 23% of damaged samples). This script recomputes the headline numbers (damaged n, median onset,
Kaplan-Meier median, and for each precursor signal the signal-first share, median lead and detector zero-loss) under:
  1. the full sample (as reported);
  2. a cluster bootstrap that resamples whole families;
  3. leave-one-family-out for every family with >= 15 damaged samples;
  4. near-duplicate removal: one random sample per (family, file size) group, repeated draws;
  5. family-weighted estimates (every family counts once).

  .venv/bin/python family_robustness.py --results results_ransomware --labels results/family_labels.csv \
      --traces traces --out results_ransomware/family_robustness.txt
"""
import argparse, glob, gzip, json

import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter

ap = argparse.ArgumentParser()
for k in ('--results', '--labels', '--traces', '--out'):
    ap.add_argument(k, required=True)
ap.add_argument('--boot', type=int, default=2000); ap.add_argument('--draws', type=int, default=500)
a = ap.parse_args()
rng = np.random.default_rng(2026)
SIG = [('enum', 't_enum', 1.0), ('ctx', 't_crypto_ctx', 0.5), ('key', 't_crypto_key', 0.5)]

t = pd.read_csv(f'{a.results}/timelines.csv', dtype={'task': str}); t = t[t.executed & ~t.is_smoketest]
lab = pd.read_csv(a.labels, dtype={'task': str})[['task', 'family']]
size = {}
for p in glob.glob(f'{a.traces}/*.jsonl.gz'):
    with gzip.open(p, 'rt') as f:
        h = json.loads(f.readline()); size[str(h['task'])] = h.get('size')
t = t.merge(lab, on='task'); t['size'] = t.task.map(size)
ev = {}
for line in gzip.open(f'{a.results}/damage.jsonl.gz', 'rt'):
    d = json.loads(line); ev[str(d['task'])] = np.array([e[0] for e in d['events']])
for name, col, lat in SIG:
    lead, zl = [], []
    for r in t.itertuples():
        s = getattr(r, col)
        if pd.notna(s) and pd.notna(r.t_damage):
            lead.append(r.t_damage - s); zl.append(float(not (ev.get(r.task, np.array([])) < s + lat).any()))
        else:
            lead.append(np.nan); zl.append(np.nan)
    t[f'lead_{name}'] = lead; t[f'zl_{name}'] = zl
t['dur'] = t.t_damage.where(t.t_damage.notna(), t.obs_end); t['ev'] = t.t_damage.notna().astype(int)


def metrics(d):
    km = KaplanMeierFitter().fit(d.dur, d.ev).median_survival_time_
    out = {'damaged n': int(d.ev.sum()), 'median onset': d.t_damage.median(), 'KM median': km}
    for name, _, _ in SIG:
        l = d[f'lead_{name}'].dropna()
        out[f'{name} first %'] = 100 * (l > 0).mean() if len(l) else np.nan
        out[f'{name} lead'] = l.median() if len(l) else np.nan
        out[f'{name} zero-loss %'] = 100 * d[f'zl_{name}'].dropna().mean() if len(l) else np.nan
    return out


L = []
p = lambda s='': (print(s), L.append(s))
cols = list(metrics(t).keys())
fmt = lambda v: f'{v:7.2f}' if abs(v) < 1000 else f'{v:7.0f}'
base = metrics(t)
p(f'executed ransomware samples {len(t)}; damaged {int(t.ev.sum())}; families {t.family.nunique()}')
p('\n1. AS REPORTED'); p('   ' + ' | '.join(f'{c}={fmt(base[c]).strip()}' for c in cols))

# 2. cluster bootstrap over families
fams = t.family.unique(); groups = {f: t[t.family == f] for f in fams}
B = []
for _ in range(a.boot):
    pick = rng.choice(fams, len(fams), replace=True)
    B.append(metrics(pd.concat([groups[f] for f in pick])))
B = pd.DataFrame(B)
p(f'\n2. CLUSTER BOOTSTRAP over {len(fams)} families ({a.boot} resamples): 95% interval')
for c in cols:
    lo, hi = np.nanpercentile(B[c], [2.5, 97.5]); p(f'   {c:18s} as reported {fmt(base[c])}   [{fmt(lo)}, {fmt(hi)}]')

# 3. leave one family out
dm = t[t.ev == 1].family.value_counts(); big = [f for f in dm.index if dm[f] >= 15]
R = {f: metrics(t[t.family != f]) for f in big}
p(f'\n3. LEAVE-ONE-FAMILY-OUT ({len(big)} families with >= 15 damaged samples): range of each metric')
for c in cols:
    v = {f: R[f][c] for f in big}; lo = min(v, key=v.get); hi = max(v, key=v.get)
    p(f'   {c:18s} as reported {fmt(base[c])}   min {fmt(v[lo])} (without {lo})   max {fmt(v[hi])} (without {hi})')

# 4. near-duplicate removal: one sample per (family, size) group
t['grp'] = t.family + '|' + t['size'].astype(str)
g = t.groupby('grp').size()
p(f'\n4. NEAR-DUPLICATES: {len(t)} samples in {len(g)} (family, file size) groups; {int((g > 1).sum())} groups hold {int(g[g > 1].sum())} samples')
D = []
idx = t.groupby('grp').indices
for _ in range(a.draws):
    D.append(metrics(t.iloc[[rng.choice(v) for v in idx.values()]]))
D = pd.DataFrame(D)
p(f'   one random sample per group ({a.draws} draws): median [2.5, 97.5 percentile] of each metric')
for c in cols:
    lo, md, hi = np.nanpercentile(D[c], [2.5, 50, 97.5]); p(f'   {c:18s} as reported {fmt(base[c])}   dedup {fmt(md)}   [{fmt(lo)}, {fmt(hi)}]')

# 5. family-weighted
p('\n5. FAMILY-WEIGHTED (each family counts once; families with >= 5 samples contributing to the metric)')
for name, _, _ in SIG:
    ls = [x for _, x in t.groupby('family') if x[f'lead_{name}'].notna().sum() >= 5]
    med = np.median([x[f'lead_{name}'].median() for x in ls]); fst = np.mean([100 * (x[f'lead_{name}'].dropna() > 0).mean() for x in ls])
    zlw = np.mean([100 * x[f'zl_{name}'].dropna().mean() for x in ls])
    p(f'   {name:4s} families={len(ls):2d}  median of family-median leads {med:5.2f} s   mean signal-first {fst:4.0f}%   mean zero-loss {zlw:4.0f}%')
open(a.out, 'w').write('\n'.join(L) + '\n')
