"""Compare the three event-attribution variants on the damaged ransomware samples (table in the paper).

  naive    : every monitored process counts (timeline.py --all-procs)
  default  : launcher shells / Windows helpers outside the sample's tree are ignored (timeline.py default)
  tree     : crypto signals only from the sample's own process tree (timeline.py --tree-only-crypto)

  .venv/bin/python attribution_table.py --labels results/family_labels.csv --out results_sensitivity/attribution_table.txt
"""
import argparse, gzip, json

import numpy as np
import pandas as pd

ap = argparse.ArgumentParser(); ap.add_argument('--labels', required=True); ap.add_argument('--out', required=True)
a = ap.parse_args()
keep = set(pd.read_csv(a.labels, dtype={'task': str}).query('category == "ransomware"').task)
VAR = [('naive', 'results_sensitivity/naive'), ('default', 'results'), ('tree', 'results_sensitivity/tree')]
SIG = [('t_enum', 'enumeration', 1.0), ('t_crypto_ctx', 'crypto context', 0.5), ('t_crypto_key', 'key generation', 0.5)]
L = []
for name, d in VAR:
    t = pd.read_csv(f'{d}/timelines.csv', dtype={'task': str}); t = t[t.task.isin(keep) & t.executed & ~t.is_smoketest]
    dmg = {}
    for line in gzip.open(f'{d}/damage.jsonl.gz', 'rt'):
        x = json.loads(line); dmg[str(x['task'])] = [e[0] for e in x['events']]
    dm = t[t.t_damage.notna()]
    L.append(f'{name:8s} damaged={len(dm)} median={dm.t_damage.median():.2f}s')
    for col, nm, lat in SIG:
        b = dm.dropna(subset=[col]); lead = b.t_damage - b[col]
        zl = np.mean([sum(1 for e in dmg.get(r.task, []) if e < getattr(r, col) + lat) == 0 for r in b.itertuples()]) if len(b) else float('nan')
        L.append(f'   {nm:15s} n={len(b):3d} ({100 * len(b) / len(dm):4.1f}% of damaged)  signal-first={100 * (lead > 0).mean():3.0f}%  median lead={lead.median():5.2f}s  zero-loss@{lat:g}s={100 * zl:3.0f}%')
txt = '\n'.join(L); open(a.out, 'w').write(txt + '\n'); print(txt)

# --- extras quoted in the text -------------------------------------------------------------------------------
nv = pd.read_csv('results_naive/timelines.csv', dtype={'task': str}).set_index('task')
df = pd.read_csv('results/timelines.csv', dtype={'task': str}).set_index('task')
ids = [k for k in nv.index if k in keep and nv.loc[k, 'executed'] and not nv.loc[k, 'is_smoketest'] and pd.notna(nv.loc[k, 't_damage'])]
E = ['', 'first signal differs between the naive and the default analysis (damaged-in-naive samples, n=%d):' % len(ids)]
for col in ('t_enum', 't_crypto_ctx', 't_crypto_key'):
    a_, b_ = nv.loc[ids, col], df.loc[ids, col]
    diff = ((a_ != b_) & ~(a_.isna() & b_.isna())).sum()
    E.append(f'   {col}: {int(diff)} of {len(ids)} ({100 * diff / len(ids):.0f}%)')
allt = df[df.executed & ~df.is_smoketest & df.t_damage.notna()]
E.append(f'median first damage over ALL executed analyses with damage (incl. decryptors/other malware): n={len(allt)} median={allt.t_damage.median():.2f}s')
dd = {}
for line in gzip.open('results/damage.jsonl.gz', 'rt'):
    x = json.loads(line); dd[str(x['task'])] = [e[0] for e in x['events']]
t = df[df.index.isin(keep) & df.executed & df.t_damage.notna() & df.t_crypto_ctx.notna()]
lost = [sum(1 for e in dd.get(k, []) if e < r.t_crypto_ctx + 0.5) for k, r in t.iterrows()]
E.append(f'crypto-context monitor (0.5 s): samples losing >= 100 damage events: {sum(1 for x in lost if x >= 100)} of {len(lost)}')
txt2 = '\n'.join(E); open(a.out, 'a').write(txt2 + '\n'); print(txt2)
