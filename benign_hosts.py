"""Benign baseline: per-program signals on both machines, host agreement, and the program lists for the paper.

Uses the attributable programs (the three PowerShell-cmdlet programs, whose signals cannot be separated from
PowerShell's own start-up, are dropped via index_attributable.csv).

  .venv/bin/python benign_hosts.py --a results_benign_intel --b results_benign_ideapad \
      --index-a ~/benign_reports_intel/index_attributable.csv --index-b ~/benign_reports_ideapad/index_attributable.csv \
      --out results_benign_intel/two_hosts.txt
"""
import argparse

import pandas as pd
from scipy import stats

COLS = ['t_enum', 't_crypto_ctx', 't_crypto_key', 't_damage']
ap = argparse.ArgumentParser()
for k in ('--a', '--b', '--index-a', '--index-b', '--out'):
    ap.add_argument(k, required=True)
a = ap.parse_args()


def load(res, idx):
    t = pd.read_csv(f'{res}/timelines.csv', dtype={'task': str})[['task', 'executed'] + COLS]
    return t.merge(pd.read_csv(idx, dtype={'task': str}), on='task')


A, B = load(a.a, a.index_a), load(a.b, a.index_b)
m = A.merge(B[['id', 'executed'] + COLS], on='id', suffixes=(' (i5)', ' (Ryzen)')).rename(columns={'name': 'program'}).drop(columns=['task'])
m.to_csv(a.out.replace('.txt', '.csv'), index=False)
e = m[m['executed (i5)'] & m['executed (Ryzen)']]
L = [f'attributable programs {len(m)}; executed (monitored process) on both {len(e)}; not observed on either: ' +
     ', '.join(sorted(m[~(m["executed (i5)"] & m["executed (Ryzen)"])].program))]
for c in COLS:
    x, y = e[f'{c} (i5)'].notna(), e[f'{c} (Ryzen)'].notna(); both = x & y
    s = f'{c:13s} fires i5={int(x.sum()):2d} Ryzen={int(y.sum()):2d} agree {int((x == y).sum())}/{len(e)}'
    if both.sum() >= 5:
        r = stats.spearmanr(e.loc[both, f'{c} (i5)'], e.loc[both, f'{c} (Ryzen)']).statistic
        s += f' | both={int(both.sum())} rho={r:.2f} median Ryzen-i5={(e.loc[both, f"{c} (Ryzen)"] - e.loc[both, f"{c} (i5)"]).median():+.2f}s'
    L.append(s)
fl = e[e['t_damage (i5)'].notna() | e['t_damage (Ryzen)'].notna()]
L.append('damage-flagged programs (t_damage i5 / Ryzen):')
L += [f'  {r.program:14s} {r.category:14s} {r["t_damage (i5)"]:.2f} / {r["t_damage (Ryzen)"]:.2f}' for _, r in fl.iterrows()]
txt = '\n'.join(L); open(a.out, 'w').write(txt + '\n'); print(txt)
