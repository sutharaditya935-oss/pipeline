"""Per-family onset statistics for the paper (Table "family" and its text).

Over ransomware samples that reached first irreversible damage: per-family n / median / p10 for families
with >= 5 damaged samples (the 'unknown' label counts as a group), the family-weighted median (median of
the per-family medians), the Kruskal-Wallis test across those groups, eta^2 of log onset (ANOVA sum of
squares between / total), and the largest-family and Phobos+Dharma shares.

  .venv/bin/python family_stats.py --results results_ransomware --labels results/family_labels.csv \
      --out results_ransomware/family_stats.txt
"""
import argparse

import numpy as np
import pandas as pd
from scipy import stats


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--results', required=True)
    ap.add_argument('--labels', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    t = pd.read_csv(f'{a.results}/timelines.csv', dtype={'task': str})
    lab = pd.read_csv(a.labels, dtype={'task': str})[['task', 'family']]
    d = t[t.executed & t.t_damage.notna()].merge(lab, on='task')
    g = d.groupby('family').t_damage.agg(n='size', median='median', p10=lambda x: x.quantile(.1))
    g = g[g.n >= 5].sort_values('n', ascending=False)
    L = [f'damaged ransomware samples: {len(d)}; median {d.t_damage.median():.2f} s, p10 {d.t_damage.quantile(.1):.2f} s',
         'family            n   median    p10']
    L += [f'{f:14s} {int(r.n):4d} {r["median"]:8.2f} {r.p10:6.2f}' for f, r in g.iterrows()]
    L.append(f'family-weighted median (median of {len(g)} per-family medians): {g["median"].median():.2f} s')
    groups = [d[d.family == f].t_damage.values for f in g.index]
    H, p = stats.kruskal(*groups)
    y = np.log(np.concatenate(groups)); gm = y.mean()
    ss_b = sum(len(np.log(x)) * (np.log(x).mean() - gm) ** 2 for x in groups); ss_t = ((y - gm) ** 2).sum()
    L.append(f'Kruskal-Wallis over {len(g)} groups: H={H:.1f}, p={p:.1e}; eta^2 of log onset = {ss_b / ss_t:.2f}')
    top = g.n.idxmax()
    L.append(f'largest family among damaged: {top} {int(g.n.max())}/{len(d)} = {100 * g.n.max() / len(d):.0f}%')
    pd_n = int(g.loc[[f for f in ('Phobos', 'Dharma') if f in g.index]].n.sum())
    L.append(f'Phobos + Dharma: {pd_n}/{len(d)} = {100 * pd_n / len(d):.0f}%')
    txt = '\n'.join(L); open(a.out, 'w').write(txt + '\n'); print(txt)


if __name__ == '__main__':
    main()
