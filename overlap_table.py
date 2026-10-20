"""Table 'overlap' of the paper: the 22 samples re-detonated on BOTH rebuilt guests.

  .venv/bin/python overlap_table.py --orig overlap/overlap_samples_attributed.csv \
      --r1 results_overlap/timelines.csv --r2 results_overlap_v2/timelines.csv
"""
import argparse
import pandas as pd
from scipy import stats

ap = argparse.ArgumentParser(); ap.add_argument('--orig', required=True); ap.add_argument('--r1', required=True); ap.add_argument('--r2', required=True)
a = ap.parse_args()
o = pd.read_csv(a.orig).query('pick == "main"')[['sha256', 'task', 't_damage']].rename(columns={'t_damage': 'o'})
r1 = pd.read_csv(a.r1)[['sha256', 't_damage']].rename(columns={'t_damage': 'r1'})
r2 = pd.read_csv(a.r2)[['sha256', 't_damage']].rename(columns={'t_damage': 'r2'})
m = o.merge(r2, on='sha256').merge(r1, on='sha256')     # the 22 samples present in both rebuilds
print('samples on both rebuilds:', len(m))
for k in ('r1', 'r2'):
    ag = (m.o.notna() == m[k].notna()).sum(); both = m.dropna(subset=['o', k])
    rho = stats.spearmanr(both.o, both[k]).statistic
    print(f'{k}: agree {ag} / disagree {len(m) - ag}; median onset {both.o.median():.1f} -> {both[k].median():.1f} (pairs reaching damage n={len(both)}); '
          f'rho={rho:.2f}; Wilcoxon p={stats.wilcoxon(both.o, both[k]).pvalue:.4f}')
# excluding the two non-ransomware / decryptor samples (tasks 674, 805)
ex = m[~m.task.astype(str).isin(['674', '805'])]
for k in ('r1', 'r2'):
    both = ex.dropna(subset=['o', k]); print(f'{k} excl 674/805: n={len(both)} rho={stats.spearmanr(both.o, both[k]).statistic:.2f}')
