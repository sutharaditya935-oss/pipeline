"""Why ransomware samples never reach irreversible damage, and whether that biases timing.

Splits non-damaging ransomware samples into: never started (by launch error),
known setup-blocked families (WannaCry DLL components, BlackCat without its
access token), other DLL-package samples, and other executed samples by run
length. Then recomputes the headline timing with the setup-blocked groups removed.

  .venv/bin/python nodamage_breakdown.py --results results --labels results/family_labels.csv \
      --out results_ransomware/nodamage_breakdown.txt
"""
import argparse

import pandas as pd
from lifelines import KaplanMeierFitter


def km_median(df):
    e = df[df.executed]
    d = e.t_damage.where(e.t_damage.notna(), e.obs_end)
    return KaplanMeierFitter().fit(d, event_observed=e.t_damage.notna()).median_survival_time_


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', required=True)
    ap.add_argument('--labels', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    t = pd.read_csv(f'{a.results}/timelines.csv', dtype={'task': str})
    lab = pd.read_csv(a.labels, dtype={'task': str})
    ls = pd.read_csv(f'{a.results}/launch_scan.csv', dtype={'task': str})
    m = t.merge(lab[['task', 'family', 'category']], on='task').merge(ls[['task', 'launch_error']], on='task', how='left')
    r = m[m.category == 'ransomware']
    blocked = ((r.family == 'WannaCry') & (r.package == 'dll')) | (r.family == 'BlackCat')
    nd = r[r.t_damage.isna()]
    ex = nd[nd.executed]
    lines = []
    p = lambda s='': (print(s), lines.append(s))

    p(f'Ransomware samples: {len(r)}; reached damage: {r.t_damage.notna().sum()}; did not: {len(nd)}')
    ns = nd[~nd.executed]
    p(f'\nA. never started: {len(ns)}')
    for k, v in ns.launch_error.fillna('(no error logged)').str[:45].value_counts().items():
        p(f'     {v:4d}  {k}')
    wd = ex[(ex.family == 'WannaCry') & (ex.package == 'dll')]
    bc = ex[ex.family == 'BlackCat']
    p(f'B. executed, setup-blocked families: WannaCry DLL components {len(wd)}, BlackCat {len(bc)}')
    rest = ex.drop(wd.index).drop(bc.index)
    p(f'C. other DLL-package samples: {(rest.package == "dll").sum()}')
    rest = rest[rest.package != 'dll']
    bins = pd.cut(rest.obs_end, [-1, 5, 30, 90, 1e9], labels=['<5 s', '5-30 s', '30-90 s', '>90 s'])
    p(f'D. other executed samples by run length: {bins.value_counts().sort_index().to_dict()}')
    lg = rest[rest.obs_end > 90]
    p(f'   of the >90 s runs: enumerated victim files {lg.t_enum.notna().sum()}, any victim write '
      f'{lg.t_victim_write.notna().sum()}, crypto context {lg.t_crypto_ctx.notna().sum()}, '
      f'ransom note {lg.t_note.notna().sum()}')

    p('\nHeadline timing with setup-blocked samples removed:')
    for name, df in (('all ransomware', r),
                     ('excl. WannaCry DLL + BlackCat', r[~blocked]),
                     ('also excl. all DLL packages', r[~blocked & (r.package != 'dll')])):
        e = df[df.executed]
        p(f'  {name:30s} n={len(df):4d} executed={len(e):4d} damaged={df.t_damage.notna().sum():3d} '
          f'({100 * df.t_damage.notna().sum() / len(e):.0f}% of executed)  '
          f'median={df.t_damage.median():.2f}s  KM median={km_median(df):.2f}s')
    open(a.out, 'w').write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
