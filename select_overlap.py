#!/usr/bin/env python3
"""Pick the overlap re-run set: original samples to re-detonate on a rebuilt VM.

Comparing their new timings with the original runs shows whether results from
the rebuilt VM can be pooled with the original corpus.

Selection (fixed seed, so it is reproducible):
  - 42 damaged samples, 7 from each sextile of time-to-first-damage
  - 8 executed samples that never reached damage
  - reserves: 2 per sextile + 3 non-damaged, for hashes that can't be downloaded

Usage:
  .venv/bin/python select_overlap.py --results results --out overlap
"""
import argparse, os
import numpy as np
import pandas as pd

COLS = ['pick', 'stratum', 'task', 'sha256', 'package',
        't_damage', 't_enum', 't_crypto_ctx', 't_crypto_key', 't_note', 'obs_end']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', default='results')
    ap.add_argument('--out', default='overlap')
    ap.add_argument('--seed', type=int, default=2026)
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)
    df = pd.read_csv(os.path.join(a.results, 'timelines.csv'))
    df = df[~df.is_smoketest & df.executed]

    rows = []
    dmg = df[df.t_damage.notna()].copy()
    dmg['stratum'] = pd.qcut(dmg.t_damage, 6, labels=[f'damage_q{i}' for i in range(1, 7)])
    for s, g in dmg.groupby('stratum', observed=True):
        idx = rng.permutation(len(g))
        rows += [dict(g.iloc[i], pick='main') for i in idx[:7]]
        rows += [dict(g.iloc[i], pick='reserve') for i in idx[7:9]]

    nod = df[df.t_damage.isna()].copy()
    nod['stratum'] = 'no_damage'
    idx = rng.permutation(len(nod))
    rows += [dict(nod.iloc[i], pick='main') for i in idx[:8]]
    rows += [dict(nod.iloc[i], pick='reserve') for i in idx[8:11]]

    out = pd.DataFrame(rows)[COLS]
    os.makedirs(a.out, exist_ok=True)
    out.to_csv(os.path.join(a.out, 'overlap_samples.csv'), index=False)
    for pick in ('main', 'reserve'):
        with open(os.path.join(a.out, f'sha256_{pick}.txt'), 'w') as f:
            f.write('\n'.join(out[out.pick == pick].sha256) + '\n')

    main_ = out[out.pick == 'main']
    print(f'main: {len(main_)}  reserve: {(out.pick == "reserve").sum()}')
    print(main_.groupby('stratum').agg(n=('task', 'size'),
                                       t_damage_min=('t_damage', 'min'),
                                       t_damage_max=('t_damage', 'max'),
                                       dll=('package', lambda s: (s == 'dll').sum())).to_string())
    print('packages (main):', main_.package.value_counts().to_dict())


if __name__ == '__main__':
    main()
