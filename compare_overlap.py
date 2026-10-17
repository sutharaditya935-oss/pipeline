"""Compare overlap re-runs on the rebuilt VM against the original corpus timings.

  .venv/bin/python compare_overlap.py --orig overlap/overlap_samples.csv \
      --new results_overlap/timelines.csv --out results_overlap
"""
import argparse

import numpy as np
import pandas as pd
from scipy import stats

MILESTONES = ['t_damage', 't_enum', 't_crypto_ctx', 't_crypto_key', 't_note']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--orig', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    orig = pd.read_csv(a.orig)
    orig = orig[orig['pick'] == 'main']
    new = pd.read_csv(a.new)
    m = orig.merge(new, on='sha256', suffixes=('_orig', '_new'))
    lines = [f'paired samples: {len(m)} of {len(orig)} selected']
    lines.append(f"new runs executed: {int(m['executed'].sum())}/{len(m)}")

    for ms in MILESTONES:
        o, n = m[f'{ms}_orig'], m[f'{ms}_new']
        both, only_o, only_n = (o.notna() & n.notna()), (o.notna() & n.isna()), (o.isna() & n.notna())
        lines.append(f'\n{ms}: reached both={both.sum()} orig-only={only_o.sum()} '
                     f'new-only={only_n.sum()} neither={(o.isna() & n.isna()).sum()}')
        if both.sum() >= 5:
            d = n[both] - o[both]
            rho, p_rho = stats.spearmanr(o[both], n[both])
            w = stats.wilcoxon(o[both], n[both])
            ratio = np.log2((n[both] + 0.1) / (o[both] + 0.1))
            lines.append(f'  median orig={o[both].median():.2f}s new={n[both].median():.2f}s '
                         f'median diff={d.median():+.2f}s IQR=[{d.quantile(.25):+.2f}, {d.quantile(.75):+.2f}]')
            lines.append(f'  Spearman rho={rho:.3f} (p={p_rho:.2g})  Wilcoxon p={w.pvalue:.3g}  '
                         f'within 2x: {(ratio.abs() <= 1).mean():.0%}')
        if only_o.sum() + only_n.sum() > 0:
            # McNemar exact on discordant pairs: does reaching the milestone depend on the VM?
            k = min(only_o.sum(), only_n.sum())
            p = stats.binomtest(k, only_o.sum() + only_n.sum(), 0.5).pvalue
            lines.append(f'  McNemar exact p={p:.3g} (discordant {only_o.sum()} vs {only_n.sum()})')

    cols = ['sha256', 'stratum', 'task_orig', 'task_new'] + [f'{ms}_{s}' for ms in MILESTONES for s in ('orig', 'new')]
    m.rename(columns={'task_x': 'task_orig', 'task_y': 'task_new'}, inplace=True)
    if 'task_orig' not in m:
        m['task_orig'], m['task_new'] = orig.set_index('sha256').loc[m['sha256'], 'task'].values, m['task']
    m[cols].to_csv(f'{a.out}/overlap_pairs.csv', index=False)
    txt = '\n'.join(lines)
    open(f'{a.out}/overlap_summary.txt', 'w').write(txt + '\n')
    print(txt)


if __name__ == '__main__':
    main()
