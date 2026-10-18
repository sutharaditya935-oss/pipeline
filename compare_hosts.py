"""Compare the same samples run on two hosts (replication on different hardware).

Pairs analyses by SHA-256 from two submission logs, then reports per milestone:
reached-in-both / only-on-A / only-on-B / neither, median onset on each host, the
median paired difference with IQR, Spearman rho, Wilcoxon p, and the share of pairs
within a factor of 2. Also writes the paired table (CSV) for inspection.

  .venv/bin/python compare_hosts.py \
      --a results_pilot_intel/timelines.csv --a-subs ../samples/overlap/submissions_pilot_intel.csv \
      --b results_pilot_ideapad/timelines.csv --b-subs ../benign/..../submissions.csv \
      --a-name "i5-11400H" --b-name "Ryzen 5 5500U" --out results_pilot_compare
Submission logs may be either format: (sha256, new_task_id) from submit_samples.py,
or (sha256, new_task) from ideapad_pilot.sh.
"""
import argparse, csv, os

import numpy as np
import pandas as pd
from scipy import stats

MILESTONES = ['t_damage', 't_enum', 't_crypto_ctx', 't_crypto_key', 't_note']


def subs(path):
    d = pd.read_csv(path, dtype=str)
    col = 'new_task_id' if 'new_task_id' in d else 'new_task'
    d = d[d[col].notna() & (d[col] != '')]
    return dict(zip(d['sha256'], d[col]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--a', required=True); ap.add_argument('--a-subs', required=True)
    ap.add_argument('--b', required=True); ap.add_argument('--b-subs', required=True)
    ap.add_argument('--a-name', default='A'); ap.add_argument('--b-name', default='B')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    ta = pd.read_csv(a.a, dtype={'task': str}).set_index('task')
    tb = pd.read_csv(a.b, dtype={'task': str}).set_index('task')
    sa, sb = subs(a.a_subs), subs(a.b_subs)
    rows = []
    for sha in sorted(set(sa) & set(sb)):
        if sa[sha] in ta.index and sb[sha] in tb.index:
            ra, rb = ta.loc[sa[sha]], tb.loc[sb[sha]]
            r = {'sha256': sha, 'task_a': sa[sha], 'task_b': sb[sha], 'executed_a': bool(ra.executed),
                 'executed_b': bool(rb.executed), 'obs_end_a': ra.obs_end, 'obs_end_b': rb.obs_end,
                 'n_calls_a': ra.n_calls, 'n_calls_b': rb.n_calls}
            for m in MILESTONES:
                r[m + '_a'], r[m + '_b'] = ra[m], rb[m]
            rows.append(r)
    m = pd.DataFrame(rows)
    m.to_csv(os.path.join(a.out, 'paired.csv'), index=False)

    A, B = a.a_name, a.b_name
    L = [f'pairs: {len(m)} (a = {A}, b = {B}); executed on both: {int((m.executed_a & m.executed_b).sum())}']
    L.append(f'median run length (obs_end): {A} {m.obs_end_a.median():.1f} s, {B} {m.obs_end_b.median():.1f} s; '
             f'median API calls: {A} {m.n_calls_a.median():.0f}, {B} {m.n_calls_b.median():.0f}')
    for ms in MILESTONES:
        x, y = m[ms + '_a'], m[ms + '_b']
        both = x.notna() & y.notna()
        L.append(f'\n{ms}: both={both.sum()} only-{A}={(x.notna() & y.isna()).sum()} '
                 f'only-{B}={(x.isna() & y.notna()).sum()} neither={(x.isna() & y.isna()).sum()}')
        if both.sum() >= 5:
            d = y[both] - x[both]
            rho = stats.spearmanr(x[both], y[both])
            try:
                w = stats.wilcoxon(x[both], y[both]).pvalue
            except ValueError:
                w = float('nan')
            ratio = np.log2((y[both] + 0.1) / (x[both] + 0.1))
            L.append(f'  median {A}={x[both].median():.2f}s {B}={y[both].median():.2f}s | '
                     f'paired diff (B-A) median={d.median():+.2f}s IQR=[{d.quantile(.25):+.2f}, {d.quantile(.75):+.2f}]')
            L.append(f'  Spearman rho={rho.statistic:.3f} (p={rho.pvalue:.2g})  Wilcoxon p={w:.3g}  '
                     f'within 2x: {(ratio.abs() <= 1).mean():.0%}')
    txt = '\n'.join(L)
    open(os.path.join(a.out, 'summary.txt'), 'w').write(txt + '\n')
    print(txt)


if __name__ == '__main__':
    main()
