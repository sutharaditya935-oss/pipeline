"""Paired scatter: original vs re-detonated time to first irreversible damage.

Uses the samples re-run on BOTH rebuilt guests (rebuild 1 = results_overlap,
rebuild 2 = results_overlap_v2) so the two series cover the same samples.

  .venv/bin/python fig_overlap.py --orig results/timelines.csv \
      --sel overlap/overlap_samples.csv --r1 results_overlap/timelines.csv \
      --r2 results_overlap_v2/timelines.csv --out results_overlap_v2/fig_overlap
"""
import argparse

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

from analyze import COL_W, SERIES, INK, MUTED, log_seconds_axis, save_fig  # shared paper style


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--orig', required=True)
    ap.add_argument('--sel', required=True)
    ap.add_argument('--r1', required=True)
    ap.add_argument('--r2', required=True)
    ap.add_argument('--out', required=True, help='output path without extension')
    a = ap.parse_args()

    sel = pd.read_csv(a.sel).query('pick == "main"')[['sha256', 'task']].rename(columns={'task': 'otask'})
    orig = pd.read_csv(a.orig)[['task', 't_damage']].rename(columns={'task': 'otask', 't_damage': 'do'})
    m = sel.merge(orig, on='otask')
    for k, f in (('r1', a.r1), ('r2', a.r2)):
        m = m.merge(pd.read_csv(f)[['sha256', 't_damage']].rename(columns={'t_damage': k}), on='sha256')

    fig, ax = plt.subplots(figsize=(COL_W, COL_W * 0.82))
    lims = (0.1, 130)
    ax.plot(lims, lims, color=MUTED, lw=0.8, ls=':', zorder=1)
    ax.text(0.42, 0.56, 'same time', color=MUTED, fontsize=7, rotation=45, ha='center', va='center')
    both = m.dropna(subset=['do', 'r1', 'r2'])
    for _, r in both.iterrows():  # faint link: how each sample moved between rebuilds
        ax.plot([r.do, r.do], [r.r1, r.r2], color='#c8c8c8', lw=0.6, zorder=2)
    for k, lab, mk, col in (('r1', 'Rebuild 1', 'o', SERIES[0]),
                            ('r2', 'Rebuild 2', '^', SERIES[1])):
        p = m.dropna(subset=['do', k])
        rho = stats.spearmanr(p['do'], p[k]).statistic
        ax.scatter(p['do'], p[k], s=26, marker=mk, color=col, edgecolors='white', linewidths=0.6,
                   zorder=3, label=f'{lab}   ρ = {rho:.2f} (n = {len(p)})')
    ax.set_yscale('log'); ax.set_ylim(*lims)
    ax.set_yticks([0.1, 1, 10, 100]); ax.set_yticklabels(['0.1', '1', '10', '100'])
    log_seconds_axis(ax)
    ax.set_xlabel('original corpus: time to first damage (s)')
    ax.set_ylabel('re-detonation: time to first damage (s)')
    ax.legend(loc='upper left', handletextpad=0.3, borderaxespad=0.2)
    ax.set_aspect('equal')
    out_dir, name = a.out.rsplit('/', 1)
    save_fig(fig, out_dir, name)
    print(f'{len(m)} samples; pairs r1={m.dropna(subset=["do","r1"]).shape[0]} '
          f'r2={m.dropna(subset=["do","r2"]).shape[0]} -> {a.out}.pdf')


if __name__ == '__main__':
    main()
