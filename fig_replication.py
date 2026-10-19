"""Two-host replication figure: (a) time to first damage on host A vs host B, (b) paired gap per milestone.

  .venv/bin/python fig_replication.py --paired results_repl_compare/paired.csv \
      --a-name "Core i5-11400H" --b-name "Ryzen 5 5500U" --out results_repl_compare/fig_replication
"""
import argparse

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

from analyze import COL_W, SERIES, INK, MUTED, log_seconds_axis, save_fig  # shared paper style

MILES = [('t_enum', 'enumeration'), ('t_crypto_ctx', 'crypto context'), ('t_crypto_key', 'key generation'),
         ('t_damage', 'first damage'), ('t_note', 'ransom note')]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--paired', required=True)
    ap.add_argument('--a-name', default='A'); ap.add_argument('--b-name', default='B')
    ap.add_argument('--out', required=True, help='output path without extension')
    a = ap.parse_args()
    m = pd.read_csv(a.paired)

    fig, (ax, bx) = plt.subplots(2, 1, figsize=(COL_W, COL_W * 1.45), gridspec_kw={'height_ratios': [1.15, 1], 'hspace': 0.5})
    # (a) first damage
    lims = (0.1, 300); edge = 200
    ax.plot(lims, lims, color=MUTED, lw=0.8, ls=':', zorder=1)
    both = m.dropna(subset=['t_damage_a', 't_damage_b'])
    rho = stats.spearmanr(both.t_damage_a, both.t_damage_b).statistic
    ax.scatter(both.t_damage_a, both.t_damage_b, s=16, color=SERIES[0], edgecolors='white', linewidths=0.4, zorder=3,
               label=f'damage on both (n = {len(both)}, ρ = {rho:.2f})')
    oa = m[m.t_damage_a.notna() & m.t_damage_b.isna()]; ob = m[m.t_damage_a.isna() & m.t_damage_b.notna()]
    ax.scatter(oa.t_damage_a, np.full(len(oa), edge), s=16, marker='v', facecolors='none', edgecolors=SERIES[1], linewidths=0.8,
               zorder=3, label=f'only on {a.a_name.split()[0]} (n = {len(oa)})')
    ax.scatter(np.full(len(ob), edge), ob.t_damage_b, s=16, marker='<', facecolors='none', edgecolors=SERIES[2], linewidths=0.8,
               zorder=3, label=f'only on {a.b_name.split()[0]} (n = {len(ob)})')
    ax.set_xscale('log'); ax.set_yscale('log'); ax.set_xlim(*lims); ax.set_ylim(*lims)
    ticks = [0.1, 1, 10, 100]; ax.set_xticks(ticks); ax.set_yticks(ticks)
    ax.set_xticklabels(['0.1', '1', '10', '100']); ax.set_yticklabels(['0.1', '1', '10', '100'])
    ax.axhline(edge * 0.72, color='#d9d9d9', lw=0.6, zorder=0); ax.axvline(edge * 0.72, color='#d9d9d9', lw=0.6, zorder=0)
    ax.set_xlabel(f'{a.a_name}: time to first damage (s)'); ax.set_ylabel(f'{a.b_name} (s)')
    ax.legend(loc='lower right', bbox_to_anchor=(1.0, 0.0), fontsize=5.6, handletextpad=0.2, borderaxespad=0.2, labelspacing=0.3)
    ax.set_aspect('equal'); ax.text(-0.2, 1.03, '(a)', transform=ax.transAxes, fontsize=8, fontweight='bold')

    # (b) paired gap per milestone, B - A (median and IQR), with agreement
    for i, (k, lab) in enumerate(MILES):
        x, y = m[k + '_a'], m[k + '_b']; ok = x.notna() & y.notna(); d = (y - x)[ok]
        q1, med, q3 = d.quantile([.25, .5, .75])
        bx.plot([q1, q3], [i, i], color=SERIES[0], lw=2.2, solid_capstyle='round', zorder=2)
        bx.scatter([med], [i], s=22, color=INK, zorder=3)
        r = stats.spearmanr(x[ok], y[ok]).statistic
        bx.text(5.9, i, f'ρ = {r:.2f}', fontsize=6.5, va='center', ha='right', color=MUTED)
    bx.axvline(0, color=MUTED, lw=0.8, ls=':', zorder=1)
    bx.set_yticks(range(len(MILES))); bx.set_yticklabels([l for _, l in MILES]); bx.invert_yaxis()
    bx.set_xlim(-1, 6); bx.set_xticks(range(-1, 7)); bx.set_xlabel(f'{a.b_name.split()[0]} minus {a.a_name.split()[0]} (s): median, IQR')
    bx.text(-0.2, 1.06, '(b)', transform=bx.transAxes, fontsize=8, fontweight='bold')
    for s in ('top', 'right'): bx.spines[s].set_visible(False)

    fig.subplots_adjust(left=0.34, right=0.97, top=0.97, bottom=0.1)
    out_dir, name = a.out.rsplit('/', 1)
    save_fig(fig, out_dir, name)
    print(f'-> {a.out}.pdf')


if __name__ == '__main__':
    main()
