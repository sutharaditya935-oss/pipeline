#!/usr/bin/env python3
"""Stage 3: statistics, survival analysis, detector replay, and figures.

Reads results/timelines.csv and results/damage.jsonl.gz (from timeline.py) and
produces:
  results/summary.txt         printed tables (also echoed to stdout)
  results/fig_milestones.png  CDF of key milestones
  results/fig_survival.png    Kaplan-Meier onset curve (censoring non-detonators)
  results/fig_leadtime.png    lead time from first crypto signal to first damage
  results/fig_detector.png    files damaged before a behavioral detector reacts
  results/fig_writeclass.png  sensitivity of onset to write classification

Optional: --labels family.csv  (columns: task,family) to add per-family medians.
"""
import argparse, csv, gzip, json, os, sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from lifelines import KaplanMeierFitter

plt.rcParams.update({'figure.dpi': 130, 'font.size': 10, 'axes.grid': True,
                     'grid.alpha': 0.3, 'axes.axisbelow': True})

def boot_ci(x, stat=np.median, n=5000, seed=0):
    x = np.asarray(x, float); x = x[~np.isnan(x)]
    if len(x) == 0:
        return (np.nan, np.nan, np.nan)
    rng = np.random.default_rng(seed)
    bs = [stat(rng.choice(x, len(x), replace=True)) for _ in range(n)]
    return (stat(x), np.percentile(bs, 2.5), np.percentile(bs, 97.5))

def fmt(x):
    return '   n/a' if (x is None or (isinstance(x, float) and np.isnan(x))) else f'{x:6.2f}'

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', default='results')
    ap.add_argument('--labels', help='optional CSV: task,family')
    a = ap.parse_args()
    R = a.results
    df = pd.read_csv(os.path.join(R, 'timelines.csv'))
    df = df[~df.is_smoketest].copy()
    out = open(os.path.join(R, 'summary.txt'), 'w')
    def p(*args):
        line = ' '.join(str(x) for x in args)
        print(line); out.write(line + '\n')

    n_all = len(df)
    n_exec = int(df.executed.sum())
    p(f'Corpus: {n_all} samples ({n_exec} executed, {n_all - n_exec} no monitored process)')
    p(f'Signature stage ran in any report: {bool(df.signature_stage_ran.any())}')
    p('')

    # ---- 1. Milestone summary table --------------------------------------------
    miles = [('enum', 'file enumeration begins'),
             ('crypto_ctx', 'first crypto context'),
             ('crypto_key', 'first key gen/import'),
             ('crypto_enc', 'first CryptEncrypt'),
             ('recovery_inhibit', 'shadow/backup deletion cmd'),
             ('note', 'first ransom note'),
             ('paper_first_write', 'paper metric: first victim write'),
             ('victim_write', 'first victim write (incl AppData)'),
             ('damage', 'first irreversible damage'),
             ('victim_overwrite_hi', '  - high-entropy overwrite'),
             ('rename_enc', '  - rename to new extension'),
             ('victim_delete', '  - victim-file delete')]
    p('MILESTONE TIMING (seconds after first process start)')
    p(f'{"milestone":40s} {"n":>5s} {"median":>8s} {"95% CI":>16s} {"p10":>7s} {"p90":>7s}')
    for key, lab in miles:
        s = df['t_' + key].dropna().values
        m, lo, hi = boot_ci(s)
        p10 = np.percentile(s, 10) if len(s) else np.nan
        p90 = np.percentile(s, 90) if len(s) else np.nan
        p(f'{lab:40s} {len(s):5d} {fmt(m)} [{fmt(lo)},{fmt(hi)}] {fmt(p10)} {fmt(p90)}')
    p('')

    # ---- 2. Write-classification sensitivity (reproduces paper Table IV idea) ---
    p('WRITE-CLASSIFICATION SENSITIVITY (median onset, s)')
    p(f'  first victim write, paper-style exclusion : n={df.t_paper_first_write.notna().sum():4d}  '
      f'median={df.t_paper_first_write.median():.2f}')
    p(f'  first irreversible damage (our definition): n={df.t_damage.notna().sum():4d}  '
      f'median={df.t_damage.median():.2f}')
    p('')

    # ---- 3. Lead time: crypto signal -> damage ---------------------------------
    d2 = df.dropna(subset=['t_damage']).copy()
    for sig in ['crypto_ctx', 'crypto_key', 'enum', 'recovery_inhibit']:
        both = d2.dropna(subset=['t_' + sig])
        lead = both['t_damage'] - both['t_' + sig]
        frac_before = (lead > 0).mean() if len(both) else np.nan
        p(f'LEAD TIME  {sig:16s} -> damage : n={len(both):4d}  '
          f'signal-first={frac_before*100:4.0f}%  median lead={lead.median():6.2f}s')
    p('')

    # ---- 4. Survival analysis (Kaplan-Meier), censoring non-detonators ----------
    # Executed samples: event = damage observed; duration = t_damage, else censored at obs_end.
    ex = df[df.executed].copy()
    dur = ex['t_damage'].copy()
    observed = dur.notna()
    dur = dur.where(observed, ex['obs_end'])
    valid = dur.notna() & (dur >= 0)
    kmf = KaplanMeierFitter()
    kmf.fit(dur[valid], event_observed=observed[valid], label='damage onset')
    try:
        med_km = kmf.median_survival_time_
    except Exception:
        med_km = np.nan
    p(f'KAPLAN-MEIER onset (executed n={valid.sum()}, events={int(observed[valid].sum())}, '
      f'censored={int((~observed[valid]).sum())})')
    p(f'  KM median time-to-damage: {med_km:.2f}s  (naive median over observed only: '
      f'{ex["t_damage"].median():.2f}s)')
    p('')

    # ---- 5. Detector replay: files damaged before reaction ---------------------
    dmg = {}
    with gzip.open(os.path.join(R, 'damage.jsonl.gz'), 'rt') as f:
        for line in f:
            r = json.loads(line)
            dmg[str(r['task'])] = r
    tmap = {str(t): row for t, row in zip(df.task, df.to_dict('records'))}

    def files_lost(task, trigger_time, latency=0.0):
        r = dmg.get(str(task))
        if not r:
            return None
        return sum(1 for (t, path, kind) in r['events'] if t < trigger_time + latency)

    detectors = {
        'crypto-context monitor (react 0.5s)': ('t_crypto_ctx', 0.5),
        'crypto-key monitor (react 0.5s)':     ('t_crypto_key', 0.5),
        'enumeration monitor (react 1.0s)':    ('t_enum', 1.0),
    }
    p('DETECTOR REPLAY: damage-events written before the detector reacts')
    p('  (only samples that both triggered the signal and produced damage)')
    for name, (sigcol, lat) in detectors.items():
        losses = []
        for _, row in df.iterrows():
            if pd.isna(row[sigcol]) or pd.isna(row['t_damage']):
                continue
            fl = files_lost(row['task'], row[sigcol], lat)
            if fl is not None:
                losses.append(fl)
        if losses:
            losses = np.array(losses)
            p(f'  {name:38s} n={len(losses):4d}  '
              f'median lost={np.median(losses):4.0f}  mean={losses.mean():5.1f}  '
              f'zero-loss={100*(losses==0).mean():3.0f}%')
    # CryptoDrop-style: trigger after k high-entropy/rename events; report pre-trigger loss.
    p('')
    p('  CryptoDrop-style (trigger after k damage events); files lost = k-1 + late detections')
    for k in (1, 3, 10):
        pre = []
        for task, r in dmg.items():
            ev = r['events']
            if len(ev) >= 1:
                pre.append(min(k, len(ev)) - 0 if len(ev) < k else k)  # files damaged up to trigger
        if pre:
            p(f'    k={k:2d}: samples with damage={len(pre):4d}  '
              f'median files damaged by trigger={int(np.median(pre))}')
    p('')

    # ---- 6. Per-family (optional) ----------------------------------------------
    if a.labels and os.path.exists(a.labels):
        lab = pd.read_csv(a.labels, dtype={'task': str})
        df['task'] = df.task.astype(str)
        m = df.merge(lab, on='task', how='left')
        p('PER-FAMILY first-damage median (n>=5)')
        g = m.dropna(subset=['t_damage']).groupby('family')['t_damage']
        for fam, s in sorted(g, key=lambda kv: -len(kv[1])):
            if len(s) >= 5:
                p(f'  {fam:20s} n={len(s):4d}  median={s.median():6.2f}  p10={s.quantile(.1):5.2f}')
        p('')
    else:
        p('PER-FAMILY: provide --labels task,family CSV to enable (classifier output needed).')
        p('')

    out.close()

    # ---------------------------------------------------------------- FIGURES ----
    def cdf(ax, s, label):
        s = np.sort(np.asarray(s, float)); s = s[~np.isnan(s)]
        if len(s) == 0:
            return
        y = np.arange(1, len(s) + 1) / len(s)
        ax.step(s, y, where='post', label=f'{label} (n={len(s)})')

    # Fig 1: milestone CDFs
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for key, lab in [('crypto_ctx', 'first crypto context'),
                     ('enum', 'file enumeration'),
                     ('note', 'first ransom note'),
                     ('damage', 'first irreversible damage')]:
        cdf(ax, df['t_' + key], lab)
    ax.set_xscale('log'); ax.set_xlim(0.1, 130)
    ax.set_xlabel('seconds after execution start (log)'); ax.set_ylabel('cumulative fraction')
    ax.set_title('Timing of ransomware milestones'); ax.legend(loc='lower right', fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(R, 'fig_milestones.png')); plt.close(fig)

    # Fig 2: KM survival (1 - survival = fraction damaged)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    kmf.plot_cumulative_density(ax=ax, ci_show=True)
    ax.set_xlabel('seconds after execution start'); ax.set_ylabel('fraction of samples damaged')
    ax.set_title('Kaplan-Meier: time to first irreversible damage\n(non-detonators censored at observation end)')
    ax.set_xlim(0, 120); ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(R, 'fig_survival.png')); plt.close(fig)

    # Fig 3: lead-time histogram (crypto_ctx -> damage)
    both = df.dropna(subset=['t_damage', 't_crypto_ctx'])
    lead = (both['t_damage'] - both['t_crypto_ctx']).values
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.hist(np.clip(lead, -10, 80), bins=40, color='#4477aa', edgecolor='white')
    ax.axvline(0, color='crimson', lw=1.5, label='damage = signal')
    ax.axvline(np.median(lead), color='k', ls='--', lw=1, label=f'median {np.median(lead):.1f}s')
    ax.set_xlabel('lead time: first crypto context -> first damage (s)')
    ax.set_ylabel('samples'); ax.set_title(f'Defensive lead time (n={len(lead)}, '
                                           f'{100*(lead>0).mean():.0f}% signal-first)')
    ax.legend(fontsize=8); fig.tight_layout()
    fig.savefig(os.path.join(R, 'fig_leadtime.png')); plt.close(fig)

    # Fig 4: detector replay - files lost before crypto-context reaction
    losses = []
    for _, row in df.iterrows():
        if pd.isna(row['t_crypto_ctx']) or pd.isna(row['t_damage']):
            continue
        fl = files_lost(row['task'], row['t_crypto_ctx'], 0.5)
        if fl is not None:
            losses.append(fl)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    if losses:
        losses = np.array(losses)
        ax.hist(np.clip(losses, 0, 50), bins=range(0, 52), color='#aa5544', edgecolor='white')
        ax.set_xlabel('damage events before a crypto-context detector reacts')
        ax.set_ylabel('samples')
        ax.set_title(f'Files damaged before detection (n={len(losses)}, '
                     f'{100*(losses==0).mean():.0f}% zero-loss)')
    fig.tight_layout(); fig.savefig(os.path.join(R, 'fig_detector.png')); plt.close(fig)

    # Fig 5: write-classification sensitivity
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for key, lab in [('victim_write', 'any victim write (incl AppData)'),
                     ('paper_first_write', 'paper-style exclusion'),
                     ('damage', 'irreversible damage only')]:
        cdf(ax, df['t_' + key], lab)
    ax.set_xscale('log'); ax.set_xlim(0.1, 130)
    ax.set_xlabel('seconds after execution start (log)'); ax.set_ylabel('cumulative fraction')
    ax.set_title('Onset depends on how "damage" is defined')
    ax.legend(loc='lower right', fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(R, 'fig_writeclass.png')); plt.close(fig)

    print('\nFigures written to', R)

if __name__ == '__main__':
    main()
