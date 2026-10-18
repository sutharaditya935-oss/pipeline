"""Sensitivity of the headline results to the damage thresholds and detector latency.

1. Rebuilds timelines (timeline.py) with alternative high-entropy thresholds and
   minimum captured lengths, then recomputes over the ransomware samples:
   damaged n, median onset, Kaplan-Meier median, enumeration lead, and the
   zero-loss rate of the crypto-context detector.
2. On the default timelines, sweeps the detector reaction latency.

  .venv/bin/python sensitivity.py --traces traces --labels results/family_labels.csv \
      --base results --out results_sensitivity
"""
import argparse, gzip, json, os, subprocess, sys

import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter

VARIANTS = [  # (name, entropy threshold, min captured bytes)
    ('H6.5', 6.5, 64), ('H7.0 (default)', 7.0, 64), ('H7.5', 7.5, 64),
    ('len32', 7.0, 32), ('len128', 7.0, 128),
]
LATENCIES = [0.1, 0.25, 0.5, 1.0, 2.0]


def load(res_dir, keep):
    df = pd.read_csv(os.path.join(res_dir, 'timelines.csv'), dtype={'task': str})
    df = df[df.task.isin(keep)]
    dmg = {}
    with gzip.open(os.path.join(res_dir, 'damage.jsonl.gz'), 'rt') as f:
        for line in f:
            d = json.loads(line)
            dmg[str(d['task'])] = d['events']
    return df, dmg


def zero_loss(df, dmg, col, latency):
    loss = [sum(1 for e in dmg.get(r.task, []) if e[0] < getattr(r, col) + latency)
            for r in df.itertuples() if pd.notna(getattr(r, col)) and pd.notna(r.t_damage)]
    return 100 * np.mean(np.array(loss) == 0) if loss else np.nan, len(loss)


def headline(df, dmg):
    ex = df[df.executed]
    dur = ex.t_damage.where(ex.t_damage.notna(), ex.obs_end)
    km = KaplanMeierFitter().fit(dur, event_observed=ex.t_damage.notna())
    both = df.dropna(subset=['t_damage', 't_enum'])
    lead = both.t_damage - both.t_enum
    zl, _ = zero_loss(df, dmg, 't_crypto_ctx', 0.5)
    return {'damaged n': int(df.t_damage.notna().sum()),
            'median onset (s)': round(df.t_damage.median(), 2),
            'KM median (s)': round(km.median_survival_time_, 2),
            'enum signal-first (%)': round(100 * (lead > 0).mean(), 1),
            'enum median lead (s)': round(lead.median(), 2),
            'crypto-ctx zero-loss (%)': round(zl, 1)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--traces', required=True)
    ap.add_argument('--labels', required=True)
    ap.add_argument('--base', required=True, help='default results dir (timelines + damage)')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    lab = pd.read_csv(a.labels, dtype={'task': str})
    keep = set(lab[lab.category == 'ransomware'].task)

    rows = []
    for name, h, n in VARIANTS:
        d = os.path.join(a.out, name.split()[0])
        if not os.path.exists(os.path.join(d, 'timelines.csv')):
            subprocess.run([sys.executable, 'timeline.py', '--traces', a.traces, '--out', d,
                            '--entropy', str(h), '--min-len', str(n)], check=True, stdout=subprocess.DEVNULL)
        df, dmg = load(d, keep)
        rows.append({'variant': name, 'entropy': h, 'min bytes': n, **headline(df, dmg)})
    tab = pd.DataFrame(rows)

    df, dmg = load(a.base, keep)
    lat = []
    for L in LATENCIES:
        r = {'latency (s)': L}
        for col, nm in (('t_crypto_ctx', 'crypto-ctx'), ('t_crypto_key', 'key-gen'), ('t_enum', 'enumeration')):
            z, n = zero_loss(df, dmg, col, L)
            r[f'{nm} zero-loss (%)'] = round(z, 1)
        lat.append(r)
    lt = pd.DataFrame(lat)

    txt = ('THRESHOLD SENSITIVITY (ransomware samples)\n' + tab.to_string(index=False) +
           '\n\nDETECTOR REACTION-LATENCY SENSITIVITY (default thresholds)\n' + lt.to_string(index=False) + '\n')
    open(os.path.join(a.out, 'sensitivity.txt'), 'w').write(txt)
    print(txt)


if __name__ == '__main__':
    main()
