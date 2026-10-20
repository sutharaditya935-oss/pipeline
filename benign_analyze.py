"""False-positive analysis of the paper's detectors on the benign baseline.

For each detector signal (file enumeration, crypto context, key generation,
recovery inhibition, and the damage heuristic itself) reports over EXECUTED benign
programs: the false-positive rate with a 95% Wilson interval, overall, per
category, and for hard cases. Then, for each detector and a set of combinations
(e.g. enumeration AND key generation within N seconds), the operating point:
true-positive rate on executed ransomware (fraction with the signal) against the
false-positive rate, and the ransomware zero-loss rate at the detector's reaction
latency.

  .venv/bin/python benign_analyze.py --benign results_benign/timelines.csv \
      --index ~/benign_reports/index.csv --ransom results_ransomware \
      --out results_benign/false_positives.txt
"""
import argparse, gzip, json, math

import pandas as pd

SIGNALS = [('t_enum', 'file enumeration', 1.0), ('t_crypto_ctx', 'crypto context', 0.5),
           ('t_crypto_key', 'key generation/import', 0.5), ('t_recovery_inhibit', 'recovery inhibition', 0.5),
           ('t_damage', 'damage heuristic (irreversible damage)', 0.0)]
WINDOWS = [2.0, 5.0, 10.0]   # seconds, for "A and B within N s"


def wilson(k, n, z=1.96):
    if n == 0:
        return (float('nan'),) * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0, c - h), min(1, c + h)


def fmt(k, n):
    p, lo, hi = wilson(k, n)
    return f'{k:3d}/{n:<4d} {100 * p:5.1f}%  [{100 * lo:4.1f}, {100 * hi:5.1f}]'


def fired(df, cols, window=None):
    """Boolean series: all columns present (and, if window, within `window` s of each other)."""
    m = df[cols].notna().all(axis=1)
    if window is not None and len(cols) > 1:
        m &= (df[cols].max(axis=1) - df[cols].min(axis=1)) <= window
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--benign', required=True, help='timelines.csv from timeline.py over traces_benign')
    ap.add_argument('--index', required=True, help='index.csv from benign_stage.py')
    ap.add_argument('--ransom', required=True, help='results_ransomware dir (timelines + damage)')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    idx = pd.read_csv(a.index, dtype={'task': str}).rename(columns={'name': 'program'})
    b = pd.read_csv(a.benign, dtype={'task': str}).merge(idx, on='task', how='inner')
    r = pd.read_csv(f'{a.ransom}/timelines.csv', dtype={'task': str})
    r = r[r.executed & ~r.is_smoketest]
    dmg = {}
    with gzip.open(f'{a.ransom}/damage.jsonl.gz', 'rt') as f:
        for line in f:
            d = json.loads(line)
            dmg[str(d['task'])] = d['events']
    lines = []
    p = lambda s='': (print(s), lines.append(s))

    be = b[b.executed]
    p(f'Benign programs: {len(b)}; executed (>=1 monitored process): {len(be)}; '
      f'hard cases among executed: {(be.hard_case.str.lower() == "yes").sum()}')
    p(f'Executed ransomware samples for comparison: {len(r)}')
    if len(be) == 0:
        p('no executed benign programs'); open(a.out, 'w').write('\n'.join(lines) + '\n'); return

    p('\nFALSE-POSITIVE RATE by detector signal (executed benign; 95% Wilson interval)')
    for col, name, _ in SIGNALS:
        p(f'  {name:42s} {fmt(int(be[col].notna().sum()), len(be))}')
    p('\n  by hard-case flag:')
    for flag, g in be.groupby(be.hard_case.str.lower()):
        for col, name, _ in SIGNALS:
            p(f'    hard_case={flag:3s} {name:42s} {fmt(int(g[col].notna().sum()), len(g))}')
    p('\n  by category (any of enumeration / crypto context / key generation / damage):')
    for cat, g in be.groupby('category'):
        anyf = g[['t_enum', 't_crypto_ctx', 't_crypto_key', 't_damage']].notna().any(axis=1).sum()
        dm = g.t_damage.notna().sum()
        p(f'    {cat:28s} n={len(g):3d}  any-signal {anyf:3d}  damage-heuristic {dm:3d}')

    fp_list = be[be.t_damage.notna()]
    if len(fp_list):
        p('\n  benign programs flagged by the damage heuristic:')
        for _, x in fp_list.iterrows():
            p(f'    {x["id"]} {x["program"]} ({x.category}) t_damage={x.t_damage:.2f}s')

    p('\nOPERATING POINTS: ransomware true-positive rate vs benign false-positive rate')
    p('  (TPR = share of executed ransomware where the detector fires at all;')
    p('   zero-loss = share of firing samples with no damage event before signal + reaction latency)')
    combos = [([c], n, lat, None) for c, n, lat in SIGNALS[:4]]
    for w in WINDOWS:
        combos.append((['t_enum', 't_crypto_key'], f'enumeration AND key generation within {w:g} s', 0.5, w))
        combos.append((['t_enum', 't_crypto_ctx'], f'enumeration AND crypto context within {w:g} s', 0.5, w))
    rd = r[r.t_damage.notna()]    # ransomware that actually reaches damage: the samples a defender must stop
    p(f'  {"detector":58s} {"TPR(all)":>9s} {"TPR(dmg)":>9s} {"FPR":>9s} {"zero-loss":>10s}')
    for cols, name, lat, w in combos:
        tp = fired(r, cols, w)
        fp = fired(be, cols, w)
        trig = r[tp].copy()
        trig['trig'] = trig[cols].max(axis=1)
        zl = [sum(1 for e in dmg.get(t, []) if e[0] < tg + lat) == 0
              for t, tg, td in zip(trig.task, trig.trig, trig.t_damage) if pd.notna(td)]
        zls = f'{100 * (sum(zl) / len(zl)):5.1f}%' if zl else '   n/a'
        tpd = fired(rd, cols, w)
        p(f'  {name:58s} {100 * tp.mean():8.1f}% {100 * tpd.mean():8.1f}% {100 * fp.mean():8.1f}% {zls:>10s}')
    open(a.out, 'w').write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
