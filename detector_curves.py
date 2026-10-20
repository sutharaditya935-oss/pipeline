"""Detector trade-off curves, confidence intervals, and where first damage lands (paper Sections IV-VI).

1. Zone of first damage: AppData vs real user folders vs other, with the onset time per zone.
2. CryptoDrop-style detector (fires at the k-th damage event, reacts after a fixed latency): benign
   false-positive rate (Wilson 95%) against ransomware coverage and files lost, for several k.
3. Bootstrap 95% CIs (samples resampled) for the lead-time table and the detector zero-loss rates.

  .venv/bin/python detector_curves.py --ransom results_ransomware --benign results_benign_intel \
      --index ~/benign_reports_intel/index_attributable.csv --out results_ransomware/detector_curves.txt
"""
import argparse, collections, gzip, json, math, re

import numpy as np
import pandas as pd

ap = argparse.ArgumentParser()
for k in ('--ransom', '--benign', '--index', '--out'):
    ap.add_argument(k, required=True)
ap.add_argument('--latency', type=float, default=0.5)
a = ap.parse_args()
rng = np.random.default_rng(2026)
L = []
p = lambda s='': (print(s), L.append(s))


def wilson(k, n, z=1.96):
    if n == 0: return float('nan'), float('nan'), float('nan')
    ph = k / n; d = 1 + z * z / n; c = (ph + z * z / (2 * n)) / d
    h = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / d
    return ph, max(0, c - h), min(1, c + h)


def events(path):
    out = {}
    for line in gzip.open(path, 'rt'):
        d = json.loads(line); out[str(d['task'])] = d['events']
    return out


r = pd.read_csv(f'{a.ransom}/timelines.csv', dtype={'task': str}); r = r[r.executed & ~r.is_smoketest]
rd = r[r.t_damage.notna()].copy(); rev = events(f'{a.ransom}/damage.jsonl.gz')

# ---- 1. zone of the first damage event
def zone_of(path):
    s = path.lower()
    if re.match(r'c:\\users\\[^\\]+\\appdata', s): return 'AppData'
    if re.match(r'c:\\users\\[^\\]+\\(documents|desktop|pictures|videos|music|downloads|onedrive)', s): return 'user folders'
    if s.startswith('c:\\users\\'): return 'other profile'
    if s.startswith(('c:\\program files', 'c:\\programdata')): return 'Program Files/ProgramData'
    if re.match(r'^[d-z]:\\', s): return 'other drives'
    if s.startswith('c:\\windows'): return 'Windows'
    return 'drive root / other'
rows = []
for t, x in rd.set_index('task').iterrows():
    ev = rev.get(t, [])
    if ev: rows.append((t, zone_of(ev[0][1]), x.t_damage, len({zone_of(e[1]) for e in ev}), sum(1 for e in ev if zone_of(e[1]) == 'user folders')))
z = pd.DataFrame(rows, columns=['task', 'zone', 't', 'nzones', 'n_user'])
p(f'1. ZONE OF THE FIRST DAMAGE EVENT ({len(z)} damaged ransomware samples)')
for zn, g in z.groupby('zone'):
    p(f'   {zn:26s} {len(g):4d} ({100 * len(g) / len(z):4.1f}%)  median onset {g.t.median():6.2f} s')
p(f'   samples with ANY damage event in the user folders (Documents/Desktop/Pictures/...): {(z.n_user > 0).sum()} ({100 * (z.n_user > 0).mean():.0f}%)')
tu = []
for t in rd.task:
    ts = [e[0] for e in rev.get(t, []) if zone_of(e[1]) == 'user folders']
    if ts: tu.append((ts[0], len(ts)))
tu = np.array(tu)
p(f'   time to first damage in the user folders (those {len(tu)} samples): median {np.median(tu[:, 0]):.2f} s, p10 {np.percentile(tu[:, 0], 10):.2f} s; '
  f'median damage events there {np.median(tu[:, 1]):.0f}')

# ---- 2. CryptoDrop-style trade-off
bidx = pd.read_csv(a.index, dtype={'task': str})
bt = pd.read_csv(f'{a.benign}/timelines.csv', dtype={'task': str}).merge(bidx, on='task'); bt = bt[bt.executed]
bev = events(f'{a.benign}/damage.jsonl.gz'); nb = len(bt)
bcount = {r_.name_y: len(bev.get(r_.task, [])) for r_ in bt.itertuples()}
p(f'\n2. CRYPTODROP-STYLE DETECTOR (fires at the k-th damage event; reaction {a.latency:g} s). Benign: {nb} executed programs.')
p('     k | benign FPR (95% CI)      | ransomware reaching k events | median files lost | p90 lost | lost <= 10')
for k in (1, 2, 3, 5, 10, 20, 50, 100):
    fp = sum(1 for v in bcount.values() if v >= k); ph, lo, hi = wilson(fp, nb)
    lost = []
    for t in rd.task:
        ts = [e[0] for e in rev.get(t, [])]
        if len(ts) >= k: lost.append(sum(1 for x in ts if x < ts[k - 1] + a.latency))
    lost = np.array(lost)
    p(f'  {k:4d} | {fp:2d}/{nb} {100 * ph:5.1f}% [{100 * lo:4.1f},{100 * hi:5.1f}] | {len(lost):3d}/{len(rd)} ({100 * len(lost) / len(rd):3.0f}%)'
      f'        | {np.median(lost):6.0f}            | {np.percentile(lost, 90):6.0f}   | {100 * np.mean(lost <= 10):4.0f}%')
big = sorted(((v, k_) for k_, v in bcount.items() if v >= 1), reverse=True)
p('   benign damage-event counts: ' + ', '.join(f'{k_} {v}' for v, k_ in big))

# ---- 3. bootstrap CIs
p('\n3. BOOTSTRAP 95% CIs (2,000 resamples of damaged samples)')
def boot(vals, stat, n=2000):
    vals = np.asarray(vals, float); s = [stat(rng.choice(vals, len(vals))) for _ in range(n)]
    return np.percentile(s, 2.5), np.percentile(s, 97.5)
SIG = [('t_enum', 'file enumeration', 1.0), ('t_crypto_ctx', 'crypto context', 0.5), ('t_crypto_key', 'key generation', 0.5), ('t_recovery_inhibit', 'recovery inhibit.', 0.5)]
for col, nm, lat in SIG:
    b = rd.dropna(subset=[col]); lead = (b.t_damage - b[col]).values
    zl = np.array([sum(1 for e in rev.get(t, []) if e[0] < s + lat) == 0 for t, s in zip(b.task, b[col])], float)
    f = boot((lead > 0).astype(float), np.mean); m = boot(lead, np.median); zz = boot(zl, np.mean)
    p(f'   {nm:17s} n={len(b):3d}  signal-first {100 * np.mean(lead > 0):3.0f}% [{100 * f[0]:3.0f},{100 * f[1]:3.0f}]  '
      f'median lead {np.median(lead):5.2f} s [{m[0]:5.2f},{m[1]:5.2f}]  zero-loss {100 * zl.mean():3.0f}% [{100 * zz[0]:3.0f},{100 * zz[1]:3.0f}]')
open(a.out, 'w').write('\n'.join(L) + '\n')
