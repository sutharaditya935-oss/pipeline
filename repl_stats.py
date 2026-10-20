"""Agreement statistics for the second-machine replication (numbers quoted in the paper's text).

  .venv/bin/python repl_stats.py --paired results_repl_compare/paired.csv \
      --batches ../samples/overlap/submissions_repl_intel_batch1.csv ../samples/overlap/submissions_repl_intel_batch2.csv \
      --truncated 340 352 355 356 358 --out results_repl_compare/agreement.txt
Reports: agreement on whether damage occurs (+ Cohen's kappa), the discordant pairs (by family, and by how long the
other machine's run lasted), agreement without the runs whose guest agent stopped responding, and per-family medians.
"""
import argparse

import pandas as pd

ap = argparse.ArgumentParser(); ap.add_argument('--paired', required=True); ap.add_argument('--batches', nargs='+', required=True)
ap.add_argument('--truncated', nargs='*', default=[]); ap.add_argument('--out', required=True)
a = ap.parse_args()
m = pd.read_csv(a.paired, dtype={'task_a': str, 'task_b': str})
fam = {}
for f in a.batches:
    for r in pd.read_csv(f).itertuples():
        fam[r.sha256] = r.family
m['family'] = m.sha256.map(fam)
da, db = m.t_damage_a.notna(), m.t_damage_b.notna()
po = (da == db).mean(); pe = da.mean() * db.mean() + (1 - da.mean()) * (1 - db.mean())
L = [f'pairs {len(m)}; damage on both {int((da & db).sum())}, neither {int((~da & ~db).sum())}, only A {int((da & ~db).sum())}, only B {int((~da & db).sum())}',
     f'agreement on whether damage occurs: {int((da == db).sum())}/{len(m)} = {100 * po:.1f}%, Cohen kappa {(po - pe) / (1 - pe):.2f}']
d = m[da != db].copy()
d['t'] = d.t_damage_a.fillna(d.t_damage_b)
d['other_end'] = [r.obs_end_b if pd.notna(r.t_damage_a) else r.obs_end_a for r in d.itertuples()]
L.append(f'discordant pairs: {len(d)}; other machine run ended within 65 s: {int((d.other_end < 65).sum())}; lasted at least 90 s: {int((d.other_end >= 90).sum())} '
         f'(minimum {d[d.other_end >= 90].other_end.min():.1f} s); onset later than 60 s: {int((d.t > 60).sum())}')
L.append('discordant by family: ' + ', '.join(f'{k} {v}' for k, v in d.family.value_counts().items()))
for fm in d.family.value_counts().index[:3]:
    n = int((m.family == fm).sum()); L.append(f'  {fm}: {int((d.family == fm).sum())} of {n} samples')
if a.truncated:
    ex = m[~m.task_b.isin(a.truncated)]
    x, y = ex.t_damage_a.notna(), ex.t_damage_b.notna()
    L.append(f'excluding {len(a.truncated)} runs with an unresponsive guest agent: agreement {100 * (x == y).mean():.1f}% of {len(ex)}')
both = m[da & db]
g = both.groupby('family')[['t_damage_a', 't_damage_b']].median().assign(n=both.groupby('family').size()).query('n >= 6').round(1)
L.append('family medians where damage on both machines (n >= 6):\n' + g.to_string())
txt = '\n'.join(L); open(a.out, 'w').write(txt + '\n'); print(txt)
