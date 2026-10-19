"""Select the cross-host replication set (target 250 executed ransomware samples).

Rules (seed 2026):
  - all executed ransomware samples of the earlier re-run set (overlap main) are included;
  - WannaCry and BlackCat (setup-blocked families that do nothing on either host) are
    capped at 5 samples each; other DLL-packaged samples at 5 in total;
  - the rest is allocated across families in proportion to sqrt(family size), so small
    families are visible, then stratified within a family by damaged / not damaged;
  - a ranked reserve (same families) of 12% is added for downloads that fail.

  .venv/bin/python select_replication.py --results results --labels results/family_labels.csv \
      --overlap overlap/overlap_samples.csv --out overlap/replication250.csv
"""
import argparse, math, random

import pandas as pd

TARGET, RESERVE_FRAC, SEED = 250, 0.12, 2026
CAP = {'WannaCry': 5, 'BlackCat': 5}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', required=True); ap.add_argument('--labels', required=True)
    ap.add_argument('--overlap', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    rng = random.Random(SEED)
    t = pd.read_csv(f'{a.results}/timelines.csv', dtype={'task': str})
    lab = pd.read_csv(a.labels, dtype={'task': str})
    m = t.merge(lab[['task', 'family', 'category']], on='task')
    m = m[(m.category == 'ransomware') & m.executed & ~m.is_smoketest].copy()
    m['damaged'] = m.t_damage.notna()
    ov = pd.read_csv(a.overlap, dtype={'task': str}); ov = ov[ov.pick == 'main']
    forced = set(ov.task) & set(m.task)

    picked = {k: 'overlap' for k in forced}
    dll_used = int(m[m.task.isin(forced)].package.eq('dll').sum())
    fam_used = m[m.task.isin(forced)].family.value_counts().to_dict()

    pool = m[~m.task.isin(forced)].copy()
    pool = pool[(pool.package != 'dll') | (pool.family == 'WannaCry')]   # exe only (+ WannaCry DLLs, capped)
    sizes = pool.family.value_counts()
    need = TARGET - len(forced)
    weights = {f: math.sqrt(n) for f, n in sizes.items()}
    tot = sum(weights.values())
    quota = {f: max(1, round(need * w / tot)) for f, w in weights.items()}
    for f, c in CAP.items():
        if f in quota:
            quota[f] = max(0, c - fam_used.get(f, 0))
    # rare families: at most 2 each
    for f, n in sizes.items():
        if n <= 3:
            quota[f] = min(quota[f], n)
    # trim / grow to hit the target
    while sum(quota.values()) > need:
        f = max((k for k in quota if k not in CAP), key=lambda k: quota[k]); quota[f] -= 1
    while sum(quota.values()) < need:
        f = max((k for k in quota if k not in CAP and quota[k] < sizes[k]), key=lambda k: sizes[k] - quota[k]); quota[f] += 1

    rows = []
    for f, q in quota.items():
        g = pool[pool.family == f]
        q = min(q, len(g))
        d, n = g[g.damaged], g[~g.damaged]
        qd = round(q * len(d) / len(g)) if len(g) else 0
        qd = min(qd, len(d)); qn = min(q - qd, len(n)); qd = min(q - qn, len(d))
        take = rng.sample(sorted(d.task), qd) + rng.sample(sorted(n.task), qn)
        rest = [x for x in sorted(g.task) if x not in take]
        rng.shuffle(rest)
        for tk in take:
            rows.append((tk, 'main'))
        for tk in rest[:max(1, math.ceil(q * RESERVE_FRAC))]:
            rows.append((tk, 'reserve'))
    sel = pd.DataFrame(rows, columns=['task', 'pick'])
    sel = pd.concat([pd.DataFrame({'task': sorted(forced), 'pick': 'overlap'}), sel])
    out = sel.merge(m[['task', 'sha256', 'family', 'package', 'damaged', 't_damage', 'obs_end', 'name']], on='task')
    out.to_csv(a.out, index=False)
    main = out[out.pick != 'reserve']
    print(f'selected {len(main)} (overlap {int((out.pick == "overlap").sum())}, new {int((out.pick == "main").sum())}) '
          f'+ {int((out.pick == "reserve").sum())} reserves')
    print(f'damaged share: selected {main.damaged.mean():.0%} vs executed ransomware {m.damaged.mean():.0%}; '
          f'DLL packages: {int((main.package == "dll").sum())}')
    print(main.groupby('family').agg(n=('task', 'size'), damaged=('damaged', 'sum')).sort_values('n', ascending=False).T.to_string())


if __name__ == '__main__':
    main()
