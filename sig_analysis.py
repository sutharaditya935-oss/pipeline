"""Summarize the reprocessed CAPE signatures (results/signatures.jsonl).

Reports, over the ransomware samples (and all analyses for reference):
  - coverage: analyses with >= 1 matched signature; median matched per analysis
  - new verdicts (malstatus/malscore) vs. the original, signature-less ones
  - ransomware-specific signatures, and agreement with the pipeline's damage label
  - most frequent signatures and ATT&CK techniques overall and per family

  .venv/bin/python sig_analysis.py --sigs results/signatures.jsonl.gz --results results \
      --labels results/family_labels.csv --out results/signature_summary.txt
"""
import argparse, collections, gzip, json

import pandas as pd

RANSOM_SIG = ('ransomware', 'ransom')   # name substrings of ransomware-behavior signatures


def load(path):
    rows = []
    for line in (gzip.open(path, 'rt') if path.endswith('.gz') else open(path)):
        if line.startswith('{"task"'):
            rows.append(json.loads(line))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--sigs', required=True)
    ap.add_argument('--results', required=True)
    ap.add_argument('--labels', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    recs = load(a.sigs)
    t = pd.read_csv(f'{a.results}/timelines.csv', dtype={'task': str})
    lab = pd.read_csv(a.labels, dtype={'task': str})
    lines = []
    p = lambda s='': (print(s), lines.append(s))

    df = pd.DataFrame([{
        'task': r['task'], 'error': r.get('error'),
        'n_sig': len(r.get('signatures') or []),
        'names': [s['name'] for s in r.get('signatures') or []],
        'ttps': [t for x in (r.get('ttps') or []) for t in (x.get('ttps') or [])],   # [{signature, ttps, mbcs}]
        'new_status': r.get('malstatus'), 'new_score': r.get('malscore'),
    } for r in recs])
    df = df.merge(t[['task', 'malstatus', 'executed', 't_damage', 'is_smoketest']], on='task', how='left') \
           .merge(lab[['task', 'family', 'category']], on='task', how='left')
    df = df[df.is_smoketest != True]
    p(f'analyses processed: {len(df)} of {len(t[t.is_smoketest != True])}; errors: {df.error.notna().sum()}')

    for scope, d in (('all analyses', df), ('ransomware', df[df.category == 'ransomware'])):
        ex = d[d.executed == True]
        p(f'\n[{scope}] n={len(d)} executed={len(ex)}')
        p(f'  >=1 signature: {(d.n_sig > 0).mean():.1%} of all, {(ex.n_sig > 0).mean():.1%} of executed; '
          f'median matched per executed analysis: {ex.n_sig.median():.0f}')
        p(f'  new malstatus (all):      {d.new_status.value_counts().to_dict()}')
        p(f'  new malstatus (executed): {ex.new_status.value_counts().to_dict()}')
        p(f'  original malstatus:       {d.malstatus.value_counts().to_dict()}')
        p('  original -> new malstatus:\n' + pd.crosstab(d.malstatus, d.new_status).to_string())

    r = df[(df.category == 'ransomware') & (df.executed == True)].copy()
    r['ransom_sig'] = r.names.apply(lambda ns: any(k in n for n in ns for k in RANSOM_SIG))
    r['damaged'] = r.t_damage.notna()
    p('\nRansomware-behavior signature vs. pipeline damage label (executed ransomware):')
    p(pd.crosstab(r.damaged, r.ransom_sig, rownames=['pipeline damage'], colnames=['ransomware signature']).to_string())
    names = collections.Counter(n for ns in r.names for n in set(ns) if any(k in n for k in RANSOM_SIG))
    p(f'  ransomware signatures: {dict(names.most_common(10))}')

    p('\nTop signatures (share of executed ransomware samples):')
    c = collections.Counter(n for ns in r.names for n in set(ns))
    for n, k in c.most_common(20):
        p(f'  {k / len(r):6.1%}  {n}')
    p('\nTop ATT&CK techniques (share of executed ransomware samples):')
    c = collections.Counter(x for xs in r.ttps for x in set(xs) if x)
    for n, k in c.most_common(15):
        p(f'  {k / len(r):6.1%}  {n}')
    p('\nPer family (executed ransomware, families with >= 10 executed):')
    for fam, g in r.groupby('family'):
        if len(g) < 10:
            continue
        p(f'  {fam:12s} n={len(g):4d} median sigs={g.n_sig.median():4.0f}  Malicious={(g.new_status == "Malicious").mean():5.1%}  '
          f'ransom-sig={g.ransom_sig.mean():5.1%}  damaged={g.damaged.mean():5.1%}')
    open(a.out, 'w').write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
