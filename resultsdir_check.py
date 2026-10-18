"""Damage counted inside CAPE's per-run results directory, and its effect.

CAPE's analyzer stores each run's results under C:\\<random> (logged as "Storing
results at: ..."). The pipeline's sandbox detection keys on the analyzer's own
files, so damage inside this results directory can be counted as victim damage.
This script measures how much, and recomputes the headline timing without it.

  .venv/bin/python resultsdir_check.py --zip ../capev2_corpus_backup_20260729.zip \
      --results results --subset results_ransomware --out results_ransomware/resultsdir_check.txt
"""
import argparse, gzip, json, re, zipfile

import pandas as pd
from lifelines import KaplanMeierFitter


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--zip', required=True)
    ap.add_argument('--results', required=True, help='dir with damage.jsonl.gz')
    ap.add_argument('--subset', required=True, help='dir with the analyzed timelines.csv')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    z = zipfile.ZipFile(a.zip)
    resdir = {}
    for n in z.namelist():
        m = re.match(r'analyses/(\d+)/analysis\.log$', n)
        if m:
            r = re.search(r'Storing results at: C:\\(\S+)', z.read(n)[:4000].decode('utf-8', 'replace'))
            if r:
                resdir[m.group(1)] = r.group(1).lower()

    tl = pd.read_csv(f'{a.subset}/timelines.csv', dtype={'task': str})
    keep = set(tl.task)
    n_samples = n_first = ev_in = ev_all = 0
    new_first = {}
    with gzip.open(f'{a.results}/damage.jsonl.gz', 'rt') as f:
        for line in f:
            d = json.loads(line)
            t = str(d['task'])
            if t not in keep:
                continue
            pre = f'c:\\{resdir.get(t, "#")}\\'
            ins = [e for e in d['events'] if e[1].lower().startswith(pre)]
            rest = [e for e in d['events'] if not e[1].lower().startswith(pre)]
            ev_in += len(ins); ev_all += len(d['events'])
            if ins:
                n_samples += 1
            if d['events'] and d['events'][0][1].lower().startswith(pre):
                n_first += 1
            new_first[t] = rest[0][0] if rest else None
    tl['t_excl'] = tl.task.map(new_first)

    def stats(col):
        e = tl[tl.executed]
        dur = e[col].where(e[col].notna(), e.obs_end)
        km = KaplanMeierFitter().fit(dur, event_observed=e[col].notna()).median_survival_time_
        return tl[col].notna().sum(), tl[col].median(), km

    lines = [
        f'analyses with a logged results directory: {len(resdir)}',
        f'damaged samples with damage events in it: {n_samples}; first damage event in it: {n_first}',
        f'damage events in it: {ev_in} of {ev_all} ({100 * ev_in / max(ev_all, 1):.3f}%)',
        'headline as published : damaged n=%d  median=%.2f s  KM median=%.2f s' % stats('t_damage'),
        'excluding results dir : damaged n=%d  median=%.2f s  KM median=%.2f s' % stats('t_excl'),
    ]
    print('\n'.join(lines))
    open(a.out, 'w').write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
