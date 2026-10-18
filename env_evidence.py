"""Reproduce the guest-environment and pitfall evidence quoted in the paper.

Writes results/env_evidence.txt with:
  1. Defender settings read by samples (non-policy Real-Time Protection key)
  2. UAC settings read by samples (EnableLUA, ConsentPromptBehaviorAdmin, ...)
  3. original analyses that touched drive D: (mounted installation media)
  4. overlap originals that wrote into the stale analyzer dirs before first damage
  5. denied writes to Program Files / System32: original vs. rebuild-1 re-runs
  6. malstatus counts and report.json sizes
Values a sample wrote itself before reading them back are not counted as reads.

  .venv/bin/python env_evidence.py --zip ../capev2_corpus_backup_20260729.zip \
      --traces traces --traces-rebuild1 traces_overlap --results results \
      --overlap overlap/overlap_samples.csv --rebuild1 results_overlap/timelines.csv
"""
import argparse, collections, csv, glob, gzip, json, re, zipfile

import numpy as np

REG_VALUES = {
    'defender': re.compile(r'\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\'
                           r'(DisableRealtimeMonitoring|DisableIOAVProtection)$', re.I),
    'uac': re.compile(r'\\Policies\\System\\(EnableLUA|ConsentPromptBehaviorAdmin|PromptOnSecureDesktop)$', re.I),
}
STALE = re.compile(r'^c:\\(o_o9j7fn|z3yxtjxt)\\', re.I)
PRIV = re.compile(r'^c:\\(program files|windows\\system32)', re.I)
WRITE_API = re.compile(r'Write|Rename|SetInformation|Delete|MoveFile')


def registry_reads(z, names):
    """value name -> Counter(data) over analyses that read it (first read per analysis)."""
    out = {k: collections.defaultdict(collections.Counter) for k in REG_VALUES}
    needle = re.compile(rb'Real-Time Protection|EnableLUA|ConsentPromptBehaviorAdmin|PromptOnSecureDesktop')
    for task, n in names.items():
        b = z.read(n)
        if not needle.search(b):
            continue
        rep = json.loads(b)
        seen, wrote = set(), set()
        for p in rep['behavior']['processes']:
            for c in p['calls']:
                api = c['api']
                if not api.startswith(('Reg', 'NtQueryValueKey', 'NtSetValueKey')):
                    continue
                a = {x['name']: x['value'] for x in c.get('arguments', [])}
                fn = str(a.get('FullName', ''))
                if 'Policies\\Microsoft\\Windows Defender' in fn:
                    continue   # the policy key is a different setting
                for kind, rx in REG_VALUES.items():
                    m = rx.search(fn)
                    if not m:
                        continue
                    v = m.group(1)
                    if api.startswith(('RegSet', 'NtSetValue')):
                        wrote.add(v)
                    elif api.startswith(('RegQueryValue', 'NtQueryValue')) and v not in wrote and v not in seen \
                            and str(c.get('status')) == 'True':
                        seen.add(v)
                        out[kind][v][str(a.get('Data', a.get('Information')))] += 1
    return out


def trace_events(path):
    with gzip.open(path, 'rt') as f:
        f.readline()
        for line in f:
            yield json.loads(line)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--zip', required=True)
    ap.add_argument('--traces', required=True)
    ap.add_argument('--traces-rebuild1', required=True)
    ap.add_argument('--results', required=True)
    ap.add_argument('--overlap', required=True, help='overlap_samples.csv (pick == main)')
    ap.add_argument('--rebuild1', required=True, help='rebuild-1 timelines.csv (pairs by sha256)')
    a = ap.parse_args()
    lines = []
    p = lambda s='': (print(s), lines.append(s))

    z = zipfile.ZipFile(a.zip)
    names = {re.search(r'(\d+)/reports', n).group(1): n for n in z.namelist() if n.endswith('reports/report.json')}
    sizes = [z.getinfo(n).file_size for n in names.values()]
    tl = list(csv.DictReader(open(f'{a.results}/timelines.csv')))
    p(f'reports: n={len(sizes)}  median {np.median(sizes)/1e6:.1f} MB  max {max(sizes)/1e6:.1f} MB')
    p(f'malstatus: {dict(collections.Counter(r["malstatus"] for r in tl if r["malstatus"]))}')

    p('\n1-2. Registry settings read by samples (analyses, first read each):')
    for kind, vals in registry_reads(z, names).items():
        for v, cnt in vals.items():
            p(f'  {kind:8s} {v:28s} {dict(cnt)}  (analyses: {sum(cnt.values())})')

    p('\n3. Original analyses that touched drive D:')
    d_runs = 0
    for fn in glob.glob(f'{a.traces}/*.jsonl.gz'):
        if any(re.match(r'^[dD]:\\', e.get('f') or '') for e in trace_events(fn)):
            d_runs += 1
    p(f'  {d_runs} analyses')

    ov = [r for r in csv.DictReader(open(a.overlap)) if r['pick'] == 'main']
    tmap = {r['task']: r for r in tl}
    p(f'\n4. Overlap originals ({len(ov)}) writing into stale analyzer dirs before first damage:')
    hit = 0
    for r in ov:
        end = float(tmap[r['task']]['t_damage'] or 1e9)
        if any(STALE.match(e.get('f') or '') and WRITE_API.search(e.get('a', '')) and e.get('t', 1e9) < end
               for e in trace_events(f'{a.traces}/{r["task"]}.jsonl.gz')):
            hit += 1
    p(f'  {hit} of {len(ov)}')

    p('\n5. Write attempts to Program Files / System32 (overlap samples): original vs rebuild 1')
    r1 = {r['sha256']: r['task'] for r in csv.DictReader(open(a.rebuild1))}
    for label, src in (('original', lambda r: f'{a.traces}/{r["task"]}.jsonl.gz'),
                       ('rebuild 1', lambda r: f'{a.traces_rebuild1}/{r1[r["sha256"]]}.jsonl.gz')):
        ok = bad = samples_ok = 0
        for r in ov:
            if label == 'rebuild 1' and r['sha256'] not in r1:
                continue
            s_ok = 0
            for e in trace_events(src(r)):
                api = e.get('a', '')
                if not PRIV.match(e.get('f') or ''):
                    continue
                if (api == 'NtCreateFile' and re.search(r'WRITE|0x4|GENERIC_ALL', str(e.get('acc')))) \
                        or api.startswith('MoveFile') or api == 'NtWriteFile':
                    if e.get('ok'):
                        ok += 1; s_ok += 1
                    else:
                        bad += 1
            samples_ok += s_ok > 0
        p(f'  {label:9s} ok={ok} denied={bad} ({100*bad/max(ok+bad,1):.0f}% denied); '
          f'samples with >=1 successful write: {samples_ok}')

    with open(f'{a.results}/env_evidence.txt', 'w') as f:
        f.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
