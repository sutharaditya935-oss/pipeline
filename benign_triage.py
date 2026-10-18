"""Read CAPE's analyzer logs for a (short) benign batch and report launch outcomes.

Use after a triage batch submitted with a short timeout (e.g. --default-timeout 20):
every program is launched unelevated exactly as in the real runs, so
ERROR_ELEVATION_REQUIRED (740), bad executable, or machine-type errors show up
within seconds. Programs that start are 'ok' (they may still fail later).

  .venv/bin/python benign_triage.py --subs ../benign/batch1/submissions.csv \
      --out ../benign/batch1/triage.csv [--storage /opt/CAPEv2/storage/analyses]
"""
import argparse, csv, os, re


def outcome(log):
    if not os.path.exists(log):
        return 'pending', ''
    s = open(log, errors='replace').read()
    m = re.search(r'Failed to execute process from path .*?\(Error: (.*?)\)\s*$', s, re.M)
    if m:
        e = m.group(1)
        kind = ('needs_admin_740' if e.strip() == '740' or 'ELEVATION' in e else
                'bad_exe_format' if 'BAD_EXE' in e or 'valid Win32' in e else
                'wrong_arch' if 'MACHINE_TYPE' in e or 'not compatible' in e else 'launch_error')
        return kind, e[:80]
    if 'Successfully executed process' in s or 'Analysis completed' in s:
        return 'ok', ''
    return 'unknown', ''


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--subs', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--storage', default='/opt/CAPEv2/storage/analyses')
    a = ap.parse_args()
    rows, counts = [], {}
    for r in csv.DictReader(open(a.subs)):
        if r['status'] != 'submitted':
            continue
        kind, detail = outcome(os.path.join(a.storage, r['task_id'], 'analysis.log'))
        counts[kind] = counts.get(kind, 0) + 1
        rows.append({'id': r['id'], 'name': r['name'], 'category': r['category'],
                     'task_id': r['task_id'], 'outcome': kind, 'detail': detail})
    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['id', 'name', 'category', 'task_id', 'outcome', 'detail'])
        w.writeheader(); w.writerows(rows)
    print(counts)
    for r in rows:
        if r['outcome'] not in ('ok', 'pending'):
            print(f'  {r["id"]} {r["name"][:30]:30s} {r["outcome"]} {r["detail"]}')


if __name__ == '__main__':
    main()
