"""Submit a validated benign program list to the local CAPE lab.

Same lab, same settings as the ransomware runs: machine cuckoo1, 120 s timeout by
default, no extra options, the package and arguments from the list. Each task is
tagged custom="benign:<id>" so results can be paired with the list. Spaces
submissions out (default 15 s) and is resumable: ids already in --out are skipped.
Run benign_prepare.py first; this refuses to start if lab_state.json is missing.

  .venv/bin/python benign_submit.py --list ../benign/batch1/programs.csv \
      --staging ../benign/batch1/staging --out ../benign/batch1/submissions.csv
"""
import argparse, csv, os, sys, time

import requests

API = 'http://127.0.0.1:8000/apiv2/tasks/create/file/'
FIELDS = ['id', 'name', 'version', 'category', 'hard_case', 'sha256', 'package', 'arguments',
          'timeout', 'task_id', 'status', 'submitted_local']


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--list', required=True)
    ap.add_argument('--staging', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--machine', default='cuckoo1')
    ap.add_argument('--delay', type=float, default=15.0)
    ap.add_argument('--default-timeout', default='120')
    a = ap.parse_args()

    state = os.path.join(os.path.dirname(os.path.abspath(a.out)), 'lab_state.json')
    if not os.path.exists(state):
        sys.exit(f'{state} missing: run lab_state.py first so the batch records its lab state')

    done = set()
    if os.path.exists(a.out):
        done = {r['id'] for r in csv.DictReader(open(a.out)) if r['status'] == 'submitted'}
    new_file = not os.path.exists(a.out)
    out = open(a.out, 'a', newline='')
    w = csv.DictWriter(out, fieldnames=FIELDS)
    if new_file:
        w.writeheader(); out.flush()

    rows = list(csv.DictReader(open(a.list)))
    for i, r in enumerate(rows, 1):
        if r['id'] in done:
            continue
        timeout = (r.get('timeout') or a.default_timeout).strip()
        data = {'package': r['package'], 'machine': a.machine, 'timeout': timeout,
                'custom': f'benign:{r["id"]}'}
        opts = []
        if (r.get('zip_file') or '').strip():          # zipped portable app: run this file from the archive
            opts.append(f'file={r["zip_file"].strip()}')
        if (r.get('arguments') or '').strip():
            opts.append(f'arguments={r["arguments"].strip()}')
        if opts:
            data['options'] = ','.join(opts)            # CAPE options are comma-separated: no commas in arguments
        status, task_id = '', ''
        try:
            with open(os.path.join(a.staging, r['filename']), 'rb') as fh:
                resp = requests.post(API, files={'file': (r['filename'], fh)}, data=data, timeout=300).json()
            ids = (resp.get('data') or {}).get('task_ids') or []
            task_id = ids[0] if ids else ''
            status = 'submitted' if task_id else 'api error: ' + str(resp.get('error_value') or resp)[:80]
        except Exception as e:
            status = f'{type(e).__name__}: {e}'[:100]
        w.writerow({'id': r['id'], 'name': r['name'], 'version': r['version'], 'category': r['category'],
                    'hard_case': r['hard_case'], 'sha256': r['sha256'], 'package': r['package'],
                    'arguments': r.get('arguments', ''), 'timeout': timeout, 'task_id': task_id,
                    'status': status, 'submitted_local': time.strftime('%Y-%m-%d %H:%M:%S')})
        out.flush()
        print(f'[{i}/{len(rows)}] {r["id"]} {r["name"][:30]:30s} -> {status} {task_id}', flush=True)
        if status == 'submitted' and i < len(rows):
            time.sleep(a.delay)
    out.close()


if __name__ == '__main__':
    main()
