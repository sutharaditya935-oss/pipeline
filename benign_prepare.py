"""Validate a benign program list before any run.

Checks every row of the list: required columns, unique ids, files present in the
staging directory, SHA-256 matches the recorded hash, no duplicate files (same
hash under two ids), package is a CAPE package, timeout numeric. Prints a
category summary and exits non-zero on any error, so a bad list never reaches the
lab.

  .venv/bin/python benign_prepare.py --list ../benign/batch1/programs.csv \
      --staging ../benign/batch1/staging
"""
import argparse, collections, csv, hashlib, os, re, sys

REQUIRED = ['id', 'name', 'version', 'category', 'hard_case', 'source_url', 'license',
            'filename', 'sha256', 'package']
PACKAGES = {'exe', 'dll', 'msi', 'zip', 'generic', 'ps1', 'bat', 'js', 'vbs', 'regsvr'}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--list', required=True)
    ap.add_argument('--staging', required=True)
    a = ap.parse_args()

    rows = list(csv.DictReader(open(a.list)))
    errs, ids, hashes = [], set(), {}
    if not rows:
        sys.exit('empty list')
    missing_cols = [c for c in REQUIRED if c not in rows[0]]
    if missing_cols:
        sys.exit(f'missing columns: {missing_cols}')
    for n, r in enumerate(rows, 2):
        tag = f'row {n} ({r["id"]})'
        for c in REQUIRED:
            if not (r[c] or '').strip():
                errs.append(f'{tag}: empty {c}')
        if r['id'] in ids:
            errs.append(f'{tag}: duplicate id')
        ids.add(r['id'])
        if 'EXAMPLE ROW' in (r.get('notes') or ''):
            errs.append(f'{tag}: template example row left in the list')
        if r['hard_case'].strip().lower() not in ('yes', 'no'):
            errs.append(f'{tag}: hard_case must be yes/no')
        if r['package'] not in PACKAGES:
            errs.append(f'{tag}: unknown package {r["package"]!r}')
        if r.get('timeout') and not re.fullmatch(r'\d+', r['timeout'].strip()):
            errs.append(f'{tag}: timeout must be an integer')
        if not re.fullmatch(r'[0-9a-fA-F]{64}', r['sha256'].strip() or ''):
            errs.append(f'{tag}: sha256 is not 64 hex characters')
            continue
        path = os.path.join(a.staging, r['filename'])
        if not os.path.isfile(path):
            errs.append(f'{tag}: file not found: {r["filename"]}')
            continue
        got = sha256(path)
        if got != r['sha256'].strip().lower():
            errs.append(f'{tag}: SHA-256 mismatch (file {got[:12]}..., list {r["sha256"][:12]}...)')
        if got in hashes:
            errs.append(f'{tag}: same file as {hashes[got]}')
        hashes[got] = r['id']

    cats = collections.Counter(r['category'] for r in rows)
    hard = sum(r['hard_case'].strip().lower() == 'yes' for r in rows)
    print(f'{len(rows)} programs, {len(cats)} categories, {hard} hard cases')
    for c, k in cats.most_common():
        print(f'  {k:4d}  {c}')
    if errs:
        print(f'\n{len(errs)} ERROR(S):')
        for e in errs[:60]:
            print('  -', e)
        sys.exit(1)
    print('\nlist OK')


if __name__ == '__main__':
    main()
