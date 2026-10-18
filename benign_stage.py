"""Stage finished benign analyses in the layout extract.py expects.

Reads submissions.csv, waits for nothing: tasks whose report.json does not exist
yet are listed and skipped. Creates <out>/<task_id>/reports/report.json symlinks
to CAPE's storage (no copying), plus <out>/index.csv mapping task -> program id.

  .venv/bin/python benign_stage.py --subs ../benign/batch1/submissions.csv \
      --out ~/benign_reports [--storage /opt/CAPEv2/storage/analyses]
"""
import argparse, csv, os


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--subs', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--storage', default='/opt/CAPEv2/storage/analyses')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    ok, pending, index = 0, [], []
    for r in csv.DictReader(open(a.subs)):
        if r['status'] != 'submitted':
            continue
        t = r['task_id']
        rep = os.path.join(a.storage, t, 'reports', 'report.json')
        if not os.path.exists(rep):
            pending.append(f'{r["id"]} (task {t})')
            continue
        d = os.path.join(a.out, t, 'reports')
        os.makedirs(d, exist_ok=True)
        link = os.path.join(d, 'report.json')
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(rep, link)
        index.append({'task': t, 'id': r['id'], 'name': r['name'], 'category': r['category'],
                      'hard_case': r['hard_case']})
        ok += 1
    with open(os.path.join(a.out, 'index.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['task', 'id', 'name', 'category', 'hard_case'])
        w.writeheader(); w.writerows(index)
    print(f'staged {ok}; pending {len(pending)}' + (': ' + ', '.join(pending[:10]) if pending else ''))


if __name__ == '__main__':
    main()
