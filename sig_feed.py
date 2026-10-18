"""Stream original report.json files to sig_run.py (signature reprocessing).

Runs as the corpus owner and writes, per analysis, a header line
"TASK <id> <nbytes>" followed by the raw report bytes, so the signature runner
(running as the CAPE user) never needs read access to the corpus archive.

  .venv/bin/python sig_feed.py --zip ../capev2_corpus_backup_20260729.zip [--tasks 486,6] \
      [--skip-done results/signatures.jsonl] | <sig_run.py as cape> >> results/signatures.jsonl
"""
import argparse, json, os, re, sys, zipfile


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--zip', required=True)
    ap.add_argument('--tasks', help='comma list (default: all)')
    ap.add_argument('--skip-done', help='existing output; tasks already in it are skipped')
    a = ap.parse_args()
    z = zipfile.ZipFile(a.zip)
    names = {re.search(r'(\d+)/reports', n).group(1): n for n in z.namelist() if n.endswith('reports/report.json')}
    tasks = a.tasks.split(',') if a.tasks else sorted(names, key=int)
    done = set()
    if a.skip_done and os.path.exists(a.skip_done):
        for line in open(a.skip_done):
            if line.startswith('{"task"'):   # CAPE also prints startup notices to stdout
                done.add(json.loads(line)['task'])
    out = sys.stdout.buffer
    for t in tasks:
        if t in done:
            continue
        raw = z.read(names[t])
        out.write(f'TASK {t} {len(raw)}\n'.encode())
        out.write(raw)
        out.flush()


if __name__ == '__main__':
    main()
