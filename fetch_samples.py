#!/usr/bin/env python3
"""Download samples from MalwareBazaar by SHA-256.

Samples are kept exactly as MalwareBazaar delivers them: an encrypted zip
(password "infected"). Nothing is extracted to disk. Each download is verified
by streaming the zip's contents through 7z and checking the SHA-256 in memory.

The Auth-Key is read from $MB_AUTH_KEY or ~/.config/malwarebazaar/auth_key.
Never hard-code it here: this file is in a public repository.

Usage:
  # plain list of hashes
  python3 -I fetch_samples.py --hashes overlap/sha256_main.txt --out ../samples/overlap

  # overlap set: unavailable 'main' hashes are replaced by a 'reserve' from the same stratum
  python3 -I fetch_samples.py --overlap-csv overlap/overlap_samples.csv --out ../samples/overlap
"""
import argparse, csv, hashlib, json, os, shutil, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

API = 'https://mb-api.abuse.ch/api/v1/'
KEY_FILE = os.path.expanduser('~/.config/malwarebazaar/auth_key')


def auth_key():
    key = os.environ.get('MB_AUTH_KEY')
    if not key and os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            key = f.read().strip()
    if not key:
        sys.exit(f'No Auth-Key: set MB_AUTH_KEY or write it to {KEY_FILE}')
    return key


def post(key, fields, retries=3):
    data = urllib.parse.urlencode(fields).encode()
    for attempt in range(retries):
        req = urllib.request.Request(API, data=data, headers={'Auth-Key': key, 'User-Agent': 'ransomware-leadtime-pipeline'})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == retries - 1:
                raise
            time.sleep(5 * (attempt + 1))


def get_info(key, sha256):
    d = json.loads(post(key, {'query': 'get_info', 'hash': sha256}))
    return d['data'][0] if d.get('query_status') == 'ok' and d.get('data') else None


def verify_zip(path, sha256):
    """Hash the zip's inner file by streaming it through 7z; nothing is written to disk."""
    if not shutil.which('7z'):
        return 'unverified (7z not installed)'
    p = subprocess.Popen(['7z', 'e', '-so', '-pinfected', path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    h = hashlib.sha256()
    for chunk in iter(lambda: p.stdout.read(1 << 20), b''):
        h.update(chunk)
    p.wait()
    if p.returncode != 0:
        return 'bad zip'
    return 'ok' if h.hexdigest() == sha256 else f'hash mismatch ({h.hexdigest()[:12]})'


def fetch(key, sha256, out_dir):
    """Return (status, path, info)."""
    path = os.path.join(out_dir, sha256 + '.zip')
    info_path = os.path.join(out_dir, sha256 + '.json')
    if os.path.exists(path) and verify_zip(path, sha256) == 'ok':
        info = json.load(open(info_path)) if os.path.exists(info_path) else None
        return 'already present', path, info
    info = get_info(key, sha256)
    if info is None:
        return 'not on MalwareBazaar', None, None
    body = post(key, {'query': 'get_file', 'sha256_hash': sha256})
    if body[:1] == b'{':  # JSON error instead of a zip
        return 'download refused: ' + json.loads(body).get('query_status', '?'), None, info
    tmp = path + '.part'
    with open(tmp, 'wb') as f:
        f.write(body)
    v = verify_zip(tmp, sha256)
    if v not in ('ok',) and not v.startswith('unverified'):
        os.remove(tmp)
        return 'verification failed: ' + v, None, info
    os.replace(tmp, path)
    with open(info_path, 'w') as f:
        json.dump(info, f, indent=1)
    return 'downloaded' + ('' if v == 'ok' else f' ({v})'), path, info


def plan_from_csv(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    main = [r for r in rows if r['pick'] == 'main']
    reserves = {}
    for r in rows:
        if r['pick'] == 'reserve':
            reserves.setdefault(r['stratum'], []).append(r)
    return main, reserves


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--hashes', help='text file, one SHA-256 per line')
    g.add_argument('--overlap-csv', help='overlap_samples.csv from select_overlap.py (uses reserves)')
    ap.add_argument('--out', required=True, help='output folder (keep it OUTSIDE the git repo)')
    ap.add_argument('--delay', type=float, default=1.0, help='seconds between samples')
    a = ap.parse_args()

    out = os.path.abspath(a.out)
    if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.git')) and \
            out.startswith(os.path.dirname(os.path.abspath(__file__)) + os.sep):
        sys.exit('Refusing to download malware into the git repository folder. Choose --out outside it.')
    os.makedirs(out, exist_ok=True)
    key = auth_key()

    if a.hashes:
        with open(a.hashes) as f:
            todo = [{'sha256': l.strip(), 'stratum': '', 'pick': 'list'} for l in f if l.strip()]
        reserves = {}
    else:
        todo, reserves = plan_from_csv(a.overlap_csv)

    log = []
    i = 0
    while i < len(todo):
        r = todo[i]
        status, path, info = fetch(key, r['sha256'], out)
        family = (info or {}).get('signature') or ''
        print(f'[{i + 1:3d}/{len(todo)}] {r["sha256"][:16]}  {r.get("stratum", ""):10s} {family:14s} {status}', flush=True)
        log.append({'sha256': r['sha256'], 'stratum': r.get('stratum', ''), 'pick': r.get('pick', ''),
                    'task': r.get('task', ''), 'package': r.get('package', ''), 'family': family,
                    'status': status, 'file': path or ''})
        if path is None and reserves.get(r.get('stratum')):
            sub = dict(reserves[r['stratum']].pop(0), pick='reserve (replaces %s)' % r['sha256'][:12])
            todo.insert(i + 1, sub)
            print(f'      -> substituting reserve {sub["sha256"][:16]} from {r["stratum"]}', flush=True)
        i += 1
        time.sleep(a.delay)

    log_path = os.path.join(out, 'download_log.csv')
    with open(log_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(log[0]))
        w.writeheader()
        w.writerows(log)
    ok = sum(1 for x in log if x['file'])
    print(f'\n{ok} samples available in {out}  (log: {log_path})')
    if a.overlap_csv:
        got = [x for x in log if x['file'] and x['pick'] != 'list']
        print(f'overlap set: {len(got)} of 50 target samples ready')


if __name__ == '__main__':
    main()
