"""Assign a family label to every analysis in the corpus.

Two sources, no re-detonation:
  1. CAPE's own YARA family detections (report.json "detections"), offline.
  2. MalwareBazaar metadata by SHA-256 (get_info: signature, tags, first_seen).
     Metadata only - no samples are downloaded. Responses are cached as JSON in
     --cache (keep it outside the repo) so a rerun makes no new requests.

Final label = MalwareBazaar signature, else CAPE detection, else "unknown",
after alias normalization. Disagreements between the two sources are kept in
the output for review.

  .venv/bin/python label_families.py --zip ../capev2_corpus_backup_20260729.zip \
      --timelines results/timelines.csv --cache ../labels_cache \
      --out results/family_labels.csv
Then: .venv/bin/python analyze.py --results results --labels results/family_labels.csv
"""
import argparse, csv, json, os, re, sys, time, zipfile

from fetch_samples import auth_key, post

# Same family under different vendor names (keep this list short and documented).
ALIASES = {'crysis': 'Dharma', 'dharma': 'Dharma', 'sodinokibi': 'REvil', 'revil': 'REvil',
           'lockbit': 'LockBit', 'lockbit3': 'LockBit', 'lockbit 3.0': 'LockBit',
           'wannacry': 'WannaCry', 'wannacryptor': 'WannaCry', 'wcry': 'WannaCry',
           'alphv': 'BlackCat', 'blackcat': 'BlackCat', 'blackmatte': 'BlackMatter',
           'arkeistealer': 'Arkei', 'arkei': 'Arkei', 'stealc': 'Arkei', 'heodo': 'Emotet',
           'conti': 'Conti', 'ryuk': 'Ryuk', 'phobos': 'Phobos', 'babuk': 'Babuk'}
# Vendor signatures that name a type, not a family.
GENERIC = {'ransomware', 'trojan', 'malware'}
# Known non-ransomware families present in this corpus (stealers, loaders/bots,
# file-infector viruses). Anything else counts as ransomware only if MalwareBazaar
# tags it 'ransomware'; otherwise it is 'unclear'.
NON_RANSOMWARE = {'AgentTesla', 'Arkei', 'RustyStealer', 'PythonStealer', 'PureLogsStealer',
                  'BuerLoader', 'BazaLoader', 'ZLoader', 'Amadey', 'TrickBot', 'Emotet',
                  'Expiro', 'Neshta', 'Worm.m0yv'}
# Unambiguous ransomware families (their MalwareBazaar tags don't always say so).
RANSOMWARE = {'WannaCry', 'LockBit', 'REvil', 'Phobos', 'Conti', 'BlackCat', 'Dharma', 'Babuk',
              'BlackMatter', 'Ryuk', 'Maze', 'CryptoLocker', 'RansomEXX', 'Medusa', 'Makop',
              'Xorist', 'Chaos', 'Vohuk'}


def norm(name):
    if not name:
        return ''
    n = name.strip()
    if n.lower() in GENERIC:
        return ''
    return ALIASES.get(n.lower(), n)


def family_from_tags(tags, known):
    """First tag that names a known family (e.g. 'conti', 'REvil')."""
    for t in tags:
        f = norm(t)
        if f in known:
            return f
    return ''


def cape_families(zip_path):
    """task -> sorted CAPE detection family names (parses only the detections value)."""
    out = {}
    dec = json.JSONDecoder()
    z = zipfile.ZipFile(zip_path)
    for n in z.namelist():
        m = re.search(r'analyses/(\d+)/reports/report\.json$', n)
        if not m:
            continue
        with z.open(n) as f:
            head = f.read(4 << 20).decode('utf-8', 'replace')  # detections sits near the top
        i = head.find('"detections":')
        fams = set()
        if i >= 0:
            try:
                val, _ = dec.raw_decode(head, i + len('"detections":') + 1)
                for d in val or []:
                    if d.get('family'):
                        fams.add(norm(d['family']))
            except ValueError:
                pass
        out[m.group(1)] = sorted(fams)
    return out


def mb_info(key, sha, cache, delay):
    path = os.path.join(cache, f'{sha}.json')
    if os.path.exists(path):
        return json.load(open(path))
    raw = post(key, {'query': 'get_info', 'hash': sha})
    d = json.loads(raw)
    with open(path, 'w') as f:
        json.dump(d, f)
    time.sleep(delay)
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--zip', required=True)
    ap.add_argument('--timelines', required=True)
    ap.add_argument('--cache', required=True, help='dir for MalwareBazaar responses (outside the repo)')
    ap.add_argument('--out', required=True)
    ap.add_argument('--delay', type=float, default=0.6, help='seconds between API requests')
    ap.add_argument('--offline', action='store_true', help='CAPE detections + cache only, no requests')
    a = ap.parse_args()
    os.makedirs(a.cache, exist_ok=True)

    rows = [r for r in csv.DictReader(open(a.timelines)) if r['is_smoketest'] != 'True']
    print(f'{len(rows)} analyses; reading CAPE detections ...', flush=True)
    cape = cape_families(a.zip)
    key = None if a.offline else auth_key()

    out, infos = [], {}
    for i, r in enumerate(rows, 1):
        sha, task = r['sha256'], r['task']
        sig = tags = first = status = ''
        cached = os.path.join(a.cache, f'{sha}.json')
        if key or os.path.exists(cached):
            try:
                d = mb_info(key, sha, a.cache, a.delay) if key else json.load(open(cached))
                status = d.get('query_status', '')
                if status == 'ok' and d.get('data'):
                    info = d['data'][0]
                    sig = norm(info.get('signature') or '')
                    tags = ';'.join(info.get('tags') or [])
                    infos[task] = info.get('tags') or []
                    first = (info.get('first_seen') or '')[:10]
            except Exception as e:
                status = f'error: {type(e).__name__}'
        cf = cape.get(task, [])
        family = sig or (cf[0] if len(cf) == 1 else '') or 'unknown'
        conflict = bool(sig and cf and sig not in cf)
        out.append({'task': task, 'sha256': sha, 'family': family, 'category': '', 'mb_signature': sig,
                    'cape_detections': ';'.join(cf), 'conflict': conflict,
                    'mb_status': status, 'mb_tags': tags, 'first_seen': first})
        if i % 100 == 0:
            print(f'  {i}/{len(rows)}', flush=True)

    # Second pass: recover families named only in tags, settle MB/CAPE conflicts
    # where the MB tags agree with CAPE, and assign a category.
    known = {o['mb_signature'] for o in out if o['mb_signature']} | {
        f for o in out for f in o['cape_detections'].split(';') if f}
    for o in out:
        tags = infos.get(o['task'], [])
        cf = [f for f in o['cape_detections'].split(';') if f]
        if o['conflict'] and any(norm(t) in cf for t in tags):
            o['family'] = next(norm(t) for t in tags if norm(t) in cf); o['conflict'] = False
        if o['family'] == 'unknown':
            o['family'] = family_from_tags(tags, known) or 'unknown'
        lower = [t.lower() for t in tags]
        if 'decryptor' in lower:
            o['category'] = 'decryptor'
        elif o['family'] in NON_RANSOMWARE:
            o['category'] = 'non-ransomware'
        elif o['family'] in RANSOMWARE or any('ransom' in t for t in lower):
            o['category'] = 'ransomware'
        else:
            o['category'] = 'unclear'

    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]))
        w.writeheader(); w.writerows(out)
    labeled = sum(o['family'] != 'unknown' for o in out)
    print(f'wrote {a.out}: {labeled}/{len(out)} labeled, '
          f'{sum(o["conflict"] for o in out)} CAPE/MB disagreements')


if __name__ == '__main__':
    sys.exit(main())
