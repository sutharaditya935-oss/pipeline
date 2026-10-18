"""Content validation of the damage heuristic using CAPE's captured CryptEncrypt buffers.

CAPE logs the *output* (ciphertext) of each CryptEncrypt call. A victim file is
*confirmed encrypted* when a process writes to it (NtWriteFile) a buffer that
begins with the output of one of its own earlier CryptEncrypt calls: the file's
new content is then demonstrably encryption output. This ground truth is
independent of the entropy heuristic, but exists only for samples that encrypt
through the Windows CryptoAPI.

Per sample, against the pipeline's damage events (damage.jsonl.gz):
  recall     = confirmed victim files the heuristic flags as damage (any kind)
  precision  = heuristic high-entropy-overwrite files that are confirmed
               (a lower bound: a sample may also encrypt some files without
               the CryptoAPI, which leaves no buffer evidence)
  timing     = first confirmed victim encryption vs. the pipeline's first damage

  .venv/bin/python validate_buffers.py --zip ../capev2_corpus_backup_20260729.zip \
      --results results_ransomware --traces traces --out results_ransomware/buffer_validation.csv
"""
import argparse, csv, gzip, json, re, zipfile
from datetime import datetime

from timeline import VICTIM_DAMAGE_ZONES, is_real_file, zone

PREFIX = 40      # characters of CAPE's escaped buffer text compared (~16-40 bytes);
                 # a match on this much encryption output cannot be coincidental


def ts(s):
    return datetime.strptime(s, '%Y-%m-%d %H:%M:%S,%f').timestamp()


def informative(buf):
    toks = re.findall(r'\\x[0-9a-f]{2}|.', buf[:PREFIX])
    return len(buf) >= PREFIX and len(set(toks)) > 4   # not zeros / one repeated byte


def header(trace_path):
    with gzip.open(trace_path, 'rt') as f:
        return json.loads(f.readline())


def confirmed_writes(report, t0, sandbox):
    """path(lower) -> first time a write stored CryptEncrypt output into that victim file."""
    conf, n_enc = {}, 0
    for p in report['behavior']['processes']:
        outs = set()   # prefixes of this process's earlier CryptEncrypt outputs
        for c in p['calls']:
            api = c['api']
            if api not in ('CryptEncrypt', 'NtWriteFile'):
                continue
            a = {x['name']: str(x['value']) for x in c.get('arguments', [])}
            buf, t = a.get('Buffer', ''), ts(c['timestamp']) - t0
            if api == 'CryptEncrypt':
                n_enc += 1
                if informative(buf):
                    outs.add(buf[:PREFIX])
                continue
            path = a.get('HandleName', '')
            if not (informative(buf) and is_real_file(path)
                    and zone(path, sandbox) in VICTIM_DAMAGE_ZONES):
                continue
            if buf[:PREFIX] in outs:
                k = path.lower()
                conf[k] = min(conf.get(k, t), t)
    return n_enc, conf


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--zip', required=True)
    ap.add_argument('--results', required=True)
    ap.add_argument('--traces', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--tasks', help='comma list (default: every sample with a CryptEncrypt call)')
    a = ap.parse_args()

    rows = list(csv.DictReader(open(f'{a.results}/timelines.csv')))
    tmap = {r['task']: r for r in rows}
    tasks = a.tasks.split(',') if a.tasks else [r['task'] for r in rows if r['t_crypto_enc']]
    corpus_sandbox = {l.split('\t')[0] for l in open(f'{a.results}/sandbox_dirs.txt') if l.strip()}
    dmg = {}
    with gzip.open(f'{a.results}/damage.jsonl.gz', 'rt') as f:
        for line in f:
            d = json.loads(line)
            dmg[str(d['task'])] = d['events']
    z = zipfile.ZipFile(a.zip)
    names = {re.search(r'(\d+)/reports', n).group(1): n for n in z.namelist() if n.endswith('reports/report.json')}

    out = []
    for i, t in enumerate(tasks, 1):
        h = header(f'{a.traces}/{t}.jsonl.gz')
        rep = json.loads(z.read(names[t]))
        n_enc, conf = confirmed_writes(rep, h['t0_abs'], corpus_sandbox)
        del rep
        flagged, flagged_hi = {}, {}
        for (te, path, kind) in dmg.get(t, []):
            k = path.lower()
            flagged[k] = min(flagged.get(k, te), te)
            if kind == 'encrypt':
                flagged_hi[k] = min(flagged_hi.get(k, te), te)
        hit = [k for k in conf if k in flagged]
        hi_conf = [k for k in flagged_hi if k in conf]
        r = tmap[t]
        first_conf = min(conf.values()) if conf else None
        out.append({
            'task': t, 'cryptencrypt_calls': n_enc,
            'confirmed_files': len(conf), 'confirmed_flagged': len(hit),
            'heuristic_hi_files': len(flagged_hi), 'heuristic_hi_confirmed': len(hi_conf),
            'first_confirmed_t': '' if first_conf is None else round(first_conf, 3),
            't_damage': r['t_damage'],
        })
        print(f'[{i}/{len(tasks)}] task {t}: enc={n_enc} confirmed={len(conf)} '
              f'flagged={len(hit)} | heuristic-hi={len(flagged_hi)} of which confirmed={len(hi_conf)}',
              flush=True)
    with open(a.out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
    print('wrote', a.out)


if __name__ == '__main__':
    main()
