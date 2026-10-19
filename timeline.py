#!/usr/bin/env python3
"""Stage 2: event traces -> per-sample timeline of early signals and damage onset.

Reads the compact traces produced by extract.py and, for each analysis, finds
the time (relative to first process start) of a set of milestones:

  - file enumeration begins          (ransomware scanning the disk)
  - first crypto context / key / RNG / encrypt call
  - first recovery-inhibition command (shadow-copy / backup deletion)
  - first ransom-note write
  - first victim-file write           (paper's "encryption onset" proxy)
  - first destructive damage          (high-entropy overwrite, rename-to-new-ext, or delete)

It also reproduces the paper's original "first victim write" definition so the
new, cleaner numbers can be checked against the published 23.09 s / n=433 result.

Usage:
  python3 timeline.py --traces traces --out results
"""
import argparse, collections, csv, glob, gzip, json, os, re, sys

# ----------------------------------------------------------------- path helpers
def lower(p):
    return (p or '').lower()

def is_real_file(pl):
    """True for a real on-disk path, False for pipes/mailslots/devices/blanks."""
    if not pl:
        return False
    p = lower(pl)
    if not re.match(r'^[a-z]:\\', p):
        return False
    if '\\namedpipe\\' in p or '\\mailslot\\' in p or p.startswith('\\device\\'):
        return False
    return True

def top_dir(pl):
    m = re.match(r'^[a-z]:\\([^\\]+)', pl)
    return m.group(1) if m else None

def ext_of(pl):
    base = pl.rsplit('\\', 1)[-1]
    i = base.rfind('.')
    return base[i:] if 0 < i < len(base) - 1 else ''

# ----------------------------------------------------- sandbox working-dir detection
# CAPE stages its guest-side toolkit in C:\<random>\ with these marker children.
SANDBOX_CHILD = ('\\analyzer.py', '\\analysis.conf', '\\modules\\packages\\',
                 '\\data\\yara\\', '\\lib\\common\\', '\\lib\\core\\', '\\lib\\api\\',
                 '\\bin\\', '\\dll\\')

def sandbox_dirs_in_trace(events):
    """Return the set of top-level C:\\<dir> names that look like CAPE working dirs."""
    found = set()
    for e in events:
        for key in ('f', 'nf'):
            p = lower(e.get(key, ''))
            if not p.startswith('c:\\'):
                continue
            td = top_dir(p)
            if not td or td in PERSIST_SYS or td in ('users', 'documents and settings',
                                                     'program files', 'program files (x86)'):
                continue
            rest = p[len('c:\\' + td):]
            if any(rest.startswith(c) for c in SANDBOX_CHILD):
                found.add(td)
    return found

# -------------------------------------------------------------------- path zones
PERSIST_SYS = {'windows', 'programdata', '$recycle.bin', 'recovery',
               'system volume information', 'boot', 'perflogs'}

def zone(pl, sandbox):
    """Classify a real file path into a coarse zone."""
    p = lower(pl)
    td = top_dir(p)
    if td is None:
        return 'root'
    if td in sandbox:
        return 'sandbox'
    if td in PERSIST_SYS:
        return 'system'
    if td.startswith('program files'):
        return 'programfiles'
    if td in ('users', 'documents and settings'):
        # temp / appdata / real user content
        if re.search(r'\\(local\\)?temp\\', p) or re.search(r'\\local settings\\temp\\', p):
            return 'temp'
        if re.search(r'\\appdata\\', p) or re.search(r'\\application data\\', p):
            return 'appdata'
        return 'user'
    # bare C:\file  vs  C:\somedir\file
    return 'root' if p.count('\\') <= 1 else 'root_other'

# Paper's original exclusion (Section III-C/D): drop appdata/temp/programdata/windows/$recycle.
PAPER_EXCL_ZONES = {'sandbox', 'temp', 'appdata', 'system'}
# Our damage definition keeps appdata (genuine victim content lives there) but still
# drops dropper/instrumentation zones.
VICTIM_DAMAGE_ZONES = {'user', 'appdata', 'programfiles', 'root', 'root_other', 'other_drive'}
PAPER_VICTIM_ZONES = {'user', 'programfiles', 'root', 'root_other', 'other_drive'}

# --------------------------------------------------------------- signal detectors
NOTE_NAME = re.compile(
    r'(readme|read_me|decrypt|how[\s_-]*to[\s_-]*(decrypt|restore|recover|back)|'
    r'restore[\s_-]*(files|my|your)|recover[\s_-]*(files|your)|unlock[\s_-]*files|'
    r'files[\s_-]*encrypted|your[\s_-]*files|help[\s_-]*(decrypt|restore)|'
    r'_readme|ransom|lock|warning|attention|instruction|recovery[\s_-]*info)',
    re.I)
NOTE_EXT = {'.txt', '.html', '.htm', '.hta', '.rtf', '.bmp', '.png', '.jpg'}
NOTE_KEYWORDS = re.compile(
    r'(encrypt|decrypt|your files|all your|bitcoin|ransom|recover|restore|'
    r'tor browser|private key|contact us|has been locked|payment)', re.I)

# recovery inhibition: shadow-copy / backup / boot-recovery tampering
RECOVERY_INHIBIT = re.compile(
    r'(vssadmin\b.*\b(delete|resize)\b.*shadow|shadowcopy\s+delete|'
    r'win32_shadowcopy|delete\s+shadows|wbadmin\b.*\bdelete|'
    r'bcdedit\b.*(recoveryenabled|bootstatuspolicy|ignoreallfailures)|'
    r'wmic\b.*shadowcopy\b.*delete)',
    re.I)

CRYPTO_CTX = {'CryptAcquireContextW', 'CryptAcquireContextA', 'BCryptOpenAlgorithmProvider'}
CRYPTO_KEY = {'CryptGenKey', 'CryptImportKey', 'CryptDeriveKey',
              'BCryptGenerateSymmetricKey', 'BCryptImportKeyPair', 'BCryptGenerateKeyPair', 'BCryptImportKey'}
CRYPTO_RNG = {'CryptGenRandom', 'BCryptGenRandom', 'SystemFunction036', 'RtlGenRandom'}
CRYPTO_ENC = {'CryptEncrypt', 'BCryptEncrypt'}
ENUM_APIS = {'FindFirstFileExW', 'FindFirstFileExA', 'NtQueryDirectoryFile', 'NtQueryDirectoryFileEx'}
DELETE_APIS = {'NtDeleteFile', 'DeleteFileW', 'DeleteFileA'}
MOVE_APIS = {'MoveFileWithProgressW', 'MoveFileWithProgressTransactedW', 'MoveFileExW', 'MoveFileW'}
PROC_LAUNCH = {'CreateProcessInternalW', 'NtCreateUserProcess', 'ShellExecuteExW', 'WinExec'}

HIGH_ENTROPY = 7.0   # bits/byte over a >=64-byte captured buffer
MIN_ENTROPY_LEN = 64


def set_thresholds(entropy, min_len):
    """Override the damage thresholds (used for the sensitivity analysis)."""
    global HIGH_ENTROPY, MIN_ENTROPY_LEN
    HIGH_ENTROPY, MIN_ENTROPY_LEN = entropy, min_len

COMMON_EXT = {'.txt', '.log', '.tmp', '.dat', '.ini', '.xml', '.json', '.dll', '.exe',
              '.lnk', '.db', '.bak', '.old', '.cfg', '.config', '.manifest', ''}

def looks_like_note(e):
    f = e.get('f', '')
    if not f:
        return False
    if ext_of(f).lower() not in NOTE_EXT:
        return False
    name_hit = bool(NOTE_NAME.search(f.rsplit('\\', 1)[-1]))
    txt = e.get('txt', '')
    text_hit = bool(txt) and e.get('H', 9) < 6.0 and bool(NOTE_KEYWORDS.search(txt))
    return name_hit or text_hit

def renamed_to_encrypted(e):
    """A move/rename whose new extension differs and is not a normal one."""
    nf = e.get('nf', '')
    f = e.get('f', '')
    if not nf:
        return False
    ne = ext_of(nf).lower()
    oe = ext_of(f).lower()
    if ne == oe:
        return False
    # Phobos/Dharma style: name.ext.id[...].<family> or .<random>
    return ne not in COMMON_EXT or re.search(r'\.id[-_\[]', lower(nf)) is not None

# ----------------------------------------------------------------- per-trace pass
MILESTONES = [
    'enum', 'crypto_ctx', 'crypto_key', 'crypto_rng', 'crypto_enc',
    'recovery_inhibit', 'note', 'paper_first_write', 'victim_write',
    'victim_overwrite_hi', 'rename_enc', 'victim_delete', 'damage',
]

def process_trace(header, events, sandbox_corpus):
    sandbox = sandbox_dirs_in_trace(events) | sandbox_corpus
    first = {}
    def mark(k, t):
        if k not in first or t < first[k]:
            first[k] = t

    counts = collections.Counter()
    damage_events = []   # (t, path, kind) for detector replay
    # slui.exe is Windows' licence-activation helper; it calls CryptAcquireContext on its own
    # (seen on the first host's rebuilt VM, never in the original lab), so it is not ransomware signal
    ignore_pids = {x['pid'] for x in header.get('procs', []) if x.get('name', '').lower() == 'slui.exe'}

    for e in events:
        api = e['a']
        t = e['t']
        ok = e.get('ok', False)

        # crypto milestones (any process except slui.exe, success or not — presence is the signal)
        if e.get('p') in ignore_pids:
            pass
        elif api in CRYPTO_CTX:
            mark('crypto_ctx', t)
        elif api in CRYPTO_KEY:
            mark('crypto_key', t)
        elif api in CRYPTO_RNG:
            mark('crypto_rng', t)
        elif api in CRYPTO_ENC:
            mark('crypto_enc', t)

        # recovery inhibition via launched process command line
        if api in PROC_LAUNCH:
            cmd = (e.get('cmd', '') or '') + ' ' + (e.get('img', '') or '')
            if RECOVERY_INHIBIT.search(cmd):
                mark('recovery_inhibit', t)

        # file enumeration on a real location
        if api in ENUM_APIS and is_real_file(e.get('f', '')):
            z = zone(e['f'], sandbox)
            if z in VICTIM_DAMAGE_ZONES:
                mark('enum', t)

        # writes
        if api == 'NtWriteFile' and ok and is_real_file(e.get('f', '')):
            z = zone(e['f'], sandbox)
            # ransom note
            if looks_like_note(e) and z in VICTIM_DAMAGE_ZONES:
                mark('note', t)
                counts['notes'] += 1
            # paper's original metric
            if z in PAPER_VICTIM_ZONES:
                mark('paper_first_write', t)
            # our victim write
            if z in VICTIM_DAMAGE_ZONES:
                mark('victim_write', t)
                counts['victim_writes'] += 1
                hi = (e.get('H') is not None and e['H'] >= HIGH_ENTROPY
                      and (e.get('bl') or 0) >= MIN_ENTROPY_LEN and not looks_like_note(e))
                if hi:
                    mark('victim_overwrite_hi', t)
                    mark('damage', t)
                    counts['hi_entropy_writes'] += 1
                    damage_events.append((t, e['f'], 'encrypt'))

        # renames to a new/encrypted extension
        if (api in MOVE_APIS or api == 'NtSetInformationFile') and ok:
            tgt = e.get('nf', '') or e.get('f', '')
            if is_real_file(e.get('f', '')) and zone(e['f'], sandbox) in VICTIM_DAMAGE_ZONES and renamed_to_encrypted(e):
                mark('rename_enc', t)
                mark('damage', t)
                counts['renames_enc'] += 1
                damage_events.append((t, e['f'], 'rename'))

        # deletes of victim files
        if api in DELETE_APIS and ok and is_real_file(e.get('f', '')):
            if zone(e['f'], sandbox) in VICTIM_DAMAGE_ZONES:
                mark('victim_delete', t)
                mark('damage', t)
                counts['victim_deletes'] += 1
                damage_events.append((t, e['f'], 'delete'))

    damage_events.sort()
    return first, counts, sorted(sandbox), damage_events

# ------------------------------------------------------------------------- driver
def load_trace(path):
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        header = json.loads(f.readline())
        events = [json.loads(l) for l in f]
    return header, events

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--traces', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--entropy', type=float, default=HIGH_ENTROPY,
                    help=f'high-entropy overwrite threshold, bits/byte (default {HIGH_ENTROPY})')
    ap.add_argument('--min-len', type=int, default=MIN_ENTROPY_LEN,
                    help=f'minimum captured bytes for the entropy test (default {MIN_ENTROPY_LEN})')
    a = ap.parse_args()
    set_thresholds(a.entropy, a.min_len)
    os.makedirs(a.out, exist_ok=True)
    paths = sorted(glob.glob(os.path.join(a.traces, '*.jsonl.gz')))
    print(f'{len(paths)} traces', flush=True)

    # Pass 1: corpus-wide sandbox dir names that recur (guest doesn't reseed its RNG).
    dir_counts = collections.Counter()
    cache = {}
    for p in paths:
        header, events = load_trace(p)
        cache[p] = (header, events)
        for d in sandbox_dirs_in_trace(events):
            dir_counts[d] += 1
    sandbox_corpus = {d for d, c in dir_counts.items() if c >= 3}
    with open(os.path.join(a.out, 'sandbox_dirs.txt'), 'w') as f:
        for d, c in dir_counts.most_common():
            f.write(f'{d}\t{c}\t{"CORPUS" if d in sandbox_corpus else ""}\n')
    print(f'{len(sandbox_corpus)} recurring sandbox dirs (>=3 analyses)', flush=True)

    # Pass 2: milestones per trace.
    cols = (['task', 'sha256', 'name', 'package', 'ftype', 'malstatus', 'malscore',
             'duration', 'obs_end', 'n_calls', 'n_events', 'n_encbuf', 'cape_payloads',
             'signature_stage_ran', 'executed', 'is_smoketest']
            + ['t_' + m for m in MILESTONES]
            + ['n_victim_writes', 'n_hi_entropy_writes', 'n_renames_enc', 'n_victim_deletes', 'n_notes'])
    rows = []
    dmg_out = gzip.open(os.path.join(a.out, 'damage.jsonl.gz'), 'wt', encoding='utf-8')
    for p in paths:
        header, events = cache[p]
        first, counts, sbx, dmg = process_trace(header, events, sandbox_corpus)
        executed = bool(header.get('procs')) and header.get('n_calls', 0) > 0
        is_smoke = (header.get('package') == 'generic'
                    or lower(header.get('name', '')) == 'smoketest.exe')
        row = {
            'task': header['task'], 'sha256': header.get('sha256'), 'name': header.get('name'),
            'package': header.get('package'), 'ftype': (header.get('ftype') or '')[:40],
            'malstatus': header.get('malstatus'), 'malscore': header.get('malscore'),
            'duration': header.get('duration'), 'obs_end': header.get('obs_end'),
            'n_calls': header.get('n_calls'), 'n_events': header.get('n_events'),
            'n_encbuf': header.get('n_encbuf'), 'cape_payloads': header.get('cape_payloads'),
            'signature_stage_ran': header.get('signature_stage_ran'),
            'executed': executed, 'is_smoketest': is_smoke,
            'n_victim_writes': counts['victim_writes'], 'n_hi_entropy_writes': counts['hi_entropy_writes'],
            'n_renames_enc': counts['renames_enc'], 'n_victim_deletes': counts['victim_deletes'],
            'n_notes': counts['notes'],
        }
        for m in MILESTONES:
            row['t_' + m] = round(first[m], 3) if m in first else ''
        rows.append(row)
        dmg_out.write(json.dumps({'task': header['task'], 'obs_end': header.get('obs_end'),
                                  'events': dmg}) + '\n')
    dmg_out.close()

    with open(os.path.join(a.out, 'timelines.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f'wrote {len(rows)} rows -> {a.out}/timelines.csv', flush=True)

if __name__ == '__main__':
    main()
