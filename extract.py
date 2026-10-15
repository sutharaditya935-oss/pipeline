#!/usr/bin/env python3
"""Stage 1: CAPEv2 report.json -> compact per-sample event trace.

Parses each (large) report once and keeps only the API calls the timeline
stage needs, normalized to a small schema. Output: one gzipped JSONL file per
analysis, first line a header record, remaining lines events sorted by time.

Usage:
  python3 extract.py --zip capev2_corpus_backup_20260729.zip --out traces/ [--label ransomware] [--workers 3]
  python3 extract.py --dir /path/to/storage/analyses   --out traces_benign/ --label benign
"""
import argparse, collections, datetime as dt, gzip, json, math, os, re, sys, zipfile
from multiprocessing import Pool

FILE_APIS = {
    'NtCreateFile', 'NtOpenFile', 'NtWriteFile', 'NtReadFile', 'NtDeleteFile',
    'DeleteFileW', 'DeleteFileA', 'NtSetInformationFile',
    'MoveFileWithProgressW', 'MoveFileWithProgressTransactedW', 'MoveFileExW', 'MoveFileW',
    'CopyFileW', 'CopyFileA', 'CopyFileExW', 'CopyFile2', 'SetFileAttributesW',
    'FindFirstFileExW', 'FindFirstFileExA', 'NtQueryDirectoryFile', 'NtQueryDirectoryFileEx',
}
CRYPTO_APIS = {
    'CryptAcquireContextW', 'CryptAcquireContextA', 'BCryptOpenAlgorithmProvider',
    'CryptGenKey', 'CryptImportKey', 'CryptExportKey', 'CryptDeriveKey', 'CryptDecrypt',
    'BCryptGenerateSymmetricKey', 'BCryptImportKeyPair', 'BCryptGenerateKeyPair', 'BCryptImportKey',
    'CryptGenRandom', 'BCryptGenRandom', 'SystemFunction036', 'RtlGenRandom',
    'CryptEncrypt', 'BCryptEncrypt', 'CryptProtectData',
}
PROC_APIS = {
    'CreateProcessInternalW', 'NtCreateUserProcess', 'ShellExecuteExW', 'NtTerminateProcess',
    'NtOpenProcess', 'WinExec',
}
SVC_APIS = {'OpenServiceW', 'OpenServiceA', 'ControlService', 'ControlServiceExW', 'ChangeServiceConfigW', 'DeleteService'}
WMI_APIS = {'WMI_ExecQuery', 'WMI_ExecMethod', 'WMI_GetObject'}
ENUM_APIS = {'GetLogicalDrives', 'GetLogicalDriveStringsW', 'GetDriveTypeW', 'WNetOpenEnumW', 'WNetEnumResourceW', 'NetShareEnum'}
KEEP = FILE_APIS | CRYPTO_APIS | PROC_APIS | SVC_APIS | WMI_APIS | ENUM_APIS

BUF_APIS = {'NtWriteFile', 'NtReadFile', 'CryptEncrypt', 'BCryptEncrypt'}


def parse_ts(s):
    try:
        return dt.datetime.strptime(s, '%Y-%m-%d %H:%M:%S,%f').timestamp()
    except (TypeError, ValueError):
        return None


def norm_path(p):
    """Normalize NT/Win32 paths to a 'C:\\...' style string (original case)."""
    if not p:
        return ''
    p = str(p)
    for pre in ('\\??\\', '\\\\?\\', '\\\\.\\'):
        if p.startswith(pre):
            p = p[len(pre):]
    m = re.match(r'\\Device\\HarddiskVolume\d+(\\.*)$', p, re.I)
    if m:
        p = 'C:' + m.group(1)
    return p


def decode_buf(s):
    """Decode CAPE's escaped buffer string to bytes (best effort)."""
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == '\\' and i + 3 < n + 0 and s[i + 1] == 'x' and re.match(r'[0-9a-fA-F]{2}', s[i + 2:i + 4]):
            out.append(int(s[i + 2:i + 4], 16)); i += 4
        elif ch == '\\' and i + 1 < n and s[i + 1] == '\\':
            out.append(92); i += 2
        else:
            o = ord(ch)
            out.extend(bytes([o]) if o < 256 else ch.encode('utf-8')); i += 1
    return bytes(out)


def entropy(b):
    if not b:
        return None
    c = collections.Counter(b)
    n = len(b)
    return round(-sum(v / n * math.log2(v / n) for v in c.values()), 3)


def text_head(b):
    """Return a short printable preview if the buffer looks like text (ASCII or UTF-16LE)."""
    if not b:
        return None
    if len(b) >= 4 and b[1::2].count(0) >= 0.8 * len(b[1::2]):
        try:
            t = b.decode('utf-16le', 'ignore')
        except Exception:
            t = ''
    else:
        t = b.decode('latin-1')
    printable = sum(ch.isprintable() or ch in '\r\n\t' for ch in t)
    if t and printable / len(t) >= 0.85:
        return t[:80]
    return None


def args_of(call):
    d = {}
    for a in call.get('arguments') or []:
        d[a.get('name')] = a.get('pretty_value', a.get('value'))
        if 'pretty_value' in a:
            d[a.get('name') + '_raw'] = a.get('value')
    return d


def event_from_call(c, pid, t):
    api = c.get('api')
    a = args_of(c)
    e = {'t': round(t, 3), 'p': pid, 'a': api, 'ok': bool(c.get('status'))}
    if api in FILE_APIS:
        path = a.get('FileName') or a.get('HandleName') or a.get('ExistingFileName') or a.get('lpFileName') or ''
        e['f'] = norm_path(path)
        if api in ('NtCreateFile', 'NtOpenFile'):
            e['acc'] = a.get('DesiredAccess')
            e['disp'] = a.get('CreateDisposition')
            e['ex'] = a.get('ExistedBefore')
        if api.startswith('MoveFile') or api.startswith('CopyFile'):
            e['f'] = norm_path(a.get('ExistingFileName') or a.get('lpExistingFileName') or path)
            e['nf'] = norm_path(a.get('NewFileName') or a.get('lpNewFileName') or '')
        if api == 'NtSetInformationFile':
            e['fic'] = a.get('FileInformationClass')
            if 'Rename' in str(e['fic']) or 'Link' in str(e['fic']):
                fi = decode_buf(str(a.get('FileInformation') or ''))
                # FILE_RENAME_INFORMATION: name is UTF-16LE after a fixed header; recover printable tail
                try:
                    txt = fi.decode('utf-16le', 'ignore')
                    m = re.search(r'([A-Za-z]:\\[^\x00]+|\\\?\?\\[^\x00]+)', txt)
                    if m:
                        e['nf'] = norm_path(m.group(1))
                except Exception:
                    pass
            elif e['fic'] not in ('FileDispositionInformation', 'FileDispositionInformationEx',
                                  'FileEndOfFileInformation', 'FileAllocationInformation'):
                return None  # position/pipe info etc. -> noise
        if api.startswith('FindFirstFile'):
            e['f'] = norm_path(a.get('FileName') or a.get('lpFileName') or '')
        if api in ('NtQueryDirectoryFile', 'NtQueryDirectoryFileEx'):
            e['f'] = norm_path(a.get('HandleName') or a.get('FileName') or '')
        if api in BUF_APIS:
            raw = a.get('Buffer')
            if raw is not None:
                b = decode_buf(str(raw))
                e['bl'] = len(b)
                e['H'] = entropy(b)
                h = text_head(b)
                if h:
                    e['txt'] = h
            ln = a.get('Length') or a.get('BufferLength')
            if ln is not None:
                try:
                    e['len'] = int(str(ln), 0)
                except ValueError:
                    pass
    elif api in CRYPTO_APIS:
        for k in ('Algid', 'BlobType', 'Provider', 'AlgId', 'pszAlgId', 'Length'):
            if k in a:
                e[k.lower()] = str(a[k])[:60]
        if api in BUF_APIS and a.get('Buffer') is not None:
            b = decode_buf(str(a['Buffer']))
            e['bl'] = len(b); e['H'] = entropy(b)
    elif api in PROC_APIS:
        if api == 'NtTerminateProcess':
            e['h'] = a.get('ProcessHandle')
        elif api == 'NtOpenProcess':
            e['acc'] = a.get('DesiredAccess'); e['tpid'] = a.get('ProcessIdentifier')
            if 'TERMINATE' not in str(e['acc']):
                return None
        else:
            e['cmd'] = str(a.get('CommandLine') or a.get('lpParameters') or a.get('lpCmdLine') or '')[:400]
            e['img'] = norm_path(a.get('ImagePathName') or a.get('ApplicationName') or a.get('lpFile') or '')
            e['cpid'] = a.get('ProcessId')
    elif api in SVC_APIS:
        for k in ('ServiceName', 'DesiredAccess', 'ControlCode', 'dwControl', 'StartType'):
            if k in a:
                e[k.lower()] = str(a[k])[:120]
    elif api in WMI_APIS:
        e['q'] = str(a.get('Query') or a.get('Method') or a.get('ObjectPath') or '')[:300]
    elif api in ENUM_APIS:
        e['f'] = norm_path(a.get('lpRootPathName') or a.get('RootPathName') or '')
    return e


def extract(report, label):
    info = report.get('info') or {}
    target = (report.get('target') or {}).get('file') or {}
    beh = report.get('behavior') or {}
    procs = beh.get('processes') or []
    firsts = [parse_ts(p.get('first_seen')) for p in procs]
    firsts = [f for f in firsts if f is not None]
    t0 = min(firsts) if firsts else None
    events, last_t = [], None
    api_counts = collections.Counter()
    n_calls = 0
    plist = []
    for p in procs:
        pid = p.get('process_id')
        fs = parse_ts(p.get('first_seen'))
        plist.append({
            'pid': pid, 'ppid': p.get('parent_id'), 'name': p.get('process_name'),
            'path': norm_path(p.get('module_path')),
            'cmd': str((p.get('environ') or {}).get('CommandLine') or '')[:400],
            't': round(fs - t0, 3) if (fs is not None and t0 is not None) else None,
        })
        for c in p.get('calls') or []:
            n_calls += 1
            api = c.get('api')
            api_counts[api] += 1
            t = parse_ts(c.get('timestamp'))
            if t is None or t0 is None:
                continue
            rel = t - t0
            if last_t is None or rel > last_t:
                last_t = rel
            if api not in KEEP:
                continue
            e = event_from_call(c, pid, rel)
            if e is not None:
                events.append(e)
    events.sort(key=lambda e: e['t'])
    machine = info.get('machine')
    header = {
        'kind': 'header', 'label': label,
        'task': str(info.get('id')), 'sha256': target.get('sha256'), 'name': target.get('name'),
        'size': target.get('size'), 'ftype': target.get('type'),
        'package': info.get('package'), 'duration': info.get('duration'), 'timeout': info.get('timeout'),
        'started': info.get('started'), 'machine': machine.get('name') if isinstance(machine, dict) else machine,
        'malstatus': report.get('malstatus'), 'malscore': report.get('malscore'),
        'n_signatures': len(report.get('signatures') or []),
        'signature_stage_ran': bool((report.get('statistics') or {}).get('signatures')),
        't0_abs': t0, 'obs_end': round(last_t, 3) if last_t is not None else None,
        'n_calls': n_calls, 'n_events': len(events), 'procs': plist,
        'n_encbuf': len(beh.get('encryptedbuffers') or []),
        'cape_payloads': len((report.get('CAPE') or {}).get('payloads') or []) if isinstance(report.get('CAPE'), dict) else 0,
        'api_counts': {k: v for k, v in api_counts.items() if k in KEEP},
        'summary_counts': {k: len(v or []) for k, v in (beh.get('summary') or {}).items() if isinstance(v, list)},
    }
    return header, events


def write_trace(out_dir, key, header, events):
    tmp = os.path.join(out_dir, key + '.jsonl.gz.tmp')
    with gzip.open(tmp, 'wt', encoding='utf-8') as f:
        f.write(json.dumps(header) + '\n')
        for e in events:
            f.write(json.dumps(e, separators=(',', ':')) + '\n')
    os.replace(tmp, os.path.join(out_dir, key + '.jsonl.gz'))


def _job(args):
    src, member, key, out_dir, label = args
    try:
        if src.endswith('.zip'):
            with zipfile.ZipFile(src) as z:
                report = json.loads(z.read(member))
        else:
            with open(member, 'rb') as f:
                report = json.load(f)
        header, events = extract(report, label)
        header['task'] = key
        write_trace(out_dir, key, header, events)
        return key, None
    except Exception as ex:  # keep going; report at the end
        return key, f'{type(ex).__name__}: {ex}'


def list_jobs(src, out_dir, label):
    jobs = []
    if src.endswith('.zip'):
        with zipfile.ZipFile(src) as z:
            for n in z.namelist():
                m = re.match(r'(?:.*/)?analyses/([^/]+)/reports/report\.json$', n)
                if m and m.group(1) != 'latest':
                    jobs.append((src, n, m.group(1), out_dir, label))
    else:
        for d in sorted(os.listdir(src)):
            p = os.path.join(src, d, 'reports', 'report.json')
            if d != 'latest' and os.path.isfile(p):
                jobs.append((src, p, d, out_dir, label))
    return jobs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--zip', help='zip archive containing analyses/<id>/reports/report.json')
    g.add_argument('--dir', help='directory containing <id>/reports/report.json')
    ap.add_argument('--out', required=True)
    ap.add_argument('--label', default='ransomware')
    ap.add_argument('--workers', type=int, default=3, help='each worker may need ~2-3 GB RAM for the largest reports')
    ap.add_argument('--force', action='store_true', help='re-extract traces that already exist')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    src = a.zip or a.dir
    jobs = list_jobs(src, a.out, a.label)
    if not a.force:
        jobs = [j for j in jobs if not os.path.exists(os.path.join(a.out, j[2] + '.jsonl.gz'))]
    print(f'{len(jobs)} reports to extract -> {a.out}', flush=True)
    errors = []
    with Pool(a.workers) as pool:
        for i, (key, err) in enumerate(pool.imap_unordered(_job, jobs, chunksize=1), 1):
            if err:
                errors.append((key, err))
            if i % 50 == 0 or i == len(jobs):
                print(f'  {i}/{len(jobs)} done, {len(errors)} errors', flush=True)
    for key, err in errors:
        print(f'ERROR {key}: {err}', file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == '__main__':
    main()
