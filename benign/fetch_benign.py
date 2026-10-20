"""Download benign programs from their official GitHub releases / vendor URLs, verify published
checksums where the project provides them, extract the main executable, and record everything.

  python3 fetch_benign.py --out batch1 [--only restic,age]
Writes batch1/downloads.csv (program, tag, url, archive_sha256, exe, exe_sha256, checksum_verified).
Archives go to batch1/archives/, the executables CAPE will run to batch1/staging/ (neither committed).
"""
import argparse, csv, hashlib, json, os, re, urllib.request, zipfile

UA = {'User-Agent': 'benign-baseline-fetch'}
# name -> (github repo, asset regex, executable name inside the zip, checksum asset regex or None)
GH = {
    'zstd':      ('facebook/zstd', r'^zstd-v[\d.]+-win64\.zip$', 'zstd.exe', None),
    'restic':    ('restic/restic', r'^restic_[\d.]+_windows_amd64\.zip$', None, r'^SHA256SUMS$'),
    'kopia':     ('kopia/kopia', r'^kopia-[\d.]+-windows-x64\.zip$', 'kopia.exe', r'^checksums\.txt$'),
    'age':       ('FiloSottile/age', r'^age-v[\d.]+-windows-amd64\.zip$', 'age.exe', None),
    'rage':      ('str4d/rage', r'^rage-v[\d.]+-x86_64-windows\.zip$', 'rage.exe', None),
    'picocrypt': ('Picocrypt/Picocrypt', r'^Picocrypt\.exe$', None, r'^(SHA256SUMS|checksums\.txt)$'),
    'syncthing': ('syncthing/syncthing', r'^syncthing-windows-amd64-v[\d.]+\.zip$', 'syncthing.exe', r'^sha256sum\.txt\.asc$'),
    'xz':        ('tukaani-project/xz', r'^xz-[\d.]+-windows\.zip$', 'xz.exe', None),
    'handbrake': ('HandBrake/HandBrake', r'HandBrakeCLI.*win.*x86_64.*\.zip$', 'HandBrakeCLI.exe', None),
    'sumatra':   ('sumatrapdfreader/sumatrapdf', r'^SumatraPDF-[\d.]+-64\.zip$', r're:SumatraPDF.*\.exe$', None),
    'ripgrep':   ('BurntSushi/ripgrep', r'^ripgrep-[\d.]+-x86_64-pc-windows-msvc\.zip$', 'rg.exe', None),
    'fd':        ('sharkdp/fd', r'^fd-v[\d.]+-x86_64-pc-windows-msvc\.zip$', 'fd.exe', None),
    'bat':       ('sharkdp/bat', r'^bat-v[\d.]+-x86_64-pc-windows-msvc\.zip$', 'bat.exe', None),
    'hyperfine': ('sharkdp/hyperfine', r'^hyperfine-v[\d.]+-x86_64-pc-windows-msvc\.zip$', 'hyperfine.exe', None),
    'delta':     ('dandavison/delta', r'^delta-[\d.]+-x86_64-pc-windows-msvc\.zip$', 'delta.exe', None),
    'jq':        ('jqlang/jq', r'^jq-windows-amd64\.exe$', None, r'^sha256sum\.txt$'),
    '7zr':       ('ip7z/7zip', r'^7zr\.exe$', None, None),
}


def get(url, binary=True):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
        b = r.read()
    return b if binary else b.decode('utf-8', 'replace')


def sha(b):
    return hashlib.sha256(b).hexdigest()


# direct vendor downloads: name -> (url, exe inside zip or None, checksum file url + file name in it, or None)
_rv = None
try:
    _rv = get('https://downloads.rclone.org/version.txt', False).split()[-1]
except Exception:
    pass
DIRECT = {
    'rclone':  (f'https://downloads.rclone.org/{_rv}/rclone-{_rv}-windows-amd64.zip', 'rclone.exe',
                (f'https://downloads.rclone.org/{_rv}/SHA256SUMS', f'rclone-{_rv}-windows-amd64.zip')),
    'sdelete': ('https://download.sysinternals.com/files/SDelete.zip', 'sdelete64.exe', None),
}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--out', required=True); ap.add_argument('--only', default='')
    a = ap.parse_args()
    arch, stage = os.path.join(a.out, 'archives'), os.path.join(a.out, 'staging')
    os.makedirs(arch, exist_ok=True); os.makedirs(stage, exist_ok=True)
    rows = []
    for name, (repo, pat, exe, csum) in GH.items():
        if a.only and name not in a.only.split(','):
            continue
        try:
            rel = json.loads(get(f'https://api.github.com/repos/{repo}/releases/latest', False))
            asset = next(x for x in rel['assets'] if re.search(pat, x['name']))
            blob = get(asset['browser_download_url'])
            verified = 'no published checksum'
            if csum:
                ca = next((x for x in rel['assets'] if re.search(csum, x['name'])), None)
                if ca:
                    txt = get(ca['browser_download_url'], False)
                    verified = 'MATCH' if re.search(rf'{sha(blob)}\s+\*?{re.escape(asset["name"])}', txt) else 'MISMATCH'
            adir = os.path.join(arch, asset['name']); open(adir, 'wb').write(blob)
            if asset['name'].endswith('.zip'):
                z = zipfile.ZipFile(adir)
                member = next(m for m in z.namelist() if re.search(exe[3:], m, re.I)) if exe and exe.startswith('re:') else next(m for m in z.namelist() if (exe and m.lower().endswith('/' + exe.lower()) or m.lower() == (exe or '').lower())
                              ) if exe else next(m for m in z.namelist() if m.lower().endswith('.exe') and 'restic' in m.lower())
                data = z.read(member); fname = os.path.basename(member)
            else:
                data, fname = blob, asset['name']
            open(os.path.join(stage, fname), 'wb').write(data)
            rows.append([name, rel['tag_name'], asset['browser_download_url'], sha(blob), fname, sha(data), verified])
            print(f'{name:10s} {rel["tag_name"]:12s} {fname:16s} {len(data)/1e6:6.1f} MB  {verified}')
        except Exception as e:
            print(f'{name:10s} FAILED: {type(e).__name__}: {e}')
    for name, (url, exe, cs) in DIRECT.items():
        if a.only and name not in a.only.split(','):
            continue
        try:
            blob = get(url); verified = 'no published checksum'
            if cs:
                txt = get(cs[0], False)
                m = re.search(rf'^([0-9a-f]{{64}})\s+{re.escape(cs[1])}\s*$', txt, re.M)
                verified = 'MATCH' if m and m.group(1) == sha(blob) else 'NO MATCH/NOT LISTED (current-name file)'
            fn = os.path.join(arch, os.path.basename(url)); open(fn, 'wb').write(blob)
            z = zipfile.ZipFile(fn); member = next(m for m in z.namelist() if m.lower().endswith('/' + exe) or m.lower() == exe)
            data = z.read(member); fname = os.path.basename(member)
            open(os.path.join(stage, fname), 'wb').write(data)
            rows.append([name, 'current', url, sha(blob), fname, sha(data), verified])
            print(f'{name:10s} {"current":12s} {fname:16s} {len(data)/1e6:6.1f} MB  {verified}')
        except Exception as e:
            print(f'{name:10s} FAILED: {type(e).__name__}: {e}')
    new = not os.path.exists(os.path.join(a.out, 'downloads.csv'))
    with open(os.path.join(a.out, 'downloads.csv'), 'a', newline='') as f:
        w = csv.writer(f)
        if new: w.writerow(['program', 'tag', 'url', 'archive_sha256', 'exe', 'exe_sha256', 'checksum_verified'])
        w.writerows(rows)


if __name__ == '__main__':
    main()
