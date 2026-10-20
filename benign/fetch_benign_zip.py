"""Download portable (zipped) benign apps and extra single-file tools from official sources.

Zipped apps are kept as the zip (CAPE's 'zip' package extracts it in the guest and runs the file named
in the 'file' option). Writes batch1/zipapps.csv (program, tag, url, zip, zip_sha256, inner_exe, verified)
and appends the single-file extras to batch1/downloads.csv. Skips anything over MAX_MB (guest agent limit).

  python3 fetch_benign_zip.py --out batch1 [--only cmake,ouch]
"""
import argparse, csv, hashlib, json, os, re, urllib.request, zipfile

UA = {'User-Agent': 'benign-baseline-fetch'}
MAX_MB = 100
# program -> (repo, asset regex, inner exe regex, checksum-asset regex or None)
ZIPGH = {
    'cmake':      ('Kitware/CMake', r'^cmake-[\d.]+-windows-x86_64\.zip$', r'bin/cmake\.exe$', r'^cmake-[\d.]+-SHA-256\.txt$'),
    'notepad++':  ('notepad-plus-plus/notepad-plus-plus', r'^npp\.[\d.]+\.portable\.x64\.zip$', r'^notepad\+\+\.exe$', r'^checksums\.sha256$'),
    'keepassxc':  ('keepassxreboot/keepassxc', r'^KeePassXC-[\d.]+-Win64\.zip$', r'KeePassXC\.exe$', r'^KeePassXC-[\d.]+-Win64\.zip\.DIGEST$'),
    'windirstat': ('windirstat/windirstat', r'x64.*\.zip$', r'WinDirStat\.exe$', None),
    'clamav':     ('Cisco-Talos/clamav', r'^clamav-[\d.]+\.win\.x64\.zip$', r'clamscan\.exe$', None),
    'peazip':     ('peazip/PeaZip', r'^peazip_portable-[\d.]+\.WIN64\.zip$', r'peazip\.exe$', None),
    'mingit':     ('git-for-windows/git', r'^MinGit-[\d.]+-64-bit\.zip$', r'^cmd/git\.exe$', None),
}
# single-file extras: program -> (repo, asset regex, exe name in the zip or None for a bare exe)
SINGLE = {
    'ouch':       ('ouch-org/ouch', r'^ouch-x86_64-pc-windows-msvc\.zip$', 'ouch.exe'),
    'dust':       ('bootandy/dust', r'^dust-v[\d.]+-x86_64-pc-windows-msvc\.zip$', 'dust.exe'),
    'tokei':      ('XAMPPRocky/tokei', r'^tokei-x86_64-pc-windows-msvc\.exe$', None),
    'sd':         ('chmln/sd', r'^sd-v[\d.]+-x86_64-pc-windows-msvc\.zip$', 'sd.exe'),
    'zoxide':     ('ajeetdsouza/zoxide', r'^zoxide-[\d.]+-x86_64-pc-windows-msvc\.zip$', 'zoxide.exe'),
    'difftastic': ('Wilfred/difftastic', r'^difft-x86_64-pc-windows-msvc\.zip$', 'difft.exe'),
    'xh':         ('ducaale/xh', r'^xh-v[\d.]+-x86_64-pc-windows-msvc\.zip$', 'xh.exe'),
    'just':       ('casey/just', r'^just-[\d.]+-x86_64-pc-windows-msvc\.zip$', 'just.exe'),
}


# extra tools whose asset names vary: program -> repo; first Windows x64 zip/exe asset is taken
LOOSE = {'lz4': 'lz4/lz4', 'duplicacy': 'gilbertchen/duplicacy', 'croc': 'schollz/croc', 'gdu': 'dundee/gdu',
         'micro': 'zyedidia/micro', 'yq': 'mikefarah/yq', 'fzf': 'junegunn/fzf', 'bottom': 'ClementTsang/bottom',
         'lsd': 'lsd-rs/lsd', 'hexyl': 'sharkdp/hexyl', 'eza': 'eza-community/eza', 'gh': 'cli/cli', 'nushell': 'nushell/nushell'}
BADWORDS = re.compile(r'arm|aarch|i686|386|32|musl|gnu|\.sha|sig|asc|\.msi|checksum|sbom|pdb|7z|tar|gz|freebsd|linux|darwin|macos|source|src', re.I)


def get(url, binary=True):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=180) as r:
        b = r.read()
    return b if binary else b.decode('utf-8', 'replace')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def verify(blob, name, txt):
    h = sha(blob)
    return 'MATCH' if re.search(rf'{h}', txt, re.I) else 'MISMATCH'


def inner_exe(z, pat):
    return next(m for m in z.namelist() if re.search(pat, m, re.I))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--out', required=True); ap.add_argument('--only', default='')
    a = ap.parse_args()
    arch, stage = os.path.join(a.out, 'archives'), os.path.join(a.out, 'staging')
    zrows, srows = [], []

    def want(n):
        return not a.only or n in a.only.split(',')

    def gh(repo, pat, csum=None):
        rel = json.loads(get(f'https://api.github.com/repos/{repo}/releases/latest', False))
        asset = next(x for x in rel['assets'] if re.search(pat, x['name']))
        if asset['size'] > MAX_MB * 1e6:
            raise RuntimeError(f'{asset["size"]/1e6:.0f} MB > {MAX_MB} MB guest limit')
        blob = get(asset['browser_download_url']); ver = 'no published checksum'
        if csum:
            ca = next((x for x in rel['assets'] if re.search(csum, x['name'])), None)
            if ca:
                ver = verify(blob, asset['name'], get(ca['browser_download_url'], False))
        return rel['tag_name'], asset, blob, ver

    for name, (repo, pat, ipat, csum) in ZIPGH.items():
        if not want(name):
            continue
        try:
            tag, asset, blob, ver = gh(repo, pat, csum)
            fn = os.path.join(stage, asset['name']); open(fn, 'wb').write(blob)
            inner = inner_exe(zipfile.ZipFile(fn), ipat)
            zrows.append([name, tag, asset['browser_download_url'], asset['name'], sha(blob), inner, ver])
            print(f'{name:11s} {tag:12s} {asset["name"][:34]:34s} {len(blob)/1e6:6.1f} MB  inner={inner}  {ver}')
        except Exception as e:
            print(f'{name:11s} FAILED: {type(e).__name__}: {str(e)[:80]}')
    # node.js (official dist index with SHASUMS256)
    if want('node'):
        try:
            base = 'https://nodejs.org/dist/latest/'; sums = get(base + 'SHASUMS256.txt', False)
            h, nm = re.search(r'([0-9a-f]{64})\s+(node-v[\d.]+-win-x64\.zip)', sums).groups()
            blob = get(base + nm); ver = 'MATCH' if sha(blob) == h else 'MISMATCH'
            fn = os.path.join(stage, nm); open(fn, 'wb').write(blob)
            zrows.append(['node', nm.split('-')[1], base + nm, nm, sha(blob), inner_exe(zipfile.ZipFile(fn), r'/node\.exe$'), ver])
            print(f'node        {nm} {len(blob)/1e6:.1f} MB {ver}')
        except Exception as e:
            print(f'node        FAILED: {type(e).__name__}: {str(e)[:80]}')
    # VLC portable zip (official mirror directory with .sha256)
    if want('vlc'):
        try:
            base = 'https://get.videolan.org/vlc/last/win64/'; idx = get(base, False)
            nm = re.search(r'(vlc-[\d.]+-win64\.zip)"', idx).group(1)
            blob = get(base + nm); ver = verify(blob, nm, get(base + nm + '.sha256', False))
            fn = os.path.join(stage, nm); open(fn, 'wb').write(blob)
            zrows.append(['vlc', nm.split('-')[1], base + nm, nm, sha(blob), inner_exe(zipfile.ZipFile(fn), r'/vlc\.exe$'), ver])
            print(f'vlc         {nm} {len(blob)/1e6:.1f} MB {ver}')
        except Exception as e:
            print(f'vlc         FAILED: {type(e).__name__}: {str(e)[:80]}')
    for name, (repo, pat, exe) in SINGLE.items():
        if not want(name):
            continue
        try:
            tag, asset, blob, ver = gh(repo, pat)
            os.makedirs(arch, exist_ok=True); open(os.path.join(arch, asset['name']), 'wb').write(blob)
            if exe:
                z = zipfile.ZipFile(os.path.join(arch, asset['name']))
                member = next(m for m in z.namelist() if m.lower().endswith(exe) )
                data, fname = z.read(member), os.path.basename(member)
            else:
                data, fname = blob, asset['name']
            open(os.path.join(stage, fname), 'wb').write(data)
            srows.append([name, tag, asset['browser_download_url'], sha(blob), fname, sha(data), ver])
            print(f'{name:11s} {tag:12s} {fname:34s} {len(data)/1e6:6.1f} MB  {ver}')
        except Exception as e:
            print(f'{name:11s} FAILED: {type(e).__name__}: {str(e)[:80]}')
    for name, repo in LOOSE.items():
        if not want(name):
            continue
        try:
            rel = json.loads(get(f'https://api.github.com/repos/{repo}/releases/latest', False))
            cands = [x for x in rel['assets'] if re.search(r'(windows|win)', x['name'], re.I) and re.search(r'(amd64|x64|x86_64|64)', x['name'], re.I)
                     and re.search(r'\.(zip|exe)$', x['name'], re.I) and not BADWORDS.search(x['name'].replace('windows', '').replace('win64', ''))]
            asset = cands[0]
            if asset['size'] > MAX_MB * 1e6:
                raise RuntimeError(f'{asset["size"]/1e6:.0f} MB > {MAX_MB} MB guest limit')
            blob = get(asset['browser_download_url']); os.makedirs(arch, exist_ok=True)
            open(os.path.join(arch, asset['name']), 'wb').write(blob)
            if asset['name'].lower().endswith('.zip'):
                z = zipfile.ZipFile(os.path.join(arch, asset['name']))
                member = next(m for m in z.namelist() if m.lower().endswith('.exe') and not m.lower().endswith('uninstall.exe'))
                data, fname = z.read(member), os.path.basename(member)
            else:
                data, fname = blob, asset['name']
            open(os.path.join(stage, fname), 'wb').write(data)
            srows.append([name, rel['tag_name'], asset['browser_download_url'], sha(blob), fname, sha(data), 'no published checksum'])
            print(f'{name:11s} {rel["tag_name"]:12s} {fname:34s} {len(data)/1e6:6.1f} MB  (from {asset["name"][:40]})')
        except Exception as e:
            print(f'{name:11s} FAILED: {type(e).__name__}: {str(e)[:80]}')
    zp = os.path.join(a.out, 'zipapps.csv'); new = not os.path.exists(zp)
    with open(zp, 'a', newline='') as f:
        w = csv.writer(f)
        if new: w.writerow(['program', 'tag', 'url', 'zip', 'zip_sha256', 'inner_exe', 'checksum_verified'])
        w.writerows(zrows)
    with open(os.path.join(a.out, 'downloads.csv'), 'a', newline='') as f:
        csv.writer(f).writerows(srows)


if __name__ == '__main__':
    main()
