"""Generate a deterministic set of realistic user files to seed the benign-baseline guest.

The ransomware corpus ran on a guest whose Documents/Pictures folders were empty, so benign tools
pointed at them would do nothing. This builds ~300 files (text, CSV, OOXML documents, PDFs, JPEG/PNG
images) under Documents/ Pictures/ Desktop/, a zip to upload with the CAPE agent's /extract endpoint, and
a manifest (path, size, sha256, entropy) usable later for canary-style verification.

  python3 make_seed_data.py --out ~/benign_seed [--seed 2026]
"""
import argparse, csv, hashlib, io, math, os, random, zipfile

from PIL import Image, ImageDraw

SYL = ['ka', 'lo', 'mi', 'ra', 'tu', 'ne', 'so', 'vi', 'da', 'pe', 'qua', 'zen', 'bri', 'tho', 'lum', 'car', 'fen', 'gor', 'han', 'jul']
TOPICS = ['budget', 'meeting', 'project', 'invoice', 'report', 'thesis', 'notes', 'plan', 'review', 'schedule', 'draft', 'summary']


def words(rng, n):
    vocab = [''.join(rng.choice(SYL) for _ in range(rng.randint(1, 3))) for _ in range(250)]
    return ' '.join(rng.choice(vocab) for _ in range(n))


def text_file(rng, kb):
    out, size = [], 0
    while size < kb * 1024:
        line = words(rng, rng.randint(8, 18)).capitalize() + '.\n'
        out.append(line); size += len(line)
    return ''.join(out).encode()


def csv_file(rng, kb):
    buf = io.StringIO(); w = csv.writer(buf); w.writerow(['id', 'date', 'name', 'amount', 'category', 'note'])
    i = 0
    while buf.tell() < kb * 1024:
        i += 1; w.writerow([i, f'2025-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}', words(rng, 2), f'{rng.uniform(1, 9999):.2f}', rng.choice(TOPICS), words(rng, 4)])
    return buf.getvalue().encode()


def zinfo(name):
    zi = zipfile.ZipInfo(name, date_time=(2025, 1, 1, 0, 0, 0)); zi.compress_type = zipfile.ZIP_DEFLATED; return zi


def ooxml(rng, kind):
    paras = ''.join(f'<w:p><w:r><w:t>{words(rng, rng.randint(20, 60))}</w:t></w:r></w:p>' for _ in range(rng.randint(15, 60)))
    ct = ('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>')
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
        if kind == 'docx':
            z.writestr(zinfo('[Content_Types].xml'), ct + '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            z.writestr(zinfo('_rels/.rels'), '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
            z.writestr(zinfo('word/document.xml'), f'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{paras}</w:body></w:document>')
        else:
            rows = ''.join(f'<row r="{r}">' + ''.join(f'<c r="{chr(65 + c)}{r}"><v>{rng.randint(0, 99999)}</v></c>' for c in range(8)) + '</row>' for r in range(1, rng.randint(80, 300)))
            z.writestr(zinfo('[Content_Types].xml'), ct + '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
            z.writestr(zinfo('_rels/.rels'), '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
            z.writestr(zinfo('xl/workbook.xml'), '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>')
            z.writestr(zinfo('xl/worksheets/sheet1.xml'), f'<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{rows}</sheetData></worksheet>')
    return b.getvalue()


def pdf_file(rng):
    text = ' '.join(words(rng, 12) for _ in range(rng.randint(20, 80)))
    stream = f'BT /F1 11 Tf 50 750 Td ({text[:900].replace("(", "").replace(")", "")}) Tj ET'
    objs = ['<</Type/Catalog/Pages 2 0 R>>', '<</Type/Pages/Kids[3 0 R]/Count 1>>',
            '<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>',
            f'<</Length {len(stream)}>>\nstream\n{stream}\nendstream', '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>']
    out, offs = '%PDF-1.4\n', []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += f'{i} 0 obj\n{o}\nendobj\n'
    xr = len(out); out += f'xref\n0 {len(objs) + 1}\n0000000000 65535 f \n' + ''.join(f'{o:010d} 00000 n \n' for o in offs)
    out += f'trailer\n<</Size {len(objs) + 1}/Root 1 0 R>>\nstartxref\n{xr}\n%%EOF\n'
    return out.encode()


def image(rng, fmt, w=1280, h=960):
    im = Image.new('RGB', (w, h)); d = ImageDraw.Draw(im)
    c1 = tuple(rng.randint(30, 225) for _ in range(3)); c2 = tuple(rng.randint(30, 225) for _ in range(3))
    for y in range(h):
        t = y / h; d.line([(0, y), (w, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(c1, c2)))
    for _ in range(40):
        x, y = rng.randint(0, w), rng.randint(0, h); r = rng.randint(20, 200)
        d.ellipse([x - r, y - r, x + r, y + r], outline=tuple(rng.randint(0, 255) for _ in range(3)), width=rng.randint(2, 8))
    px = im.load()
    for _ in range(w * h // 6):                       # photo-like noise so JPEGs are realistically sized
        x, y = rng.randrange(w), rng.randrange(h); p = px[x, y]
        px[x, y] = tuple(max(0, min(255, v + rng.randint(-25, 25))) for v in p)
    b = io.BytesIO(); im.save(b, fmt, **({'quality': 85} if fmt == 'JPEG' else {})); return b.getvalue()


def entropy(b):
    if not b: return 0.0
    c = [0] * 256
    for x in b[:65536]: c[x] += 1
    n = min(len(b), 65536); return -sum(v / n * math.log2(v / n) for v in c if v)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--out', required=True); ap.add_argument('--seed', type=int, default=2026)
    a = ap.parse_args(); rng = random.Random(a.seed); root = os.path.expanduser(a.out)
    files = {}
    for i in range(110): files[f'Documents/{rng.choice(["Work", "Personal", "School", "Notes"])}/{rng.choice(TOPICS)}_{i:03d}.txt'] = text_file(rng, rng.randint(1, 50))
    for i in range(40): files[f'Documents/Finance/{rng.choice(TOPICS)}_{i:03d}.csv'] = csv_file(rng, rng.randint(10, 250))
    for i in range(45): files[f'Documents/{rng.choice(["Work", "School", "Reports"])}/{rng.choice(TOPICS)}_{i:03d}.docx'] = ooxml(rng, 'docx')
    for i in range(25): files[f'Documents/Finance/sheet_{i:03d}.xlsx'] = ooxml(rng, 'xlsx')
    for i in range(30): files[f'Documents/Reports/{rng.choice(TOPICS)}_{i:03d}.pdf'] = pdf_file(rng)
    for i in range(45): files[f'Pictures/{rng.choice(["2024", "2025", "Holiday"])}/IMG_{i:04d}.jpg'] = image(rng, 'JPEG')
    for i in range(10): files[f'Pictures/Screenshots/shot_{i:03d}.png'] = image(rng, 'PNG', 800, 500)
    for i in range(8): files[f'Desktop/note_{i}.txt'] = text_file(rng, rng.randint(1, 5))
    os.makedirs(root, exist_ok=True)
    man = csv.writer(open(os.path.join(root, 'manifest.csv'), 'w', newline='')); man.writerow(['path', 'size', 'sha256', 'entropy_bits_per_byte'])
    with zipfile.ZipFile(os.path.join(root, 'seed.zip'), 'w', zipfile.ZIP_STORED) as z:
        for p, b in sorted(files.items()):
            zi = zipfile.ZipInfo(p, date_time=(2025, 1, 1, 0, 0, 0)); z.writestr(zi, b); man.writerow([p, len(b), hashlib.sha256(b).hexdigest(), f'{entropy(b):.2f}'])
    tot = sum(len(b) for b in files.values())
    print(f'{len(files)} files, {tot / 1e6:.1f} MB -> {root}/seed.zip, manifest.csv')


if __name__ == '__main__':
    main()
