"""Build a blind human-annotation workbook for validating the damage heuristic.

Selects 100 executed ransomware samples (seed 2026): up to 30 that the heuristic
does not mark as damaged but that modify at least one victim file, and damaged
samples (stratified by family) for the rest. For each, the workbook lists the first 12
modifications of distinct victim files in neutral form (time, action, path,
entropy, size, new name, text preview) WITHOUT the heuristic's verdict, and asks:
  Q1  Did this sample damage victim files?             Yes / No / Unsure
  Q2  If yes, at which event does damage first occur?  1-12 or "later"
  Q3  Is the detected ransom-note text a real note?    Yes / No / Unsure / N/A
The heuristic's answers go to a separate key file that annotators must not see.
Each annotator gets an identical copy and fills it in independently.

  .venv/bin/python annotation_sheet.py --results results --traces traces \
      --labels results/family_labels.csv --out annotation
"""
import argparse, gzip, json, os, random

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.datavalidation import DataValidation

import timeline
from timeline import (DELETE_APIS, MOVE_APIS, VICTIM_DAMAGE_ZONES, is_real_file,
                      looks_like_note, sandbox_dirs_in_trace, zone)

N_DAMAGED, N_UNDAMAGED, MAX_EVENTS, SEED = 70, 30, 12, 2026
FONT = 'Arial'
FILL_IN = PatternFill('solid', fgColor='FFF2CC')     # yellow: cells annotators fill in
HEAD = PatternFill('solid', fgColor='D9E2F3')
SAMPLE = PatternFill('solid', fgColor='EDEDED')
THIN = Side(style='thin', color='BFBFBF')


def clean(s):
    """Printable text for a cell: control/non-printable bytes shown as a middle dot."""
    return ''.join(ch if ch.isprintable() else '\u00b7' for ch in (s or ''))


def load_trace(path):
    with gzip.open(path, 'rt') as f:
        header = json.loads(f.readline())
        events = [json.loads(l) for l in f]
    # same attribution as the timeline stage: drop launcher shells and Windows helpers outside the sample
    timeline.IGNORE_PROCS = {x for x in timeline.DEFAULT_IGNORE_PROCS.split(',') if x}
    drop = timeline.attribution_drop_pids(header)
    if drop:
        events = [e for e in events if e.get('p') not in drop]
    return header, events


def victim_events(events, sandbox):
    """First modifications of distinct victim files: [(t, action, path, detail, preview, raw)]."""
    out, seen = [], set()
    for e in sorted((e for e in events if 't' in e), key=lambda e: float(e['t'])):
        api, ok, f = e.get('a', ''), e.get('ok'), e.get('f', '')
        if not ok or not is_real_file(f) or zone(f, sandbox) not in VICTIM_DAMAGE_ZONES:
            continue
        if api == 'NtWriteFile':
            act = 'write'
            h = e.get('H')
            detail = f'entropy {float(h):.2f} bits/byte over {e.get("bl")} bytes' if h is not None else f'{e.get("len")} bytes'
            preview = clean(e.get('txt'))[:80]
        elif api in MOVE_APIS or (api == 'NtSetInformationFile' and e.get('nf')):
            act, detail, preview = 'rename', 'new name: ' + (e.get('nf') or '').rsplit('\\', 1)[-1], ''
        elif api in DELETE_APIS:
            act, detail, preview = 'delete', '', ''
        else:
            continue
        key = (f.lower(), act)
        if key in seen:
            continue
        seen.add(key)
        out.append((float(e['t']), act, f, detail, preview, e))
        if len(out) == MAX_EVENTS:
            break
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--results', required=True)
    ap.add_argument('--traces', required=True)
    ap.add_argument('--labels', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    t = pd.read_csv(f'{a.results}/timelines.csv', dtype={'task': str})
    lab = pd.read_csv(a.labels, dtype={'task': str})
    corpus_sb = {l.split('\t')[0] for l in open(f'{a.results}/sandbox_dirs.txt') if l.strip().endswith('CORPUS')}
    dmg = {}
    with gzip.open(f'{a.results}/damage.jsonl.gz', 'rt') as f:
        for line in f:
            d = json.loads(line)
            dmg[str(d['task'])] = d['events']
    r = t.merge(lab[['task', 'family', 'category']], on='task')
    r = r[(r.category == 'ransomware') & r.executed]

    rng = random.Random(SEED)
    data, cand = {}, sorted(r[r.t_damage.isna()].task)
    rng.shuffle(cand)
    und = []
    for task in cand:   # undamaged samples need at least one victim-file event to judge
        h, ev = load_trace(f'{a.traces}/{task}.jsonl.gz')
        sb = corpus_sb | sandbox_dirs_in_trace(ev)
        ve = victim_events(ev, sb)
        if ve:
            und.append(task); data[task] = (h, ve, ev, sb)
        if len(und) == N_UNDAMAGED:
            break
    # damaged samples fill the rest of the 100, stratified by family, then topped up at random
    n_dam = N_DAMAGED + N_UNDAMAGED - len(und)
    damaged = r[r.t_damage.notna()]
    picks = []
    for fam, g in damaged.groupby('family'):
        k = round(n_dam * len(g) / len(damaged))
        picks += rng.sample(sorted(g.task), min(k, len(g)))
    rest = sorted(set(damaged.task) - set(picks))
    rng.shuffle(rest)
    picks = (picks + rest)[:n_dam]
    for task in picks:
        h, ev = load_trace(f'{a.traces}/{task}.jsonl.gz')
        sb = corpus_sb | sandbox_dirs_in_trace(ev)
        data[task] = (h, victim_events(ev, sb), ev, sb)

    order = picks + und
    rng.shuffle(order)
    rows = r.set_index('task')
    key = []
    samples = []
    for i, task in enumerate(order, 1):
        sid = f'S{i:03d}'
        h, ve, ev, sb = data[task]
        row = rows.loc[task]
        first = dmg.get(task, [None])[0] if pd.notna(row.t_damage) else None
        idx = ''
        if first:
            for j, (te, act, f, *_ ) in enumerate(ve, 1):
                if abs(te - first[0]) < 1e-6 and f.lower() == first[1].lower():
                    idx = j; break
            idx = idx or 'later'
        note = next((e for e in sorted((e for e in ev if 't' in e), key=lambda e: float(e['t']))
                     if e.get('a') == 'NtWriteFile' and e.get('ok') and is_real_file(e.get('f', ''))
                     and zone(e['f'], sb) in VICTIM_DAMAGE_ZONES and looks_like_note(e)), None)
        key.append({'id': sid, 'task': task, 'family': row.family,
                    'heuristic_damaged': 'Yes' if first else 'No', 'heuristic_first_event': idx,
                    'note_detected': 'Yes' if note else 'No'})
        samples.append((sid, float(row.obs_end), ve, note))

    pd.DataFrame(key).to_csv(os.path.join(a.out, 'KEY_do_not_share.csv'), index=False)
    for who in ('A', 'B'):
        write_book(os.path.join(a.out, f'annotation_annotator_{who}.xlsx'), samples, who)
    print(f'{len(samples)} samples ({len(picks)} heuristic-damaged, {len(und)} not) -> {a.out}')


def write_book(path, samples, who):
    wb = Workbook()
    ins = wb.active
    ins.title = 'Instructions'
    text = [
        ('Ransomware damage annotation', True),
        (f'Annotator {who}. Work alone: do not discuss samples with the other annotator until both sheets are done.', False),
        ('', False),
        ('For each sample, the Annotate sheet lists the first (up to) 12 modifications of distinct VICTIM files', False),
        ('(user folders, AppData, Program Files, drive root) in time order. Sandbox and Windows system files are excluded.', False),
        ('A few of the sandbox\'s own files can still appear (for example C:\\agent.py, or a folder named CAPE inside a', False),
        ('randomly named folder directly under C:\\). Events on those files are NOT damage to a victim: skip them and say so in Notes.', False),
        ('', False),
        ('"Damage" means an irreversible change to a victim file: its content replaced with encrypted/random data,', False),
        ('a rename to a ransomware extension, or a deletion. Ordinary activity (small settings/log writes, readable', False),
        ('text, a ransom note itself) is NOT damage.', False),
        ('Hints: entropy near 8 bits/byte means random-looking (encrypted) content; ordinary text is about 4-5.', False),
        ('', False),
        ('Fill in only the yellow cells, on each sample\'s grey header row:', True),
        ('  Q1  Did this sample damage victim files?  Yes / No / Unsure', False),
        ('  Q2  If Q1 = Yes: the event number (1-12) where damage first occurs, or "later" if none of the listed events is damage.', False),
        ('  Q3  If a "Ransom note text" is shown: is it a real ransom note?  Yes / No / Unsure.  Otherwise N/A.', False),
        ('  Notes: optional, anything unclear.', False),
        ('', False),
        ('Example (format only, not a real sample):', True),
    ]
    for i, (s, bold) in enumerate(text, 1):
        c = ins.cell(row=i, column=1, value=s)
        c.font = Font(name=FONT, bold=bold, size=12 if i == 1 else 10)
    ex = len(text) + 1
    hdr = ['ID / #', 'Time (s)', 'Action', 'Victim file', 'Detail', 'Content preview', 'Q1 damage?', 'Q2 first event', 'Q3 note real?', 'Notes']
    for j, hname in enumerate(hdr, 1):
        c = ins.cell(row=ex, column=j, value=hname); c.font = Font(name=FONT, bold=True, size=9); c.fill = HEAD
    exrows = [['S000', 'ran 120 s', '', 'Ransom note text: "All your files are encrypted. Contact ..."', '', '', 'Yes', 2, 'Yes', ''],
              [1, 0.84, 'write', r'C:\Users\analyst\Documents\notes.txt', 'entropy 4.21 bits/byte over 256 bytes', 'meeting at 10 ...'],
              [2, 1.02, 'write', r'C:\Users\analyst\Documents\report.docx', 'entropy 7.96 bits/byte over 256 bytes', ''],
              [3, 1.05, 'rename', r'C:\Users\analyst\Documents\report.docx', 'new name: report.docx.locked', '']]
    for k, vals in enumerate(exrows, ex + 1):
        for j, v in enumerate(vals, 1):
            c = ins.cell(row=k, column=j, value=v); c.font = Font(name=FONT, size=9)
            if k == ex + 1:
                c.fill = SAMPLE if j < 7 else FILL_IN
    ins.column_dimensions['A'].width = 14
    for col, w in zip('BCDEFGHIJ', (10, 9, 50, 34, 30, 11, 12, 12, 20)):
        ins.column_dimensions[col].width = w

    ws = wb.create_sheet('Annotate')
    for j, hname in enumerate(hdr, 1):
        c = ws.cell(row=1, column=j, value=hname)
        c.font = Font(name=FONT, bold=True, size=9); c.fill = HEAD
        c.alignment = Alignment(wrap_text=True, vertical='center')
    ws.freeze_panes = 'A2'
    dv1 = DataValidation(type='list', formula1='"Yes,No,Unsure"', allow_blank=True)
    dv2 = DataValidation(type='list', formula1='"1,2,3,4,5,6,7,8,9,10,11,12,later"', allow_blank=True)
    dv3 = DataValidation(type='list', formula1='"Yes,No,Unsure,N/A"', allow_blank=True)
    for dv in (dv1, dv2, dv3):
        ws.add_data_validation(dv)
    r = 2
    for sid, obs, ve, note in samples:
        note_txt = f'Ransom note text: "{clean(note.get("txt"))[:120]}"' if note else '(no ransom-note text detected)'
        vals = [sid, f'ran {obs:.0f} s', '', note_txt, '', '']
        for j, v in enumerate(vals, 1):
            c = ws.cell(row=r, column=j, value=v)
            c.font = Font(name=FONT, size=9, bold=(j == 1)); c.fill = SAMPLE; c.border = Border(top=THIN)
        for j in range(7, 11):
            c = ws.cell(row=r, column=j); c.fill = FILL_IN; c.border = Border(top=THIN, left=THIN, right=THIN, bottom=THIN)
            c.font = Font(name=FONT, size=9)
        dv1.add(ws.cell(row=r, column=7)); dv2.add(ws.cell(row=r, column=8)); dv3.add(ws.cell(row=r, column=9))
        if not note:
            ws.cell(row=r, column=9, value='N/A')
        r += 1
        for k, (te, act, f, detail, preview, _) in enumerate(ve, 1):
            for j, v in enumerate([k, round(te, 3), act, clean(f), clean(detail), preview], 1):
                c = ws.cell(row=r, column=j, value=v); c.font = Font(name=FONT, size=9)
            r += 1
    for col, w in zip('ABCDEFGHIJ', (8, 9, 8, 60, 36, 34, 11, 12, 12, 24)):
        ws.column_dimensions[col].width = w
    wb.active = 1
    wb.save(path)


if __name__ == '__main__':
    main()
