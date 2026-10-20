"""Survey of processes OUTSIDE each sample's own process tree that are not in timeline.py's ignore list, with the
signal events they emit; used to justify DEFAULT_IGNORE_PROCS (run with the OLD list to see what it would add).

  .venv/bin/python helper_survey.py
"""
import gzip,json,glob,collections,csv,re
ENUM={'FindFirstFileExW','FindFirstFileExA','NtQueryDirectoryFile','NtQueryDirectoryFileEx'}
CTX={'CryptAcquireContextW','CryptAcquireContextA','BCryptOpenAlgorithmProvider'}
KEY={'CryptGenKey','CryptImportKey','CryptExportKey','CryptDeriveKey','BCryptGenerateSymmetricKey','BCryptImportKeyPair','BCryptGenerateKeyPair','BCryptImportKey'}
import sys; sys.path.insert(0,'.')
IGN=set(__import__('timeline').DEFAULT_IGNORE_PROCS.split(','))
lab={r['task']:r['category'] for r in csv.DictReader(open('results/family_labels.csv'))}
ntr=collections.Counter(); sig=collections.defaultdict(collections.Counter)
for p in glob.glob('traces/*.jsonl.gz'):
    L=[json.loads(l) for l in gzip.open(p,'rt')]; h=L[0]
    if lab.get(h['task'])!='ransomware' or not h['procs']: continue
    procs=h['procs']; names={x['pid']:x['name'].lower() for x in procs}
    kids=collections.defaultdict(list)
    for x in procs: kids[x['ppid']].append(x['pid'])
    tree=set(); todo=[procs[0]['pid']]
    while todo:
        q=todo.pop()
        if q not in tree: tree.add(q); todo.extend(kids.get(q,[]))
    seen=set()
    for x in procs:
        nm=x['name'].lower()
        if x['pid'] in tree or nm in IGN: continue
        seen.add(nm)
    for nm in seen: ntr[nm]+=1
    for e in L[1:]:
        nm=names.get(e['p'],'?')
        if e['p'] in tree or nm in IGN: continue
        k='enum' if e['a'] in ENUM else 'ctx' if e['a'] in CTX else 'key' if e['a'] in KEY else None
        if k: sig[nm][k]+=1
hashy=re.compile(r'^[0-9a-f]{20}\.(exe|dll)$')
rows=[(nm,n) for nm,n in ntr.most_common(60) if not hashy.match(nm)]
print('non-sample processes OUTSIDE the tree and NOT in the ignore list (name, #traces | signal events enum/ctx/key):')
for nm,n in rows[:30]: print(f'  {nm:28s} {n:5d} | {sig[nm]["enum"]:7d} {sig[nm]["ctx"]:6d} {sig[nm]["key"]:5d}')
