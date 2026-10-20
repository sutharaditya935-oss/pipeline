#!/bin/bash
# Re-run every result in the paper from the extracted traces with the DEFAULT (attributed) timeline analysis:
# events from launcher shells and Windows helper processes are ignored (see timeline.py DEFAULT_IGNORE_PROCS).
# Run from pipeline/ with the venv python; the original-corpus reports zip is only needed by 3 steps.
set -euo pipefail
PY=.venv/bin/python; ZIP=${ZIP:-/mnt/u26/rc-static/capev2_corpus_backup_20260729.zip}
L=results/family_labels.csv
step() { echo; echo "[$(date +%T)] $*"; }

step "corpus timelines (attributed) and ransomware-only subset"
$PY timeline.py --traces traces --out results | tail -1
$PY - <<'PYEOF'
import pandas as pd, gzip, json, os
lab = pd.read_csv('results/family_labels.csv', dtype={'task': str}); keep = set(lab[lab.category == 'ransomware'].task)
t = pd.read_csv('results/timelines.csv', dtype={'task': str}); t = t[t.task.isin(keep)]
os.makedirs('results_ransomware', exist_ok=True); t.to_csv('results_ransomware/timelines.csv', index=False)
# results_ransomware/damage.jsonl.gz may be a symlink to results/: never write through it (that truncates the source)
if os.path.islink('results_ransomware/damage.jsonl.gz'): os.remove('results_ransomware/damage.jsonl.gz')
with gzip.open('results/damage.jsonl.gz', 'rt') as f, gzip.open('results_ransomware/damage.jsonl.gz.tmp', 'wt') as g:
    for l in f:
        if str(json.loads(l)['task']) in keep: g.write(l)
os.replace('results_ransomware/damage.jsonl.gz.tmp', 'results_ransomware/damage.jsonl.gz')
PYEOF
step "naive (any-process) baseline, for the comparison tables"
$PY timeline.py --traces traces --all-procs --out results_naive | tail -1
step "main analysis, figures, family statistics"
$PY analyze.py --results results_ransomware --labels $L > /dev/null
$PY family_stats.py --results results_ransomware --labels $L --out results_ransomware/family_stats.txt > /dev/null
step "non-damaging breakdown"
$PY nodamage_breakdown.py --results results --labels $L --out results_ransomware/nodamage_breakdown.txt > /dev/null
step "signature agreement"
$PY sig_analysis.py --sigs results/signatures.jsonl.gz --results results --labels $L --out results/signature_summary.txt > /dev/null
step "overlap re-detonation (rebuilds 1 and 2)"
$PY timeline.py --traces traces_overlap --out results_overlap | tail -1
$PY timeline.py --traces traces_overlap_v2 --out results_overlap_v2 | tail -1
# overlap_samples.csv keeps the ORIGINAL (naive) timings the stratified selection was based on; compare against the attributed ones
$PY - <<'PYEOF'
import pandas as pd
o = pd.read_csv('overlap/overlap_samples.csv'); t = pd.read_csv('results/timelines.csv', dtype={'task': str}).set_index('task')
for c in ['t_damage', 't_enum', 't_crypto_ctx', 't_crypto_key', 't_note', 'obs_end']:
    o[c] = [t.loc[str(k), c] if str(k) in t.index else float('nan') for k in o.task]
o.to_csv('overlap/overlap_samples_attributed.csv', index=False)
PYEOF
$PY compare_overlap.py --orig overlap/overlap_samples_attributed.csv --new results_overlap/timelines.csv --out results_overlap > /dev/null
$PY compare_overlap.py --orig overlap/overlap_samples_attributed.csv --new results_overlap_v2/timelines.csv --out results_overlap_v2 > /dev/null
$PY fig_overlap.py --orig results/timelines.csv --sel overlap/overlap_samples.csv --r1 results_overlap/timelines.csv --r2 results_overlap_v2/timelines.csv --out results_overlap_v2/fig_overlap > /dev/null
step "buffer validation (needs the corpus zip)"
$PY validate_buffers.py --zip "$ZIP" --results results_ransomware --traces traces --out results_ransomware/buffer_validation.csv > results_ransomware/buffer_validation.txt
step "results-dir residue (needs the corpus zip)"
$PY resultsdir_check.py --zip "$ZIP" --results results --subset results_ransomware --out results_ransomware/resultsdir_check.txt > /dev/null
step "environment evidence (needs the corpus zip)"
$PY env_evidence.py --zip "$ZIP" --traces traces --traces-rebuild1 traces_overlap --results results --overlap overlap/overlap_samples.csv --rebuild1 results_overlap/timelines.csv > results/env_evidence.txt
step "sensitivity (threshold, length, latency, process-tree, naive)"
rm -rf results_sensitivity
$PY sensitivity.py --traces traces --labels $L --base results --out results_sensitivity > /dev/null
step "second-machine replication"
for h in intel ideapad; do $PY timeline.py --traces traces_repl_$h --out results_repl_$h | tail -1; done
$PY compare_hosts.py --a results_repl_intel/timelines.csv --a-subs ~/subs_repl_intel.csv --b results_repl_ideapad/timelines.csv --b-subs ~/subs_repl_ideapad.csv --a-name "i5-11400H" --b-name "Ryzen 5 5500U" --out results_repl_compare > /dev/null
$PY fig_replication.py --paired results_repl_compare/paired.csv --a-name "Core i5-11400H" --b-name "Ryzen 5 5500U" --out results_repl_compare/fig_replication > /dev/null
for h in intel intel_repeat ideapad; do $PY timeline.py --traces traces_pilot_$h --out results_pilot_$h | tail -1; done
$PY compare_hosts.py --a results_pilot_intel/timelines.csv --a-subs ../samples/overlap/submissions_pilot_intel.csv --b results_pilot_intel_repeat/timelines.csv --b-subs ../samples/overlap/submissions_pilot_intel_repeat.csv --a-name run1 --b-name run2 --out results_pilot_samehost > /dev/null
step "benign baseline"
for h in intel ideapad control; do $PY timeline.py --traces traces_benign_$h --out results_benign_$h | tail -1; done
for h in intel ideapad control; do $PY timeline.py --traces traces_benign_$h --all-procs --out results_benign_${h}_naive | tail -1; done
$PY - <<'PYEOF'
import pandas as pd, gzip, json, os
lab = pd.read_csv('results/family_labels.csv', dtype={'task': str}); keep = set(lab[lab.category == 'ransomware'].task)
os.makedirs('results_ransomware_naive', exist_ok=True)
t = pd.read_csv('results_naive/timelines.csv', dtype={'task': str}); t[t.task.isin(keep)].to_csv('results_ransomware_naive/timelines.csv', index=False)
with gzip.open('results_naive/damage.jsonl.gz', 'rt') as f, gzip.open('results_ransomware_naive/damage.jsonl.gz.tmp', 'wt') as g:
    for l in f:
        if str(json.loads(l)['task']) in keep: g.write(l)
os.replace('results_ransomware_naive/damage.jsonl.gz.tmp', 'results_ransomware_naive/damage.jsonl.gz')
bad = ('Windows compress archive', 'Windows expand archive', 'Windows get filehash')   # PowerShell cmdlets: not attributable
for h in ('intel', 'ideapad'):
    i = pd.read_csv(os.path.expanduser(f'~/benign_reports_{h}/index.csv'), dtype={'task': str})
    i[~i.name.isin(bad)].to_csv(os.path.expanduser(f'~/benign_reports_{h}/index_attributable.csv'), index=False)
PYEOF
for h in intel ideapad; do
  $PY benign_analyze.py --benign results_benign_$h/timelines.csv --index ~/benign_reports_$h/index_attributable.csv --ransom results_ransomware --out results_benign_$h/false_positives.txt > /dev/null
  $PY benign_analyze.py --benign results_benign_${h}_naive/timelines.csv --index ~/benign_reports_$h/index.csv --ransom results_ransomware_naive --out results_benign_${h}_naive/false_positives.txt > /dev/null
done
$PY benign_hosts.py --a results_benign_intel --b results_benign_ideapad --index-a ~/benign_reports_intel/index_attributable.csv --index-b ~/benign_reports_ideapad/index_attributable.csv --out results_benign_intel/two_hosts.txt > /dev/null
$PY repl_stats.py --paired results_repl_compare/paired.csv --batches ../samples/overlap/submissions_repl_intel_batch1.csv ../samples/overlap/submissions_repl_intel_batch2.csv --truncated 340 352 355 356 358 --out results_repl_compare/agreement.txt > /dev/null
$PY overlap_table.py --orig overlap/overlap_samples_attributed.csv --r1 results_overlap/timelines.csv --r2 results_overlap_v2/timelines.csv > results_overlap_v2/overlap_table.txt
step "DONE"
