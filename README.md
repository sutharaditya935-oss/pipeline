# Ransomware lead-time pipeline

Analysis pipeline for the paper *Seconds, Not Minutes: Measuring the Defensive
Lead Time Between Ransomware Execution and Irreversible Damage*.

It reduces CAPEv2 sandbox reports to per-sample behavioral timelines and
measures:

- when precursor signals appear: file enumeration, crypto API use, shadow-copy deletion;
- when the first *irreversible* damage to victim files happens;
- how much lead time each signal gives a defender, and how many files simple
  execution-time detectors would lose before reacting.

This repository contains **code and derived results only**. It contains no
malware samples and no raw CAPE reports.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

`extract.py` and `timeline.py` use only the Python standard library.
`analyze.py` needs the packages in `requirements.txt`.

## Usage

The pipeline has three stages:

```bash
# 1. CAPE report.json files -> compact per-sample traces (parses each report once)
python3 -I extract.py --zip /path/to/cape_analyses.zip --out traces --workers 3
python3 -I extract.py --dir /path/to/storage/analyses --out traces --label ransomware

# 2. Traces -> per-sample milestone timelines
.venv/bin/python timeline.py --traces traces --out results

# 3. Statistics, survival analysis, detector replay, figures
.venv/bin/python analyze.py --results results [--labels family.csv]
```

Input layout: `analyses/<task_id>/reports/report.json`, either as a zip or a
directory. One worker can need 2–3 GB of RAM for the largest reports
(about 250 MB of JSON).

## Re-running samples on a new VM

Timings depend on the analysis VM, so results from a rebuilt VM are pooled with
the original corpus only if a subset of the original samples gives the same
timings there.

```bash
# Pick the overlap set: 7 damaged samples from each sextile of time-to-damage,
# plus 8 that never reached damage, with reserves (fixed seed)
.venv/bin/python select_overlap.py --results results --out overlap

# Download them from MalwareBazaar by SHA-256 (needs an Auth-Key in
# $MB_AUTH_KEY or ~/.config/malwarebazaar/auth_key). Unavailable hashes are
# replaced by a reserve from the same stratum.
python3 -I fetch_samples.py --overlap-csv overlap/overlap_samples.csv --out ../samples/overlap
```

`fetch_samples.py` keeps each sample in MalwareBazaar's encrypted zip
(password `infected`) and verifies its SHA-256 by streaming it through `7z`, so
nothing is extracted to disk. It refuses to save into this repository.
`overlap/` lists the selected samples and their original timings.

## Outputs (`results/`)

| File | Contents |
|---|---|
| `timelines.csv` | One row per analysis: milestone times (seconds after first process start) and counts |
| `damage.jsonl.gz` | Ordered irreversible-damage events per analysis, used for detector replay |
| `summary.txt` | All tables reported in the paper |
| `sandbox_dirs.txt` | CAPE guest working directories detected across the corpus |
| `fig_*.png` | Figures in the paper |

The committed `results/` were produced from 1,213 ransomware samples (identified
by SHA-256 in `timelines.csv`), detonated in CAPEv2 2.5 on a Windows 10
Enterprise 22H2 guest.

## Key definitions

- **t0**: the earliest process-start timestamp in an analysis. All times are relative to it.
- **Zones**: each file path is classified as sandbox, system, temp, AppData,
  user, Program Files or root. CAPE's own working directories are detected per
  trace (from `analyzer.py`, `analysis.conf`, `modules\packages\`, `data\yara\`)
  and across the corpus. The latter matters because the guest's random directory
  names recur between runs.
- **Irreversible damage**: the first high-entropy overwrite of a victim file
  (entropy ≥ 7.0 bits/byte over ≥ 64 captured bytes), rename to a new or
  non-standard extension, or deletion of a victim file. AppData counts as
  victim content.
- **Kaplan–Meier onset**: computed over executed samples. Samples that never
  reach damage are censored at the end of observation.

## Limitations

- Entropy is computed on CAPE's captured buffers, which are capped at 256 bytes.
- Rename detection relies on file extensions.
- "Files lost" counts damage events, not distinct files.
- Precursor signals such as crypto API calls also occur in benign software.
  False-positive rates need a benign baseline, which is not yet included.

## License

MIT. See `LICENSE`.
