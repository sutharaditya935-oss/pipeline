# Benign baseline

Purpose: measure the false-positive rate of the paper's detectors on ordinary
software, run in the same CAPE lab as the ransomware corpus.

## Files
- `program_list_template.csv`: one row per program (copy to `batch1/programs.csv`).
  Columns: `id` (unique), `name`, `version`, `category`, `hard_case` (yes/no: the
  program legitimately enumerates or encrypts many files), `source_url`,
  `license`, `filename` (file in the staging dir), `sha256` (record YOURSELF when
  you download), `package` (CAPE package, usually `exe`), `arguments` (command
  line, e.g. a silent-install switch), `timeout` (seconds, default 120),
  `how_run` (what the run does), `notes`.
- `batch1/staging/`: the downloaded files (not committed).
- `batch1/lab_state.json`: written by `lab_state.py` before each batch.
- `batch1/submissions.csv`: written by `benign_submit.py` (id -> CAPE task id).

## Procedure
1. Download each program from its official source; compute SHA-256; fill the row.
2. `python pipeline/benign_prepare.py --list pipeline/benign/batch1/programs.csv --staging pipeline/benign/batch1/staging`
   (checks hashes, duplicates, missing files; refuses a bad list).
3. `python pipeline/lab_state.py --out pipeline/benign/batch1/lab_state.json` with CAPE running.
4. `python pipeline/benign_submit.py --list ... --staging ... --out pipeline/benign/batch1/submissions.csv`
   (same settings as the ransomware runs; resumable; do NOT touch the VM during runs).
5. `python pipeline/benign_stage.py --subs pipeline/benign/batch1/submissions.csv --out ~/benign_reports`
   then `python pipeline/extract.py --dir ~/benign_reports --out traces_benign --label benign`
   and `python pipeline/benign_analyze.py ...` (false-positive rates).

Rules learned from the ransomware batch: record everything up front, one lab
snapshot per batch, no manual interaction with the guest during runs, and keep the
benign batch separate from the ransomware corpus statistics.
