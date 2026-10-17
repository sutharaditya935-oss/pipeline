#!/usr/bin/env python3
"""Enqueue the overlap samples to the local CAPE lab, matching the original runs.

Reads fetch_samples.py's download_log.csv (each row = one downloaded sample, kept
in its MalwareBazaar-encrypted zip) and, for every sample:

  1. unpacks it from the zip (password "infected") with 7z into a private temp
     folder outside this repository, and checks its SHA-256;
  2. enqueues it to the local CAPE web API under the SAME filename and package
     the original analysis used (first 20 hex of the SHA-256 + extension, looked
     up in results/timelines.csv by original task id), with CAPE's default
     timeout and options, tagged custom="orig:<task>" so the new run can be
     paired with the original;
  3. deletes the unpacked file right after enqueuing.

Submissions are spaced out (default 15 s) so the API rate limit is never hit; the
single lab VM then works through the queue one task at a time. The run is
resumable: samples already recorded in the output CSV are skipped.

Usage:
  .venv/bin/python submit_samples.py \
      --log ../samples/overlap/download_log.csv \
      --results results \
      --out ../samples/overlap/submissions.csv \
      --machine cuckoo1
"""
import argparse, csv, hashlib, os, subprocess, sys, tempfile, time
import urllib.request

try:
    import requests  # optional; we fall back to urllib if absent
except Exception:
    requests = None

API = "http://127.0.0.1:8000/apiv2/tasks/create/file/"


def unzip_one(zip_path, password="infected"):
    """Return (filename, bytes) for the single file inside the encrypted zip."""
    names = subprocess.run(
        ["7z", "-ba", "-p" + password, "l", zip_path],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    inner = subprocess.run(
        ["7z", "e", "-so", "-p" + password, zip_path],
        capture_output=True, check=True,
    ).stdout
    # inner filename is the last token on the listing line; MB uses the sha256
    fname = subprocess.run(
        ["7z", "-ba", "-slt", "-p" + password, "l", zip_path],
        capture_output=True, text=True, check=True,
    ).stdout
    name = ""
    for line in fname.splitlines():
        if line.startswith("Path = "):
            name = line[len("Path = "):].strip()
            break
    return name or os.path.basename(zip_path), inner


def submit(path, submit_name, package, machine, custom):
    data = {"package": package, "machine": machine, "custom": custom}
    if requests is not None:
        with open(path, "rb") as fh:
            r = requests.post(API, files={"file": (submit_name, fh)}, data=data, timeout=120)
        return r.json()
    # urllib multipart fallback
    import json as _json, uuid
    boundary = uuid.uuid4().hex
    with open(path, "rb") as fh:
        payload = fh.read()
    parts = []
    for k, v in data.items():
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{submit_name}\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
        + payload + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    req = urllib.request.Request(API, data=body,
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return _json.loads(resp.read())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", required=True, help="download_log.csv from fetch_samples.py")
    ap.add_argument("--results", default="results", help="dir with timelines.csv (for original name/package)")
    ap.add_argument("--out", required=True, help="submissions CSV (resumable; keep outside the repo)")
    ap.add_argument("--machine", default="cuckoo1")
    ap.add_argument("--delay", type=float, default=15.0, help="seconds between enqueues (API rate limit)")
    ap.add_argument("--only", choices=["main", "reserve", "all"], default="main")
    a = ap.parse_args()

    orig = {}
    with open(os.path.join(a.results, "timelines.csv")) as f:
        for r in csv.DictReader(f):
            orig[str(r["task"])] = {"name": r.get("name") or "", "package": r.get("package") or ""}

    done = {}
    if os.path.exists(a.out):
        with open(a.out) as f:
            for r in csv.DictReader(f):
                done[r["sha256"]] = r
    fields = ["sha256", "orig_task", "stratum", "family", "submit_name", "package", "new_task_id", "status"]
    out_f = open(a.out, "a", newline="")
    w = csv.DictWriter(out_f, fieldnames=fields)
    if not done:
        w.writeheader(); out_f.flush()

    with open(a.log) as f:
        rows = [r for r in csv.DictReader(f) if r.get("file")]
    if a.only != "all":
        rows = [r for r in rows if r.get("pick", "main").startswith(a.only)]

    submitted = 0
    for i, r in enumerate(rows, 1):
        sha = r["sha256"]
        if sha in done:
            print(f"[{i}/{len(rows)}] {sha[:16]}  already submitted (task {done[sha].get('new_task_id')})")
            continue
        task = str(r.get("task") or "")
        info = orig.get(task, {})
        package = info.get("package") or r.get("package") or "exe"
        ext = ("." + package) if package in ("exe", "dll") else (".exe")
        submit_name = info.get("name") or (sha[:20] + ext)

        tmpdir = tempfile.mkdtemp(prefix="capesub_")
        status = new_id = ""
        try:
            name, blob = unzip_one(r["file"])
            got = hashlib.sha256(blob).hexdigest()
            if got != sha:
                status = f"sha mismatch ({got[:12]})"
            else:
                tmp_path = os.path.join(tmpdir, submit_name)
                with open(tmp_path, "wb") as fh:
                    fh.write(blob)
                resp = submit(tmp_path, submit_name, package, a.machine, custom=f"orig:{task}")
                if resp.get("error"):
                    status = "api error: " + str(resp.get("error_value") or resp.get("errors"))[:80]
                else:
                    ids = (resp.get("data") or {}).get("task_ids") or []
                    new_id = ids[0] if ids else ""
                    status = "submitted" if new_id else "no task id"
        except subprocess.CalledProcessError as e:
            status = "unzip failed: " + (e.stderr.decode(errors="replace")[:80] if e.stderr else str(e))
        except Exception as e:
            status = f"{type(e).__name__}: {e}"[:100]
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

        w.writerow({"sha256": sha, "orig_task": task, "stratum": r.get("stratum", ""),
                    "family": r.get("family", ""), "submit_name": submit_name, "package": package,
                    "new_task_id": new_id, "status": status})
        out_f.flush()
        print(f"[{i}/{len(rows)}] {sha[:16]}  orig#{task:<5} {r.get('family',''):14s} -> {status} {('task '+str(new_id)) if new_id else ''}")
        if status == "submitted":
            submitted += 1
            if i < len(rows):
                time.sleep(a.delay)

    out_f.close()
    print(f"\nEnqueued {submitted} new tasks. Output: {a.out}")
    print("Watch progress: curl -s http://127.0.0.1:8000/apiv2/tasks/list/ | ... , or the CAPE web UI.")


if __name__ == "__main__":
    main()
