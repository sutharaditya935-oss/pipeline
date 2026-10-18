"""Re-run CAPE's signature engine on original reports streamed by sig_feed.py.

Must run as the CAPE user inside CAPE's environment, from /opt/CAPEv2:
  cd /opt/CAPEv2 && poetry run python /mnt/u26/rc-static/iso/sig/sig_run.py
Mirrors utils/process.py --signatures (load report.json, reset statistics, run
RunSignatures) without needing the task in CAPE's database. Each analysis gets a
fake task id so no signature reads the current lab's storage/analyses folders.
Prints one JSON line per analysis to stdout.
"""
import json
import logging
import os
import sys

os.chdir('/opt/CAPEv2')
sys.path.insert(0, '/opt/CAPEv2')
logging.basicConfig(level=logging.CRITICAL)

from lib.cuckoo.core.plugins import RunSignatures  # noqa: E402
from lib.cuckoo.core.startup import init_modules  # noqa: E402

FAKE_ID_BASE = 90_000_000


def main():
    init_modules()
    inp = sys.stdin.buffer
    while True:
        head = inp.readline()
        if not head:
            break
        _, task, n = head.decode().split()
        raw = inp.read(int(n))
        rec = {'task': task}
        try:
            results = json.loads(raw)
            del raw
            results['statistics'] = {'signatures': []}
            results['signatures'] = []
            task_dict = {'id': FAKE_ID_BASE + int(task), 'platform': 'windows',
                         'category': results.get('target', {}).get('category', 'file')}
            RunSignatures(task=task_dict, results=results).run()
            rec['signatures'] = [{'name': s.get('name'), 'severity': s.get('severity'),
                                  'categories': s.get('categories'), 'families': s.get('families'),
                                  'description': s.get('description')} for s in results.get('signatures', [])]
            rec['ttps'] = results.get('ttps')
            rec['malscore'] = results.get('malscore')
            rec['malstatus'] = results.get('malstatus')
            rec['n_signatures_run'] = len(results['statistics']['signatures'])
        except Exception as e:  # keep going; record the failure
            rec['error'] = f'{type(e).__name__}: {e}'[:300]
        print(json.dumps(rec), flush=True)


if __name__ == '__main__':
    main()
