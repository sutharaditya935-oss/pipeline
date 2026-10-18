"""Record the host-side lab state automatically, so every batch is reproducible.

Written next to a batch's submission log (lab_state.json). It captures what can be
read from the host without touching the guest: CAPE commit and config values, the
VM definition, the current snapshot, the guest disk's size/mtime, attached media,
the libvirt network, kernel and QEMU/libvirt versions. Guest-side settings (UAC,
Defender, installed software) live in the snapshot; record them in the snapshot
description when you take it and refer to it here.

  .venv/bin/python lab_state.py --out ../benign/batch1/lab_state.json
"""
import argparse, configparser, datetime, hashlib, json, os, subprocess

VIRSH = ['virsh', '-c', 'qemu:///system']
CAPE = '/opt/CAPEv2'
VM = 'cuckoo1'


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception as e:
        return f'error: {e}'


def conf_values(path, wanted):
    cp = configparser.RawConfigParser(strict=False)
    try:
        cp.read(path)
    except Exception as e:
        return {'error': str(e)}
    return {f'{s}.{k}': cp.get(s, k, fallback=None) for s, k in wanted}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    xml = run(VIRSH + ['dumpxml', VM])
    snap = run(VIRSH + ['snapshot-current', VM, '--name'])
    snap_xml = run(VIRSH + ['snapshot-dumpxml', VM, snap]) if snap and not snap.startswith('error') else ''
    disk = next((l.split()[1] for l in run(VIRSH + ['domblklist', VM]).splitlines()[2:] if l.split()[1:2]
                 and l.split()[1].endswith('.qcow2')), '')
    st = os.stat(disk) if disk and os.path.exists(disk) else None
    state = {
        'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'host': {'kernel': run(['uname', '-r']), 'qemu': run(['qemu-system-x86_64', '--version']).splitlines()[:1],
                 'libvirt': run(['virsh', '--version'])},
        'cape': {
            'commit': run(['git', '-c', 'safe.directory=*', '-C', CAPE, 'rev-parse', 'HEAD']),
            'branch': run(['git', '-c', 'safe.directory=*', '-C', CAPE, 'branch', '--show-current']),
            'uncommitted_changes': run(['git', '-c', 'safe.directory=*', '-C', CAPE, 'status', '--short'])[:2000],
            'cuckoo.conf': conf_values(f'{CAPE}/conf/cuckoo.conf', [('cuckoo', 'machinery'), ('timeouts', 'default'),
                                                                   ('timeouts', 'critical'), ('resultserver', 'ip')]),
            'routing.conf': conf_values(f'{CAPE}/conf/routing.conf', [('routing', 'route'), ('routing', 'internet')]),
            'kvm.conf': conf_values(f'{CAPE}/conf/kvm.conf', [(VM, 'ip'), (VM, 'arch'), (VM, 'tags'), (VM, 'label')]),
        },
        'vm': {
            'name': VM, 'state': run(VIRSH + ['domstate', VM]),
            'vcpus_memory': run(VIRSH + ['dominfo', VM]),
            'snapshot_current': snap,
            'snapshot_description': next((l.strip() for l in snap_xml.splitlines() if '<description>' in l), ''),
            'snapshot_xml_sha256': hashlib.sha256(snap_xml.encode()).hexdigest() if snap_xml else '',
            'snapshots': run(VIRSH + ['snapshot-list', VM, '--name']).split(),
            'disk': disk, 'disk_bytes': st.st_size if st else None,
            'disk_mtime': datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds') if st else None,
            'block_devices': run(VIRSH + ['domblklist', VM]),
            'definition_sha256': hashlib.sha256(xml.encode()).hexdigest(),
        },
        'network': {'libvirt_default': run(VIRSH + ['net-dumpxml', 'default'])},
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(state, open(a.out, 'w'), indent=2)
    print(f"snapshot={state['vm']['snapshot_current']} cape={state['cape']['commit'][:8]} "
          f"timeout={state['cape']['cuckoo.conf'].get('timeouts.default')} -> {a.out}")


if __name__ == '__main__':
    main()
