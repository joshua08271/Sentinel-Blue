"""Defensive acceptance with isolated Azure targets and expiring private evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import signal
import tempfile
import zipfile
from pathlib import Path
import datetime
import fcntl

from azure_private_transfer import cli, private_payload

import azure_lab_setup_rehearsal as lifecycle

PRACTICE_FILES = lifecycle.GUEST_FILES + ['native_defender_startup.py', 'smoke_release.py',
    'windows_query_contract.py', 'measure_collection_pressure.py',
    'agent_transport_rehearsal.py', 'probe_timing_rehearsal.py', 'service_repair_native.py']


WINDOWS_SCORING_WHEELS = [{'url': 'https://files.pythonhosted.org/packages/42/8b/cb12b1b60c91b074ca6bf0fdd59aa8f10d8bc5f73af8faece86ef0421b37/cryptography-50.0.1-cp311-abi3-win_amd64.whl', 'sha256': 'aed8db4f6d71c51efb89530e12d9464e7bf2923d46c3205dc794a2a93f8c0648'}, {'url': 'https://files.pythonhosted.org/packages/60/a6/8b149b2c3f2e11aaa1618ef64500b45f50f22c57a977a4dff1aff1f91042/cffi-2.1.1-cp313-cp313-win_amd64.whl', 'sha256': '1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d'}, {'url': 'https://files.pythonhosted.org/packages/0c/c3/44f3fbbfa403ea2a7c779186dc20772604442dde72947e7d01069cbe98e3/pycparser-3.0-py3-none-any.whl', 'sha256': 'b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992'}]

BOOTSTRAP = r'''
import base64, gzip, hashlib, io, json, os, pathlib, runpy, subprocess, sys, traceback, urllib.request, zipfile
root=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(root/'runtime.pyz'))
sys.path.insert(0,str(root))
deps=root/'dependencies'
deps.mkdir(mode=0o700)
sys.path.insert(0,str(deps))
report={'status':'failed','passed':False,'full_competition_readiness_proven':False,'live_red_team_executed':False}
try:
    if os.name=='nt':
        assert sys.version_info[:2]==(3,13), 'Reviewed Windows wheels require Python 3.13'
        for row in json.loads((root/'dependencies.json').read_text()):
            with urllib.request.urlopen(row['url'],timeout=60) as response:
                data=response.read(32*1024*1024+1)
            assert len(data)<=32*1024*1024 and hashlib.sha256(data).hexdigest()==row['sha256']
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for name in archive.namelist():
                    p=pathlib.PurePosixPath(name)
                    assert not p.is_absolute() and '..' not in p.parts and '\\' not in name and ':' not in name
                archive.extractall(deps)
    elif json.loads((root/'dependencies.json').read_text()):
        subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-input',
                        '--target',str(deps),'cryptography==50.0.1'],check=True,timeout=180,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    from sentinel_blue import __version__
    fixture=runpy.run_path(str(root/'defensive_practice_native.py'))
    report.update(fixture['rehearse']())
    report.update(version=__version__,
                  runtime_sha256=hashlib.sha256((root/'runtime.pyz').read_bytes()).hexdigest())
    report['status']='passed' if report['passed'] else 'failed'
except Exception as exc:
    (root/'private-error.txt').write_text(traceback.format_exc())
    report['error_type']=type(exc).__name__
(root/'result.json').write_text(json.dumps(report,indent=2))
summary=fixture['summary'](report) if 'fixture' in locals() and 'summary' in fixture else report
encoded=json.dumps(summary,separators=(',',':'))
if len(encoded.encode())>2500:
    packed=base64.b64encode(gzip.compress(encoded.encode(),mtime=0)).decode()
    assert len(packed)<=3500, 'Native summary exceeds bounded transport'
    print('SB_SETUP_RESULT_GZIP='+packed,flush=True)
else:
    print('SB_SETUP_RESULT='+encoded,flush=True)
'''


def pack(runtime, expected, fixture='defensive', *, mode='full', setup_budget_seconds=180):
    data = runtime.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("runtime checksum mismatch")
    dependencies = [row for row in WINDOWS_SCORING_WHEELS
                    if any('/' + name in row['url'] for name in ('cryptography-', 'cffi-', 'pycparser-'))]
    if fixture != 'defensive':
        raise ValueError('Only defensive acceptance is supported')
    if mode not in ('full', 'recovery'):
        raise ValueError('Only full or recovery defensive modes are supported')
    if type(setup_budget_seconds) is not int or not 180 <= setup_budget_seconds <= 600:
        raise ValueError('Setup diagnostic stop limit must be 180..600 seconds')
    fixture_file = 'defensive_practice_native.py'
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('runtime.pyz', data)
        archive.writestr('defensive_practice_native.py', Path(__file__).with_name(fixture_file).read_bytes())
        archive.writestr('tools/__init__.py', b'')
        for name in PRACTICE_FILES:
            archive.writestr('tools/' + name, Path(__file__).with_name(name).read_bytes())
        archive.writestr('bootstrap.py', BOOTSTRAP)
        archive.writestr('dependencies.json', json.dumps(dependencies))
        archive.writestr('run-options.json', json.dumps({'mode': mode, 'setup_budget_seconds': setup_budget_seconds}))
    payload = stream.getvalue()
    return base64.b64encode(payload).decode(), hashlib.sha256(payload).hexdigest()


def script(name, identity, packed, packed_sha, run_id):
    # Keep the previously verified IMDS checks, staging ACLs and size-bounded
    # Linux transport. Only the fixture entry point and archive allowlist change.
    original = lifecycle.guest_script(name, identity, packed, packed_sha, run_id)
    old = "{'runtime.pyz','tools/__init__.py','tools/azure_setup_guest.py','tools/setup_native_inputs.py','tools/competition_native_inputs.py','tools/measure_setup_acceptance.py'}"
    new = "{'runtime.pyz','defensive_practice_native.py','tools/__init__.py','bootstrap.py','dependencies.json','run-options.json'}"
    new = new[:-1] + ',' + ','.join(repr('tools/' + name) for name in PRACTICE_FILES) + '}'
    if name == 'sb-linux-target':
        if old not in original:
            raise ValueError('Linux archive validation template changed')
        original = original.replace(old, new)
        old_call = "[sys.executable,str(root/'tools/azure_setup_guest.py'),'--runtime',str(root/'runtime.pyz'),'--expected-resource-id'," + repr(identity) + ",'--output',str(root/'result.json')]"
        if old_call not in original:
            raise ValueError('Linux fixture entry template changed')
        return original.replace(old_call, "[sys.executable,str(root/'bootstrap.py')]")
    old_call = "& $py[0] ($root+'\\tools\\azure_setup_guest.py') --runtime ($root+'\\runtime.pyz') --expected-resource-id '" + identity + "' --output ($root+'\\result.json')"
    if old_call not in original:
        raise ValueError('Windows fixture entry template changed')
    return original.replace(old_call, "& $py[0] ($root+'\\bootstrap.py')")



def download_script(name, identity, packed, packed_sha, run_id, url):
    """One authenticated transfer, retaining guest identity and archive checks."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != 'https' or not parsed.hostname.endswith('.blob.core.windows.net') or "'" in url:
        raise ValueError('Private Azure HTTPS staging URL required')
    original = script(name, identity, packed, packed_sha, run_id)
    if name == 'sb-linux-target':
        count = (len(packed)+lifecycle.LINUX_CHUNK_SIZE-1)//lifecycle.LINUX_CHUNK_SIZE
        old = "data=base64.b64decode(''.join((root/f'part-{i:03d}.b64').read_text() for i in range("+str(count)+")),validate=True)"
        if old not in original:
            raise ValueError('Linux delivery template changed')
        original = original.replace('assert root.is_dir() and not root.is_symlink()', 'root.mkdir(mode=0o700)')
        return original.replace(old, "with urllib.request.urlopen("+repr(url)+",timeout=45) as response:\n    data=response.read(32*1024*1024+1)\nassert len(data)<=32*1024*1024")
    old = "[IO.File]::WriteAllBytes($root+'\\payload.zip',[Convert]::FromBase64String('"+packed+"'))"
    if old not in original:
        raise ValueError('Windows delivery template changed')
    return original.replace(old, "$ProgressPreference='SilentlyContinue'\nInvoke-WebRequest -UseBasicParsing -Uri '"+url+"' -OutFile ($root+'\\payload.zip') -TimeoutSec 45")



EVIDENCE = r"""
import hashlib,io,json,pathlib,urllib.request,zipfile
root=pathlib.Path.cwd()
names={'result.json','setup-defensive-result.json','defensive-progress.json'}
names.update('defensive-'+phase+'.json' for phase in ('setup','transport','probe_deadlines','controller_continuity','service_repair','native_recovery','collection_pressure'))
stream=io.BytesIO()
total=0
with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:
    for name in sorted(names):
        p=root/name
        if not p.exists(): continue
        assert not p.is_symlink() and p.is_file()
        assert p.stat().st_size<=4*1024*1024
        data=p.read_bytes(); total+=len(data)
        assert total<=16*1024*1024
        json.loads(data)
        archive.writestr(name,data)
data=stream.getvalue()
request=urllib.request.Request(__URL__,data=data,method='PUT',headers={'x-ms-blob-type':'BlockBlob','If-None-Match':'*','Content-Type':'application/zip'})
with urllib.request.urlopen(request,timeout=45) as response:
    assert response.status==201
print('SB_JSON_EVIDENCE_UPLOADED='+hashlib.sha256(data).hexdigest(),flush=True)
"""


def captured_script(name, identity, packed, packed_sha, run_id, download_url, evidence_url):
    original = download_script(name, identity, packed, packed_sha, run_id, download_url)
    encoded = base64.b64encode(EVIDENCE.replace('__URL__', repr(evidence_url)).encode()).decode()
    if name == 'sb-linux-target':
        marker = 'sys.exit(result.returncode)'
        if original.count(marker) != 1:
            raise ValueError('Linux evidence template changed')
        return original.replace(marker, "os.chdir(root)\nexec(base64.b64decode("+repr(encoded)+"))\n"+marker)
    return original + "\n& $py[0] -c \"import base64;exec(base64.b64decode('"+encoded+"'))\"\nif ($LASTEXITCODE -ne 0) {throw 'JSON evidence capture failed'}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--runtime-sha256', required=True)
    parser.add_argument('--expected-network-sha256')
    parser.add_argument('--private-storage-account', required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--target', action='append', choices=lifecycle.TARGETS)
    parser.add_argument('--mode', choices=['full', 'recovery'], default='full')
    parser.add_argument('--setup-budget-seconds', type=int, default=180,
                        help='diagnostic stop limit; the opening target remains 180 seconds')
    args = parser.parse_args()
    targets = args.target or list(lifecycle.TARGETS)
    if len(set(targets)) != len(targets):
        parser.error('Targets must be unique')
    packed, packed_sha = pack(args.runtime, args.runtime_sha256, mode=args.mode,
                             setup_budget_seconds=args.setup_budget_seconds)
    for name in targets:
        captured_script(name, '/reviewed-resource', packed, packed_sha, 'templatecheck',
                        'https://example.blob.core.windows.net/test/input?sig=review',
                        'https://example.blob.core.windows.net/test/output?sig=review')
    os.umask(0o077)
    descriptor = os.open(Path.home()/'.sentinel-azure-preflight.lock', os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        work = Path(tempfile.mkdtemp(prefix='sentinel-defensive-'))
        print('SB_DEFENSIVE_WORK='+str(work), flush=True)
        azure = lifecycle.lab.Azure(work)
        state = lifecycle.iso.snapshot(azure)
        digest = lifecycle.iso.network_digest(state)
        (work/'initial-network.json').write_text(json.dumps(state, indent=2))
        if not args.execute:
            print(json.dumps({'status':'network_reviewed','network_sha256':digest}), flush=True)
            return 0
        if digest != args.expected_network_sha256:
            raise ValueError('Reviewed network changed; no changes attempted')
        lifecycle.iso.require_off(azure, state['vms'])
        def interrupted(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
        archive = work/'payload.zip'
        archive.write_bytes(base64.b64decode(packed, validate=True))
        with private_payload(archive, account=args.private_storage_account, group=lifecycle.lab.GROUP) as delivery:
            common = ['--account-name', args.private_storage_account, '--auth-mode', 'key']
            expiry = (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=45)).strftime('%Y-%m-%dT%H:%MZ')
            urls = {}
            for name in targets:
                token = cli('storage', 'blob', 'generate-sas', '--container-name', delivery['container'],
                            '--name', name+'-evidence.zip', '--permissions', 'cw', '--expiry', expiry, '--https-only', *common)
                urls[name] = 'https://'+args.private_storage_account+'.blob.core.windows.net/'+delivery['container']+'/'+name+'-evidence.zip?'+token
            factory = lambda name,*values: captured_script(name,*values,delivery['url'],urls[name])
            report = lifecycle.run(azure, state, digest, packed, packed_sha, targets=targets,
                                   guest_script_factory=factory, stage_linux_payload=False)
            report.update(kind='azure-defensive-acceptance', live_red_team_executed=False, evidence_capture={})
            for name in targets:
                present = cli('storage', 'blob', 'exists', '--container-name', delivery['container'], '--name', name+'-evidence.zip', *common)
                if present['exists']:
                    cli('storage', 'blob', 'download', '--container-name', delivery['container'], '--name', name+'-evidence.zip', '--file', str(work/(name+'-evidence.zip')), *common)
                    report['evidence_capture'][name] = 'downloaded'
                else:
                    report['evidence_capture'][name] = 'not returned'
            if any(value != 'downloaded' for value in report['evidence_capture'].values()):
                report['status'] = 'evidence_incomplete'
            (work/'result.json').write_text(json.dumps(report, indent=2))
        report['private_staging_cleanup_verified'] = True
        (work/'result.json').write_text(json.dumps(report, indent=2))
        # Only selected JSON evidence is downloadable; command files contain SAS URLs.
        evidence_path = Path.cwd()/'sentinel-defensive-evidence.zip'
        with zipfile.ZipFile(evidence_path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in [work/'result.json', *sorted(work.glob('*-evidence.zip'))]:
                archive.write(path, path.name)
        print('SB_DEFENSIVE_COMPLETE='+json.dumps(report, separators=(',', ':')), flush=True)
        print('SB_DEFENSIVE_EVIDENCE='+str(evidence_path), flush=True)
        return 0 if report['status']=='guest_local_setup_passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
