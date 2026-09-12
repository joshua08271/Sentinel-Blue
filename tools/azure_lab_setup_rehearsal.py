"""Private, reversible Azure power/network wrapper for native setup acceptance.

Default: read-only network review. --execute additionally requires its exact
digest and the reviewed runtime SHA256. Only the two lab targets are started.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import signal
import tempfile
import time
import uuid
import zipfile
import zlib
from pathlib import Path

if __package__:
    from tools import azure_lab_isolated_boot as iso, azure_lab_preflight as lab
else:
    import azure_lab_isolated_boot as iso
    import azure_lab_preflight as lab

TARGETS = ["sb-linux-target", "sb-windows-target"]
GUEST_FILES = ["azure_setup_guest.py", "setup_native_inputs.py", "competition_native_inputs.py", "measure_setup_acceptance.py"]
LINUX_CHUNK_SIZE = 60000


def decode_guest_summary(line):
    """Keep diagnostic results intact inside Run Command's small output tail."""
    if line.startswith('SB_SETUP_RESULT_GZIP='):
        encoded = line.split('=', 1)[1]
        if len(encoded) > 3500:
            raise ValueError('guest summary exceeds transport bound')
        packed = base64.b64decode(encoded, validate=True)
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = decoder.decompress(packed, 1024 * 1024 + 1)
        if len(raw) > 1024 * 1024 or not decoder.eof or decoder.unused_data:
            raise ValueError('guest summary compression is incomplete or oversized')
        result = json.loads(raw)
    elif line.startswith('SB_SETUP_RESULT='):
        if len(line) > 1024 * 1024:
            raise ValueError('guest summary exceeds legacy bound')
        result = json.loads(line.split('=', 1)[1])
    else:
        return None
    if not isinstance(result, dict):
        raise ValueError('guest summary must be an object')
    return result


def payload(runtime: Path, expected: str) -> tuple[str, str]:
    data = runtime.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Runtime digest mismatch before Azure changes")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("runtime.pyz", data)
        archive.writestr("tools/__init__.py", b"")
        for name in GUEST_FILES:
            archive.writestr("tools/" + name, Path(__file__).with_name(name).read_bytes())
    packed = stream.getvalue()
    return base64.b64encode(packed).decode(), hashlib.sha256(packed).hexdigest()


def guest_script(name, identity, packed, packed_sha, run_id):
    # No credentials or tenant secrets are embedded. The exact runtime and
    # harness bytes travel through the operator's authorized Run Command.
    if name == "sb-linux-target":
        count = (len(packed) + LINUX_CHUNK_SIZE - 1) // LINUX_CHUNK_SIZE
        return f'''set -eu
umask 077
echo SB_GUEST_STAGE_STARTED
python3 - <<'SB_STAGE'
import base64, hashlib, io, json, os, pathlib, subprocess, sys, urllib.request, zipfile
assert sys.version_info >= (3,11)
request=urllib.request.Request('http://169.254.169.254/metadata/instance?api-version=2021-02-01',headers={{'Metadata':'true'}})
with urllib.request.build_opener(urllib.request.ProxyHandler({{}})).open(request,timeout=5) as response:
    metadata=json.load(response)
assert metadata['compute']['resourceId'].casefold()=={identity!r}.casefold()
root=pathlib.Path('/var/lib/sentinel-azure-setup-{run_id}')
assert root.is_dir() and not root.is_symlink()
data=base64.b64decode(''.join((root/f'part-{{i:03d}}.b64').read_text() for i in range({count})),validate=True)
assert hashlib.sha256(data).hexdigest()=={packed_sha!r}
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    assert set(archive.namelist())=={{'runtime.pyz','tools/__init__.py','tools/azure_setup_guest.py','tools/setup_native_inputs.py','tools/competition_native_inputs.py','tools/measure_setup_acceptance.py'}}
    archive.extractall(root)
print('SB_GUEST_STAGE_VERIFIED',flush=True)
result=subprocess.run([sys.executable,str(root/'tools/azure_setup_guest.py'),'--runtime',str(root/'runtime.pyz'),'--expected-resource-id',{identity!r},'--output',str(root/'result.json')],cwd=root,timeout=2220)
sys.exit(result.returncode)
SB_STAGE
'''
    return f'''$ErrorActionPreference='Stop'
$request=[Net.WebRequest]::Create('http://169.254.169.254/metadata/instance?api-version=2021-02-01')
$request.Proxy=$null
$request.Timeout=5000
$request.ReadWriteTimeout=5000
$request.Headers.Add('Metadata','true')
$response=$request.GetResponse()
$reader=[IO.StreamReader]::new($response.GetResponseStream())
try {{$metadata=$reader.ReadToEnd() | ConvertFrom-Json}} finally {{$reader.Dispose();$response.Dispose()}}
if ($metadata.compute.resourceId -ne '{identity}') {{throw 'Azure scope mismatch'}}
$py=@(Get-ChildItem 'C:\\ProgramData\\SentinelBlue' -Filter python.exe -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
if ($py.Count -ne 1) {{throw 'Expected one existing Sentinel Python runtime'}}
$root='C:\\ProgramData\\SentinelAzureSetup-{run_id}'
if (Test-Path -LiteralPath $root) {{throw 'Staging directory already exists'}}
New-Item -ItemType Directory -Path $root | Out-Null
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {{throw 'Staging ACL failed'}}
[IO.File]::WriteAllBytes($root+'\\payload.zip',[Convert]::FromBase64String('{packed}'))
if ((Get-FileHash ($root+'\\payload.zip') -Algorithm SHA256).Hash.ToLowerInvariant() -ne '{packed_sha}') {{throw 'Payload checksum mismatch'}}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory($root+'\\payload.zip',$root)
Set-Location -LiteralPath $root
Write-Output 'SB_GUEST_STAGE_VERIFIED'
& $py[0] ($root+'\\tools\\azure_setup_guest.py') --runtime ($root+'\\runtime.pyz') --expected-resource-id '{identity}' --output ($root+'\\result.json')
if ($LASTEXITCODE -ne 0) {{throw ('Guest setup rehearsal exited '+$LASTEXITCODE)}}
'''


def stage_linux(azure, identity, packed, run_id):
    """Keep each Azure Linux script below 64 KiB and require every write's ack.

    The target returned empty output for a ~493 KiB script, without creating its
    staging directory. Small commands succeeded. No service mutation is attempted
    until the complete separately staged payload passes its original checksum.
    """
    root = "/var/lib/sentinel-azure-setup-" + run_id
    scripts = [("ready", f'''set -eu
umask 077
python3 - <<'SB_PREPARE'
import json, pathlib, urllib.request
request=urllib.request.Request('http://169.254.169.254/metadata/instance?api-version=2021-02-01',headers={{'Metadata':'true'}})
with urllib.request.build_opener(urllib.request.ProxyHandler({{}})).open(request,timeout=5) as response:
    metadata=json.load(response)
assert metadata['compute']['resourceId'].casefold()=={identity!r}.casefold()
pathlib.Path({root!r}).mkdir(mode=0o700)
print('SB_LINUX_STAGE_READY',flush=True)
SB_PREPARE
''', "SB_LINUX_STAGE_READY")]
    for index, offset in enumerate(range(0, len(packed), LINUX_CHUNK_SIZE)):
        chunk = packed[offset:offset + LINUX_CHUNK_SIZE]
        marker = "SB_LINUX_PART_" + str(index)
        scripts.append((str(index), f'''set -eu
umask 077
python3 - <<'SB_PART'
from pathlib import Path
with Path({root + '/part-' + format(index, '03d') + '.b64'!r}).open('x') as stream:
    stream.write({chunk!r})
print({marker!r},flush=True)
SB_PART
''', marker))
    for label, script, marker in scripts:
        if len(script.encode()) >= 65536:
            raise ValueError("Linux staging script exceeds its bounded transport size")
        path = azure.work / ("linux-stage-" + label + ".sh")
        path.write_text(script)
        result = azure.call("vm", "run-command", "invoke", "--ids", identity,
                            "--command-id", "RunShellScript", "--scripts", "@" + str(path), timeout=180)
        (azure.work / ("linux-stage-" + label + "-response.json")).write_text(json.dumps(result))
        output = "\n".join(row.get("message", "") for row in result.get("value", []))
        if marker not in output.splitlines():
            raise lab.PreflightError("Linux payload write was not acknowledged; no automatic replay")
        print("Linux payload stage verified: " + label, flush=True)


def run(azure, state, expected_digest, packed, packed_sha, *, targets=None, guest_script_factory=None,
        stage_linux_payload=True):
    targets = list(TARGETS if targets is None else targets)
    if not targets or len(set(targets)) != len(targets) or set(targets) - set(TARGETS):
        raise ValueError("Only the existing Linux/Windows targets may be selected")
    if not stage_linux_payload and guest_script_factory is None:
        raise ValueError('A verified download script is required without staged payload chunks')
    if iso.network_digest(state) != expected_digest:
        raise lab.PreflightError("Network changed since review; no changes attempted")
    report = {"kind": "azure-native-service-setup", "status": "failed", "targets": targets,
              "full_network_setup_test_executed": False, "full_competition_readiness_proven": False}
    (azure.work / "initial-network.json").write_text(json.dumps(state, indent=2))
    run_id = uuid.uuid4().hex[:12]
    report["run_id"] = run_id
    try:
        for name in sorted(iso.PUBLIC_HOSTS):
            iso.require_off(azure, state["vms"])
            iso.change_association(azure, name, state["network"][name], restore=False)
        vms = lab.guard(azure)
        started = time.monotonic()
        (azure.work / "power-intent.json").write_text(json.dumps({"vms": vms, "attempted_starts": targets}))
        _, errors = lab.parallel(targets, lambda name: azure.call("vm", "start", "--ids", vms[name]["id"], "--no-wait", timeout=90))
        if errors:
            raise lab.PreflightError("Target start request failed")
        lab.wait_for(azure, vms, targets, 600, running=True)
        report["boot_seconds_excluded_from_setup"] = round(time.monotonic() - started, 3)
        print("Targets ready; starting actual guest-local service setup checks concurrently.", flush=True)
        rehearsal_started = time.monotonic()

        def invoke(name):
            if name == "sb-linux-target" and stage_linux_payload:
                stage_linux(azure, vms[name]["id"], packed, run_id)
            script = (guest_script_factory or guest_script)(name, vms[name]["id"], packed, packed_sha, run_id)
            path = azure.work / (name + (".ps1" if name == "sb-windows-target" else ".sh"))
            path.write_text(script)
            command_id = "RunPowerShellScript" if name == "sb-windows-target" else "RunShellScript"
            result = azure.call("vm", "run-command", "invoke", "--ids", vms[name]["id"],
                                "--command-id", command_id, "--scripts", "@" + str(path), timeout=2400)
            (azure.work / (name + "-response.json")).write_text(json.dumps(result))
            summaries = []
            for item in result.get("value", []):
                for line in item.get("message", "").splitlines():
                    summary = decode_guest_summary(line)
                    if summary is not None:
                        summaries.append(summary)
            if len(summaries) != 1:
                raise lab.PreflightError("Guest did not return one complete setup result")
            print(name + ": " + json.dumps(summaries[0], separators=(",", ":")), flush=True)
            return summaries[0]

        report["guests"], report["guest_errors"] = lab.parallel(targets, invoke)
        report["guest_rehearsal_wall_seconds"] = round(time.monotonic() - rehearsal_started, 3)
        if (not report["guest_errors"] and len(report["guests"]) == len(targets) and
                all(row["status"] == "passed" for row in report["guests"].values())):
            report["status"] = "guest_local_setup_passed"
    except (Exception, KeyboardInterrupt) as exc:
        report["error"] = str(exc) if isinstance(exc, lab.PreflightError) else type(exc).__name__
    finally:
        print("Restoring original VM power and reserved IP associations.", flush=True)
        try:
            lab.cleanup(azure, state["vms"], targets)
            iso.require_off(azure, state["vms"])
            report["all_vms_deallocated"] = True
        except (Exception, KeyboardInterrupt):
            report["all_vms_deallocated"] = False
        errors = {}
        if report["all_vms_deallocated"]:
            for name in sorted(iso.PUBLIC_HOSTS):
                try:
                    iso.require_off(azure, state["vms"])
                    iso.change_association(azure, name, state["network"][name], restore=True)
                except (Exception, KeyboardInterrupt) as exc:
                    errors[name] = type(exc).__name__
        else:
            errors["power"] = "Public association restoration held for unverified power state"
        if not errors:
            try:
                if iso.network_digest(iso.snapshot(azure)) != expected_digest:
                    raise lab.PreflightError("Final network digest mismatch")
            except Exception as exc:
                errors["final_snapshot"] = type(exc).__name__
        report["network_restored"] = not errors
        report["network_restore_errors"] = errors
        if errors:
            report["status"] = "cleanup_not_verified"
        (azure.work / "result.json").write_text(json.dumps(report, indent=2))
    return report


def main():
    if os.name != "posix":
        raise RuntimeError("Run the Azure wrapper in an authenticated Cloud Shell Bash session")
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--runtime-sha256")
    parser.add_argument("--expected-network-sha256")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--target", action="append", choices=TARGETS,
                        help="Select an existing target; default is both. Does not count unselected targets as tested.")
    args = parser.parse_args()
    os.umask(0o077)
    if args.execute and not all([args.runtime, args.runtime_sha256, args.expected_network_sha256]):
        parser.error("execution requires the exact runtime and reviewed network digests")
    packed, packed_sha = payload(args.runtime, args.runtime_sha256) if args.execute else (None, None)
    descriptor = os.open(Path.home() / ".sentinel-azure-preflight.lock",
                         os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = Path(tempfile.mkdtemp(prefix="sentinel-azure-setup-"))
        print("Private diagnostic directory: " + str(work), flush=True)
        azure = lab.Azure(work)
        state = iso.snapshot(azure)
        (work / "initial-network.json").write_text(json.dumps(state, indent=2))
        if not args.execute:
            print(json.dumps({"status": "network_reviewed", "network_sha256": iso.network_digest(state)}))
            return 0
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
        result = run(azure, state, args.expected_network_sha256, packed, packed_sha, targets=args.target)
        print(json.dumps(result, indent=2), flush=True)
        return 0 if result["status"] == "guest_local_setup_passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
