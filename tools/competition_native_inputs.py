"""Owned native competition-service fixtures; not an event-specific inventory.

Used only after the existing Azure guest identity guard. Existing services and
accounts are not repurposed. Test users, shares, units, keys, and data are unique.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tools.setup_native_inputs import linux_inputs, windows_inputs, source, runbook, manifest, free_port


WINDOWS_SCORING_WHEELS = [{'url': 'https://files.pythonhosted.org/packages/4f/07/2519c128aad9c4062aa46bb8d584e01f8154d119e0a09191258da5935788/sspilib-0.6.0-cp311-abi3-win_amd64.whl', 'sha256': 'b841fabe630101d9e2be6ba56407a2a539087ee85d6ca1477748c21135c9f636'}, {'url': 'https://files.pythonhosted.org/packages/76/d3/250e13e7b3473a0f441f4d680d511ad30ce432d0180115dec9840d88fe89/smbprotocol-1.17.0-py3-none-any.whl', 'sha256': 'bd1abff5417f5af83ca516a64ab8e5acece3dbdcf58d4e5e23e47f5165a77349'}, {'url': 'https://files.pythonhosted.org/packages/42/8b/cb12b1b60c91b074ca6bf0fdd59aa8f10d8bc5f73af8faece86ef0421b37/cryptography-50.0.1-cp311-abi3-win_amd64.whl', 'sha256': 'aed8db4f6d71c51efb89530e12d9464e7bf2923d46c3205dc794a2a93f8c0648'}, {'url': 'https://files.pythonhosted.org/packages/60/a6/8b149b2c3f2e11aaa1618ef64500b45f50f22c57a977a4dff1aff1f91042/cffi-2.1.1-cp313-cp313-win_amd64.whl', 'sha256': '1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d'}, {'url': 'https://files.pythonhosted.org/packages/0c/c3/44f3fbbfa403ea2a7c779186dc20772604442dde72947e7d01069cbe98e3/pycparser-3.0-py3-none-any.whl', 'sha256': 'b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992'}, {'url': 'https://files.pythonhosted.org/packages/0e/8c/3d0154b8781a371ef1b791063da5a223187dd17738c5b188edc5e9657f9a/pyspnego-0.12.2-py3-none-any.whl', 'sha256': '04e7c9260ced15197b3f42b891ffa30fa98c37bb09372c5c2bf927bcdfe30b53'}]


def download_windows_observer_wheels(deadline):
    """Fetch independent hash-pinned dependencies with three bounded workers."""
    def download(item):
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('opening deadline exhausted installing observers')
        with urllib.request.urlopen(item['url'],timeout=min(25,remaining)) as response:
            data = response.read(8*1024*1024+1)
        if time.monotonic() >= deadline:
            raise TimeoutError('opening deadline exhausted downloading observers')
        if len(data)>8*1024*1024 or hashlib.sha256(data).hexdigest()!=item['sha256']:
            raise ValueError('observer wheel checksum mismatch')
        return data
    with ThreadPoolExecutor(max_workers=3) as pool:
        return list(pool.map(download, WINDOWS_SCORING_WHEELS))


def prepare_opening_observer(root, deadline):
    """Install observers inside the opening clock, before asserting cold state."""
    dependencies = root / 'observer-dependencies'
    if dependencies.exists():
        raise RuntimeError('fresh observer directory required')
    if os.name == 'nt':
        payloads = download_windows_observer_wheels(deadline)
        dependencies.mkdir()
        for data in payloads:
            if time.monotonic() >= deadline:
                raise TimeoutError('opening deadline exhausted unpacking observers')
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if any(Path(name).is_absolute() or '..' in name.split('/') or '\\' in name or ':' in name
                       for name in archive.namelist()):
                    raise ValueError('invalid observer archive path')
                archive.extractall(dependencies)
    else:
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('opening deadline exhausted installing observers')
        subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-input',
                        '--target',str(dependencies),'paramiko==5.0.0','smbprotocol==1.17.0'],
                       check=True,timeout=remaining,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    from sentinel_blue.native_probes import dependency_readiness
    import importlib
    importlib.invalidate_caches()
    checked = dependency_readiness([{'kind':kind} for kind in
                                   (['smb'] if os.name=='nt' else ['ssh-login','smb','postgres','dns-update'])])
    if not checked['ready']:
        raise RuntimeError('native observer prerequisites unavailable: '+', '.join(checked['missing']))
    (dependencies/'verified').write_text('ready')


def diagnose_owned_windows_smb_write(spec):
    """Bounded protocol diagnostics on this helper's disposable loopback share.

    Never changes a measured failure to a pass or changes server security. Every
    trial uses an exclusive fresh filename and delete-on-close. Only fixed stage
    names and exception types leave the subprocess; no credentials or dumps.
    """
    if os.name != "nt" or spec.get("target") != "127.0.0.1" or not spec.get("share", "").startswith("SBS"):
        raise ValueError("SMB diagnosis requires this helper's owned Windows fixture")
    from sentinel_blue.native_probes import _command
    code = r'''import json,sys,time,uuid,secrets
sys.path[:0]=json.loads(sys.argv[1])
from sentinel_blue.native_probes import _secret
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open,ImpersonationLevel,FilePipePrinterAccessMask as A,ShareAccess,CreateDisposition,CreateOptions
from smbprotocol.file_info import FileAttributes
request=json.load(sys.stdin)
spec=request['spec']; variant=request['variant']
connection=None; stage='connect'; started=time.monotonic()
try:
    connection=Connection(uuid.uuid4(),'127.0.0.1',port=445,require_signing=True)
    connection.connect(timeout=4)
    stage='login'
    session=Session(connection,username=spec['username'],password=_secret(spec),require_encryption=True,auth_protocol='ntlm')
    session.connect()
    stage='tree'
    tree=TreeConnect(session,'\\\\127.0.0.1\\'+spec['share']);tree.connect()
    stage='create'
    access=A.FILE_READ_DATA|A.FILE_WRITE_DATA|A.DELETE
    if variant.startswith('attributes'): access|=A.FILE_READ_ATTRIBUTES|A.SYNCHRONIZE
    opened=Open(tree,'probes\\sb-diagnostic-'+secrets.token_hex(16))
    opened.create(ImpersonationLevel.Impersonation,access,FileAttributes.FILE_ATTRIBUTE_NORMAL,
                  ShareAccess.FILE_SHARE_READ|ShareAccess.FILE_SHARE_WRITE|ShareAccess.FILE_SHARE_DELETE,
                  CreateDisposition.FILE_CREATE,CreateOptions.FILE_NON_DIRECTORY_FILE|CreateOptions.FILE_DELETE_ON_CLOSE)
    stage='write'; payload=secrets.token_bytes(64)
    assert opened.write(payload,write_through=not variant.endswith('flush'))==len(payload)
    if variant.endswith('flush'):
        stage='flush';opened.flush()
    stage='readback';assert opened.read(0,len(payload))==payload
    stage='close';opened.close()
    stage='disconnect';tree.disconnect();session.disconnect()
    result={'healthy':True,'stage':'complete'}
except Exception as exc:
    result={'healthy':False,'stage':stage,'exception_type':type(exc).__name__}
finally:
    if connection is not None: connection.disconnect(close=False)
result.update(variant=variant,seconds=round(time.monotonic()-started,3))
print(json.dumps(result))
'''
    output = []
    paths = json.dumps([str(Path(p).absolute()) for p in sys.path if p])
    for variant in ("original", "attributes", "flush", "attributes-flush"):
        try:
            data = _command([sys.executable, "-c", code, paths], 5,
                            incoming=json.dumps({"spec": spec, "variant": variant}).encode())
            output.append(json.loads(data))
        except Exception as exc:
            output.append({"variant": variant, "healthy": False, "exception_type": type(exc).__name__})
    return output


def linux_competition_inputs(root, suffix):
    import pwd
    tasks, services, initial, old_identities, old_cleanup, private_values = linux_inputs(root, suffix)
    base = Path("/var/lib") / ("sentinel-setup-" + suffix)
    cache = Path("/var/cache/bind") / ("sentinel-" + suffix)
    ssh_user, smb_user = "sbh" + suffix[:10], "sbm" + suffix[:10]
    for username in (ssh_user, smb_user):
        try:
            pwd.getpwnam(username)
        except KeyError:
            continue
        raise RuntimeError("a fixture account already exists")
    password = private_values[0]
    password_path = Path(source(root, "scoring-password", password)["path"])
    extra_packages = ["samba", "openssh-server", "bind9-dnsutils", "iputils-ping", "python3-pip"]
    tasks[0]["options"]["packages"].extend(extra_packages)
    for name in extra_packages:
        initial[name] = subprocess.run(["dpkg-query", "-W", "-f=${Status}", name], capture_output=True, text=True).stdout == "install ok installed"
    dependencies = root / "observer-dependencies"
    sys.path.insert(0, str(dependencies))
    os.environ["PYTHONPATH"] = str(dependencies) + os.pathsep + os.environ.get("PYTHONPATH", "")

    def revise(reference, content):
        reference.update(source(root, Path(reference["path"]).name, content))
    def text(reference):
        return Path(reference["path"]).read_text()
    def file_row(name, path, content, mode="0644"):
        return {"path": str(path), "source": source(root, name, content), "mode": mode, "previous_sha256": "absent"}
    header = "[Unit]\nDescription=Owned Sentinel competition rehearsal\n[Service]\nType=simple\n"
    footer = "\nRestart=no\n[Install]\nWantedBy=multi-user.target\n"
    extra_units = {}
    ports = {"ssh": free_port(), "smb": free_port(), "https": free_port()}
    if len(set(ports.values())) != 3:
        raise RuntimeError("fixture port collision")
    host_key = root / "ssh-host-key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True, capture_output=True, timeout=20)
    known_hosts = source(root, "scoring-known-hosts", f"[127.0.0.1]:{ports['ssh']} " + host_key.with_suffix(".pub").read_text())
    certificate, tls_key = root / "tls-cert.pem", root / "tls-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(tls_key),
                    "-out", str(certificate), "-subj", "/CN=www.setup.test", "-addext", "subjectAltName=DNS:www.setup.test,IP:127.0.0.1"],
                   check=True, capture_output=True, timeout=30)
    tls_key.chmod(0o600)
    tsig = base64.b64encode(os.urandom(32)).decode()
    private_values.append(tsig)
    key_content = f'key "sb-{suffix}" {{ algorithm hmac-sha256; secret "{tsig}"; }};\n'
    update_key = source(root, "update.key", key_content)
    dynamic_zone = "$TTL 30\n@ IN SOA ns.dynamic.setup.test. hostmaster.setup.test. (1 30 30 30 30)\n@ IN NS ns.dynamic.setup.test.\nns IN A 127.0.0.1\n"
    layout = next(task for task in tasks if task["id"] == "layout")
    extra_layout = f"""
test -d /run/sshd || install -d -o root -g root -m 0755 /run/sshd
install -d -m 0755 {base}/ssh {base}/tls {base}/smb {base}/smb/share
install -d -m 0700 {base}/smb/private {base}/smb/lock {base}/smb/cache {base}/smb/state
for name in {ssh_user} {smb_user}; do
  ! id "$name" >/dev/null 2>&1
  useradd --system --user-group --no-create-home --home-dir {base}/smb/share --shell /bin/sh "$name"
  id -u "$name" > {base}/"$name.uid"
done
printf '%s\\n' '{ssh_user}:{password}' | chpasswd
chown {smb_user}:{smb_user} {base}/smb/share
install -d -o {smb_user} -g {smb_user} -m 0700 {base}/smb/share/probes
printf '%s\\n' sentinel-smb-scored-file > {base}/smb/share/read.txt
chmod 0644 {base}/smb/share/read.txt
cat > {cache}/dynamic.zone <<'SB_ZONE'
{dynamic_zone}SB_ZONE
cat > {cache}/update.key <<'SB_KEY'
{key_content}SB_KEY
chown bind:bind {cache}/dynamic.zone {cache}/update.key
chmod 0600 {cache}/update.key
test -f {dependencies}/verified || python3 -m pip install --disable-pip-version-check --no-input --target {dependencies} paramiko==5.0.0 smbprotocol==1.17.0
"""
    revise(layout["options"]["apply"], text(layout["options"]["apply"]) + extra_layout)
    revise(layout["options"]["check"], text(layout["options"]["check"]) + f"test -f {base}/{ssh_user}.uid\ntest -f {base}/{smb_user}.uid\n")
    web = next(task for task in tasks if task["id"] == "web")
    config = web["options"]["files"][0]["source"]
    conf = text(config).replace("http {", f"http {{ server {{ listen 127.0.0.1:{ports['https']} ssl; ssl_certificate {base}/tls/cert.pem; ssl_certificate_key {base}/tls/key.pem; root {base}/web; }} ")
    revise(config, conf)
    web["options"]["files"].extend([file_row("tls-cert-source", base / "tls/cert.pem", certificate.read_text()),
                                        file_row("tls-key-source", base / "tls/key.pem", tls_key.read_text(), "0600")])
    web_manifest = next(service for service in services if service["protocol"] == "http")
    web_manifest["expected_transactions"].append({"name": "WWW SSL", "kind": "https", "target": f"https://127.0.0.1:{ports['https']}/index.txt",
        "server_name": "www.setup.test", "expected_status": [200], "expected_body": "sentinel-native-setup-content-v1",
        "ca_file": str(certificate), "ca_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest(), "verify": True})
    dns = next(task for task in tasks if task["id"] == "dns")
    dns_ref = dns["options"]["files"][0]["source"]
    reverse_path = Path("/etc/bind") / ("sentinel-" + suffix + ".reverse.zone")
    revise(dns_ref, text(dns_ref) + f'include "{cache}/update.key";\nzone "dynamic.setup.test" {{ type primary; file "{cache}/dynamic.zone"; allow-update {{ key "sb-{suffix}"; }}; }};\nzone "0.0.127.in-addr.arpa" {{ type primary; file "{reverse_path}"; }};\n')
    reverse_zone = "$TTL 30\n@ IN SOA ns.setup.test. hostmaster.setup.test. (1 30 30 30 30)\n@ IN NS ns.setup.test.\n1 IN PTR www.setup.test.\n"
    dns["options"]["files"].append(file_row("reverse.zone", reverse_path, reverse_zone))
    dns_manifest = next(service for service in services if service["protocol"] == "dns")
    dns_port = dns_manifest["port"]
    dns_manifest["expected_transactions"].extend([
        {"name": "DNS TCP FWD", "kind": "dns", "target": "127.0.0.1", "port": dns_port, "query": "www.setup.test", "record_type": "A", "expected_answers": ["127.0.0.1"], "transport": "tcp"},
        {"name": "DNS PTR", "kind": "dns", "target": "127.0.0.1", "port": dns_port, "query": "1.0.0.127.in-addr.arpa", "record_type": "PTR", "expected_answers": ["www.setup.test"], "transport": "tcp"},
        {"name": "Dynamic DNS", "kind": "dns-update", "target": "127.0.0.1", "port": dns_port, "zone": "dynamic.setup.test", "prefix": "sb", "key_file": update_key["path"], "value": "127.0.0.1", "allow_write": True, "timeout": 3},
    ])
    db = next(service for service in services if service["protocol"] == "postgresql")
    db["expected_transactions"] = [{"name": "Postgres Access", "kind": "postgres", "target": "127.0.0.1", "port": db["port"],
        "username": "sb_setup_test", "database": "sb_setup_test", "password_file": str(password_path), "sslmode": "disable"}]

    def add_service(role, config_files, argv, checks, *, covers=True):
        unit = f"sentinel-setup-{suffix}-{role}"
        extra_units[role] = unit
        files = config_files + [file_row(role + ".service", Path("/etc/systemd/system") / (unit + ".service"), header + "ExecStart=" + argv + footer)]
        task = {"id": role, "host": "target", "recipe": "linux-service", "requires": ["layout"], "estimate_seconds": 30,
                "timeout_seconds": 180, "options": {"service": unit, "enable": True, "files": files}}
        if covers:
            task["service_id"] = unit
        tasks.append(task)
        services.append(manifest(unit, role, ports[role], checks))
        return unit
    ssh_config = f"""Port {ports['ssh']}
ListenAddress 127.0.0.1
HostKey {base}/ssh/host-key
PidFile {base}/ssh/sshd.pid
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
AllowUsers {ssh_user}
"""
    add_service("ssh", [file_row("sshd.conf", base / "ssh/sshd.conf", ssh_config), file_row("sshd-host-key", base / "ssh/host-key", host_key.read_text(), "0600")],
                f"/usr/sbin/sshd -D -e -f {base}/ssh/sshd.conf", [{"name": "SSH Login", "kind": "ssh-login", "target": "127.0.0.1", "port": ports["ssh"],
                "username": ssh_user, "password_file": str(password_path), "known_hosts_file": known_hosts["path"], "timeout": 3}])
    smb_config = f"""[global]
server role = standalone server
workgroup = SBSETUP
security = user
map to guest = Never
server min protocol = SMB3
smb encrypt = required
interfaces = 127.0.0.1
bind interfaces only = yes
smb ports = {ports['smb']}
disable netbios = yes
load printers = no
printing = bsd
printcap name = /dev/null
lock directory = {base}/smb/lock
state directory = {base}/smb/state
cache directory = {base}/smb/cache
private dir = {base}/smb/private
pid directory = {base}/smb
log file = {base}/smb/log.%m
[scoring]
path = {base}/smb/share
valid users = {smb_user}
read only = no
guest ok = no
"""
    smb_checks = [{"name": "SMB " + operation.title(), "kind": "smb", "target": "127.0.0.1", "port": ports["smb"], "share": "scoring",
        "username": smb_user, "password_file": str(password_path), "operation": operation, "encrypt": True, "timeout": 3,
        **({"path": "read.txt", "expected_sha256": hashlib.sha256(b"sentinel-smb-scored-file\n").hexdigest()} if operation == "read" else {}),
        **({"directory": "probes", "allow_write": True} if operation == "write" else {})} for operation in ("login", "write", "read")]
    smb_unit = add_service("smb", [file_row("smb.conf", base / "smb/smb.conf", smb_config)],
                          f"/usr/sbin/smbd --foreground --no-process-group --configfile={base}/smb/smb.conf", smb_checks, covers=False)
    tasks.append(runbook(root, "smb-account", f"set -eu\npdbedit -s {base}/smb/smb.conf -L -u {smb_user} | cut -d: -f1 | grep -Fx {smb_user}\n",
        f"set -eu\nprintf '%s\\n%s\\n' '{password}' '{password}' | smbpasswd -s -a -c {base}/smb/smb.conf {smb_user}\n", requires=["smb"], service=smb_unit))

    def identities():
        return old_identities() | {role: subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit], capture_output=True, text=True).stdout.strip() for role, unit in extra_units.items()}
    def cleanup():
        verified = True
        for unit in extra_units.values():
            subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=30)
            subprocess.run(["systemctl", "disable", unit], capture_output=True, timeout=20)
            if subprocess.run(["systemctl", "is-active", "--quiet", unit], capture_output=True).returncode == 0:
                verified = False
            else:
                (Path("/etc/systemd/system") / (unit + ".service")).unlink(missing_ok=True)
        for username in (ssh_user, smb_user):
            try:
                current = pwd.getpwnam(username)
            except KeyError:
                continue
            record = base / (username + ".uid")
            if not record.is_file() or record.read_text().strip() != str(current.pw_uid) or not verified:
                verified = False
                continue
            verified = subprocess.run(["userdel", username], capture_output=True).returncode == 0 and verified
        if not verified:
            return {"verified": False, "reason": "owned account or service cleanup requires review"}
        result = old_cleanup()
        reverse_path.unlink(missing_ok=True)
        result["verified"] = result["verified"] and not reverse_path.exists()
        result["owned_scoring_accounts_removed"] = True
        return result
    return tasks, services, initial, identities, cleanup, private_values


def windows_competition_inputs(root, suffix):
    """Owned Windows SMB share and account plus the existing IIS/DNS fixtures."""
    if os.name != "nt" or sys.version_info[:2] != (3, 13):
        raise ValueError("Windows scoring fixture requires the reviewed CPython 3.13 guest")
    tasks, services, initial, old_identities, old_cleanup, private_values = windows_inputs(root, suffix)
    from sentinel_blue.setup_transport import powershell_environment
    ps = shutil.which("powershell.exe") or shutil.which("pwsh")
    def command(code):
        return subprocess.run([ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", code],
                              capture_output=True, text=True, timeout=120, env=powershell_environment(ps))
    header = "$ErrorActionPreference='Stop'\n"
    username, share = "sbu" + suffix, "SBS" + suffix
    base, dependencies = root / "smb-share", root / "observer-dependencies"
    marker = root / "smb-account.sid"
    password = "Sb9!" + os.urandom(20).hex()
    secret = source(root, "smb-password", password)
    private_values.append(password)
    before = command(header + "Get-Service LanmanServer | Select-Object Name,@{n='Status';e={[string]$_.Status}},@{n='StartType';e={[string]$_.StartType}} | ConvertTo-Json -Compress")
    if before.returncode:
        raise RuntimeError("Windows SMB service state was not established")
    before = json.loads(before.stdout)
    initial.append({"Name": "LanmanServer", **before})
    collision = command(header + f"if ((Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue) -or (Get-SmbShare -Name '{share}' -ErrorAction SilentlyContinue)) {{ exit 10 }}; exit 0")
    if collision.returncode or base.exists() or marker.exists():
        raise RuntimeError("Windows fixture account, share, or path already exists")
    sys.path.insert(0, str(dependencies))
    # Every wheel is downloaded and SHA-256 checked before any extraction.
    download = f"""import hashlib,io,pathlib,sys,urllib.request,zipfile
assert sys.version_info[:2]==(3,13)
root=pathlib.Path({str(dependencies)!r})
assert not root.exists()
items={WINDOWS_SCORING_WHEELS!r}
payloads=[]
for item in items:
    with urllib.request.urlopen(item['url'],timeout=25) as response:
        data=response.read(8*1024*1024+1)
    assert len(data)<=8*1024*1024 and hashlib.sha256(data).hexdigest()==item['sha256']
    payloads.append(data)
root.mkdir()
for data in payloads:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert all(not pathlib.PurePosixPath(name).is_absolute() and '..' not in pathlib.PurePosixPath(name).parts and '\\\\' not in name and ':' not in name for name in archive.namelist())
        archive.extractall(root)
sys.path.insert(0,str(root))
import smbprotocol,spnego,cryptography
(root/'verified').write_text('ready')
"""
    encoded = base64.b64encode(download.encode()).decode()
    tasks.append(runbook(root, "scoring-clients", header + f"if (!(Test-Path -LiteralPath '{dependencies}\\verified')) {{exit 10}}; exit 0\n",
        header + f"& '{sys.executable}' -c \"import base64; exec(base64.b64decode('{encoded}'))\"\nif ($LASTEXITCODE -ne 0) {{throw 'Scoring client installation failed'}}\nexit 0\n"))
    tasks[0]["options"]["features"].append("FS-FileServer")
    tasks.append({"id": "smb-service", "host": "target", "recipe": "windows-service", "requires": ["features"],
                  "options": {"service": "LanmanServer", "enable": True}})
    check = header + f"""$user=Get-LocalUser -Name '{username}'
if (!(Test-Path -LiteralPath '{marker}') -or $user.SID.Value -ne (Get-Content -Raw -LiteralPath '{marker}').Trim() -or !$user.Enabled) {{exit 10}}
$share=Get-SmbShare -Name '{share}'
if ($share.Path -ne '{base}' -or !$share.EncryptData) {{exit 10}}
exit 0
"""
    apply = header + f"""if ((Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue) -or (Get-SmbShare -Name '{share}' -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath '{base}')) {{throw 'Fixture objects already exist'}}
$password=ConvertTo-SecureString (Get-Content -Raw -LiteralPath '{secret['path']}') -AsPlainText -Force
$user=New-LocalUser -Name '{username}' -Password $password -PasswordNeverExpires -AccountNeverExpires -Description 'Owned Sentinel native scoring fixture'
Set-Content -LiteralPath '{marker}' -Value $user.SID.Value -Encoding Ascii
New-Item -ItemType Directory -Path '{base}\\probes' -Force | Out-Null
[IO.File]::WriteAllBytes('{base}\\read.txt',[Text.Encoding]::ASCII.GetBytes("sentinel-windows-smb`n"))
$acl=Get-Acl -LiteralPath '{base}'
$rule=New-Object System.Security.AccessControl.FileSystemAccessRule($user.SID,'Modify','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath '{base}' -AclObject $acl
New-SmbShare -Name '{share}' -Path '{base}' -ChangeAccess ($env:COMPUTERNAME+'\\{username}') -EncryptData $true | Out-Null
exit 0
"""
    tasks.append(runbook(root, "smb-share", check, apply, requires=["smb-service", "scoring-clients"], service="LanmanServer"))
    checks = [{"name": "SMB " + operation.title(), "kind": "smb", "target": "127.0.0.1", "port": 445, "share": share,
        "username": os.environ["COMPUTERNAME"] + "\\" + username, "password_file": secret["path"], "operation": operation,
        "encrypt": True, "timeout": 5,
        **({"path": "read.txt", "expected_sha256": hashlib.sha256(b"sentinel-windows-smb\n").hexdigest()} if operation == "read" else {}),
        **({"directory": "probes", "allow_write": True} if operation == "write" else {})} for operation in ("login", "write", "read")]
    services.append(manifest("LanmanServer", "smb", 445, checks))
    dns = next(service for service in services if service["protocol"] == "dns")
    dns["expected_transactions"].append(dict(dns["expected_transactions"][0], name="DNS TCP", transport="tcp"))

    def identities():
        return old_identities() + [{"Name": "LanmanServer", "Status": command("(Get-Service LanmanServer).Status").stdout.strip()}]
    def cleanup():
        code = header + f"""$share=Get-SmbShare -Name '{share}' -ErrorAction SilentlyContinue
if ($share) {{if ($share.Path -ne '{base}') {{throw 'Share ownership changed'}}; Remove-SmbShare -Name '{share}' -Force}}
$user=Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue
if ($user) {{if (!(Test-Path -LiteralPath '{marker}') -or $user.SID.Value -ne (Get-Content -Raw -LiteralPath '{marker}').Trim()) {{throw 'Account ownership changed'}}; Remove-LocalUser -SID $user.SID}}
if (Test-Path -LiteralPath '{base}') {{Remove-Item -LiteralPath '{base}' -Recurse -Force}}
if ((Get-SmbShare -Name '{share}' -ErrorAction SilentlyContinue) -or (Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue)) {{throw 'Fixture cleanup incomplete'}}
"""
        if before["Status"] != "Running":
            code += "Stop-Service LanmanServer -Force\n"
        code += f"Set-Service LanmanServer -StartupType {before['StartType']}\nexit 0\n"
        result = command(code)
        if result.returncode:
            return {"verified": False, "reason": "owned SMB cleanup requires review"}
        restored = old_cleanup()
        restored["verified"] = restored["verified"] and not base.exists()
        restored["owned_smb_share_and_account_removed"] = True
        return restored
    return tasks, services, initial, identities, cleanup, private_values
