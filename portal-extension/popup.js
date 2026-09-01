// Fail-closed, secret-local bootstrap for one explicitly selected relay.
const fields = [
  'portalOrigin', 'frameOrigins', 'packageUrl', 'checksum', 'controllerHost',
  'operatorPrincipal', 'operatorEpoch', 'tlsCertPath', 'tlsKeyPath',
  'tlsCaPath', 'networks', 'inventory', 'deviceSelector', 'consoleSelector',
  'operatingSystem'
];
const status = document.getElementById('status');
const value = id => document.getElementById(id).value.trim();
const releaseVersion = chrome.runtime.getManifest().version;

function exactOrigin(raw, label) {
  const parsed = new URL(raw);
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.origin !== raw) {
    throw new Error(`${label} must be an exact HTTP(S) origin`);
  }
  return parsed.origin;
}

function validateLocalPath(path, label, operatingSystem) {
  if (!path || path.length > 512 || /[\r\n\0]/.test(path)) {
    throw new Error(`Controller ${label} path is invalid`);
  }
  if (operatingSystem === 'linux' && !path.startsWith('/')) {
    throw new Error(`Linux controller ${label} path must be absolute`);
  }
  if (operatingSystem === 'windows' && !/^[A-Za-z]:\\/.test(path)) {
    throw new Error(`Windows controller ${label} path must be an absolute drive path`);
  }
}

async function profile() {
  const p = {};
  for (const id of fields) p[id] = value(id);
  p.authorizedNetworks = p.networks.split(/\s+/).filter(Boolean);
  p.allowedFrameOrigins = p.frameOrigins
    .split(/\s+/)
    .filter(Boolean)
    .map(origin => exactOrigin(origin, 'Console-frame entry'));
  p.inventoryObject = JSON.parse(p.inventory);
  p.portalOrigin = exactOrigin(p.portalOrigin, 'Portal origin');
  const packageUrl = new URL(p.packageUrl);
  if (packageUrl.protocol !== 'https:' || packageUrl.username || packageUrl.password) {
    throw new Error('Package URL must use HTTPS without embedded credentials');
  }
  p.packageUrl = packageUrl.href;
  if (!/^[a-f0-9]{64}$/i.test(p.checksum)) {
    throw new Error('SHA-256 must contain 64 hexadecimal characters');
  }
  if (!p.controllerHost || !/^[A-Za-z0-9.:[\]-]+$/.test(p.controllerHost)) {
    throw new Error('Controller host is missing or contains unsupported characters');
  }
  try {
    new URL(`https://${p.controllerHost}:8765`);
  } catch (_error) {
    throw new Error('Controller host is not a valid address');
  }
  if (!/^[A-Za-z0-9_.:@-]{1,128}$/.test(p.operatorPrincipal)) {
    throw new Error('Operator principal ID is invalid');
  }
  if (!/^[2-9][0-9]*$/.test(p.operatorEpoch) ||
      !Number.isSafeInteger(Number(p.operatorEpoch))) {
    throw new Error('Operator credential epoch must be an integer from 2 upward');
  }
  p.operatorCredentialEpoch = Number(p.operatorEpoch);
  if (!p.authorizedNetworks.length) {
    throw new Error('At least one authorized network is required');
  }
  if (!['linux', 'windows'].includes(p.operatingSystem)) {
    throw new Error('Operating system must be Linux or Windows');
  }
  validateLocalPath(p.tlsCertPath, 'certificate', p.operatingSystem);
  validateLocalPath(p.tlsKeyPath, 'private key', p.operatingSystem);
  validateLocalPath(p.tlsCaPath, 'CA', p.operatingSystem);
  if (p.authorizedNetworks.some(network => !/^[0-9A-Fa-f:.]+\/\d{1,3}$/.test(network))) {
    throw new Error('Authorized networks must be CIDR values');
  }
  if (!Array.isArray(p.inventoryObject.hosts)) {
    throw new Error('Inventory must contain a hosts array');
  }
  if (!Array.isArray(p.inventoryObject.authorized_networks)) {
    throw new Error('Inventory must contain authorized_networks');
  }
  const event = p.inventoryObject.event_profile;
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new Error('Inventory must contain an event_profile object');
  }
  if (event.profile_version !== 1) {
    throw new Error('Event profile_version must be 1');
  }
  if (event.environment !== 'live-competition') {
    throw new Error('Portal bootstrap requires a live-competition profile');
  }
  if (event.architecture?.single_live_scored_network !== true ||
      event.architecture?.blue_staging_non_authoritative !== true) {
    throw new Error('Event profile must preserve one live scored network and non-authoritative staging');
  }
  if (event.approval?.status !== 'approved' || !event.approval?.approved_by) {
    throw new Error('Event profile requires explicit approval');
  }
  if (event.release?.approved !== true || event.release?.version !== releaseVersion) {
    throw new Error(`Event profile must approve Sentinel Blue ${releaseVersion}`);
  }
  if (String(event.release?.sha256 || '').toLowerCase() !== p.checksum.toLowerCase()) {
    throw new Error('Event profile release SHA-256 must match the selected package');
  }
  if (!/^[a-f0-9]{64}$/.test(String(event.release?.controller_ca_sha256 || ''))) {
    throw new Error('Event profile must pin an exact controller CA SHA-256');
  }
  if (event.release?.public_url !== p.packageUrl) {
    throw new Error('Event profile public release URL must match the selected package');
  }
  if (event.release?.frozen !== true ||
      event.release?.submitted_to_officials !== true ||
      event.release?.submission_approved !== true ||
      event.release?.public_and_equal_access !== true) {
    throw new Error('Event profile release must be frozen, submitted, approved, public, and equally available');
  }
  if (event.release?.cloud_processing !== false ||
      event.release?.external_telemetry_export !== false) {
    throw new Error('Portal bootstrap requires local processing and no external telemetry export');
  }
  if (event.competition === 'ccdc-strict' &&
      (event.release?.public_days_before_event < 90 ||
       event.release?.submitted_days_before_event < 30)) {
    throw new Error('CCDC Strict requires 90 public days and 30 submitted days');
  }
  if (event.competition === 'ncae-standard' &&
      (event.release?.public_days_before_event < 7 ||
       event.release?.submitted_days_before_event < 7)) {
    throw new Error('NCAE Standard requires public disclosure and approval at least 7 days before the event');
  }
  if (!Array.isArray(event.scope?.authorized_networks) ||
      !Array.isArray(event.scope?.authorized_hosts) ||
      !Array.isArray(event.scope?.controller_ingress_hosts) ||
      !Array.isArray(event.scope?.excluded_hosts)) {
    throw new Error('Event profile requires explicit networks, hosts, controller ingress, and exclusions');
  }
  if (!event.services_confirmed ||
      !Array.isArray(event.services) ||
      !event.services.length) {
    throw new Error('Live portal bootstrap requires confirmed service manifests');
  }
  if (!Array.isArray(event.official_identities)) {
    throw new Error('Event profile requires an official identity manifest');
  }
  if (p.inventoryObject.hosts.length > 1024 || p.authorizedNetworks.length > 64) {
    throw new Error('Profile exceeds the host or network safety limit');
  }
  if (new TextEncoder().encode(JSON.stringify(p.inventoryObject)).length > 1048576) {
    throw new Error('Inventory exceeds the 1 MiB relay limit');
  }
  if (!p.deviceSelector || !p.consoleSelector ||
      p.deviceSelector.length > 512 || p.consoleSelector.length > 512) {
    throw new Error('Portal selectors must contain 1 to 512 characters');
  }
  const profileScope = [...p.authorizedNetworks].sort().join('\n');
  const inventoryScope = p.inventoryObject.authorized_networks.map(String).sort().join('\n');
  const eventScope = event.scope.authorized_networks.map(String).sort().join('\n');
  if (profileScope !== inventoryScope || profileScope !== eventScope) {
    throw new Error('Profile, inventory, and event-profile networks must match exactly');
  }
  const inventoryHosts = p.inventoryObject.hosts
    .map(host => String(host?.address || ''))
    .filter(Boolean)
    .sort()
    .join('\n');
  const eventHosts = event.scope.authorized_hosts.map(String).sort().join('\n');
  if (inventoryHosts !== eventHosts) {
    throw new Error('Event-profile and inventory hosts must match exactly');
  }
  if (!event.scope.controller_ingress_hosts.length ||
      event.scope.controller_ingress_hosts.some(host => !event.scope.authorized_hosts.includes(host))) {
    throw new Error('Controller ingress hosts must be a non-empty subset of authorized hosts');
  }
  if (event.scope.excluded_hosts.some(host => event.scope.authorized_hosts.includes(host))) {
    throw new Error('Excluded hosts cannot also be authorized');
  }
  if (p.inventoryObject.hosts.some(host => host?.allow_restoration === true) &&
      event.capabilities?.file_restoration !== true) {
    throw new Error('Restoration requested but not approved by the event profile');
  }
  if (p.inventoryObject.hosts.some(host => host?.allow_containment === true) &&
      event.capabilities?.session_containment !== true) {
    throw new Error('Containment requested but not approved by the event profile');
  }
  if (p.inventoryObject.hosts.some(host =>
      host && typeof host === 'object' &&
      ['password', 'secret', 'private_key'].some(key => key in host))) {
    throw new Error('Inventory must not contain passwords or inline private keys');
  }
  return p;
}

function shellQuote(text) {
  return "'" + String(text).replace(/'/g, "'\\''") + "'";
}

function encodeUtf8(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

function linuxBootstrap(p) {
  const root = '$HOME/.sentinel-blue';
  const inventory = encodeUtf8(JSON.stringify(p.inventoryObject));
  const setupPython = `
import base64
import hashlib
import json
import os
import pathlib
import secrets
import stat
import urllib.request

url = ${JSON.stringify(p.packageUrl)}
expected = ${JSON.stringify(p.checksum.toLowerCase())}
limit = 134217728
with urllib.request.urlopen(url, timeout=30) as response:
    content_length = response.headers.get("Content-Length")
    if content_length is not None and int(content_length) > limit:
        raise ValueError("package exceeds 128 MiB limit")
    package_bytes = response.read(limit + 1)
if len(package_bytes) > limit:
    raise ValueError("package exceeds 128 MiB limit")
if hashlib.sha256(package_bytes).hexdigest() != expected:
    raise ValueError("checksum mismatch")

root = pathlib.Path.home() / ".sentinel-blue"
root.mkdir(mode=0o700, exist_ok=True)
if root.is_symlink():
    raise ValueError("state root must not be a symbolic link")
os.chmod(root, 0o700)

certificate = pathlib.Path(${JSON.stringify(p.tlsCertPath)})
private_key = pathlib.Path(${JSON.stringify(p.tlsKeyPath)})
controller_ca = pathlib.Path(${JSON.stringify(p.tlsCaPath)})
for tls_file in (certificate, private_key, controller_ca):
    if not tls_file.is_file() or tls_file.is_symlink():
        raise ValueError("pre-provisioned TLS files are unavailable or unsafe")
if stat.S_IMODE(private_key.stat().st_mode) & 0o077:
    raise ValueError("controller private key permissions are too broad")
if hashlib.sha256(controller_ca.read_bytes()).hexdigest() != ${JSON.stringify(String(p.inventoryObject.event_profile.release.controller_ca_sha256).toLowerCase())}:
    raise ValueError("controller CA checksum mismatch")

def secure_create(path, data, mode):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("private file write did not advance")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def atomic_replace(path, data, mode):
    incoming = root / (".incoming-" + secrets.token_hex(8))
    secure_create(incoming, data, mode)
    os.replace(incoming, path)

atomic_replace(root / "sentinel-blue.pyz", package_bytes, 0o700)
atomic_replace(root / "inventory.json", base64.b64decode(${JSON.stringify(inventory)}), 0o600)
controller_token = root / "controller-token.json"
if not controller_token.exists():
    secure_create(
        controller_token,
        json.dumps({"token": secrets.token_urlsafe(48)}).encode("ascii"),
        0o600,
    )
operator_token = root / "operator-token.txt"
if not operator_token.exists():
    secure_create(operator_token, secrets.token_urlsafe(48).encode("ascii"), 0o600)
recovery_key = root / "recovery.key"
if not recovery_key.exists():
    secure_create(recovery_key, secrets.token_bytes(48), 0o600)
(root / "backups").mkdir(mode=0o700, exist_ok=True)
`;
  const setupEncoded = encodeUtf8(setupPython);
  const setupCommand = `python3 -c ${shellQuote(`import base64;exec(base64.b64decode("${setupEncoded}"))`)}`;
  const controller = `https://${p.controllerHost}:8765`;
  const healthPython = `
import ssl
import time
import urllib.request

url = ${JSON.stringify(controller + '/api/v1/health')}
context = ssl.create_default_context(cafile=${JSON.stringify(p.tlsCaPath)})
last = None
for _ in range(30):
    try:
        with urllib.request.urlopen(url, timeout=2, context=context) as response:
            response.read()
        break
    except Exception as error:
        last = error
        time.sleep(1)
else:
    raise RuntimeError(f"controller health check failed: {last}")
`;
  const healthEncoded = encodeUtf8(healthPython);
  const healthCommand = `python3 -c ${shellQuote(`import base64;exec(base64.b64decode("${healthEncoded}"))`)}`;
  const networks = p.authorizedNetworks
    .flatMap(network => ['--authorized-network', shellQuote(network)])
    .join(' ');
  const recovery = `(if [ -e ${root}/controller.db ] || [ -e ${root}/recovery.anchor ]; then test -f ${root}/controller.db && test -f ${root}/recovery.anchor && python3 ${root}/sentinel-blue.pyz recovery-status --database ${root}/controller.db --recovery-key-file ${root}/recovery.key --recovery-anchor ${root}/recovery.anchor >/dev/null; else python3 ${root}/sentinel-blue.pyz recovery-init --database ${root}/controller.db --recovery-key-file ${root}/recovery.key --recovery-anchor ${root}/recovery.anchor >/dev/null; fi)`;
  const commonLauncher = `python3 ${root}/sentinel-blue.pyz launcher --inventory ${root}/inventory.json --event-profile ${root}/inventory.json --package ${root}/sentinel-blue.pyz --checksum ${shellQuote(p.checksum)} --controller ${shellQuote(controller)} --ca-file ${shellQuote(p.tlsCaPath)}`;
  const controllerCommand = `python3 ${root}/sentinel-blue.pyz controller --bind 0.0.0.0 --event-profile ${root}/inventory.json --token-file ${root}/controller-token.json --database ${root}/controller.db --operator-token-file ${root}/operator-token.txt --operator-principal-id ${shellQuote(p.operatorPrincipal)} --operator-credential-epoch ${p.operatorCredentialEpoch} --recovery-key-file ${root}/recovery.key --recovery-anchor ${root}/recovery.anchor --probe-config ${root}/inventory.json --backup-directory ${root}/backups --tls-cert ${shellQuote(p.tlsCertPath)} --tls-key ${shellQuote(p.tlsKeyPath)} --tls-ca-file ${shellQuote(p.tlsCaPath)} ${networks}`;
  return `${setupCommand} && ${recovery} && ${commonLauncher} --preflight && { nohup ${controllerCommand} >${root}/controller.log 2>&1 & controller_pid=$!; if ! ${healthCommand}; then kill "$controller_pid" 2>/dev/null || true; wait "$controller_pid" 2>/dev/null || true; exit 1; fi; sleep 1; if ! kill -0 "$controller_pid" 2>/dev/null; then echo 'controller exited during startup' >&2; exit 1; fi; if ! ${commonLauncher} --token-file ${root}/controller-token.json --execute --yes; then kill "$controller_pid" 2>/dev/null || true; wait "$controller_pid" 2>/dev/null || true; exit 1; fi; }`;
}

function windowsBootstrap(p) {
  const inventory = encodeUtf8(JSON.stringify(p.inventoryObject));
  const controller = `https://${p.controllerHost}:8765`;
  const healthPython = `
import ssl
import time
import urllib.request

url = ${JSON.stringify(controller + '/api/v1/health')}
context = ssl.create_default_context(cafile=${JSON.stringify(p.tlsCaPath)})
last = None
for _ in range(30):
    try:
        with urllib.request.urlopen(url, timeout=2, context=context) as response:
            response.read()
        break
    except Exception as error:
        last = error
        time.sleep(1)
else:
    raise RuntimeError(f"controller health check failed: {last}")
`;
  const healthEncoded = encodeUtf8(healthPython);
  const networkArguments = p.authorizedNetworks
    .map(network => `'--authorized-network','${network.replace(/'/g, "''")}'`)
    .join(',');
  const script = `
$ErrorActionPreference = 'Stop'
function New-RandomBytes([int]$Count) {
  $bytes = New-Object byte[] $Count
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return $bytes
}
function To-Base64Url([byte[]]$Bytes) {
  return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

$root = Join-Path $env:ProgramData 'SentinelBlue'
New-Item -ItemType Directory -Force -Path $root | Out-Null
icacls $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Sentinel Blue ACL setup failed' }

$package = Join-Path $root 'sentinel-blue.pyz'
$incoming = Join-Path $root ('runtime-' + [guid]::NewGuid().ToString('N') + '.incoming')
Invoke-WebRequest -UseBasicParsing -Uri '${p.packageUrl.replace(/'/g, "''")}' -OutFile $incoming
if ((Get-Item -LiteralPath $incoming).Length -gt 134217728) { throw 'package exceeds 128 MiB limit' }
if ((Get-FileHash -Algorithm SHA256 $incoming).Hash.ToLower() -ne '${p.checksum.toLowerCase()}') { throw 'checksum mismatch' }
Move-Item -Force -LiteralPath $incoming -Destination $package

$tlsCert = '${p.tlsCertPath.replace(/'/g, "''")}'
$tlsKey = '${p.tlsKeyPath.replace(/'/g, "''")}'
$tlsCa = '${p.tlsCaPath.replace(/'/g, "''")}'
foreach ($path in @($tlsCert, $tlsKey, $tlsCa)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'pre-provisioned TLS file is unavailable' }
  if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'TLS reparse points are refused' }
}
if ((Get-FileHash -Algorithm SHA256 $tlsCa).Hash.ToLower() -ne '${String(p.inventoryObject.event_profile.release.controller_ca_sha256).toLowerCase()}') {
  throw 'controller CA checksum mismatch'
}

$tokenPath = Join-Path $root 'controller-token.json'
if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
  @{token=(To-Base64Url (New-RandomBytes 48))} |
    ConvertTo-Json -Compress |
    Set-Content -NoNewline -Encoding ascii $tokenPath
}
$operatorPath = Join-Path $root 'operator-token.txt'
if (-not (Test-Path -LiteralPath $operatorPath -PathType Leaf)) {
  To-Base64Url (New-RandomBytes 48) | Set-Content -NoNewline -Encoding ascii $operatorPath
}
$recoveryKey = Join-Path $root 'recovery.key'
if (-not (Test-Path -LiteralPath $recoveryKey -PathType Leaf)) {
  [IO.File]::WriteAllBytes($recoveryKey, (New-RandomBytes 48))
}
$inventoryPath = Join-Path $root 'inventory.json'
[IO.File]::WriteAllBytes($inventoryPath, [Convert]::FromBase64String('${inventory}'))
$database = Join-Path $root 'controller.db'
$anchor = Join-Path $root 'recovery.anchor'
$backups = Join-Path $root 'backups'
New-Item -ItemType Directory -Force -Path $backups | Out-Null

$hasDatabase = Test-Path -LiteralPath $database -PathType Leaf
$hasAnchor = Test-Path -LiteralPath $anchor -PathType Leaf
if ($hasDatabase -xor $hasAnchor) { throw 'controller database and recovery anchor must both exist or both be absent' }
if ($hasDatabase) {
  py -3 $package recovery-status --database $database --recovery-key-file $recoveryKey --recovery-anchor $anchor | Out-Null
} else {
  py -3 $package recovery-init --database $database --recovery-key-file $recoveryKey --recovery-anchor $anchor | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw 'authenticated recovery preflight failed' }

py -3 $package launcher --inventory $inventoryPath --event-profile $inventoryPath --package $package --checksum '${p.checksum.toLowerCase()}' --controller '${controller}' --ca-file $tlsCa --preflight
if ($LASTEXITCODE -ne 0) { throw 'deployment preflight failed' }

$controllerProcess = Start-Process py.exe -PassThru -ArgumentList '-3',"$package",'controller','--bind','0.0.0.0','--event-profile',"$inventoryPath",'--token-file',"$tokenPath",'--database',"$database",'--operator-token-file',"$operatorPath",'--operator-principal-id','${p.operatorPrincipal.replace(/'/g, "''")}','--operator-credential-epoch','${p.operatorCredentialEpoch}','--recovery-key-file',"$recoveryKey",'--recovery-anchor',"$anchor",'--probe-config',"$inventoryPath",'--backup-directory',"$backups",'--tls-cert',"$tlsCert",'--tls-key',"$tlsKey",'--tls-ca-file',"$tlsCa",${networkArguments}
$health = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${healthEncoded}'))
py -3 -c $health
Start-Sleep -Seconds 1
$controllerProcess.Refresh()
if ($LASTEXITCODE -ne 0 -or $controllerProcess.HasExited) {
  if (-not $controllerProcess.HasExited) { Stop-Process -Id $controllerProcess.Id -Force }
  throw 'controller health check failed'
}
py -3 $package launcher --inventory $inventoryPath --event-profile $inventoryPath --package $package --checksum '${p.checksum.toLowerCase()}' --controller '${controller}' --ca-file $tlsCa --token-file $tokenPath --execute --yes
if ($LASTEXITCODE -ne 0) {
  if (-not $controllerProcess.HasExited) { Stop-Process -Id $controllerProcess.Id -Force }
  throw 'deployment execution failed'
}
`;
  const raw = Array.from(script)
    .map(character => String.fromCharCode(
      character.charCodeAt(0) & 255,
      character.charCodeAt(0) >> 8
    ))
    .join('');
  return `powershell.exe -NoLogo -NoProfile -EncodedCommand ${btoa(raw)}`;
}

async function commandMap() {
  const p = await profile();
  return {profile: p, commands: {linux: linuxBootstrap(p), windows: windowsBootstrap(p)}};
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  if (!tab?.id) throw new Error('No active portal tab');
  return tab;
}

async function send(action) {
  const {profile: p, commands} = await commandMap();
  const tab = await activeTab();
  if (new URL(tab.url).origin !== p.portalOrigin) {
    throw new Error('Active tab is outside the configured portal origin');
  }
  const origins = [p.portalOrigin, ...p.allowedFrameOrigins].map(origin => origin + '/*');
  const granted = await chrome.permissions.request({origins});
  if (!granted) throw new Error('Portal origin access was not approved');
  await chrome.scripting.executeScript({
    target: {tabId: tab.id, allFrames: true},
    files: ['content.js']
  });
  const frames = await chrome.webNavigation.getAllFrames({tabId: tab.id});
  const discoveries = [];
  for (const frame of frames) {
    try {
      const response = await chrome.tabs.sendMessage(
        tab.id,
        {action: 'discover', profile: p, commands},
        {frameId: frame.frameId}
      );
      if (response?.ok) discoveries.push({frameId: frame.frameId, response});
    } catch (_error) {}
  }
  if (!discoveries.length) {
    throw new Error('No allowed portal frame accepted the operation');
  }
  const totals = {
    devices: discoveries.reduce((count, item) => count + (item.response.devices || 0), 0),
    consoles: discoveries.reduce((count, item) => count + (item.response.consoles || 0), 0)
  };
  if (action === 'discover') return {ok: true, ...totals};
  const candidates = discoveries.filter(item => item.response.consoles === 1);
  if (totals.consoles !== 1 || candidates.length !== 1) {
    throw new Error(`Expected exactly one console input across approved frames; found ${totals.consoles}`);
  }
  const selected = candidates[0];
  const response = await chrome.tabs.sendMessage(
    tab.id,
    {action, profile: p, commands},
    {frameId: selected.frameId}
  );
  if (!response?.ok) {
    throw new Error(response?.error || 'The selected console rejected the bootstrap');
  }
  return response;
}

async function load() {
  const saved = await chrome.storage.local.get('sentinelBlueProfile');
  if (!saved.sentinelBlueProfile) return;
  for (const id of fields) {
    document.getElementById(id).value = saved.sentinelBlueProfile[id] || '';
  }
}

document.getElementById('save').onclick = async () => {
  try {
    const p = await profile();
    await chrome.storage.local.set({sentinelBlueProfile: p});
    status.textContent = 'Profile saved locally.';
  } catch (error) {
    status.textContent = error.message;
  }
};
document.getElementById('discover').onclick = async () => {
  try {
    const result = await send('discover');
    status.textContent = `Found ${result.devices} assigned device element(s) and ${result.consoles} console input(s).`;
  } catch (error) {
    status.textContent = error.message;
  }
};
document.getElementById('current').onclick = async () => {
  try {
    const result = await send('bootstrapCurrent');
    status.textContent = result.message;
  } catch (error) {
    status.textContent = error.message;
  }
};
load();
