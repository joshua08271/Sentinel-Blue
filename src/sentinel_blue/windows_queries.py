"""Fixed read-only Windows queries shared by direct and batched inventory.

Sections share one current native SCM snapshot, native modules and the helper
process. A missing section never borrows data from a previous collection.
"""
from types import MappingProxyType
from .windows_service_query import SERVICE_SNAPSHOT

WINDOWS_QUERIES = MappingProxyType({
    "BOOT": "Get-CimInstance Win32_OperatingSystem -Property LastBootUpTime | Select LastBootUpTime | ConvertTo-Json -Compress",
    "ACCOUNTS": r"""
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
$admins = @($adminGroup | Get-LocalGroupMember -ErrorAction Stop | ForEach-Object {$_.SID.Value})
Get-LocalUser | ForEach-Object {
  [PSCustomObject]@{Name=$_.Name; SID=$_.SID.Value; Enabled=$_.Enabled; Privileged=($admins -contains $_.SID.Value)}
} | ConvertTo-Json -Compress
""",
    "SERVICES": SERVICE_SNAPSHOT + r"""
$restartFailures = @{}
$queryErrors = @()
# Keep the exact channel, provider, IDs and fifteen-minute window in one
# native event selector, without a separate provider-name lookup.
$restartEvents = @(Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Service Control Manager'] and (EventID=7031 or EventID=7034) and TimeCreated[timediff(@SystemTime) <= 900000]]]" -MaxEvents 513 -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
if (@($queryErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }).Count) { throw 'Service restart event query was incomplete' }
if ($restartEvents.Count -gt 512) { throw 'Service restart event inventory exceeded its bound' }
$restartEvents | ForEach-Object {
  if ($_.Properties.Count -gt 0) { $key = [string]$_.Properties[0].Value; $restartFailures[$key] = 1 + [int]$restartFailures[$key] }
}
Get-SentinelServiceSnapshot | ForEach-Object {
  $count = [int]$restartFailures[$_.Name]
  if ($_.DisplayName -ine $_.Name) { $count += [int]$restartFailures[$_.DisplayName] }
  [PSCustomObject]@{Name=$_.Name;State=$_.State;StartMode=$_.StartMode;Status=$_.Status;ExitCode=$_.ExitCode;RestartCount=$count}
} | ConvertTo-Json -Compress
""",
    "TOPOLOGY": r"""
$problems = @{}
try { $routes = @(Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric) }
catch { $routes = @(); $problems['Routes'] = [string]$_.Exception.Message }
try { $neighbors = @(Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State) }
catch { $neighbors = @(); $problems['Neighbors'] = [string]$_.Exception.Message }
try { $listeners = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess) }
catch { $listeners = @(); $problems['Listeners'] = [string]$_.Exception.Message }
[PSCustomObject]@{Schema=1;Routes=$routes;Neighbors=$neighbors;Listeners=$listeners;Errors=$problems} | ConvertTo-Json -Depth 4 -Compress
""",
    "PROCESSES": r"""
$admins = @(Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Get-LocalGroupMember -ErrorAction SilentlyContinue | ForEach-Object {$_.Name.Split('\')[-1]})
# One bulk owner query avoids a CIM round trip for every process. Correlate
# creation time as well as PID so a reused PID never inherits another owner.
$owners = @{}
Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object {
  try {
    if ($_.UserName) { $owners[[int]$_.Id] = [PSCustomObject]@{UserName=$_.UserName;Started=$_.StartTime.ToUniversalTime()} }
  } catch { }
}
Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate | Select-Object -First 4096 | ForEach-Object {
  $owner = $owners[[int]$_.ProcessId]
  $user = 'unknown'
  if ($owner -and $_.CreationDate) {
    $delta = [Math]::Abs(($_.CreationDate.ToUniversalTime() - $owner.Started).TotalMilliseconds)
    if ($delta -lt 1) { $user = $owner.UserName.Split('\')[-1] }
  }
  [PSCustomObject]@{ProcessId=$_.ProcessId;ParentProcessId=$_.ParentProcessId;Name=$_.Name;ExecutablePath=$_.ExecutablePath;UserName=$user;Privileged=($user -eq 'SYSTEM' -or $user -eq 'Administrator' -or $admins -contains $user)}
} | ConvertTo-Json -Compress
""",
    "PERSISTENCE": SERVICE_SNAPSHOT + r"""
$items = [Collections.Generic.List[object]]::new()
Get-ScheduledTask | ForEach-Object {
  $actionText = ([PSCustomObject]@{Actions=$_.Actions;Triggers=$_.Triggers;Principal=$_.Principal;Settings=$_.Settings} | ConvertTo-Json -Depth 6 -Compress)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($actionText)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
  $references = @($_.Actions | ForEach-Object { '"'+$_.Execute+'" '+$_.Arguments })
  $items.Add([PSCustomObject]@{Kind='scheduled-task';Name=($_.TaskPath+$_.TaskName);Owner=$_.Author;Enabled=($_.State -ne 'Disabled');SHA256=$hash;References=$references})
}
$locations = @(
  [PSCustomObject]@{Path='Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run';Label='HKLM\Software\Microsoft\Windows\CurrentVersion\Run';Owner='SYSTEM'},
  [PSCustomObject]@{Path='Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run';Label='HKCU\Software\Microsoft\Windows\CurrentVersion\Run';Owner=[Security.Principal.WindowsIdentity]::GetCurrent().Name}
)
$locations+=@(
  [PSCustomObject]@{Path='Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce';Label='HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce';Owner='SYSTEM'},
  [PSCustomObject]@{Path='Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';Label='HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';Owner='SYSTEM'},
  [PSCustomObject]@{Path='Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';Label='HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';Owner='SYSTEM'}
)
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object PSChildName -Match '^S-1-5-21-' | ForEach-Object {
  $sid=$_.PSChildName
  foreach($suffix in @('Run','RunOnce')) {
    $locations += [PSCustomObject]@{Path=('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\'+$suffix);Label=('HKU\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\'+$suffix);Owner=$sid}
  }
}
foreach ($location in $locations) {
  $key = Get-Item -LiteralPath $location.Path -ErrorAction SilentlyContinue
  if ($null -eq $key) { continue }
  foreach ($name in @($key.GetValueNames() | Sort-Object)) {
    $kind = [string]$key.GetValueKind($name)
    $value = [string]$key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $actionText = [PSCustomObject]@{Kind=$kind;Value=$value} | ConvertTo-Json -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($actionText)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $items.Add([PSCustomObject]@{Kind='registry-run';Name=($location.Label+'\'+$name);Owner=$location.Owner;Enabled=$true;SHA256=$hash;References=@([Environment]::ExpandEnvironmentVariables($value))})
  }
}
Get-SentinelServiceSnapshot | ForEach-Object {
  $sha=[Security.Cryptography.SHA256]::Create()
  try { $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$_.PathName)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
  $items.Add([PSCustomObject]@{Kind='windows-service-command';Name=$_.Name;Owner='SYSTEM';Enabled=($_.StartMode -ne 'Disabled');SHA256=$hash;References=@($_.PathName)})
}
Get-CimInstance Win32_Process -Property CommandLine,ExecutablePath | Select-Object -First 4097 | ForEach-Object {
  $items.Add([PSCustomObject]@{Kind='process-reference';References=@(('"'+$_.ExecutablePath+'"'),$_.CommandLine)})
}
$items.Add([PSCustomObject]@{Kind='startup-folder';Name=($env:ProgramData+'\Microsoft\Windows\Start Menu\Programs\Startup');Owner='SYSTEM'})
$profiles=@(Get-CimInstance Win32_UserProfile -Property LocalPath,SID,Special | Where-Object { !$_.Special } | Select-Object -First 257)
if ($profiles.Count -gt 256) { throw 'Windows Startup profile inventory exceeded its bound' }
foreach ($profile in $profiles) {
  $items.Add([PSCustomObject]@{Kind='startup-folder';Name=($profile.LocalPath+'\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup');Owner=$profile.SID})
}
function Get-SentinelWmiIdentity($instance, [int]$depth=0) {
  if ($depth -gt 2) { throw 'WMI persistence reference nesting exceeded its bound' }
  $className=[string]$instance.CimSystemProperties.ClassName
  if (!$className) { throw 'WMI persistence reference has no native class' }
  # Windows PowerShell 5.1 does not expose every newer CIM SDK path helper.
  # These WMI classes have defined keys: Name, or Filter plus Consumer.
  $keys=[ordered]@{}
  $keyNames=if ($className -eq '__FilterToConsumerBinding') {@('Filter','Consumer')} else {@('Name')}
  foreach ($keyName in $keyNames) {
    $key=$instance.CimInstanceProperties[$keyName]
    if ($null -eq $key -or $null -eq $key.Value) { throw 'WMI persistence reference lacks its native key' }
    if ([string]$key.CimType -eq 'Reference') { $keys[$keyName]=Get-SentinelWmiIdentity $key.Value ($depth+1) }
    else { $keys[$keyName]=[string]$key.Value }
  }
  $identity=@([string]$instance.CimSystemProperties.ServerName,[string]$instance.CimSystemProperties.Namespace,$className,$keys)
  return ($identity | ConvertTo-Json -Depth 6 -Compress)
}
foreach ($class in @('__EventFilter','__EventConsumer','__FilterToConsumerBinding')) {
  $subscriptions=@(Get-CimInstance -Namespace 'root/subscription' -ClassName $class | Select-Object -First 257)
  if ($subscriptions.Count -gt 256) { throw 'WMI persistence inventory exceeded its class bound' }
  foreach ($subscription in $subscriptions) {
    $properties=[ordered]@{}
    foreach ($property in @($subscription.CimInstanceProperties | Sort-Object Name)) {
      if ([string]$property.CimType -eq 'Reference') {
        $properties[$property.Name]=Get-SentinelWmiIdentity $property.Value
      } else { $properties[$property.Name]=$property.Value }
    }
    $text=$properties | ConvertTo-Json -Depth 6 -Compress
    if ($text.Length -gt 2097152) { throw 'WMI persistence object exceeded its size bound' }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $kind=if ($class -eq '__EventFilter') {'wmi-event-filter'} elseif ($class -eq '__EventConsumer') {'wmi-event-consumer'} else {'wmi-event-binding'}
    $name=Get-SentinelWmiIdentity $subscription
    if (!$name -or $name.Length -gt 512) { throw 'WMI persistence object has no bounded stable native identity' }
    $references=@($subscription.ExecutablePath,$subscription.CommandLineTemplate,$subscription.ScriptFileName)
    $items.Add([PSCustomObject]@{Kind=$kind;Name=$name;Owner='native-wmi';Enabled=$true;SHA256=$hash;References=$references})
  }
}
$items | ConvertTo-Json -Compress
""",
    "FIREWALL": r"""
$ErrorActionPreference = 'Stop'
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,@{Name='Enabled';Expression={([string]$_.Enabled -eq 'True')}},DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,AllowLocalIPsecRules,AllowUserApps,AllowUserPorts,AllowUnicastResponseToMulticast,EnableStealthModeForIPsec)
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object Name,InstanceID,Enabled,Direction,Action,Profile,EdgeTraversalPolicy,LooseSourceMapping,LocalOnlyMapping,Owner,Platform,PolicyStoreSource,PolicyStoreSourceType)
# Filter objects hold enforcement conditions absent from Get-NetFirewallRule.
# Batch retrieval preserves rule/filter identity without one call per rule.
$filters = [ordered]@{
  Address = @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore | Select-Object InstanceID,LocalAddress,RemoteAddress)
  Port = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore | Select-Object InstanceID,Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget)
  Application = @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore | Select-Object InstanceID,Program,Package)
  Service = @(Get-NetFirewallServiceFilter -PolicyStore ActiveStore | Select-Object InstanceID,Service)
  Interface = @(Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore | Select-Object InstanceID,InterfaceAlias)
  InterfaceType = @(Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore | Select-Object InstanceID,InterfaceType)
  Security = @(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore | Select-Object InstanceID,Authentication,Encryption,OverrideBlockRules,LocalUser,RemoteUser,RemoteMachine)
}
[PSCustomObject]@{Schema=2;Profiles=$profiles;Rules=$rules;Filters=$filters} | ConvertTo-Json -Depth 6 -Compress
""",
    "INTERFACES": r"""Get-NetIPAddress | Where-Object {$_.AddressState -ne 'Tentative'} | Select InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress""",
    "SECURITY_EVENTS": r"""
$ids = 1102,4624,4625,4697,4698,4700,4701,4702,4719,4720,4722,4725,4726,4728,4729,4732,4733,4735,4738,4756,4757,4946,4947,4948,4950
# A 25-ID FilterHashtable silently returned NoMatchingEventsFound on native
# Windows despite fresh matching logins. Keep each native XPath query small.
$since = (Get-Date).AddMinutes(-5)
$events = @(for ($offset = 0; $offset -lt $ids.Count; $offset += 10) {
  $batch = @($ids[$offset..([Math]::Min($offset + 9, $ids.Count - 1))])
  $queryErrors = @()
  $batchEvents = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=$batch;StartTime=$since} -MaxEvents 257 -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
  if (@($queryErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }).Count) { throw 'Security event query was incomplete' }
  $batchEvents
})
$events = @($events | Sort-Object RecordId -Descending | Select-Object -First 257)
$events | ForEach-Object {
  $record = $_
  $xml = [xml]$record.ToXml(); $data = @{}
  foreach ($node in $xml.Event.EventData.Data) { $data[[string]$node.Name] = [string]$node.'#text' }
  $category = switch ($record.Id) {
    1102 {'audit_cleared'}
    4624 {'auth_success'}
    4625 {'auth_failure'}
    4697 {'service_installed'}
    {$_ -in 4698,4700,4701,4702} {'scheduled_task_changed'}
    4719 {'audit_policy_changed'}
    4720 {'account_created'}
    {$_ -in 4725,4726} {'account_disabled_or_deleted'}
    {$_ -in 4722,4738} {'account_changed'}
    {$_ -in 4946,4947,4948,4950} {'firewall_changed'}
    default {'privilege_change'}
  }
  $outcome = if ($record.Id -eq 4625) {'failure'} else {'success'}
  $account = if ($data.MemberName) {$data.MemberName} elseif ($data.MemberSid) {$data.MemberSid} elseif ($data.TargetUserName) {$data.TargetUserName} elseif ($data.TaskName) {$data.TaskName} elseif ($data.ServiceName) {$data.ServiceName} else {'unknown'}
  [PSCustomObject]@{
    EventId=('windows-'+$record.RecordId);Category=$category;Outcome=$outcome
    Account=([string]$account);Actor=([string]$data.SubjectUserName)
    AccountId=([string]$data.TargetUserSid);AccountDomain=([string]$data.TargetDomainName)
    RemoteAddress=([string]$data.IpAddress)
    OccurredAt=([DateTimeOffset]$record.TimeCreated).ToUnixTimeMilliseconds()/1000.0
    Detail=($record.ProviderName+' event '+$record.Id)
  }
} | ConvertTo-Json -Compress
""",
    "SESSIONS": r"""
$names = @('powershell','pwsh','cmd','WindowsTerminal','ssh','sshd','wsmprovhost')
Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -ne $PID -and $names -contains $_.ProcessName } |
  Select-Object Id,ProcessName,SessionId,UserName |
  ConvertTo-Json -Compress
""",
})
