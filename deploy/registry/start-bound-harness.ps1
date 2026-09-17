param(
  [Parameter(Mandatory = $true)]
  [string]$HarnessRoot,

  [Parameter(Mandatory = $true)]
  [string]$NodePath,

  [Parameter(Mandatory = $true)]
  [string]$EnvFile,

  [Parameter(Mandatory = $true)]
  [string]$CaCertificate,

  [Parameter(Mandatory = $true)]
  [string]$DshHome,

  [Parameter(Mandatory = $true)]
  [string]$LogDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') {
  throw '此启动器只支持 Windows。'
}
if ($PSVersionTable.PSVersion.Major -lt 7 -or
  -not (Get-Command Start-Process).Parameters.ContainsKey('Environment')) {
  throw '需要支持 Start-Process -Environment 的 PowerShell 7。'
}
if ($null -ne (Get-Item -LiteralPath 'Env:NODE_OPTIONS' -ErrorAction SilentlyContinue)) {
  throw '启动 Harness 前必须移除 NODE_OPTIONS。'
}

$deviceEnvironmentNames = @(
  'DSH_REGISTRY_ORGANIZATION_ID',
  'DSH_INSTANCE_ID',
  'DSH_REGISTRY_SYNC_URL',
  'DSH_REGISTRY_DEVICE_TOKEN',
  'DSH_REGISTRY_DEVICE_PRIVATE_KEY'
)

function Assert-AbsoluteWindowsPath([string]$Path, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains([char]0) -or
    $Path -notmatch '^[A-Za-z]:[\\/]') {
    throw "$Label 必须是本地固定磁盘上的绝对 Windows 路径。"
  }
  $driveName = $Path.Substring(0, 1)
  $drive = Get-PSDrive -Name $driveName -PSProvider FileSystem -ErrorAction Stop
  $driveInfo = New-Object IO.DriveInfo("${driveName}:\")
  if ($null -ne $drive.DisplayRoot -or $driveInfo.DriveType -ne [IO.DriveType]::Fixed) {
    throw "$Label 必须位于本地固定磁盘，不能使用映射盘、UNC 或可移动介质。"
  }
}

function Assert-NoReparsePointInPath([string]$Path, [string]$Label) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  $root = [IO.Path]::GetPathRoot($fullPath)
  $current = $root
  foreach ($segment in $fullPath.Substring($root.Length).Split(
      [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
      [StringSplitOptions]::RemoveEmptyEntries)) {
    $current = Join-Path $current $segment
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Label 的路径不能穿过重解析点。"
    }
  }
}

function Resolve-ExistingFile([string]$Path, [string]$Label) {
  Assert-AbsoluteWindowsPath $Path $Label
  $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
  if ($resolved.Provider.Name -ne 'FileSystem') { throw "$Label 必须位于文件系统。" }
  $item = Get-Item -LiteralPath $resolved.ProviderPath -Force
  Assert-NoReparsePointInPath $item.FullName $Label
  if ($item.PSIsContainer) {
    throw "$Label 必须是普通文件，不能是目录或重解析点。"
  }
  return [IO.Path]::GetFullPath($item.FullName)
}

function Resolve-ExistingDirectory([string]$Path, [string]$Label) {
  Assert-AbsoluteWindowsPath $Path $Label
  $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
  if ($resolved.Provider.Name -ne 'FileSystem') { throw "$Label 必须位于文件系统。" }
  $item = Get-Item -LiteralPath $resolved.ProviderPath -Force
  Assert-NoReparsePointInPath $item.FullName $Label
  if (-not $item.PSIsContainer) {
    throw "$Label 必须是普通目录，不能是文件或重解析点。"
  }
  $fullPath = [IO.Path]::GetFullPath($item.FullName)
  $root = [IO.Path]::GetPathRoot($fullPath)
  if ($fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) -eq
    $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)) {
    throw "$Label 不能是卷根目录。"
  }
  return $fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-OutsideDirectory([string]$Path, [string]$Directory, [string]$Label) {
  $prefix = $Directory + [IO.Path]::DirectorySeparatorChar
  if ($Path.Equals($Directory, [StringComparison]::OrdinalIgnoreCase) -or
    $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label 不能放在 Harness 源码目录内。"
  }
}

function Get-Sid([object]$Identity) {
  try {
    if ($Identity -is [Security.Principal.SecurityIdentifier]) { return $Identity.Value }
    $reference = if ($Identity -is [Security.Principal.IdentityReference]) {
      $Identity
    } else {
      New-Object Security.Principal.NTAccount([string]$Identity)
    }
    return $reference.Translate([Security.Principal.SecurityIdentifier]).Value
  } catch {
    throw '无法验证 ACL 中的账号。'
  }
}

function Assert-PrivateAcl([string]$Path, [string]$Label, [bool]$RequireProtectedInheritance) {
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $allowedSids = @(
    $currentSid,
    'S-1-5-18',       # LocalSystem
    'S-1-5-32-544'    # BUILTIN\Administrators，可选恢复账号
  )
  $acl = Get-Acl -LiteralPath $Path
  if ($RequireProtectedInheritance -and -not $acl.AreAccessRulesProtected) {
    throw "$Label 必须先关闭 ACL 继承。"
  }
  $ownerSid = Get-Sid $acl.Owner
  if ($allowedSids -notcontains $ownerSid) {
    throw "$Label 的所有者不在允许列表中。"
  }
  $currentUserCanRead = $false
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = Get-Sid $rule.IdentityReference
    if ($allowedSids -notcontains $sid) {
      throw "$Label 含有未授权账号的 Allow 权限。"
    }
    if ($sid -eq $currentSid -and
      (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read) -ne 0)) {
      $currentUserCanRead = $true
    }
  }
  if (-not $currentUserCanRead) { throw "$Label 未授权当前 Harness 账号读取。" }
}

function Assert-NoUnauthorizedWriteAcl(
  [string]$Path,
  [string]$Label,
  [bool]$RequireProtectedInheritance
) {
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $allowedSids = @(
    $currentSid,
    'S-1-5-18',       # LocalSystem
    'S-1-5-32-544'    # BUILTIN\Administrators
  )
  $writeMask = [Security.AccessControl.FileSystemRights]::Write `
    -bor [Security.AccessControl.FileSystemRights]::Modify `
    -bor [Security.AccessControl.FileSystemRights]::Delete `
    -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles `
    -bor [Security.AccessControl.FileSystemRights]::ChangePermissions `
    -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $acl = Get-Acl -LiteralPath $Path
  if ($RequireProtectedInheritance -and -not $acl.AreAccessRulesProtected) {
    throw "$Label 必须先关闭 ACL 继承。"
  }
  $ownerSid = Get-Sid $acl.Owner
  if ($allowedSids -notcontains $ownerSid) {
    throw "$Label 的所有者不在可信列表中。"
  }
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = Get-Sid $rule.IdentityReference
    if ($allowedSids -notcontains $sid -and (($rule.FileSystemRights -band $writeMask) -ne 0)) {
      throw "$Label 允许未授权账号修改可执行内容。"
    }
  }
}

function Test-PortInUse([int]$Port) {
  $listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
  return @($listeners | Where-Object { $_.Port -eq $Port }).Count -gt 0
}

function Test-ProcessOwnsLoopbackListener([int]$OwnerProcessId, [int]$Port) {
  $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
  return @($listeners | Where-Object {
      $_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -eq $OwnerProcessId
    }).Count -gt 0
}

function Read-EnrollmentEnvironment([string]$Path) {
  if ((Get-Item -LiteralPath $Path -Force).Length -gt 16KB) {
    throw 'enrollment 环境文件超过大小限制。'
  }
  $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
  try {
    $lines = [IO.File]::ReadAllLines($Path, $strictUtf8)
  } catch {
    throw '无法以严格 UTF-8 读取 enrollment 环境文件。'
  }
  $values = @{}
  foreach ($line in $lines) {
    if ($line.Length -eq 0) { continue }
    $separator = $line.IndexOf('=')
    if ($separator -le 0) { throw 'enrollment 环境文件格式无效。' }
    $name = $line.Substring(0, $separator)
    $value = $line.Substring($separator + 1)
    if ($deviceEnvironmentNames -cnotcontains $name) {
      throw 'enrollment 环境文件只能包含绑定工具导出的五个变量。'
    }
    if ($values.ContainsKey($name)) {
      throw 'enrollment 环境文件中的变量不能重复。'
    }
    if ($value.Length -eq 0 -or $value -ne $value.Trim() -or
      $value.IndexOfAny([char[]]@([char]0, [char]10, [char]13)) -ge 0) {
      throw 'enrollment 环境文件含有空值或非法字符。'
    }
    $values[$name] = $value
  }
  if ($values.Count -ne $deviceEnvironmentNames.Count -or
    @($deviceEnvironmentNames | Where-Object { -not $values.ContainsKey($_) }).Count -ne 0) {
    throw 'enrollment 环境文件必须各包含一次绑定工具导出的五个变量。'
  }
  if ($values['DSH_REGISTRY_ORGANIZATION_ID'] -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$' -or
    $values['DSH_INSTANCE_ID'] -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$') {
    throw 'enrollment 环境文件中的标识符无效。'
  }
  try {
    $syncUri = [Uri]$values['DSH_REGISTRY_SYNC_URL']
  } catch {
    throw 'enrollment 环境文件中的同步地址无效。'
  }
  if (-not $syncUri.IsAbsoluteUri -or $syncUri.Scheme -ne 'wss' -or
    -not [string]::IsNullOrEmpty($syncUri.UserInfo) -or -not [string]::IsNullOrEmpty($syncUri.Query) -or
    -not [string]::IsNullOrEmpty($syncUri.Fragment)) {
    throw 'enrollment 环境文件中的同步地址必须是无凭据、无查询参数的 WSS 地址。'
  }
  if ($values['DSH_REGISTRY_DEVICE_TOKEN'].Length -gt 512 -or
    $values['DSH_REGISTRY_DEVICE_TOKEN'] -notmatch '^dsh1\.[A-Za-z0-9_-]+\.[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$' -or
    $values['DSH_REGISTRY_DEVICE_PRIVATE_KEY'] -notmatch '^[A-Za-z0-9_-]+$') {
    throw 'enrollment 环境文件中的设备凭据格式无效。'
  }
  return $values
}

$childInheritedEnvironmentNames = [Collections.Generic.HashSet[string]]::new(
  [StringComparer]::OrdinalIgnoreCase)
foreach ($name in @(
    'ALLUSERSPROFILE', 'APPDATA', 'CommonProgramFiles', 'CommonProgramFiles(x86)',
    'CommonProgramW6432', 'ComSpec', 'DriverData', 'HOMEDRIVE', 'HOMEPATH', 'HOME',
    'LOCALAPPDATA', 'LOGONSERVER', 'NUMBER_OF_PROCESSORS', 'OS', 'Path', 'PATHEXT',
    'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'PROCESSOR_LEVEL', 'PROCESSOR_REVISION',
    'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'PUBLIC', 'SESSIONNAME',
    'SystemDrive', 'SystemRoot', 'TEMP', 'TMP', 'USERDOMAIN', 'USERDOMAIN_ROAMINGPROFILE',
    'USERNAME', 'USERPROFILE', 'WINDIR'
  )) {
  [void]$childInheritedEnvironmentNames.Add($name)
}

function Start-WhitelistedProcess([hashtable]$Parameters, [hashtable]$Environment) {
  $removed = @{}
  try {
    foreach ($item in @(Get-ChildItem Env:)) {
      if ($childInheritedEnvironmentNames.Contains($item.Name)) { continue }
      $removed[$item.Name] = $item.Value
      Remove-Item -LiteralPath "Env:$($item.Name)" -ErrorAction Stop
    }
    $Parameters['Environment'] = $Environment
    return Start-Process @Parameters
  } finally {
    foreach ($name in $removed.Keys) {
      Set-Item -LiteralPath "Env:$name" -Value $removed[$name]
    }
  }
}

function Assert-DeviceCredentialMaterial([string]$Runtime, [hashtable]$Values) {
  $validator = @'
const { createPrivateKey } = require('node:crypto')
const identifier = /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$/u
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
const canonical = (value, expectedBytes) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) return undefined
  const bytes = Buffer.from(value, 'base64url')
  if ((expectedBytes !== undefined && bytes.byteLength !== expectedBytes)
    || bytes.toString('base64url') !== value) return undefined
  return bytes
}
let keyBytes
let valid = false
try {
  const organizationId = process.env.DSH_REGISTRY_ORGANIZATION_ID ?? ''
  const token = process.env.DSH_REGISTRY_DEVICE_TOKEN ?? ''
  const privateKey = process.env.DSH_REGISTRY_DEVICE_PRIVATE_KEY ?? ''
  const parts = token.split('.')
  if (!identifier.test(organizationId) || Buffer.byteLength(token, 'utf8') > 512
    || parts.length !== 4 || parts[0] !== 'dsh1' || !uuid.test(parts[2] ?? '')) throw new Error()
  const organizationBytes = canonical(parts[1])
  const secretBytes = canonical(parts[3], 32)
  if (organizationBytes === undefined || secretBytes === undefined) throw new Error()
  const selectedOrganization = organizationBytes.toString('utf8')
  if (!identifier.test(selectedOrganization) || selectedOrganization !== organizationId
    || Buffer.from(selectedOrganization, 'utf8').toString('base64url') !== parts[1]) throw new Error()
  keyBytes = canonical(privateKey)
  if (keyBytes === undefined) throw new Error()
  const key = createPrivateKey({ key: keyBytes, format: 'der', type: 'pkcs8' })
  const exported = key.export({ format: 'der', type: 'pkcs8' })
  if (key.asymmetricKeyType !== 'ed25519' || !Buffer.isBuffer(exported) || !exported.equals(keyBytes)) {
    throw new Error()
  }
  valid = true
} catch {}
finally { if (keyBytes !== undefined) keyBytes.fill(0) }
if (!valid) process.exit(1)
'@
  $encodedValidator = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($validator))
  $validationEnvironment = @{
    DSH_REGISTRY_ORGANIZATION_ID = $Values['DSH_REGISTRY_ORGANIZATION_ID']
    DSH_REGISTRY_DEVICE_TOKEN = $Values['DSH_REGISTRY_DEVICE_TOKEN']
    DSH_REGISTRY_DEVICE_PRIVATE_KEY = $Values['DSH_REGISTRY_DEVICE_PRIVATE_KEY']
  }
  try {
    $validation = Start-WhitelistedProcess @{
      FilePath = $Runtime
      ArgumentList = @(
        '--eval',
        "eval(Buffer.from(process.argv[1],'base64').toString('utf8'))",
        $encodedValidator
      )
      WindowStyle = 'Hidden'
      Wait = $true
      PassThru = $true
    } $validationEnvironment
  } catch {
    throw '无法在隔离环境中验证设备凭据。'
  }
  if ($validation.ExitCode -ne 0) {
    throw '设备 token 与组织不匹配，或私钥不是规范 Ed25519 PKCS8。'
  }
}

$HarnessRoot = Resolve-ExistingDirectory $HarnessRoot 'HarnessRoot'
$NodePath = Resolve-ExistingFile $NodePath 'NodePath'
$EnvFile = Resolve-ExistingFile $EnvFile 'EnvFile'
$CaCertificate = Resolve-ExistingFile $CaCertificate 'CaCertificate'
$DshHome = Resolve-ExistingDirectory $DshHome 'DshHome'
$LogDirectory = Resolve-ExistingDirectory $LogDirectory 'LogDirectory'

if (-not [IO.Path]::GetFileName($NodePath).Equals('node.exe', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'NodePath 必须指向 node.exe。'
}
Assert-NoUnauthorizedWriteAcl $NodePath 'NodePath' $false
$nodeVersion = @(& $NodePath -p 'process.versions.node' 2>$null)
if ($LASTEXITCODE -ne 0 -or $nodeVersion.Count -ne 1 -or $nodeVersion[0] -notmatch '^[0-9]+\.') {
  throw '无法验证 Node.js 版本。'
}
$nodeMajor = [int]$nodeVersion[0].Split('.')[0]
if ($nodeMajor -lt 24) { throw '需要 Node.js 24 或更高版本。' }

$cliPath = Resolve-ExistingFile (Join-Path $HarnessRoot 'apps\cli\lib\bin.js') 'Harness CLI'
$launcherRoot = Resolve-ExistingDirectory $PSScriptRoot '启动器目录'
$overlayPath = Resolve-ExistingFile (Join-Path $launcherRoot 'harness-registry-connection.example.patch.yml') '连接专用 overlay'
$envParent = Resolve-ExistingDirectory (Split-Path -Parent $EnvFile) 'EnvFile 父目录'
$caParent = Resolve-ExistingDirectory (Split-Path -Parent $CaCertificate) 'CaCertificate 父目录'
Assert-OutsideDirectory $EnvFile $HarnessRoot 'EnvFile'
Assert-OutsideDirectory $DshHome $HarnessRoot 'DshHome'
Assert-OutsideDirectory $LogDirectory $HarnessRoot 'LogDirectory'

if (Test-PortInUse 3080) {
  throw 'TCP 端口 3080 已被占用；启动器不会停止或替换现有进程。'
}

Assert-PrivateAcl $envParent 'EnvFile 父目录' $true
Assert-PrivateAcl $EnvFile 'EnvFile' $false
Assert-PrivateAcl $DshHome 'DshHome' $true
Assert-PrivateAcl $LogDirectory 'LogDirectory' $true
Assert-NoUnauthorizedWriteAcl $HarnessRoot 'HarnessRoot' $true
Assert-NoUnauthorizedWriteAcl $cliPath 'Harness CLI' $false
Assert-NoUnauthorizedWriteAcl $launcherRoot '启动器目录' $true
Assert-NoUnauthorizedWriteAcl $overlayPath '连接专用 overlay' $false
Assert-NoUnauthorizedWriteAcl $caParent 'CaCertificate 父目录' $true
Assert-NoUnauthorizedWriteAcl $CaCertificate 'CaCertificate' $false

$certificateText = [IO.File]::ReadAllText($CaCertificate)
if ($certificateText -notmatch '-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----') {
  throw 'CaCertificate 不是 PEM 证书文件。'
}
$certificateText = $null
$deviceEnvironment = Read-EnrollmentEnvironment $EnvFile
$childEnvironment = $null
try {
  Assert-DeviceCredentialMaterial $NodePath $deviceEnvironment

  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
  $stdoutPath = Join-Path $LogDirectory "harness-$stamp.stdout.log"
  $stderrPath = Join-Path $LogDirectory "harness-$stamp.stderr.log"
  if ((Test-Path -LiteralPath $stdoutPath) -or (Test-Path -LiteralPath $stderrPath)) {
    throw '无法安全分配 Harness 日志文件。'
  }

  $childEnvironment = @{
    DSH_HOME = $DshHome
    NODE_EXTRA_CA_CERTS = $CaCertificate
    NODE_TLS_REJECT_UNAUTHORIZED = '1'
  }
  foreach ($name in $deviceEnvironmentNames) {
    $childEnvironment[$name] = $deviceEnvironment[$name]
  }

  $arguments = @(
    "`"$cliPath`"",
    '--profile', 'web',
    '--patch', "`"$overlayPath`"",
    '--no-open',
    '--host', '127.0.0.1',
    '--port', '3080'
  )
  try {
    $process = Start-WhitelistedProcess @{
      FilePath = $NodePath
      ArgumentList = $arguments
      WorkingDirectory = $DshHome
      WindowStyle = 'Hidden'
      PassThru = $true
      RedirectStandardOutput = $stdoutPath
      RedirectStandardError = $stderrPath
    } $childEnvironment
  } catch {
    throw '无法启动 Harness；未输出任何设备环境值。'
  }

  $ready = $false
  $deadline = [DateTime]::UtcNow.AddSeconds(30)
  try {
    while ([DateTime]::UtcNow -lt $deadline) {
      $process.Refresh()
      if ($process.HasExited) {
        throw "Harness 在本地监听就绪前退出；请检查日志路径：$stdoutPath 和 $stderrPath"
      }
      if (Test-ProcessOwnsLoopbackListener $process.Id 3080) {
        $process.Refresh()
        if (-not $process.HasExited) {
          $ready = $true
          break
        }
      }
      Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
      throw "Harness 未在 30 秒内以新 PID 监听 127.0.0.1:3080；请检查日志路径：$stdoutPath 和 $stderrPath"
    }
  } catch {
    try {
      $process.Refresh()
      if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction Stop
        [void]$process.WaitForExit(5000)
      }
    } catch {
      # Preserve the startup failure without broadening cleanup beyond this exact child PID.
    }
    throw
  }
} finally {
  if ($null -ne $childEnvironment) {
    foreach ($name in @($childEnvironment.Keys)) { $childEnvironment[$name] = $null }
    $childEnvironment = $null
  }
  foreach ($name in $deviceEnvironmentNames) { $deviceEnvironment[$name] = $null }
  $deviceEnvironment = $null
}

Write-Output 'bound-harness-launcher: 本地 Harness 监听已就绪。'
Write-Output 'Registry Presence: 未在本启动器中验证，请在注册站确认实例在线。'
Write-Output "PID: $($process.Id)"
Write-Output "DSH_HOME: $DshHome"
Write-Output "overlay: $overlayPath"
Write-Output "stdout: $stdoutPath"
Write-Output "stderr: $stderrPath"
