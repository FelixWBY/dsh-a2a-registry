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
  [string]$LogDirectory,

  [ValidateSet('ConnectionOnly', 'Production')]
  [string]$RuntimeMode = 'ConnectionOnly',

  [ValidateRange(1, 65535)]
  [int]$Port = 3080
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
if ($null -ne (Get-Item -LiteralPath 'Env:NODE_OPTIONS' -ErrorAction SilentlyContinue) -or
  $null -ne (Get-Item -LiteralPath 'Env:NODE_PATH' -ErrorAction SilentlyContinue)) {
  throw '启动 Harness 前必须移除 NODE_OPTIONS 和 NODE_PATH。'
}

$requiredDeviceEnvironmentNames = @(
  'DSH_REGISTRY_ORGANIZATION_ID',
  'DSH_INSTANCE_ID',
  'DSH_REGISTRY_SYNC_URL',
  'DSH_REGISTRY_DEVICE_TOKEN',
  'DSH_REGISTRY_DEVICE_PRIVATE_KEY'
)
$deviceEnvironmentNames = @($requiredDeviceEnvironmentNames) + @('DSH_REGISTRY_DISCLOSURE_TOKEN')
$productionEnvironmentNames = @($deviceEnvironmentNames) + @(
  'DSH_REGISTRY_DISCLOSURE_BRIDGE_URL',
  'DSH_DISCLOSURE_STATE_PATH',
  'DEEPSEEK_API_KEY'
)

. (Join-Path $PSScriptRoot 'windows-private-path-gate.ps1')

function Assert-OutsideDirectory([string]$Path, [string]$Directory, [string]$Label) {
  $prefix = $Directory + [IO.Path]::DirectorySeparatorChar
  if ($Path.Equals($Directory, [StringComparison]::OrdinalIgnoreCase) -or
    $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label 不能放在 Harness 源码目录内。"
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

function Read-HarnessEnvironment([string]$Path, [string]$SelectedMode) {
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
    $allowedNames = if ($SelectedMode -eq 'Production') {
      $productionEnvironmentNames
    } else {
      $deviceEnvironmentNames
    }
    if ($allowedNames -cnotcontains $name) {
      throw 'enrollment 环境文件包含当前运行模式不允许的变量。'
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
  if ($SelectedMode -eq 'Production') {
    if ($values.Count -ne $productionEnvironmentNames.Count -or
      @($productionEnvironmentNames | Where-Object { -not $values.ContainsKey($_) }).Count -ne 0) {
      throw 'Production 环境文件必须严格包含六项设备变量、bridge／state 配置和 DEEPSEEK_API_KEY。'
    }
  } elseif (($values.Count -ne $requiredDeviceEnvironmentNames.Count -and
      $values.Count -ne $deviceEnvironmentNames.Count) -or
    @($requiredDeviceEnvironmentNames | Where-Object { -not $values.ContainsKey($_) }).Count -ne 0) {
    throw 'ConnectionOnly 环境文件必须严格包含旧版五项连接变量，或包含新增独立 disclosure token 的六项变量。'
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
  if ($values.ContainsKey('DSH_REGISTRY_DISCLOSURE_TOKEN') -and
    ($values['DSH_REGISTRY_DISCLOSURE_TOKEN'].Length -gt 512 -or
      $values['DSH_REGISTRY_DISCLOSURE_TOKEN'] -notmatch '^dshb1\.[A-Za-z0-9_-]+\.[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$')) {
      throw 'enrollment 环境文件中的设备凭据格式无效。'
  }
  if ($SelectedMode -eq 'Production') {
    try {
      $bridgeUri = [Uri]$values['DSH_REGISTRY_DISCLOSURE_BRIDGE_URL']
    } catch {
      throw 'Production disclosure bridge 地址无效。'
    }
    if (-not $syncUri.IsDefaultPort -or
      -not $syncUri.Authority.Equals($syncUri.Host, [StringComparison]::OrdinalIgnoreCase) -or
      $syncUri.AbsolutePath -cne '/a2a/v1/sync' -or
      -not $bridgeUri.IsAbsoluteUri -or $bridgeUri.Scheme -ne 'https' -or
      -not [string]::IsNullOrEmpty($bridgeUri.UserInfo) -or
      -not [string]::IsNullOrEmpty($bridgeUri.Query) -or
      -not [string]::IsNullOrEmpty($bridgeUri.Fragment) -or
      -not $bridgeUri.IsDefaultPort -or
      -not $bridgeUri.Authority.Equals($bridgeUri.Host, [StringComparison]::OrdinalIgnoreCase) -or
      $bridgeUri.AbsolutePath -cne '/a2a/v1/disclosure-publication' -or
      -not $bridgeUri.Host.Equals($syncUri.Host, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Production 同步与 disclosure bridge 必须是同主机、无显式端口的固定公网 WSS／HTTPS 路径。'
    }
    Assert-AbsoluteWindowsPath $values['DSH_DISCLOSURE_STATE_PATH'] 'DSH_DISCLOSURE_STATE_PATH'
    $modelCredentialBytes = [Text.Encoding]::UTF8.GetByteCount($values['DEEPSEEK_API_KEY'])
    if ($modelCredentialBytes -lt 16 -or $modelCredentialBytes -gt 4096) {
      throw 'DEEPSEEK_API_KEY 必须是 16 到 4096 字节的非空凭据。'
    }
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
let deviceSecretBytes
let disclosureSecretBytes
let valid = false
try {
  const organizationId = process.env.DSH_REGISTRY_ORGANIZATION_ID ?? ''
  const token = process.env.DSH_REGISTRY_DEVICE_TOKEN ?? ''
  const disclosureToken = process.env.DSH_REGISTRY_DISCLOSURE_TOKEN ?? ''
  const hasDisclosureToken = disclosureToken.length > 0
  const privateKey = process.env.DSH_REGISTRY_DEVICE_PRIVATE_KEY ?? ''
  const parts = token.split('.')
  const disclosureParts = disclosureToken.split('.')
  if (!identifier.test(organizationId) || Buffer.byteLength(token, 'utf8') > 512
    || parts.length !== 4 || parts[0] !== 'dsh1' || !uuid.test(parts[2] ?? '')) throw new Error()
  if (hasDisclosureToken && (Buffer.byteLength(disclosureToken, 'utf8') > 512
    || disclosureParts.length !== 4 || disclosureParts[0] !== 'dshb1'
    || !uuid.test(disclosureParts[2] ?? ''))) throw new Error()
  const organizationBytes = canonical(parts[1])
  deviceSecretBytes = canonical(parts[3], 32)
  const disclosureOrganizationBytes = hasDisclosureToken ? canonical(disclosureParts[1]) : undefined
  disclosureSecretBytes = hasDisclosureToken ? canonical(disclosureParts[3], 32) : undefined
  if (organizationBytes === undefined || deviceSecretBytes === undefined
    || (hasDisclosureToken
      && (disclosureOrganizationBytes === undefined || disclosureSecretBytes === undefined))) throw new Error()
  const selectedOrganization = organizationBytes.toString('utf8')
  if (!identifier.test(selectedOrganization) || selectedOrganization !== organizationId
    || Buffer.from(selectedOrganization, 'utf8').toString('base64url') !== parts[1]) throw new Error()
  if (hasDisclosureToken) {
    const selectedDisclosureOrganization = disclosureOrganizationBytes.toString('utf8')
    if (selectedDisclosureOrganization !== organizationId
      || Buffer.from(selectedDisclosureOrganization, 'utf8').toString('base64url') !== disclosureParts[1]
      || disclosureParts[2] !== parts[2] || disclosureSecretBytes.equals(deviceSecretBytes)) throw new Error()
  }
  keyBytes = canonical(privateKey)
  if (keyBytes === undefined) throw new Error()
  const key = createPrivateKey({ key: keyBytes, format: 'der', type: 'pkcs8' })
  const exported = key.export({ format: 'der', type: 'pkcs8' })
  if (key.asymmetricKeyType !== 'ed25519' || !Buffer.isBuffer(exported) || !exported.equals(keyBytes)) {
    throw new Error()
  }
  valid = true
} catch {}
finally {
  if (keyBytes !== undefined) keyBytes.fill(0)
  if (deviceSecretBytes !== undefined) deviceSecretBytes.fill(0)
  if (disclosureSecretBytes !== undefined) disclosureSecretBytes.fill(0)
}
if (!valid) process.exit(1)
'@
  $encodedValidator = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($validator))
  $validationEnvironment = @{
    DSH_REGISTRY_ORGANIZATION_ID = $Values['DSH_REGISTRY_ORGANIZATION_ID']
    DSH_REGISTRY_DEVICE_TOKEN = $Values['DSH_REGISTRY_DEVICE_TOKEN']
    DSH_REGISTRY_DEVICE_PRIVATE_KEY = $Values['DSH_REGISTRY_DEVICE_PRIVATE_KEY']
  }
  if ($Values.ContainsKey('DSH_REGISTRY_DISCLOSURE_TOKEN')) {
    $validationEnvironment['DSH_REGISTRY_DISCLOSURE_TOKEN'] = $Values['DSH_REGISTRY_DISCLOSURE_TOKEN']
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

function Invoke-IsolatedRuntimeHashVerification(
  [string]$Runtime,
  [string]$RuntimeRoot,
  [string]$ManifestPath
) {
  $verifier = @'
const { createHash } = require('node:crypto')
const { readFileSync, readdirSync } = require('node:fs')
const { relative, resolve } = require('node:path')
const { TextDecoder } = require('node:util')

const root = resolve(process.argv[2])
const manifestPath = resolve(process.argv[3])
const normalize = value => value.replaceAll('\\', '/')
const fail = () => { throw new Error('runtime hash verification failed') }

try {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(manifestPath))
  if (!text.endsWith('\n') || text.includes('\r')) fail()
  const lines = text.slice(0, -1).split('\n')
  if (lines.length === 0) fail()
  const expected = new Map()
  for (const line of lines) {
    const match = /^([0-9a-f]{64})  (.+)$/u.exec(line)
    if (match === null) fail()
    const selected = match[2]
    const segments = selected.split('/')
    if (selected.includes('\\') || selected.includes(':') || selected.startsWith('/')
      || segments.some(segment => segment === '' || segment === '.' || segment === '..')) fail()
    const key = selected.toLowerCase()
    if (expected.has(key)) fail()
    expected.set(key, { hash: match[1], path: selected })
  }

  const manifestRelative = normalize(relative(root, manifestPath)).toLowerCase()
  const actual = new Map()
  const pending = [root]
  while (pending.length > 0) {
    const directory = pending.pop()
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) fail()
      const fullPath = resolve(directory, entry.name)
      if (entry.isDirectory()) {
        pending.push(fullPath)
      } else if (entry.isFile()) {
        const selected = normalize(relative(root, fullPath))
        const key = selected.toLowerCase()
        if (key === manifestRelative) continue
        if (actual.has(key)) fail()
        actual.set(key, { path: selected, fullPath })
      } else {
        fail()
      }
    }
  }
  if (actual.size !== expected.size) fail()
  for (const [key, selected] of expected) {
    const file = actual.get(key)
    if (file === undefined || file.path !== selected.path) fail()
    const hash = createHash('sha256').update(readFileSync(file.fullPath)).digest('hex')
    if (hash !== selected.hash) fail()
  }
} catch {
  process.exitCode = 1
}
'@
  $encodedVerifier = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($verifier))
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Runtime
  $startInfo.WorkingDirectory = $RuntimeRoot
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  foreach ($argument in @(
      '--eval', "eval(Buffer.from(process.argv[1],'base64').toString('utf8'))",
      $encodedVerifier, $RuntimeRoot, $ManifestPath
    )) {
    [void]$startInfo.ArgumentList.Add($argument)
  }
  $startInfo.Environment.Clear()
  foreach ($name in @(
      'ALLUSERSPROFILE', 'APPDATA', 'CommonProgramFiles', 'CommonProgramFiles(x86)',
      'CommonProgramW6432', 'DriverData', 'HOMEDRIVE', 'HOMEPATH',
      'LOCALAPPDATA', 'NUMBER_OF_PROCESSORS', 'OS', 'PATHEXT',
      'PROCESSOR_ARCHITECTURE', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)',
      'ProgramW6432', 'SystemDrive', 'SystemRoot', 'TEMP', 'TMP', 'USERNAME',
      'USERPROFILE', 'WINDIR'
    )) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if (-not [string]::IsNullOrEmpty($value)) { $startInfo.Environment[$name] = $value }
  }
  $systemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
  $startInfo.Environment['ComSpec'] = Join-Path $systemDirectory 'cmd.exe'
  $startInfo.Environment['Path'] = "$(Split-Path -Parent $Runtime);$systemDirectory"
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  if (-not $process.Start()) { throw '无法启动隔离的运行包摘要验证器。' }
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit(120000)) {
    try { $process.Kill($true) } catch {}
    [void]$process.WaitForExit(5000)
    throw '隔离的运行包摘要验证器超时。'
  }
  [void]$stdoutTask.GetAwaiter().GetResult()
  [void]$stderrTask.GetAwaiter().GetResult()
  $exitCode = $process.ExitCode
  $process.Dispose()
  if ($exitCode -ne 0) { throw '运行包逐文件 SHA-256 验证失败。' }
}

function Assert-ProtectedRuntime(
  [string]$SelectedHarnessRoot,
  [string]$SelectedNodePath,
  [string]$SelectedMode
) {
  $launcherRoot = Resolve-ExistingDirectory $PSScriptRoot '启动器目录'
  $runtimeRoot = Resolve-ExistingDirectory (Split-Path -Parent $launcherRoot) '运行包根目录'
  $expectedHarnessRoot = Resolve-ExistingDirectory (Join-Path $runtimeRoot 'harness') '运行包 HarnessRoot'
  $expectedNodeRoot = Resolve-ExistingDirectory (Join-Path $runtimeRoot 'node') '运行包 Node.js 目录'
  $expectedNodePath = Resolve-ExistingFile (Join-Path $expectedNodeRoot 'node.exe') '运行包 Node.js'
  if (-not $SelectedHarnessRoot.Equals($expectedHarnessRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not $SelectedNodePath.Equals($expectedNodePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'HarnessRoot 和 NodePath 必须指向当前受保护运行包内的固定位置。'
  }

  Assert-NoUntrustedNamespaceReplacement $runtimeRoot '运行包根目录'
  Assert-NoUnauthorizedWriteAcl $runtimeRoot '运行包根目录' $true
  Assert-NoUnauthorizedWriteAcl $expectedHarnessRoot 'HarnessRoot' $true
  Assert-NoUnauthorizedWriteAcl $expectedNodeRoot 'Node.js 目录' $true
  Assert-NoUnauthorizedWriteAcl $launcherRoot '启动器目录' $true
  $runtimeItems = @(Get-ChildItem -LiteralPath $runtimeRoot -Force -Recurse)
  $reparse = $runtimeItems | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
  } | Select-Object -First 1
  if ($null -ne $reparse) { throw '受保护运行包不能包含 junction 或符号链接。' }

  $manifestPath = Resolve-ExistingFile (Join-Path $runtimeRoot 'runtime-files.sha256') '运行包摘要清单'
  if ((Get-Item -LiteralPath $manifestPath -Force).Length -gt 32MB) {
    throw '运行包摘要清单超过大小限制。'
  }
  try {
    $manifestLines = [IO.File]::ReadAllLines($manifestPath, [Text.UTF8Encoding]::new($false, $true))
  } catch {
    throw '运行包摘要清单不是严格 UTF-8 文本。'
  }
  $manifestEntries = [Collections.Generic.Dictionary[string, string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
  foreach ($line in $manifestLines) {
    if ($line.Length -lt 67 -or $line.Substring(0, 64) -notmatch '^[0-9a-f]{64}$' -or
      $line.Substring(64, 2) -cne '  ') {
      throw '运行包摘要清单格式无效。'
    }
    $relative = $line.Substring(66)
    $segments = @($relative.Split('/'))
    if ($relative.Length -eq 0 -or $relative.Contains('\') -or $relative.Contains(':') -or
      $relative.StartsWith('/', [StringComparison]::Ordinal) -or
      @($segments | Where-Object { $_.Length -eq 0 -or $_ -eq '.' -or $_ -eq '..' }).Count -ne 0 -or
      $manifestEntries.ContainsKey($relative)) {
      throw '运行包摘要清单包含重复或越界路径。'
    }
    $manifestEntries.Add($relative, $line.Substring(0, 64))
  }
  if ($manifestEntries.Count -eq 0) { throw '运行包摘要清单不能为空。' }

  foreach ($requiredRelative in @(
      'harness/apps/cli/lib/bin.js',
      'node/node.exe',
      'launcher/start-bound-harness.ps1',
      'launcher/windows-private-path-gate.ps1',
      'launcher/harness-registry-connection.example.patch.yml',
      'launcher/harness-production-publication.example.patch.yml',
      'runtime-package-lock.json',
      'runtime-build.json'
    )) {
    if (-not $manifestEntries.ContainsKey($requiredRelative)) {
      throw "运行包摘要清单缺少必要文件：$requiredRelative"
    }
    Assert-NoUnauthorizedWriteAcl (Join-Path $runtimeRoot $requiredRelative.Replace('/', '\')) `
      "运行包关键文件 $requiredRelative" $false
  }
  $nodeRelative = 'node/node.exe'
  $nodeHash = (Get-FileHash -LiteralPath $expectedNodePath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($nodeHash -cne $manifestEntries[$nodeRelative]) {
    throw '运行包 Node.js 摘要不匹配。'
  }
  Invoke-IsolatedRuntimeHashVerification $expectedNodePath $runtimeRoot $manifestPath

  $evidencePath = Resolve-ExistingFile (Join-Path $runtimeRoot 'runtime-build.json') '运行包构建证据'
  try {
    $evidence = [IO.File]::ReadAllText($evidencePath, [Text.UTF8Encoding]::new($false, $true)) |
      ConvertFrom-Json -AsHashtable -ErrorAction Stop
  } catch {
    throw '运行包构建证据不是有效的严格 UTF-8 JSON。'
  }
  $nodeEvidenceMatch = [regex]::Match([string]$evidence.nodeVersion, '^([0-9]+)\.')
  if ($evidence.schemaVersion -ne 2 -or $evidence.lifecycleScripts -ne $false -or
    $evidence.optionalDependenciesInstalled -ne $false -or
    [string]$evidence.credentialInputs -cne 'external-at-launch' -or
    [string]::IsNullOrWhiteSpace([string]$evidence.harnessVersion) -or
    -not $nodeEvidenceMatch.Success -or [int]$nodeEvidenceMatch.Groups[1].Value -lt 24 -or
    @($evidence.packages).Count -eq 0) {
    throw '运行包构建证据不满足无脚本、Node.js 24+ 和包来源要求。'
  }
  $validatedModes = @($evidence.validatedModes)
  if (([string]$evidence.runtimeMode -cne 'ConnectionOnly' -and
      [string]$evidence.runtimeMode -cne 'Production') -or
    $validatedModes -cnotcontains 'ConnectionOnly' -or
    ([string]$evidence.runtimeMode -ceq 'ConnectionOnly' -and $validatedModes.Count -ne 1) -or
    ([string]$evidence.runtimeMode -ceq 'Production' -and
      ($validatedModes.Count -ne 2 -or $validatedModes -cnotcontains 'Production')) -or
    ($SelectedMode -eq 'Production' -and $validatedModes -cnotcontains 'Production')) {
    throw '运行包未记录当前启动模式所需的配置合成验收。'
  }
  return $evidence
}

$HarnessRoot = Resolve-ExistingDirectory $HarnessRoot 'HarnessRoot'
$NodePath = Resolve-ExistingFile $NodePath 'NodePath'
$EnvFile = Resolve-ExistingFile $EnvFile 'EnvFile'
$CaCertificate = Resolve-ExistingFile $CaCertificate 'CaCertificate'
$DshHome = Resolve-ExistingDirectory $DshHome 'DshHome'
$LogDirectory = Resolve-ExistingDirectory $LogDirectory 'LogDirectory'
$runtimeEvidence = Assert-ProtectedRuntime $HarnessRoot $NodePath $RuntimeMode

if (-not [IO.Path]::GetFileName($NodePath).Equals('node.exe', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'NodePath 必须指向 node.exe。'
}
Assert-NoUntrustedNamespaceReplacement (Split-Path -Parent $NodePath) 'NodePath 父目录'
Assert-NoUnauthorizedWriteAcl $NodePath 'NodePath' $false
$nodeVersion = @(& $NodePath -p 'process.versions.node' 2>$null)
if ($LASTEXITCODE -ne 0 -or $nodeVersion.Count -ne 1 -or $nodeVersion[0] -notmatch '^[0-9]+\.') {
  throw '无法验证 Node.js 版本。'
}
$nodeMajor = [int]$nodeVersion[0].Split('.')[0]
if ($nodeMajor -lt 24) { throw '需要 Node.js 24 或更高版本。' }
if ($nodeVersion[0] -cne [string]$runtimeEvidence.nodeVersion) {
  throw 'Node.js 版本与受保护运行包构建证据不一致。'
}

$cliPath = Resolve-ExistingFile (Join-Path $HarnessRoot 'apps\cli\lib\bin.js') 'Harness CLI'
$launcherRoot = Resolve-ExistingDirectory $PSScriptRoot '启动器目录'
$runtimeRoot = Resolve-ExistingDirectory (Split-Path -Parent $launcherRoot) '运行包根目录'
$overlayName = if ($RuntimeMode -eq 'Production') {
  'harness-production-publication.example.patch.yml'
} else {
  'harness-registry-connection.example.patch.yml'
}
$overlayPath = Resolve-ExistingFile (Join-Path $launcherRoot $overlayName) 'Harness overlay'
$envParent = Resolve-ExistingDirectory (Split-Path -Parent $EnvFile) 'EnvFile 父目录'
$caParent = Resolve-ExistingDirectory (Split-Path -Parent $CaCertificate) 'CaCertificate 父目录'
Assert-NoUntrustedNamespaceReplacement $envParent 'EnvFile 父目录'
Assert-NoUntrustedNamespaceReplacement $DshHome 'DshHome'
Assert-NoUntrustedNamespaceReplacement $LogDirectory 'LogDirectory'
Assert-NoUntrustedNamespaceReplacement $HarnessRoot 'HarnessRoot'
Assert-NoUntrustedNamespaceReplacement $launcherRoot '启动器目录'
Assert-NoUntrustedNamespaceReplacement $caParent 'CaCertificate 父目录'
Assert-OutsideDirectory $EnvFile $runtimeRoot 'EnvFile'
Assert-OutsideDirectory $CaCertificate $runtimeRoot 'CaCertificate'
Assert-OutsideDirectory $DshHome $runtimeRoot 'DshHome'
Assert-OutsideDirectory $LogDirectory $runtimeRoot 'LogDirectory'

if (Test-PortInUse $Port) {
  throw "TCP 端口 $Port 已被占用；启动器不会停止或替换现有进程。"
}

Assert-PrivateAcl $envParent 'EnvFile 父目录' $true
Assert-PrivateAcl $EnvFile 'EnvFile' $false
Assert-PrivateAcl $DshHome 'DshHome' $true
Assert-PrivateAcl $LogDirectory 'LogDirectory' $true
Assert-NoUnauthorizedWriteAcl $HarnessRoot 'HarnessRoot' $true
Assert-NoUnauthorizedWriteAcl $cliPath 'Harness CLI' $false
Assert-NoUnauthorizedWriteAcl $launcherRoot '启动器目录' $true
Assert-NoUnauthorizedWriteAcl $overlayPath 'Harness overlay' $false
Assert-NoUnauthorizedWriteAcl $caParent 'CaCertificate 父目录' $true
Assert-NoUnauthorizedWriteAcl $CaCertificate 'CaCertificate' $false

$certificateText = [IO.File]::ReadAllText($CaCertificate)
if ($certificateText -notmatch '-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----') {
  throw 'CaCertificate 不是 PEM 证书文件。'
}
$certificateText = $null
$deviceEnvironment = Read-HarnessEnvironment $EnvFile $RuntimeMode
$disclosureStatePath = $null
$portableCliVersion = @(& $NodePath $cliPath '--version' 2>$null)
if ($LASTEXITCODE -ne 0 -or $portableCliVersion.Count -ne 1 -or
  $portableCliVersion[0] -cne [string]$runtimeEvidence.harnessVersion) {
  throw 'Harness CLI 版本与受保护运行包构建证据不一致。'
}
if ($RuntimeMode -eq 'Production') {
  $disclosureStatePath = Resolve-ExistingDirectory `
    $deviceEnvironment['DSH_DISCLOSURE_STATE_PATH'] 'DSH_DISCLOSURE_STATE_PATH'
  Assert-OutsideDirectory $disclosureStatePath $runtimeRoot 'DSH_DISCLOSURE_STATE_PATH'
  Assert-NoUntrustedNamespaceReplacement $disclosureStatePath 'DSH_DISCLOSURE_STATE_PATH'
  Assert-PrivateAcl $disclosureStatePath 'DSH_DISCLOSURE_STATE_PATH' $true $true
  $deviceEnvironment['DSH_DISCLOSURE_STATE_PATH'] = $disclosureStatePath
}
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
  foreach ($name in @($deviceEnvironment.Keys)) {
    $childEnvironment[$name] = $deviceEnvironment[$name]
  }

  $arguments = @(
    "`"$cliPath`"",
    '--profile', 'web',
    '--patch', "`"$overlayPath`"",
    '--no-open',
    '--host', '127.0.0.1',
    '--port', "$Port"
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
      if (Test-ProcessOwnsLoopbackListener $process.Id $Port) {
        $process.Refresh()
        if (-not $process.HasExited) {
          $ready = $true
          break
        }
      }
      Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
      throw "Harness 未在 30 秒内以新 PID 监听 127.0.0.1:$Port；请检查日志路径：$stdoutPath 和 $stderrPath"
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
  foreach ($name in @($deviceEnvironment.Keys)) { $deviceEnvironment[$name] = $null }
  $deviceEnvironment = $null
}

Write-Output 'bound-harness-launcher: 本地 Harness 监听已就绪。'
Write-Output 'Registry Presence: 未在本启动器中验证，请在注册站确认实例在线。'
Write-Output "PID: $($process.Id)"
Write-Output "URL: http://127.0.0.1:$Port/"
Write-Output "DSH_HOME: $DshHome"
Write-Output "Runtime mode: $RuntimeMode"
Write-Output "overlay: $overlayPath"
Write-Output "stdout: $stdoutPath"
Write-Output "stderr: $stderrPath"
