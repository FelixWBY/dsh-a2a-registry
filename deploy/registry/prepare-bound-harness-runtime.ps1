param(
  [Parameter(Mandatory = $true)]
  [string[]]$TarballDirectory,

  [Parameter(Mandatory = $true)]
  [string]$NodePath,

  [Parameter(Mandatory = $true)]
  [string]$DestinationRoot,

  [ValidateSet('ConnectionOnly', 'Production')]
  [string]$RuntimeMode = 'ConnectionOnly',

  [string]$NpmRegistry = 'https://registry.npmjs.org/'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') {
  throw '此准备器只支持 Windows。'
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
  throw '需要 PowerShell 7 或更高版本。'
}
if ($null -ne (Get-Item -LiteralPath 'Env:NODE_OPTIONS' -ErrorAction SilentlyContinue) -or
  $null -ne (Get-Item -LiteralPath 'Env:NODE_PATH' -ErrorAction SilentlyContinue)) {
  throw '准备运行包前必须移除 NODE_OPTIONS 和 NODE_PATH。'
}

. (Join-Path $PSScriptRoot 'windows-private-path-gate.ps1')

$systemDirectory = Resolve-ExistingDirectory `
  ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'Windows 系统目录'
Assert-NoUntrustedNamespaceReplacement $systemDirectory 'Windows 系统目录'
$icaclsPath = Resolve-ExistingFile (Join-Path $systemDirectory 'icacls.exe') 'icacls.exe'
$tarPath = Resolve-ExistingFile (Join-Path $systemDirectory 'tar.exe') 'tar.exe'
$cmdPath = Resolve-ExistingFile (Join-Path $systemDirectory 'cmd.exe') 'cmd.exe'
Assert-NoUnauthorizedWriteAcl $icaclsPath 'icacls.exe' $false
Assert-NoUnauthorizedWriteAcl $tarPath 'tar.exe' $false
Assert-NoUnauthorizedWriteAcl $cmdPath 'cmd.exe' $false
$launcherSourceRoot = Resolve-ExistingDirectory $PSScriptRoot '准备器目录'
Assert-NoUntrustedNamespaceReplacement $launcherSourceRoot '准备器目录'
Assert-NoUnauthorizedWriteAcl $launcherSourceRoot '准备器目录' $false

function Protect-Directory([string]$Path, [bool]$ResetChildren = $true) {
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & $icaclsPath $Path '/inheritance:r' '/grant:r' `
    "*$($currentSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "无法限制运行包 ACL：$Path" }
  if ($ResetChildren -and
    $null -ne (Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1)) {
    & $icaclsPath (Join-Path $Path '*') '/reset' '/T' '/C' '/Q' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "无法重置运行包子项 ACL：$Path" }
  }
}

function Assert-ChildPath([string]$Path, [string]$Parent, [string]$Label) {
  $fullPath = [IO.Path]::GetFullPath($Path)
  $fullParent = [IO.Path]::GetFullPath($Parent).TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $prefix = $fullParent + [IO.Path]::DirectorySeparatorChar
  if (-not $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label 必须位于指定父目录内。"
  }
}

function Remove-StagingDirectory([string]$Path, [string]$Parent, [string]$ExpectedName) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $fullPath = [IO.Path]::GetFullPath($Path)
  Assert-ChildPath $fullPath $Parent '临时目录'
  if (-not [IO.Path]::GetFileName($fullPath).Equals($ExpectedName, [StringComparison]::Ordinal)) {
    throw '拒绝清理非本次创建的临时目录。'
  }
  Remove-Item -LiteralPath $fullPath -Recurse -Force
}

function Get-PackageManifest([string]$TarExecutable, [string]$Tarball) {
  $lines = @(& $TarExecutable '-xOf' $Tarball 'package/package.json' 2>$null)
  if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) {
    throw "无法读取 tarball 清单：$([IO.Path]::GetFileName($Tarball))"
  }
  try {
    return ($lines -join "`n") | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "tarball 的 package.json 无效：$([IO.Path]::GetFileName($Tarball))"
  }
}

function Read-StrictUtf8Lines([string]$Path, [string]$Label) {
  try {
    return [IO.File]::ReadAllLines($Path, [Text.UTF8Encoding]::new($false, $true))
  } catch {
    throw "$Label 不是严格 UTF-8 文本。"
  }
}

function Assert-PublishOrder([string]$Directory, [string[]]$TarballNames) {
  $orderPath = Join-Path $Directory 'publish-order.txt'
  if (-not (Test-Path -LiteralPath $orderPath)) { return $false }
  $entries = @(Read-StrictUtf8Lines $orderPath 'publish-order.txt' | Where-Object { $_.Length -gt 0 })
  if ($entries.Count -eq 0 -or @($entries | Where-Object {
      $_ -notmatch '^[A-Za-z0-9._-]+\.tgz$'
    }).Count -ne 0 -or (@($entries | Sort-Object -Unique)).Count -ne $entries.Count) {
    throw 'publish-order.txt 含有空集合、重复项或非法文件名。'
  }
  $expected = @($TarballNames | Sort-Object)
  $actual = @($entries | Sort-Object)
  if (($expected -join "`n") -cne ($actual -join "`n")) {
    throw 'publish-order.txt 与 tarball 目录不精确一致。'
  }
  return $true
}

function Invoke-IsolatedNode(
  [string]$Runtime,
  [string]$WorkingDirectory,
  [string[]]$Arguments,
  [hashtable]$AdditionalEnvironment,
  [bool]$CaptureOutput = $false,
  [int]$TimeoutMilliseconds = 900000
) {
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $Runtime
  $startInfo.WorkingDirectory = $WorkingDirectory
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $CaptureOutput
  $startInfo.RedirectStandardError = $CaptureOutput
  foreach ($argument in $Arguments) { [void]$startInfo.ArgumentList.Add($argument) }
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
  $runtimeDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Runtime))
  $startInfo.Environment['ComSpec'] = $cmdPath
  $startInfo.Environment['Path'] = "$runtimeDirectory;$systemDirectory"
  foreach ($name in $AdditionalEnvironment.Keys) {
    $startInfo.Environment[$name] = [string]$AdditionalEnvironment[$name]
  }
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  if (-not $process.Start()) { throw '无法启动隔离的 Node.js 子进程。' }
  $stdoutTask = if ($CaptureOutput) { $process.StandardOutput.ReadToEndAsync() } else { $null }
  $stderrTask = if ($CaptureOutput) { $process.StandardError.ReadToEndAsync() } else { $null }
  if (-not $process.WaitForExit($TimeoutMilliseconds)) {
    try { $process.Kill($true) } catch {}
    [void]$process.WaitForExit(5000)
    throw '隔离的 Node.js 子进程超时。'
  }
  $stdout = if ($CaptureOutput) { $stdoutTask.GetAwaiter().GetResult() } else { '' }
  $stderr = if ($CaptureOutput) { $stderrTask.GetAwaiter().GetResult() } else { '' }
  $exitCode = $process.ExitCode
  $process.Dispose()
  return @{ ExitCode = $exitCode; Stdout = $stdout; Stderr = $stderr }
}

function Get-BoundedProcessDiagnostic([hashtable]$Result) {
  $diagnostic = (@($Result.Stderr, $Result.Stdout) |
      Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join "`n"
  $diagnostic = $diagnostic.Trim()
  if ($diagnostic.Length -gt 4000) {
    $diagnostic = $diagnostic.Substring($diagnostic.Length - 4000)
  }
  return $diagnostic
}

function Assert-NoReparsePointsRecursively([string]$Root) {
  $rootItem = Get-Item -LiteralPath $Root -Force
  if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw '运行包根目录不能是重解析点。'
  }
  $reparse = Get-ChildItem -LiteralPath $Root -Force -Recurse | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
  } | Select-Object -First 1
  if ($null -ne $reparse) {
    throw "运行包包含 junction 或符号链接：$($reparse.FullName)"
  }
}

function Assert-TrustedFileTree([string]$Root, [string]$Label) {
  Assert-NoReparsePointsRecursively $Root
  Assert-NoUnauthorizedWriteAcl $Root $Label $false
  foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
    Assert-NoUnauthorizedWriteAcl $item.FullName $Label $false
  }
}

function Get-CompositionSection([string]$Output, [string]$Id) {
  $lines = @($Output -split '\r?\n')
  $starts = @()
  for ($index = 0; $index -lt $lines.Count; $index += 1) {
    if ($lines[$index] -ceq "- id: $Id") { $starts += $index }
  }
  if ($starts.Count -ne 1) { throw "配置合成结果必须恰好包含一个 $Id 条目。" }
  $start = $starts[0]
  $end = $lines.Count
  for ($index = $start + 1; $index -lt $lines.Count; $index += 1) {
    if ($lines[$index].StartsWith('- id: ', [StringComparison]::Ordinal)) {
      $end = $index
      break
    }
  }
  return ($lines[$start..($end - 1)] -join "`n")
}

function Assert-ConnectionOnlyComposition([string]$Output) {
  $section = Get-CompositionSection $Output 'web-runtime'
  foreach ($required in @(
      "name: '@deepseek-ai/dsh-web-app'",
      '- credentials',
      'productionRegistryConnection:',
      'mode: production',
      'organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID',
      'instanceId: !!js process.env.DSH_INSTANCE_ID',
      'tokenEnv: DSH_REGISTRY_DEVICE_TOKEN',
      'privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY',
      'url: !!js process.env.DSH_REGISTRY_SYNC_URL'
    )) {
    if (-not $section.Contains($required, [StringComparison]::Ordinal)) {
      throw "connection-only 配置合成缺少字段：$required"
    }
  }
  foreach ($forbidden in @(
      'testOnlyDisclosurePublication:', 'productionDisclosureHttpsBridge:',
      'productionDisclosurePublication:', 'registryDisclosureImport:',
      'productionRegistryDisclosureImport:', 'productionRegistryQuestionConsumer:',
      'registryA2aConsumer:',
      'productionDisclosureAuthority', 'registryDisclosureKeyPublisher',
      'a2aDisclosureDecryption:', 'loopbackDisclosureImport:',
      'loopbackA2aConsumer:', 'loopbackDisclosureRefresh:',
      'registryUrl:', 'sharedSecretEnv:'
    )) {
    if ($Output.Contains($forbidden, [StringComparison]::Ordinal)) {
      throw "connection-only 配置合成意外启用：$forbidden"
    }
  }
}

function Assert-ProductionComposition([string]$Output) {
  $webSection = Get-CompositionSection $Output 'web-runtime'
  $sessionSection = Get-CompositionSection $Output 'session-controller'
  foreach ($required in @(
      "name: '@deepseek-ai/dsh-web-app'",
      '- credentials',
      'productionRegistryConnection:',
      'organizationId: !!js process.env.DSH_REGISTRY_ORGANIZATION_ID',
      'instanceId: !!js process.env.DSH_INSTANCE_ID',
      'tokenEnv: DSH_REGISTRY_DEVICE_TOKEN',
      'privateKeyEnv: DSH_REGISTRY_DEVICE_PRIVATE_KEY',
      'url: !!js process.env.DSH_REGISTRY_SYNC_URL',
      'productionDisclosureHttpsBridge:',
      'url: !!js process.env.DSH_REGISTRY_DISCLOSURE_BRIDGE_URL',
      'tokenEnv: DSH_REGISTRY_DISCLOSURE_TOKEN',
      'productionDisclosurePublication:',
      'storageRoot: !!js process.env.DSH_DISCLOSURE_STATE_PATH',
      'productionRegistryDisclosureImport:',
      'maxRetainedBytes: 16777216',
      'productionRegistryQuestionConsumer:',
      'handling: automatic',
      'provider: deepseek-official',
      'model: deepseek-flash',
      'modelCredentialEnv: DEEPSEEK_API_KEY',
      'maxClaims: 10000',
      'maxRequests: 10000',
      'maxRetainedRequests: 100000',
      'maxPendingOperations: 256'
    )) {
    if (-not $webSection.Contains($required, [StringComparison]::Ordinal)) {
      throw "production 配置合成缺少字段：$required"
    }
  }
  foreach ($required in @(
      "name: '@deepseek-ai/dsh-api-session-controller'",
      'disclosurePreview:'
    )) {
    if (-not $sessionSection.Contains($required, [StringComparison]::Ordinal)) {
      throw "production Session 配置合成缺少字段：$required"
    }
  }
  foreach ($forbidden in @(
      'testOnlyDisclosurePublication:', 'registryDisclosureImport:',
      'registryA2aConsumer:', 'productionDisclosureAuthority',
      'registryDisclosureKeyPublisher', 'a2aDisclosureDecryption:',
      'loopbackDisclosureImport:', 'loopbackA2aConsumer:',
      'loopbackDisclosureRefresh:', 'registryUrl:', 'sharedSecretEnv:'
    )) {
    if ($webSection.Contains($forbidden, [StringComparison]::Ordinal) -or
      $sessionSection.Contains($forbidden, [StringComparison]::Ordinal)) {
      throw "production 配置合成意外启用：$forbidden"
    }
  }
}

function Write-HashManifest([string]$Root, [string]$Output) {
  $outputFullPath = [IO.Path]::GetFullPath($Output)
  $lines = Get-ChildItem -LiteralPath $Root -File -Force -Recurse |
    Where-Object { -not $_.FullName.Equals($outputFullPath, [StringComparison]::OrdinalIgnoreCase) } |
    ForEach-Object {
      $relative = [IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\', '/')
      $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      [PSCustomObject]@{ Relative = $relative; Line = "$hash  $relative" }
    } | Sort-Object -Property Relative
  [IO.File]::WriteAllText($Output, (($lines.Line -join "`n") + "`n"),
    [Text.UTF8Encoding]::new($false))
}

$NodePath = Resolve-ExistingFile $NodePath 'NodePath'
$launcherSourceRoot = Resolve-ExistingDirectory $launcherSourceRoot '准备器目录'
Assert-NoReparsePointsRecursively $launcherSourceRoot
if (-not [IO.Path]::GetFileName($NodePath).Equals('node.exe', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'NodePath 必须指向 node.exe。'
}
$nodeSourceRoot = Resolve-ExistingDirectory (Split-Path -Parent $NodePath) 'NodePath 父目录'
Assert-NoUntrustedNamespaceReplacement $nodeSourceRoot 'NodePath 父目录'
Assert-NoUnauthorizedWriteAcl $NodePath 'NodePath' $false
$npmCli = Resolve-ExistingFile (Join-Path $nodeSourceRoot 'node_modules\npm\bin\npm-cli.js') 'npm CLI'
Assert-NoUnauthorizedWriteAcl $npmCli 'npm CLI' $false
$npmRoot = Resolve-ExistingDirectory (Join-Path $nodeSourceRoot 'node_modules\npm') 'npm 根目录'
Assert-NoUntrustedNamespaceReplacement $npmRoot 'npm 根目录'
Assert-TrustedFileTree $npmRoot 'npm 代码树'
$nodeVersion = @(& $NodePath -p 'process.versions.node' 2>$null)
if ($LASTEXITCODE -ne 0 -or $nodeVersion.Count -ne 1 -or
  [int]$nodeVersion[0].Split('.')[0] -lt 24) {
  throw '需要可执行的 Node.js 24 或更高版本。'
}

try {
  $registryUri = [Uri]$NpmRegistry
} catch {
  throw 'NpmRegistry 无效。'
}
if (-not $registryUri.IsAbsoluteUri -or $registryUri.Scheme -ne 'https' -or
  -not [string]::IsNullOrEmpty($registryUri.UserInfo) -or
  -not [string]::IsNullOrEmpty($registryUri.Query) -or
  -not [string]::IsNullOrEmpty($registryUri.Fragment)) {
  throw 'NpmRegistry 必须是无凭据、无查询参数的 HTTPS 地址。'
}
$registryPrefix = $registryUri.AbsoluteUri.TrimEnd('/') + '/'

$resolvedTarballDirectories = @($TarballDirectory | ForEach-Object {
  Resolve-ExistingDirectory $_ 'TarballDirectory'
})
if ($resolvedTarballDirectories.Count -ne 3 -or
  (@($resolvedTarballDirectories | Sort-Object -Unique)).Count -ne 3) {
  throw 'TarballDirectory 必须各提供一次 dsh、vendor 和 system native 三个发布目录。'
}
$sourceGroups = @()
foreach ($directory in $resolvedTarballDirectories) {
  Assert-NoUntrustedNamespaceReplacement $directory 'TarballDirectory'
  Assert-NoUnauthorizedWriteAcl $directory 'TarballDirectory' $false
  $files = @(Get-ChildItem -LiteralPath $directory -Force -File -Filter '*.tgz' |
    Sort-Object -Property Name)
  if ($files.Count -eq 0) { throw '每个 TarballDirectory 都必须包含 .tgz 文件。' }
  foreach ($file in $files) {
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "tarball 不能是重解析点：$($file.Name)"
    }
    Assert-NoUnauthorizedWriteAcl $file.FullName 'tarball' $false
  }
  $orderPath = Join-Path $directory 'publish-order.txt'
  if (Test-Path -LiteralPath $orderPath) {
    $orderPath = Resolve-ExistingFile $orderPath 'publish-order.txt'
    Assert-NoUnauthorizedWriteAcl $orderPath 'publish-order.txt' $false
  } else {
    $orderPath = $null
  }
  $sourceGroups += [PSCustomObject]@{
    Directory = $directory
    Files = $files
    OrderPath = $orderPath
  }
}

Assert-AbsoluteWindowsPath $DestinationRoot 'DestinationRoot'
$DestinationRoot = [IO.Path]::GetFullPath($DestinationRoot).TrimEnd(
  [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
if (Test-Path -LiteralPath $DestinationRoot) { throw 'DestinationRoot 已存在，准备器不会覆盖。' }
$destinationParentPath = Split-Path -Parent $DestinationRoot
$destinationParent = Resolve-ExistingDirectory $destinationParentPath 'DestinationRoot 父目录'
Assert-NoUntrustedNamespaceReplacement $destinationParent 'DestinationRoot 父目录'
Assert-PrivateAcl $destinationParent 'DestinationRoot 父目录' $true $true

$stagingName = ".$([IO.Path]::GetFileName($DestinationRoot)).staging-$([Guid]::NewGuid().ToString('N'))"
$stagingRoot = Join-Path $destinationParent $stagingName
Assert-ChildPath $stagingRoot $destinationParent '临时目录'
$sourceNodeHash = (Get-FileHash -LiteralPath $NodePath -Algorithm SHA256).Hash.ToLowerInvariant()
try {
  New-Item -ItemType Directory -Path $stagingRoot | Out-Null
  Protect-Directory $stagingRoot
  $harnessRoot = New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'harness')
  $nodeRoot = New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'node')
  $launcherRoot = New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'launcher')
  $packageSourcesRoot = New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'package-sources')

  $protectedGroups = @()
  for ($groupIndex = 0; $groupIndex -lt $sourceGroups.Count; $groupIndex += 1) {
    $sourceGroup = $sourceGroups[$groupIndex]
    $groupRoot = New-Item -ItemType Directory -Path (
      Join-Path $packageSourcesRoot.FullName $groupIndex.ToString('D2'))
    $copiedFiles = @()
    foreach ($sourceFile in $sourceGroup.Files) {
      $beforeHash = (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      $destination = Join-Path $groupRoot.FullName $sourceFile.Name
      Copy-Item -LiteralPath $sourceFile.FullName -Destination $destination
      $copiedHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
      $afterHash = (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($beforeHash -ne $copiedHash -or $beforeHash -ne $afterHash) {
        throw "复制期间 tarball 发生变化：$($sourceFile.Name)"
      }
      $copiedFiles += Get-Item -LiteralPath $destination -Force
    }
    $copiedOrder = $null
    if ($null -ne $sourceGroup.OrderPath) {
      $beforeHash = (Get-FileHash -LiteralPath $sourceGroup.OrderPath -Algorithm SHA256).Hash.ToLowerInvariant()
      $copiedOrder = Join-Path $groupRoot.FullName 'publish-order.txt'
      Copy-Item -LiteralPath $sourceGroup.OrderPath -Destination $copiedOrder
      $copiedHash = (Get-FileHash -LiteralPath $copiedOrder -Algorithm SHA256).Hash.ToLowerInvariant()
      $afterHash = (Get-FileHash -LiteralPath $sourceGroup.OrderPath -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($beforeHash -ne $copiedHash -or $beforeHash -ne $afterHash) {
        throw '复制期间 publish-order.txt 发生变化。'
      }
    }
    $protectedGroups += [PSCustomObject]@{
      Index = $groupIndex
      Directory = $groupRoot.FullName
      Files = $copiedFiles
      OrderPath = $copiedOrder
    }
  }

  $dependencies = [ordered]@{}
  $expectedDeepseekVersions = @{}
  $packageEvidence = @()
  $packageManifests = @()
  $groupPackages = @{}
  foreach ($group in $protectedGroups) {
    $names = @()
    foreach ($tarball in $group.Files) {
      $manifest = Get-PackageManifest $tarPath $tarball.FullName
      if ($manifest.name -isnot [string] -or $manifest.name -notmatch '^@deepseek-ai/[a-z0-9._-]+$' -or
        $manifest.version -isnot [string] -or
        $manifest.version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
        throw "tarball 的名称或版本无效：$($tarball.Name)"
      }
      if ($dependencies.Contains($manifest.name)) { throw "tarball 包名重复：$($manifest.name)" }
      $relativeTarball = [IO.Path]::GetRelativePath(
        $harnessRoot.FullName, $tarball.FullName).Replace('\', '/')
      $expectedPrefix = "../package-sources/$($group.Index.ToString('D2'))/"
      if (-not $relativeTarball.StartsWith($expectedPrefix, [StringComparison]::Ordinal) -or
        [IO.Path]::GetFileName($relativeTarball) -cne $tarball.Name) {
        throw '受保护 tarball 的相对路径越出预期发布组。'
      }
      $dependencies[$manifest.name] = "file:$relativeTarball"
      $expectedDeepseekVersions[$manifest.name] = $manifest.version
      $packageManifests += $manifest
      $tarballHash = (Get-FileHash -LiteralPath $tarball.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      $packageEvidence += [ordered]@{
        name = $manifest.name
        version = $manifest.version
        file = $tarball.Name
        sha256 = $tarballHash
        sourceGroup = $group.Index
      }
      $names += $manifest.name
    }
    $groupPackages[$group.Index] = $names
    $hasOrder = Assert-PublishOrder $group.Directory @($group.Files.Name)
    if ($hasOrder -ne ($null -ne $group.OrderPath)) {
      throw 'publish-order.txt 状态不一致。'
    }
  }

  $approvedRegistryDeepseekVersions = @{}
  $requiredRegistryDeepseekVersions = @{}
  foreach ($manifest in $packageManifests) {
    foreach ($dependencyKind in @('dependencies', 'optionalDependencies')) {
      $dependencyProperty = $manifest.PSObject.Properties[$dependencyKind]
      if ($null -eq $dependencyProperty -or $null -eq $dependencyProperty.Value) { continue }
      foreach ($dependency in $dependencyProperty.Value.PSObject.Properties) {
        if ($dependency.Name -notmatch '^@deepseek-ai/[a-z0-9._-]+$' -or
          $dependencies.Contains($dependency.Name)) {
          continue
        }
        $version = [string]$dependency.Value
        if ($version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
          throw "受保护输入声明的外部 DeepSeek 依赖必须固定精确版本：$($dependency.Name)"
        }
        if ($approvedRegistryDeepseekVersions.ContainsKey($dependency.Name) -and
          [string]$approvedRegistryDeepseekVersions[$dependency.Name] -cne $version) {
          throw "受保护输入对外部 DeepSeek 依赖声明了冲突版本：$($dependency.Name)"
        }
        $approvedRegistryDeepseekVersions[$dependency.Name] = $version
        if ($dependencyKind -eq 'dependencies') {
          $requiredRegistryDeepseekVersions[$dependency.Name] = $version
        }
      }
    }
  }

  $dshGroups = @($protectedGroups | Where-Object {
    $groupPackages[$_.Index] -contains '@deepseek-ai/dsh'
  })
  $vendorGroups = @($protectedGroups | Where-Object {
    $groupPackages[$_.Index] -contains '@deepseek-ai/cordis' -and
    $groupPackages[$_.Index] -contains '@deepseek-ai/schemastery'
  })
  $nativeSystemGroups = @($protectedGroups | Where-Object {
    $groupPackages[$_.Index] -contains '@deepseek-ai/node-addon-system'
  })
  if ($dshGroups.Count -ne 1 -or $vendorGroups.Count -ne 1 -or $nativeSystemGroups.Count -ne 1) {
    throw 'tarball 输入无法唯一识别 dsh、vendor 和 system native 发布族。'
  }
  $roleIndices = @($dshGroups[0].Index, $vendorGroups[0].Index, $nativeSystemGroups[0].Index)
  if (@($roleIndices | Sort-Object -Unique).Count -ne 3) {
    throw 'tarball 输入无法唯一识别 dsh、vendor 和 system native 发布族。'
  }
  $nativeSystemPackages = @($groupPackages[$nativeSystemGroups[0].Index])
  if ($null -eq $dshGroups[0].OrderPath -or $null -eq $vendorGroups[0].OrderPath -or
    $null -eq $nativeSystemGroups[0].OrderPath -or
    @($nativeSystemPackages | Where-Object {
      $_ -notmatch '^@deepseek-ai/node-addon-system(?:-[a-z0-9._-]+)?$'
    }).Count -ne 0) {
    throw '发布目录的 publish-order.txt 或 system native 包边界无效。'
  }
  $dshVersion = @($packageEvidence | Where-Object { $_.name -eq '@deepseek-ai/dsh' })[0].version
  $dshFamilyVersions = @($packageEvidence | Where-Object {
    $_.sourceGroup -eq $dshGroups[0].Index
  } | ForEach-Object { $_.version } | Sort-Object -Unique)
  if ($dshFamilyVersions.Count -ne 1 -or $dshFamilyVersions[0] -ne $dshVersion) {
    throw 'dsh 发布族不是同一版本。'
  }

  $installManifest = [ordered]@{
    name = 'dsh-bound-runtime-staging'
    version = '0.0.0'
    private = $true
    dependencies = $dependencies
  }
  $installManifestPath = Join-Path $harnessRoot.FullName 'package.json'
  [IO.File]::WriteAllText($installManifestPath,
    (($installManifest | ConvertTo-Json -Depth 5) + "`n"), [Text.UTF8Encoding]::new($false))
  $userConfig = Join-Path $stagingRoot 'empty-user.npmrc'
  $globalConfig = Join-Path $stagingRoot 'empty-global.npmrc'
  [IO.File]::WriteAllText($userConfig, '', [Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText($globalConfig, '', [Text.UTF8Encoding]::new($false))
  $npmCache = New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'npm-cache')
  $processEnvironmentRoot = New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'process-environment')
  $processAppData = New-Item -ItemType Directory -Path (Join-Path $processEnvironmentRoot.FullName 'appdata')
  $processLocalAppData = New-Item -ItemType Directory -Path (Join-Path $processEnvironmentRoot.FullName 'local-appdata')
  $processTemp = New-Item -ItemType Directory -Path (Join-Path $processEnvironmentRoot.FullName 'temp')
  $installEnvironment = @{
    DSH_TELEMETRY_DISABLED = '1'
    HOME = $processEnvironmentRoot.FullName
    USERPROFILE = $processEnvironmentRoot.FullName
    APPDATA = $processAppData.FullName
    LOCALAPPDATA = $processLocalAppData.FullName
    TEMP = $processTemp.FullName
    TMP = $processTemp.FullName
    NPM_CONFIG_USERCONFIG = $userConfig
    NPM_CONFIG_GLOBALCONFIG = $globalConfig
    NPM_CONFIG_CACHE = $npmCache.FullName
    NPM_CONFIG_REGISTRY = $registryUri.AbsoluteUri
  }
  $installArguments = @(
    $npmCli, 'install', '--no-audit', '--no-fund', '--package-lock=true',
    '--install-strategy=hoisted', '--registry', $registryUri.AbsoluteUri,
    '--userconfig', $userConfig, '--globalconfig', $globalConfig,
    '--ignore-scripts', '--omit=optional'
  )
  $install = Invoke-IsolatedNode $NodePath $harnessRoot.FullName $installArguments $installEnvironment $true
  if ($install.ExitCode -ne 0) {
    $diagnostic = Get-BoundedProcessDiagnostic $install
    $suffix = if ([string]::IsNullOrEmpty($diagnostic)) { '' } else { "`n$diagnostic" }
    throw "npm 安装失败，退出码：$($install.ExitCode)$suffix"
  }
  Assert-NoReparsePointsRecursively $harnessRoot.FullName

  $lockPath = Resolve-ExistingFile (Join-Path $harnessRoot.FullName 'package-lock.json') 'npm lockfile'
  try {
    $lock = [IO.File]::ReadAllText($lockPath, [Text.UTF8Encoding]::new($false, $true)) |
      ConvertFrom-Json -AsHashtable -ErrorAction Stop
  } catch {
    throw 'npm lockfile 无法作为严格 UTF-8 JSON 读取。'
  }
  if ($lock.lockfileVersion -lt 3 -or -not $lock.ContainsKey('packages')) {
    throw 'npm lockfile 缺少可审计的 packages 闭包。'
  }
  foreach ($entryPath in $lock.packages.Keys) {
    $normalized = ([string]$entryPath).Replace('\', '/')
    if ($normalized.Length -eq 0) { continue }
    $entry = $lock.packages[$entryPath]
    if ($normalized -match '^node_modules/(@deepseek-ai/[^/]+)$') {
      $packageName = $Matches[1]
      if ($expectedDeepseekVersions.ContainsKey($packageName)) {
        if ([string]$entry.version -cne [string]$expectedDeepseekVersions[$packageName] -or
          [string]$entry.resolved -cne [string]$dependencies[$packageName]) {
          throw "lockfile 未精确绑定受保护输入包：$packageName"
        }
        continue
      }
      if ($approvedRegistryDeepseekVersions.ContainsKey($packageName) -and
        [string]$entry.version -cne [string]$approvedRegistryDeepseekVersions[$packageName]) {
        throw "lockfile 未精确绑定受保护输入声明的外部 DeepSeek 依赖：$packageName"
      }
    }
    if ($entry.ContainsKey('inBundle') -and $entry.inBundle -eq $true) { continue }
    if (-not $entry.ContainsKey('resolved') -or $entry.resolved -isnot [string] -or
      -not $entry.ContainsKey('integrity') -or $entry.integrity -isnot [string] -or
      $entry.integrity -notmatch '^sha(?:256|384|512)-[A-Za-z0-9+/=]+') {
      throw "外部依赖缺少固定 HTTPS 来源或 integrity：$normalized"
    }
    try { $resolvedUri = [Uri]$entry.resolved } catch {
      throw "外部依赖来源无效：$normalized"
    }
    if (-not $resolvedUri.IsAbsoluteUri -or $resolvedUri.Scheme -ne 'https' -or
      -not [string]::IsNullOrEmpty($resolvedUri.UserInfo) -or
      -not [string]::IsNullOrEmpty($resolvedUri.Query) -or
      -not [string]::IsNullOrEmpty($resolvedUri.Fragment) -or
      -not $resolvedUri.AbsoluteUri.StartsWith($registryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "外部依赖未绑定指定 HTTPS npm registry：$normalized"
    }
  }
  foreach ($entryPath in $lock.packages.Keys) {
    $normalized = ([string]$entryPath).Replace('\', '/')
    if ($normalized -match '(?:^|/)node_modules/(@deepseek-ai/[^/]+)$') {
      $packageName = $Matches[1]
      $installedEntryManifest = Join-Path $harnessRoot.FullName (
        $normalized.Replace('/', '\') + '\package.json')
      if ((Test-Path -LiteralPath $installedEntryManifest -PathType Leaf) -and
        -not $dependencies.Contains($packageName) -and
        -not $approvedRegistryDeepseekVersions.ContainsKey($packageName)) {
        throw "安装闭包混入未由输入 tarball 声明的 DeepSeek 包：$packageName"
      }
    }
  }
  $installedDeepseekVersions = @{}
  foreach ($manifestFile in Get-ChildItem -LiteralPath (Join-Path $harnessRoot.FullName 'node_modules') `
      -File -Filter 'package.json' -Force -Recurse) {
    $relativeManifest = [IO.Path]::GetRelativePath(
      $harnessRoot.FullName, $manifestFile.FullName).Replace('\', '/')
    if ($relativeManifest -notmatch '(?:^|/)node_modules/@deepseek-ai/([^/]+)/package\.json$') {
      continue
    }
    try {
      $installedManifest = [IO.File]::ReadAllText(
        $manifestFile.FullName, [Text.UTF8Encoding]::new($false, $true)) |
        ConvertFrom-Json -AsHashtable -ErrorAction Stop
    } catch {
      throw "已安装 DeepSeek 包清单无效：$relativeManifest"
    }
    $expectedName = "@deepseek-ai/$($Matches[1])"
    $expectedVersion = if ($expectedDeepseekVersions.ContainsKey($expectedName)) {
      [string]$expectedDeepseekVersions[$expectedName]
    } elseif ($approvedRegistryDeepseekVersions.ContainsKey($expectedName)) {
      [string]$approvedRegistryDeepseekVersions[$expectedName]
    } else {
      $null
    }
    if ([string]$installedManifest.name -cne $expectedName -or
      $null -eq $expectedVersion -or
      [string]$installedManifest.version -cne $expectedVersion) {
      throw "实际安装的 DeepSeek 包不属于受保护输入闭包：$relativeManifest"
    }
    $lockEntry = $relativeManifest.Substring(0, $relativeManifest.Length - '/package.json'.Length)
    if ($lockEntry -cne "node_modules/$expectedName" -or
      -not $lock.packages.ContainsKey($lockEntry)) {
      throw "实际安装的 DeepSeek 包未写入 lockfile：$relativeManifest"
    }
    $installedDeepseekVersions[$expectedName] = $installedManifest.version
  }
  foreach ($packageName in $dependencies.Keys) {
    $installedManifest = Join-Path $harnessRoot.FullName (
      'node_modules\' + $packageName.Replace('/', '\') + '\package.json')
    Resolve-ExistingFile $installedManifest "已安装包 $packageName" | Out-Null
    if (-not $installedDeepseekVersions.ContainsKey($packageName)) {
      throw "受保护输入包未出现在实际安装闭包：$packageName"
    }
  }
  foreach ($packageName in $requiredRegistryDeepseekVersions.Keys) {
    if (-not $installedDeepseekVersions.ContainsKey($packageName)) {
      throw "受保护输入声明的必要外部 DeepSeek 依赖未出现在实际安装闭包：$packageName"
    }
  }

  $installedPackage = Join-Path $harnessRoot.FullName 'node_modules\@deepseek-ai\dsh'
  $installedCli = Resolve-ExistingFile (Join-Path $installedPackage 'lib\bin.js') '已安装 Harness CLI'
  $versionProbe = Invoke-IsolatedNode $NodePath $harnessRoot.FullName @($installedCli, '--version') @{
    DSH_HOME = (Join-Path $stagingRoot 'probe-home')
    DSH_TELEMETRY_DISABLED = '1'
  } $true
  if ($versionProbe.ExitCode -ne 0 -or
    $versionProbe.Stdout.Trim() -ne $dshVersion) {
    throw '安装后的 Harness CLI 未通过版本烟测。'
  }
  $harnessVersion = $versionProbe.Stdout.Trim()

  $cliTarget = New-Item -ItemType Directory -Path (Join-Path $harnessRoot.FullName 'apps\cli') -Force
  Get-ChildItem -LiteralPath $installedPackage -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $cliTarget.FullName -Recurse -Force
  }
  $portableCli = Resolve-ExistingFile (Join-Path $cliTarget.FullName 'lib\bin.js') '可移植 Harness CLI'
  Copy-Item -LiteralPath $NodePath -Destination (Join-Path $nodeRoot.FullName 'node.exe')
  if ((Get-FileHash -LiteralPath (Join-Path $nodeRoot.FullName 'node.exe') -Algorithm SHA256).Hash.ToLowerInvariant() `
    -ne $sourceNodeHash) {
    throw '复制后的 Node.js 与源文件摘要不一致。'
  }
  foreach ($name in @(
      'start-bound-harness.ps1', 'windows-private-path-gate.ps1',
      'harness-registry-connection.example.patch.yml',
      'harness-production-publication.example.patch.yml'
    )) {
    $sourcePath = Resolve-ExistingFile (Join-Path $PSScriptRoot $name) "启动文件 $name"
    Assert-NoUnauthorizedWriteAcl $sourcePath "启动文件 $name" $false
    $beforeHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $destinationPath = Join-Path $launcherRoot.FullName $name
    Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
    $copiedHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $afterHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($beforeHash -ne $copiedHash -or $beforeHash -ne $afterHash) {
      throw "复制期间启动文件发生变化：$name"
    }
  }

  foreach ($path in @(
      $installManifestPath, $userConfig, $globalConfig,
      (Join-Path $harnessRoot.FullName 'node_modules\.package-lock.json')
    )) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
  }
  Move-Item -LiteralPath $lockPath -Destination (Join-Path $stagingRoot 'runtime-package-lock.json')
  Remove-StagingDirectory $npmCache.FullName $stagingRoot 'npm-cache'
  Remove-StagingDirectory $processEnvironmentRoot.FullName $stagingRoot 'process-environment'

  $probeHome = New-Item -ItemType Directory -Path (Join-Path $stagingRoot 'probe-home')
  $composition = Invoke-IsolatedNode (Join-Path $nodeRoot.FullName 'node.exe') $probeHome.FullName @(
    $portableCli, '--profile', 'web', '--patch',
    (Join-Path $launcherRoot.FullName 'harness-registry-connection.example.patch.yml'),
    '--dump-config'
  ) @{
    DSH_HOME = $probeHome.FullName
    DSH_TELEMETRY_DISABLED = '1'
    DSH_REGISTRY_ORGANIZATION_ID = 'runtime-preparation-organization'
    DSH_INSTANCE_ID = 'runtime-preparation-instance'
    DSH_REGISTRY_SYNC_URL = 'wss://registry.invalid/a2a/v1/sync'
  } $true
  if ($composition.ExitCode -ne 0) { throw '可移植 Harness 未通过 connection-only 配置合成烟测。' }
  Assert-ConnectionOnlyComposition $composition.Stdout
  $validatedModes = @('ConnectionOnly')
  if ($RuntimeMode -eq 'Production') {
    $productionComposition = Invoke-IsolatedNode (Join-Path $nodeRoot.FullName 'node.exe') `
      $probeHome.FullName @(
        $portableCli, '--profile', 'web', '--patch',
        (Join-Path $launcherRoot.FullName 'harness-production-publication.example.patch.yml'),
        '--dump-config'
      ) @{
        DSH_HOME = $probeHome.FullName
        DSH_TELEMETRY_DISABLED = '1'
        DSH_REGISTRY_ORGANIZATION_ID = 'runtime-preparation-organization'
        DSH_INSTANCE_ID = 'runtime-preparation-instance'
        DSH_REGISTRY_SYNC_URL = 'wss://registry.invalid/a2a/v1/sync'
        DSH_REGISTRY_DISCLOSURE_BRIDGE_URL = 'https://registry.invalid/a2a/v1/disclosure-publication'
        DSH_DISCLOSURE_STATE_PATH = (Join-Path $probeHome.FullName 'disclosures')
      } $true
    if ($productionComposition.ExitCode -ne 0) {
      throw '可移植 Harness 未通过 production publication/import/question 配置合成烟测。'
    }
    Assert-ProductionComposition $productionComposition.Stdout
    $validatedModes += 'Production'
  }
  Remove-StagingDirectory $probeHome.FullName $stagingRoot 'probe-home'

  $evidencePath = Join-Path $stagingRoot 'runtime-build.json'
  $evidence = [ordered]@{
    schemaVersion = 2
    harnessVersion = $harnessVersion
    nodeVersion = $nodeVersion[0]
    runtimeMode = $RuntimeMode
    validatedModes = $validatedModes
    lifecycleScripts = $false
    optionalDependenciesInstalled = $false
    credentialInputs = 'external-at-launch'
    createdAt = [DateTime]::UtcNow.ToString('o')
    packages = $packageEvidence
    registryDeepseekDependencies = @($approvedRegistryDeepseekVersions.Keys | Sort-Object | ForEach-Object {
      [ordered]@{
        name = $_
        version = $approvedRegistryDeepseekVersions[$_]
        required = $requiredRegistryDeepseekVersions.ContainsKey($_)
      }
    })
  }
  [IO.File]::WriteAllText($evidencePath, (($evidence | ConvertTo-Json -Depth 6) + "`n"),
    [Text.UTF8Encoding]::new($false))
  Remove-StagingDirectory $packageSourcesRoot.FullName $stagingRoot 'package-sources'
  if ((Get-FileHash -LiteralPath $NodePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceNodeHash) {
    throw '准备期间源 Node.js 发生变化。'
  }

  Assert-NoReparsePointsRecursively $stagingRoot
  Protect-Directory $stagingRoot
  foreach ($protectedRoot in @($harnessRoot.FullName, $nodeRoot.FullName, $launcherRoot.FullName)) {
    Protect-Directory $protectedRoot $false
  }
  Assert-PrivateAcl $stagingRoot '运行包根目录' $true $true
  Assert-NoUnauthorizedWriteAcl $stagingRoot '运行包根目录' $true
  Assert-NoUnauthorizedWriteAcl $harnessRoot.FullName 'HarnessRoot' $true
  Assert-NoUnauthorizedWriteAcl $nodeRoot.FullName 'Node.js 目录' $true
  Assert-NoUnauthorizedWriteAcl $launcherRoot.FullName '启动器目录' $true
  Assert-NoUnauthorizedWriteAcl (Join-Path $harnessRoot.FullName 'apps\cli\lib\bin.js') 'Harness CLI' $false
  Assert-NoUnauthorizedWriteAcl (Join-Path $nodeRoot.FullName 'node.exe') 'Node.js' $false
  $hashManifest = Join-Path $stagingRoot 'runtime-files.sha256'
  Write-HashManifest $stagingRoot $hashManifest

  $moveAttempt = 0
  while ($true) {
    try {
      [IO.Directory]::Move($stagingRoot, $DestinationRoot)
      break
    } catch [UnauthorizedAccessException], [IO.IOException] {
      $moveAttempt += 1
      if ($moveAttempt -ge 20 -or (Test-Path -LiteralPath $DestinationRoot)) { throw }
      Start-Sleep -Milliseconds 500
    }
  }
  if (-not (Test-Path -LiteralPath $DestinationRoot -PathType Container) -or
    (Test-Path -LiteralPath $stagingRoot)) {
    throw '运行包原子发布后的目录状态无效。'
  }
} catch {
  $failure = $_
  try {
    Remove-StagingDirectory $stagingRoot $destinationParent $stagingName
  } catch {
    [Console]::Error.WriteLine("警告：本次临时目录未能自动清理：$stagingRoot")
  }
  throw $failure
}

Write-Output 'bound-harness-runtime: 受保护运行包已准备完成。'
Write-Output "root: $DestinationRoot"
Write-Output "HarnessRoot: $(Join-Path $DestinationRoot 'harness')"
Write-Output "NodePath: $(Join-Path $DestinationRoot 'node\node.exe')"
Write-Output "launcher: $(Join-Path $DestinationRoot 'launcher\start-bound-harness.ps1')"
Write-Output "Harness version: $harnessVersion"
Write-Output "Node version: $($nodeVersion[0])"
Write-Output "Runtime mode: $RuntimeMode"
Write-Output "hash manifest: $(Join-Path $DestinationRoot 'runtime-files.sha256')"
