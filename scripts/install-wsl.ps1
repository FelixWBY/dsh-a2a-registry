# Run elevated by the setup workflow. Never reboots Windows automatically.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root '.artifacts\docker-setup'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
try {
  Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform |
    Select-Object FeatureName, @{ Name = 'State'; Expression = { $_.State.ToString() } } | ConvertTo-Json |
    Set-Content (Join-Path $logs 'wsl-feature-state.json') -Encoding utf8
  & bcdedit.exe /enum | Set-Content (Join-Path $logs 'boot-configuration.txt') -Encoding utf8
  $process = Start-Process -FilePath "$env:SystemRoot\System32\wsl.exe" `
    -ArgumentList '--install','--no-distribution' `
    -WindowStyle Hidden -Wait -PassThru `
    -RedirectStandardOutput (Join-Path $logs 'wsl-install.stdout.log') `
    -RedirectStandardError (Join-Path $logs 'wsl-install.stderr.log')
  @{ exitCode = $process.ExitCode; completedAt = (Get-Date).ToString('o'); automaticReboot = $false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logs 'wsl-install-result.json') -Encoding utf8
  exit $process.ExitCode
} catch {
  @{ error = $_.Exception.Message; automaticReboot = $false } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logs 'wsl-install-result.json') -Encoding utf8
  exit 1
}
