# Elevated, read-only diagnostics. Does not enable features, repair Windows or reboot.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root '.artifacts\docker-setup'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
try {
  $features = foreach ($feature in @('VirtualMachinePlatform', 'Microsoft-Windows-Subsystem-Linux', 'Microsoft-Hyper-V-Hypervisor', 'HypervisorPlatform')) {
    $state = Get-WindowsOptionalFeature -Online -FeatureName $feature
    @{ feature = $feature; state = $state.State.ToString() }
  }
  $features | ConvertTo-Json | Set-Content (Join-Path $logs 'wsl-diagnostic-features.json') -Encoding utf8
  & bcdedit.exe /enum all | Set-Content (Join-Path $logs 'wsl-diagnostic-boot.txt') -Encoding utf8
  Get-WindowsPackage -Online | Where-Object { $_.PackageName -match 'VirtualMachinePlatform|HyperV-Hypervisor' } |
    Select-Object PackageName, @{ Name = 'State'; Expression = { $_.PackageState.ToString() } } |
    ConvertTo-Json | Set-Content (Join-Path $logs 'wsl-diagnostic-packages.json') -Encoding utf8
  Repair-WindowsImage -Online -CheckHealth | Select-Object @{ Name = 'ImageHealthState'; Expression = { $_.ImageHealthState.ToString() } }, RestartNeeded |
    ConvertTo-Json | Set-Content (Join-Path $logs 'wsl-diagnostic-health.json') -Encoding utf8
  @{ completedAt = (Get-Date).ToString('o'); readOnly = $true } |
    ConvertTo-Json | Set-Content (Join-Path $logs 'wsl-diagnostic-result.json') -Encoding utf8
} catch {
  $_.Exception.Message | Set-Content (Join-Path $logs 'wsl-diagnostic-error.log') -Encoding utf8
  exit 1
}
