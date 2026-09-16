# Run elevated. Enables prerequisites only; never restarts Windows.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root '.artifacts\docker-setup'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$results = @()
try {
  foreach ($name in @('VirtualMachinePlatform', 'Microsoft-Windows-Subsystem-Linux')) {
    $before = Get-WindowsOptionalFeature -Online -FeatureName $name
    $restart = $false
    if ($before.State -eq 'Disabled') {
      $enabled = Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart
      $restart = $enabled.RestartNeeded
    }
    $after = Get-WindowsOptionalFeature -Online -FeatureName $name
    $results += @{ feature = $name; before = $before.State.ToString(); after = $after.State.ToString(); restartNeeded = $restart }
    $results | ConvertTo-Json | Set-Content (Join-Path $logs 'windows-features-result.json') -Encoding utf8
  }
} catch {
  $_.Exception.Message | Set-Content (Join-Path $logs 'windows-features-error.log') -Encoding utf8
  exit 1
}
