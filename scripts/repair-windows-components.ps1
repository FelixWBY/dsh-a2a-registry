# Requires explicit user approval and an elevated PowerShell session.
# Repairs the online component store only. Never reboots, resets Docker or edits boot settings.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root '.artifacts\docker-setup'
$run = Join-Path $logs ('windows-repair-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $run -Force | Out-Null
$statusFile = Join-Path $logs 'windows-repair-status.json'
$status = @{ state = 'running'; startedAt = (Get-Date).ToString('o'); logDirectory = $run; automaticReboot = $false; processId = $PID }
$status | ConvertTo-Json | Set-Content -LiteralPath $statusFile -Encoding utf8
try {
  $process = Start-Process -FilePath "$env:SystemRoot\System32\dism.exe" `
    -ArgumentList '/English','/Online','/Cleanup-Image','/RestoreHealth','/NoRestart',"/LogPath:$run\dism.log" `
    -WindowStyle Hidden -Wait -PassThru `
    -RedirectStandardOutput (Join-Path $run 'stdout.log') `
    -RedirectStandardError (Join-Path $run 'stderr.log')
  $status.exitCode = $process.ExitCode
  $status.completedAt = (Get-Date).ToString('o')
  if ($process.ExitCode -notin @(0, 3010)) {
    $status.state = 'failed'
  } else {
    $health = Repair-WindowsImage -Online -CheckHealth
    $status.health = $health.ImageHealthState.ToString()
    $status.restartNeeded = ($process.ExitCode -eq 3010 -or $health.RestartNeeded)
    $status.hypervisorPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    $status.vmcomputePresent = [bool](Get-Service vmcompute -ErrorAction SilentlyContinue)
    $status.state = if ($status.health -eq 'Healthy') { 'completed' } else { 'repair-not-confirmed' }
  }
  $status | ConvertTo-Json | Set-Content -LiteralPath $statusFile -Encoding utf8
  exit $process.ExitCode
} catch {
  $status.state = 'failed'
  $status.error = $_.Exception.Message
  $status.completedAt = (Get-Date).ToString('o')
  $status | ConvertTo-Json | Set-Content -LiteralPath $statusFile -Encoding utf8
  exit 1
}
