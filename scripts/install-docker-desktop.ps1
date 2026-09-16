# Official, pinned installer. Verifies size, SHA256 and Authenticode before running.
# Does not restart Windows or alter the machine's proxy settings.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$directory = Join-Path $root '.artifacts\docker-setup'
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$url = 'https://desktop.docker.com/win/main/amd64/239619/Docker%20Desktop%20Installer.exe'
$expectedHash = 'AC405B09942701770D581B173747FC1024CF0E6047CBE60F13D1DF85437311AC'
$total = 628014512L
$count = 16
$chunkSize = [long][Math]::Ceiling($total / $count)
$downloads = @()
$joins = @()
for ($i = 0; $i -lt $count; $i++) {
  $start = $i * $chunkSize
  $end = [Math]::Min($total - 1, $start + $chunkSize - 1)
  $file = Join-Path $directory "docker-part-$i.bin"
  if ((Test-Path $file) -and (Get-Item $file).Length -eq ($end - $start + 1)) { continue }
  $pieceSize = [long][Math]::Ceiling(($end - $start + 1) / 4)
  $pieces = @()
  for ($j = 0; $j -lt 4; $j++) {
    $pieceStart = $start + $j * $pieceSize
    $pieceEnd = [Math]::Min($end, $pieceStart + $pieceSize - 1)
    $piece = Join-Path $directory "docker-piece-$i-$j.bin"
    $pieces += $piece
    if ((Test-Path $piece) -and (Get-Item $piece).Length -eq ($pieceEnd - $pieceStart + 1)) { continue }
    $arguments = @('--fail', '--location', '--silent', '--show-error', '--retry', '2', '--retry-all-errors', '--connect-timeout', '20', '--max-time', '300', '--range', "$pieceStart-$pieceEnd", '--output', $piece, $url)
    $process = Start-Process curl.exe -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $directory "docker-piece-$i-$j.log")
    $downloads += @{ process = $process; file = $piece; size = ($pieceEnd - $pieceStart + 1) }
  }
  $joins += @{ file = $file; pieces = $pieces }
}
$failed = @()
foreach ($download in $downloads) {
  $download.process.WaitForExit()
  # Some Windows PowerShell versions lose ExitCode after WaitForExit; size plus
  # the mandatory full-file SHA256 below are the download acceptance criteria.
  if (-not (Test-Path $download.file) -or (Get-Item $download.file).Length -ne $download.size) { $failed += $download.file }
}
if ($failed.Count -gt 0) { throw 'Some download pieces are incomplete. Rerun to retry missing pieces.' }
foreach ($join in $joins) {
  $output = [IO.File]::Create($join.file)
  try {
    foreach ($piece in $join.pieces) {
      $inputFile = [IO.File]::OpenRead($piece)
      try { $inputFile.CopyTo($output) } finally { $inputFile.Dispose() }
    }
  } finally { $output.Dispose() }
}
$installer = Join-Path $directory 'DockerDesktop-verified.exe'
$stream = [IO.File]::Create($installer)
try {
  for ($i = 0; $i -lt $count; $i++) {
    $part = [IO.File]::OpenRead((Join-Path $directory "docker-part-$i.bin"))
    try { $part.CopyTo($stream) } finally { $part.Dispose() }
  }
} finally { $stream.Dispose() }
if ((Get-FileHash $installer -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Installer SHA256 mismatch; installation refused.' }
$signature = Get-AuthenticodeSignature $installer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Docker Inc') { throw 'Installer publisher verification failed; installation refused.' }
Write-Host 'Official Docker installer verified. Installing per-user with WSL 2 backend.'
$process = Start-Process $installer -ArgumentList 'install', '--user', '--quiet', '--accept-license', '--backend=wsl-2', '--no-windows-containers' -WindowStyle Hidden -Wait -PassThru
@{ exitCode = $process.ExitCode; completedAt = (Get-Date).ToString('o'); automaticReboot = $false } | ConvertTo-Json | Set-Content (Join-Path $directory 'docker-install-result.json') -Encoding utf8
if ($process.ExitCode -notin @(0, 3010)) { throw "Docker installer failed with exit code $($process.ExitCode)." }
Write-Host 'Docker Desktop installer completed. No automatic Windows restart was performed.'
