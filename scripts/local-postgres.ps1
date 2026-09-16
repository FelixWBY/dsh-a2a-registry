param([ValidateSet('Prepare', 'Start', 'Stop', 'Status', 'Backup')][string]$Action = 'Start')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$private = Join-Path $root '.artifacts\postgres\private'
$compose = Join-Path $root 'deploy\postgres\compose.yaml'

if ($Action -in @('Prepare', 'Start')) {
  New-Item -ItemType Directory -Path $private -Force | Out-Null
  # Secrets stay local and are readable only by this user and Windows administrators.
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls.exe $private /inheritance:r /grant:r "*$($identity):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot secure the local secrets directory.' }
  $adminFile = Join-Path $private 'admin-password'
  $appFile = Join-Path $private 'app-password'
  if ((Test-Path $adminFile) -xor (Test-Path $appFile)) {
    throw 'One password file is missing. Restore the original credentials; do not regenerate against an existing volume.'
  }
  if (-not (Test-Path $adminFile)) {
    # Fail closed if an existing data volume could outlive missing local secrets.
    $dockerCommand = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($dockerCommand) {
      & docker.exe --context desktop-linux info --format '{{.ServerVersion}}' 2>$null | Out-Null
      if ($LASTEXITCODE -eq 0) {
        $volumes = & docker.exe --context desktop-linux volume ls --format '{{.Name}}'
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect existing volumes.' }
        if ($volumes -contains 'dsh-registry-postgres-data') { throw 'Database volume already exists. Restore its password files from backup.' }
      }
    }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
      foreach ($file in @($adminFile, $appFile)) {
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        $password = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
        [IO.File]::WriteAllText($file, $password, (New-Object Text.UTF8Encoding $false))
      }
    } finally { $rng.Dispose() }
  }
  $appPassword = [IO.File]::ReadAllText($appFile).Trim()
  $urlFile = Join-Path $private 'connection.env'
  [IO.File]::WriteAllText($urlFile, "DATABASE_URL=postgresql://registry_app:$appPassword@127.0.0.1:5432/registry`n", (New-Object Text.UTF8Encoding $false))
  Write-Host 'Local credentials prepared; not printed or loaded into Registry automatically.'
  if ($Action -eq 'Prepare') { exit 0 }
}

if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
  $dockerCandidates = @(
    "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe",
    'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
  )
  $dockerPath = $dockerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $dockerPath) { throw 'Docker Desktop is not installed. Install it, restart Windows if requested, and start Docker Desktop.' }
  $env:PATH = "$(Split-Path -Parent $dockerPath);$env:PATH"
}
# Never operate on a remote Docker context selected elsewhere by the user.
$dockerArgs = @('--context', 'desktop-linux', 'compose', '-f', $compose)
& docker.exe --context desktop-linux info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'The local Docker Desktop Linux engine is not ready. Start Docker Desktop after the required Windows restart.' }

switch ($Action) {
  'Start' {
    & docker.exe @dockerArgs up -d --wait --wait-timeout 120
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL failed to start. Check Docker Desktop and compose logs; do not delete the data volume.' }
    'SELECT current_database(), current_user, current_schema();' | & docker.exe @dockerArgs exec -T postgres sh -c 'export PGPASSWORD=$(cat /run/secrets/postgres_app_password); exec psql -h 127.0.0.1 -U registry_app -d registry -v ON_ERROR_STOP=1'
    if ($LASTEXITCODE -ne 0) { throw 'Application login verification failed.' }
    Write-Host 'PostgreSQL ready at 127.0.0.1:5432. Start Registry with deploy/registry/registry-postgres.example.patch.yml.'
  }
  'Stop' {
    & docker.exe @dockerArgs stop
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL stop failed.' }
  }
  'Status' {
    & docker.exe @dockerArgs ps
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL status failed.' }
  }
  'Backup' {
    $destination = Join-Path $root '.artifacts\postgres-backups'
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $name = 'registry-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N') + '.dump'
    & docker.exe @dockerArgs exec -T postgres pg_dump -U postgres -d registry -Fc -f "/tmp/$name"
    if ($LASTEXITCODE -ne 0) { throw 'Database backup failed.' }
    & docker.exe @dockerArgs cp "postgres:/tmp/$name" (Join-Path $destination $name)
    if ($LASTEXITCODE -ne 0) { throw 'Backup copy failed; dump remains inside the container.' }
    & docker.exe @dockerArgs exec -T postgres rm -- "/tmp/$name"
    if ($LASTEXITCODE -ne 0) { throw 'Backup copied, but temporary dump cleanup failed.' }
    Write-Host "Backup saved: $(Join-Path $destination $name)"
  }
}
