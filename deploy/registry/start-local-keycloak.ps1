param(
  [string]$NodePath = '',
  [switch]$RegistryOnly,
  [switch]$UpgradeDatabase
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifactRoot = Join-Path $repositoryRoot '.artifacts\registry-oidc-local'
$privateConfigPath = Join-Path $artifactRoot 'private-runtime.json'
$tlsDataPath = Join-Path $artifactRoot 'caddy-data'
$caCertificatePath = Join-Path $tlsDataPath 'caddy\pki\authorities\local\root.crt'
$postgresConfigPath = Join-Path $repositoryRoot '.artifacts\postgres\private\connection.env'
$postgresComposePath = Join-Path $repositoryRoot 'deploy\postgres\compose.yaml'
$roleSplitPath = Join-Path $repositoryRoot 'deploy\postgres\split-registry-runtime-role.sql'
$composePath = Join-Path $PSScriptRoot 'keycloak-local.compose.yaml'
if ($NodePath -eq '') {
  $NodePath = (Get-Command node -ErrorAction Stop).Source
  if ((& $NodePath -p "Number(process.versions.node.split('.')[0])") -lt 24) {
    $NodePath = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages\OpenJS.NodeJS.LTS_*') `
      -Filter node.exe -Recurse -File -ErrorAction SilentlyContinue `
      | Where-Object { (& $_.FullName -p "Number(process.versions.node.split('.')[0])") -ge 24 } `
      | Select-Object -Last 1 -ExpandProperty FullName
  }
}
function New-Secret([int]$bytes) {
  $buffer = New-Object byte[] $bytes
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($buffer)
    return [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  } finally {
    $rng.Dispose()
    [Array]::Clear($buffer, 0, $buffer.Length)
  }
}

function Wait-Http([string]$uri, [int]$attempts = 60) {
  for ($attempt = 0; $attempt -lt $attempts; $attempt += 1) {
    try {
      $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri $uri
      if ($response.StatusCode -eq 200) { return }
    } catch {
      # Startup is expected to refuse connections until the service is ready.
    }
    Start-Sleep -Seconds 1
  }
  throw "Service did not become ready: $uri"
}

function Wait-File([string]$path, [int]$attempts = 60) {
  for ($attempt = 0; $attempt -lt $attempts; $attempt += 1) {
    if ((Test-Path -LiteralPath $path -PathType Leaf) -and (Get-Item -LiteralPath $path).Length -gt 0) {
      return
    }
    Start-Sleep -Seconds 1
  }
  throw "Service did not create the expected file: $path"
}

function Wait-Https([string]$uri, [string]$caCertificate, [int]$attempts = 60) {
  for ($attempt = 0; $attempt -lt $attempts; $attempt += 1) {
    # The local Caddy CA has no public CRL. Schannel still validates its chain and hostname,
    # while --ssl-no-revoke prevents an unrelated online revocation lookup from failing closed.
    & curl.exe --silent --fail --ssl-no-revoke --cacert $caCertificate `
      --noproxy localhost --output NUL $uri 2>$null
    if ($LASTEXITCODE -eq 0) { return }
    Start-Sleep -Seconds 1
  }
  throw "TLS service did not become ready: $uri"
}

function Enable-SelfRegistration([string]$username, [string]$password) {
  $token = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:3182/realms/master/protocol/openid-connect/token' `
    -ContentType 'application/x-www-form-urlencoded' `
    -Body @{ client_id = 'admin-cli'; grant_type = 'password'; username = $username; password = $password }
  if ($null -eq $token.access_token) { throw 'Cannot authenticate the local Keycloak administrator' }
  try {
    Invoke-RestMethod -Method Put -Uri 'http://127.0.0.1:3182/admin/realms/dsh-local' `
      -Headers @{ Authorization = "Bearer $($token.access_token)" } -ContentType 'application/json' `
      -Body '{"registrationAllowed":true}' | Out-Null
  } finally {
    $token = $null
  }
}

if (Get-NetTCPConnection -LocalPort 3181 -State Listen -ErrorAction SilentlyContinue) {
  throw 'TCP port 3181 is already in use'
}
if ($UpgradeDatabase -and (Get-NetTCPConnection -LocalPort 3081 -State Listen -ErrorAction SilentlyContinue)) {
  throw 'Database upgrade requires the Registry processes on ports 3081 and 3181 to be stopped'
}

if ($null -eq $NodePath -or -not (Test-Path -LiteralPath $NodePath)) {
  throw 'Node.js 24 or newer was not found; pass -NodePath with its absolute node.exe path'
}
if ((& $NodePath -p "Number(process.versions.node.split('.')[0])") -lt 24) {
  throw 'Node.js 24 or newer was not found; pass -NodePath with its absolute node.exe path'
}
if (-not (Test-Path -LiteralPath $postgresConfigPath)) {
  throw 'Local PostgreSQL is not prepared; run scripts/local-postgres.ps1 Start first'
}
$databaseUrlLine = Get-Content -LiteralPath $postgresConfigPath `
  | Where-Object { $_.StartsWith('DATABASE_URL=') } | Select-Object -First 1
$migratorUrlLine = Get-Content -LiteralPath $postgresConfigPath `
  | Where-Object { $_.StartsWith('DSH_REGISTRY_POSTGRES_MIGRATOR_URL=') } | Select-Object -First 1
if ($null -eq $databaseUrlLine -or $databaseUrlLine.Length -le 'DATABASE_URL='.Length) {
  throw 'Local PostgreSQL connection configuration is unavailable'
}
if ($UpgradeDatabase -and ($null -eq $migratorUrlLine `
  -or $migratorUrlLine.Length -le 'DSH_REGISTRY_POSTGRES_MIGRATOR_URL='.Length)) {
  throw 'Local PostgreSQL migrator configuration is unavailable; run scripts/local-postgres.ps1 Start'
}
if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
  $dockerCandidates = @(
    "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe",
    'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
  )
  $dockerPath = $dockerCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $dockerPath) { throw 'Docker Desktop is required for the local OIDC stack' }
  $env:PATH = "$(Split-Path -Parent $dockerPath);$env:PATH"
}
& docker.exe --context desktop-linux info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'The local Docker Desktop Linux engine is not ready' }
if ($UpgradeDatabase) {
  & docker.exe --context desktop-linux compose -f $postgresComposePath exec -T postgres `
    psql -U postgres -d registry -v ON_ERROR_STOP=1 `
    -c 'CREATE SCHEMA IF NOT EXISTS registry_saas_local AUTHORIZATION registry_migrator' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the isolated local SaaS PostgreSQL schema' }
  $roleSplitSql = Get-Content -LiteralPath $roleSplitPath -Raw
  $roleSplitSql | & docker.exe --context desktop-linux compose -f $postgresComposePath exec -T postgres `
    psql -U postgres -d registry -v ON_ERROR_STOP=1 --set=target_schema=registry_saas_local | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot separate local PostgreSQL migration and runtime ownership' }
  $env:DSH_REGISTRY_POSTGRES_MIGRATOR_URL = $migratorUrlLine.Substring(
    'DSH_REGISTRY_POSTGRES_MIGRATOR_URL='.Length)
  try {
    & $NodePath --import tsx/esm (Join-Path $PSScriptRoot 'migrate-postgres-schemas.mjs') `
      --schema registry_saas_local --execute --confirm-runtime-stopped | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Local PostgreSQL offline schema migration failed' }
  } finally {
    Remove-Item Env:\DSH_REGISTRY_POSTGRES_MIGRATOR_URL -ErrorAction SilentlyContinue
  }
  $roleSplitSql | & docker.exe --context desktop-linux compose -f $postgresComposePath exec -T postgres `
    psql -U postgres -d registry -v ON_ERROR_STOP=1 --set=target_schema=registry_saas_local | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot finalize local PostgreSQL runtime privileges' }
}
# Never let an operator's offline credential leak into the online Registry child process.
Remove-Item Env:\DSH_REGISTRY_POSTGRES_MIGRATOR_URL -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $artifactRoot 'home') -Force | Out-Null
New-Item -ItemType Directory -Path $tlsDataPath -Force | Out-Null
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $artifactRoot /inheritance:r /grant:r "*$($identity):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot secure the local OIDC artifacts directory' }

if (Test-Path -LiteralPath $privateConfigPath) {
  $privateConfig = Get-Content -LiteralPath $privateConfigPath -Raw | ConvertFrom-Json
} else {
  $privateConfig = [pscustomobject]@{
    adminUsername = 'dsh-local-admin'
    adminPassword = "Adm!$(New-Secret 18)"
    username = 'registry-owner'
    password = "Dsh!$(New-Secret 18)"
    clientSecret = New-Secret 32
    sessionSecret = New-Secret 48
  }
  [IO.File]::WriteAllText($privateConfigPath, ($privateConfig | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
}

$env:KC_BOOTSTRAP_ADMIN_USERNAME = $privateConfig.adminUsername
$env:KC_BOOTSTRAP_ADMIN_PASSWORD = $privateConfig.adminPassword
$env:DSH_LOCAL_OIDC_CLIENT_SECRET = $privateConfig.clientSecret
$env:DSH_LOCAL_OIDC_USER_PASSWORD = $privateConfig.password
$env:DSH_LOCAL_REGISTRY_ORIGIN = 'http://127.0.0.1:3181'
$env:DSH_LOCAL_CADDY_DATA = $tlsDataPath

$localStackStarted = $false
if (-not $RegistryOnly) {
  & docker.exe --context desktop-linux compose -f $composePath up -d
  if ($LASTEXITCODE -ne 0) { throw 'Local Keycloak and Caddy containers failed to start' }
  $localStackStarted = $true
}

$registry = $null
try {
  Wait-Http 'http://127.0.0.1:3182/realms/dsh-local/.well-known/openid-configuration'
  Wait-File $caCertificatePath
  Enable-SelfRegistration $privateConfig.adminUsername $privateConfig.adminPassword

  $env:DSH_HOME = Join-Path $artifactRoot 'home'
  $env:DSH_REGISTRY_POSTGRES_URL = $databaseUrlLine.Substring('DATABASE_URL='.Length)
  $env:DSH_LOCAL_REGISTRY_SESSION_SECRET = $privateConfig.sessionSecret
  $registry = Start-Process -FilePath $NodePath `
    -ArgumentList @('--import', 'tsx/esm', 'src/dsh.ts', '--profile', 'registry', '--patch', (Join-Path $PSScriptRoot 'registry-keycloak-local.example.patch.yml')) `
    -WorkingDirectory $repositoryRoot `
    -RedirectStandardOutput (Join-Path $artifactRoot 'registry.stdout.log') `
    -RedirectStandardError (Join-Path $artifactRoot 'registry.stderr.log') `
    -WindowStyle Hidden -PassThru

  Wait-Http 'http://127.0.0.1:3181/readyz'
  Wait-Https 'https://localhost:3183/readyz' $caCertificatePath
} catch {
  if ($null -ne $registry -and -not $registry.HasExited) { Stop-Process -Id $registry.Id }
  if ($localStackStarted) { & docker.exe --context desktop-linux compose -f $composePath stop | Out-Null }
  throw
}

[pscustomobject]@{
  keycloakContainer = (& docker.exe --context desktop-linux compose -f $composePath ps keycloak --format json | ConvertFrom-Json).Name
  caddyContainer = (& docker.exe --context desktop-linux compose -f $composePath ps caddy --format json | ConvertFrom-Json).Name
  registryPid = $registry.Id
  issuer = 'http://127.0.0.1:3182/realms/dsh-local'
  registry = 'http://127.0.0.1:3181/#/sign-in'
  sync = 'wss://localhost:3183/a2a/v1/sync'
  caCertificate = $caCertificatePath
  username = $privateConfig.username
  privateConfig = $privateConfigPath
} | ConvertTo-Json
