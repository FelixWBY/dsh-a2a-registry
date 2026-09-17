param(
  [string]$NodePath = '',
  [switch]$RegistryOnly
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifactRoot = Join-Path $repositoryRoot '.artifacts\registry-oidc-local'
$privateConfigPath = Join-Path $artifactRoot 'private-runtime.json'
$postgresConfigPath = Join-Path $repositoryRoot '.artifacts\postgres\private\connection.env'
$postgresComposePath = Join-Path $repositoryRoot 'deploy\postgres\compose.yaml'
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
if ($null -eq $databaseUrlLine -or $databaseUrlLine.Length -le 'DATABASE_URL='.Length) {
  throw 'Local PostgreSQL connection configuration is unavailable'
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
& docker.exe --context desktop-linux compose -f $postgresComposePath exec -T postgres `
  psql -U postgres -d registry -v ON_ERROR_STOP=1 `
  -c 'CREATE SCHEMA IF NOT EXISTS registry_saas_local AUTHORIZATION registry_app' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the isolated local SaaS PostgreSQL schema' }

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $artifactRoot 'home') -Force | Out-Null
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

$keycloakStarted = $false
if (-not $RegistryOnly) {
  & docker.exe --context desktop-linux compose -f $composePath up -d
  if ($LASTEXITCODE -ne 0) { throw 'Local Keycloak container failed to start' }
  $keycloakStarted = $true
}

$registry = $null
try {
  Wait-Http 'http://127.0.0.1:3182/realms/dsh-local/.well-known/openid-configuration'
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
} catch {
  if ($null -ne $registry -and -not $registry.HasExited) { Stop-Process -Id $registry.Id }
  if ($keycloakStarted) { & docker.exe --context desktop-linux compose -f $composePath stop | Out-Null }
  throw
}

[pscustomobject]@{
  keycloakContainer = (& docker.exe --context desktop-linux compose -f $composePath ps --format json | ConvertFrom-Json).Name
  registryPid = $registry.Id
  issuer = 'http://127.0.0.1:3182/realms/dsh-local'
  registry = 'http://127.0.0.1:3181/#/sign-in'
  username = $privateConfig.username
  privateConfig = $privateConfigPath
} | ConvertTo-Json
