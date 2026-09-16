param(
  [string]$KeycloakPath = '',
  [string]$NodePath = '',
  [switch]$RegistryOnly
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$artifactRoot = Join-Path $repositoryRoot '.artifacts\registry-oidc-local'
$privateConfigPath = Join-Path $artifactRoot 'private-runtime.json'
if ($KeycloakPath -eq '') { $KeycloakPath = Join-Path $repositoryRoot '.artifacts\keycloak-26.7.3' }
if ($NodePath -eq '') {
  $NodePath = (Get-Command node -ErrorAction Stop).Source
  if ((& $NodePath -p "Number(process.versions.node.split('.')[0])") -lt 24) {
    $NodePath = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages\OpenJS.NodeJS.LTS_*') `
      -Filter node.exe -Recurse -File -ErrorAction SilentlyContinue `
      | Where-Object { (& $_.FullName -p "Number(process.versions.node.split('.')[0])") -ge 24 } `
      | Select-Object -Last 1 -ExpandProperty FullName
  }
}
$javaHome = $env:JAVA_HOME
if ([string]::IsNullOrWhiteSpace($javaHome)) {
  throw 'Java 21 was not found; set JAVA_HOME before starting the local OIDC stack'
}
if ((Split-Path -Leaf $javaHome) -eq 'bin' -and (Test-Path -LiteralPath (Join-Path $javaHome 'java.exe'))) {
  $javaHome = Split-Path -Parent $javaHome
}

function New-Secret([int]$bytes) {
  return [Convert]::ToBase64String(
    [Security.Cryptography.RandomNumberGenerator]::GetBytes($bytes)
  ).TrimEnd('=').Replace('+', '-').Replace('/', '_')
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

foreach ($port in @($(if ($RegistryOnly) { 3181 } else { 3181, 3182 }))) {
  if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    throw "TCP port $port is already in use"
  }
}

if (-not (Test-Path -LiteralPath (Join-Path $KeycloakPath 'bin\kc.bat'))) {
  throw "Keycloak was not found at $KeycloakPath"
}
if ($null -eq $NodePath -or -not (Test-Path -LiteralPath $NodePath)) {
  throw 'Node.js 24 or newer was not found; pass -NodePath with its absolute node.exe path'
}
if ((& $NodePath -p "Number(process.versions.node.split('.')[0])") -lt 24) {
  throw 'Node.js 24 or newer was not found; pass -NodePath with its absolute node.exe path'
}
if (-not (Test-Path -LiteralPath (Join-Path $javaHome 'bin\java.exe'))) {
  throw "Java 21 was not found at $javaHome"
}

New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $artifactRoot 'home') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $artifactRoot 'storage') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $KeycloakPath 'data\import') -Force | Out-Null

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
  $privateConfig | ConvertTo-Json | Set-Content -LiteralPath $privateConfigPath -Encoding utf8NoBOM
}

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'keycloak-local-realm.example.json') `
  -Destination (Join-Path $KeycloakPath 'data\import\dsh-local-realm.json') -Force

$env:KC_BOOTSTRAP_ADMIN_USERNAME = $privateConfig.adminUsername
$env:KC_BOOTSTRAP_ADMIN_PASSWORD = $privateConfig.adminPassword
$env:JAVA_HOME = $javaHome
$env:DSH_LOCAL_OIDC_CLIENT_SECRET = $privateConfig.clientSecret
$env:DSH_LOCAL_OIDC_USER_PASSWORD = $privateConfig.password
$env:DSH_LOCAL_REGISTRY_ORIGIN = 'http://127.0.0.1:3181'

$keycloak = $null
if (-not $RegistryOnly) {
  $keycloak = Start-Process -FilePath (Join-Path $KeycloakPath 'bin\kc.bat') `
    -ArgumentList @('start-dev', '--http-host=127.0.0.1', '--http-port=3182', '--import-realm', '--health-enabled=true') `
    -WorkingDirectory $KeycloakPath `
    -RedirectStandardOutput (Join-Path $artifactRoot 'keycloak.stdout.log') `
    -RedirectStandardError (Join-Path $artifactRoot 'keycloak.stderr.log') `
    -WindowStyle Hidden -PassThru
}

$registry = $null
try {
  Wait-Http 'http://127.0.0.1:3182/realms/dsh-local/.well-known/openid-configuration'

  $env:DSH_HOME = Join-Path $artifactRoot 'home'
  $env:DSH_LOCAL_REGISTRY_STORAGE = Join-Path $artifactRoot 'storage'
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
  if ($null -ne $keycloak -and -not $keycloak.HasExited) { Stop-Process -Id $keycloak.Id }
  throw
}

[pscustomobject]@{
  keycloakPid = (Get-NetTCPConnection -LocalPort 3182 -State Listen).OwningProcess
  registryPid = $registry.Id
  issuer = 'http://127.0.0.1:3182/realms/dsh-local'
  registry = 'http://127.0.0.1:3181/#/sign-in'
  username = $privateConfig.username
  password = $privateConfig.password
  privateConfig = $privateConfigPath
} | ConvertTo-Json
