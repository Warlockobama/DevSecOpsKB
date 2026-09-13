[CmdletBinding()]
param(
  [string]$Image = "codeberg.org/forgejo/forgejo:15.0.8",
  [string]$EvidenceDir = "",
  [switch]$KeepEvidence
)

$ErrorActionPreference = "Stop"
$moduleRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$suffix = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$containerName = "devsecopskb-demo-$suffix"
$volumeName = "devsecopskb-demo-$suffix"
$userName = "demo-$suffix"
$email = "$userName@example.invalid"

if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
  $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  $EvidenceDir = Join-Path $moduleRoot "out/demo-acceptance/$stamp"
}
$EvidenceDir = [IO.Path]::GetFullPath($EvidenceDir)

function Invoke-Docker {
  param([Parameter(Mandatory)][string[]]$Arguments)
  $output = & docker @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Docker command failed: $($output -join [Environment]::NewLine)"
  }
  return @($output)
}

function Wait-Forgejo {
  param([Parameter(Mandatory)][string]$BaseUrl)
  $deadline = (Get-Date).AddMinutes(2)
  do {
    try {
      $response = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/api/healthz" -TimeoutSec 3
      if ($response.StatusCode -eq 200) { return }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  } while ((Get-Date) -lt $deadline)
  throw "Disposable Forgejo did not become ready within two minutes."
}

$oldUrl = $env:E2E_FORGEJO_URL
$oldToken = $env:E2E_FORGEJO_TOKEN
$oldAcceptance = $env:DEMO_FORGEJO_ACCEPTANCE
$oldEvidence = $env:DEMO_EVIDENCE_DIR
$started = $false

try {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is required for the disposable Forgejo acceptance check."
  }
  Invoke-Docker @("version", "--format", "{{.Server.Version}}") | Out-Null
  Invoke-Docker @("volume", "create", $volumeName) | Out-Null
  Invoke-Docker @(
    "run", "--detach", "--name", $containerName,
    "--cpus", "3", "--memory", "1g",
    "--publish", "127.0.0.1::3000",
    "--volume", "${volumeName}:/data",
    "--env", "FORGEJO__database__DB_TYPE=sqlite3",
    "--env", "FORGEJO__security__INSTALL_LOCK=true",
    "--env", "FORGEJO__service__DISABLE_REGISTRATION=true",
    $Image
  ) | Out-Null
  $started = $true

  $portLine = (Invoke-Docker @("port", $containerName, "3000/tcp") | Select-Object -First 1).ToString()
  if ($portLine -notmatch ":(?<port>[0-9]+)$") {
    throw "Could not resolve the disposable Forgejo loopback port."
  }
  $baseUrl = "http://127.0.0.1:$($Matches.port)"
  Wait-Forgejo -BaseUrl $baseUrl

  Invoke-Docker @(
    "exec", "--user", "git", $containerName,
    "forgejo", "admin", "user", "create", "--admin",
    "--username", $userName, "--email", $email,
    "--random-password", "--must-change-password=false"
  ) | Out-Null
  $tokenOutput = Invoke-Docker @(
    "exec", "--user", "git", $containerName,
    "forgejo", "admin", "user", "generate-access-token",
    "--username", $userName, "--raw", "--scopes", "all"
  )
  $token = ($tokenOutput | Select-Object -Last 1).ToString().Trim()
  if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Forgejo did not return an access token."
  }

  New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
  $env:E2E_FORGEJO_URL = $baseUrl
  $env:E2E_FORGEJO_TOKEN = $token
  $env:DEMO_FORGEJO_ACCEPTANCE = "1"
  $env:DEMO_EVIDENCE_DIR = $EvidenceDir

  Push-Location $moduleRoot
  try {
    go test -tags=e2e ./internal/e2e/forgejo -run '^TestDemoArtifactToForgejo$' -count=1 -v -timeout 12m
    if ($LASTEXITCODE -ne 0) {
      throw "Disposable artifact-to-Forgejo acceptance failed."
    }
  } finally {
    Pop-Location
  }
  Write-Host "Portable input:     $EvidenceDir\accepted-run.json"
  Write-Host "Sanitized readback: $EvidenceDir\forgejo-readback.json"
}
finally {
  $env:E2E_FORGEJO_URL = $oldUrl
  $env:E2E_FORGEJO_TOKEN = $oldToken
  $env:DEMO_FORGEJO_ACCEPTANCE = $oldAcceptance
  $env:DEMO_EVIDENCE_DIR = $oldEvidence
  if ($started) {
    & docker rm --force $containerName 2>&1 | Out-Null
  }
  & docker volume rm --force $volumeName 2>&1 | Out-Null
  if (-not $KeepEvidence -and (Test-Path $EvidenceDir) -and -not (Test-Path (Join-Path $EvidenceDir "forgejo-readback.json"))) {
    Remove-Item -LiteralPath $EvidenceDir -Force -ErrorAction SilentlyContinue
  }
}
