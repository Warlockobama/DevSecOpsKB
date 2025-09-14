[CmdletBinding()]
param(
  [string]$ZapUrl = "http://127.0.0.1:8090",
  [string]$ApiKey = "kb-demo-$(Get-Date -UFormat %s)",
  [switch]$NoCompose
)

$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Write-Host "Using ZAP_API_KEY=$ApiKey" -ForegroundColor Cyan

if (-not $NoCompose) {
  Write-Host "Starting containers (ZAP + Juice Shop)…" -ForegroundColor Cyan
  $env:ZAP_API_KEY = $ApiKey
  Push-Location (Join-Path $root 'examples/compose')
  try {
    docker compose up -d | Out-Null
  } finally { Pop-Location }

  Write-Host "Waiting for Juice Shop…"
  for ($i=0; $i -lt 60; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:3000' -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Seconds 2 }
  }
  Write-Host "Waiting for ZAP…"
  for ($i=0; $i -lt 60; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -Uri "$ZapUrl/JSON/core/view/version/" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Seconds 2 }
  }
}

# Spider
Write-Host "Starting spider…" -ForegroundColor Cyan
$encTarget = [System.Web.HttpUtility]::UrlEncode('http://juice-shop:3000')
$scan = Invoke-RestMethod -Method Get -Uri "$ZapUrl/JSON/spider/action/scan/?apikey=$ApiKey&url=$encTarget&recurse=true"
$scanId = $scan.scan
for ($i=0; $i -lt 120; $i++) {
  $pct = (Invoke-RestMethod -Method Get -Uri "$ZapUrl/JSON/spider/view/status/?scanId=$scanId").status
  Write-Host "Spider $pct%"
  if ($pct -eq '100') { break }
  Start-Sleep -Seconds 2
}

# Active scan
Write-Host "Starting active scan…" -ForegroundColor Cyan
$asc = Invoke-RestMethod -Method Get -Uri "$ZapUrl/JSON/ascan/action/scan/?apikey=$ApiKey&url=$encTarget&recurse=true&inScopeOnly=false"
$aid = $asc.scan
for ($i=0; $i -lt 600; $i++) {
  $pct = (Invoke-RestMethod -Method Get -Uri "$ZapUrl/JSON/ascan/view/status/?scanId=$aid").status
  Write-Host "Active scan $pct%"
  if ($pct -eq '100') { break }
  Start-Sleep -Seconds 5
}

# Build artifacts
Write-Host "Building KB artifacts…" -ForegroundColor Cyan
Push-Location (Join-Path $root 'zap-kb')
try {
  New-Item -ItemType Directory -Force -Path 'out' | Out-Null
  $runId = "demo-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  go run ./cmd/zap-kb -format entities -out out/entities.json `
    -zap-url $ZapUrl -api-key $ApiKey -baseurl 'http://juice-shop:3000' `
    -include-traffic -traffic-scope first -traffic-max-bytes 2048 `
    -include-detection -detection-details summary `
    -scan-label $runId -site-label 'Juice Shop' -zap-base-url $ZapUrl `
    -redact cookies,auth `
    -run-out out/run.json

  go run ./cmd/zap-kb -format obsidian -entities-in out/entities.json -obsidian-dir kb-new/obsidian -zap-base-url $ZapUrl -scan-label $runId

  go run ./cmd/zap-kb -format both -out out/alerts.json -entities-in out/entities.json -zip-out out/kb.zip
} finally { Pop-Location }

Write-Host "Done. Artifacts in zap-kb/out and vault in zap-kb/kb-new/obsidian" -ForegroundColor Green
Write-Host "Stop containers with: docker compose -f $($root)/examples/compose/docker-compose.yml down" -ForegroundColor DarkGray

