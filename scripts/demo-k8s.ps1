[CmdletBinding()]
param(
  [string]$Namespace = 'kb-demo',
  [int]$LocalPort = 8090,
  [string]$ApiKey = 'kb-demo'
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$zapUrl = "http://127.0.0.1:$LocalPort"

Write-Host "Applying Kubernetes demo manifests…" -ForegroundColor Cyan
kubectl apply -f (Join-Path $root 'examples/k8s/kb-demo.yaml') | Out-Null

Write-Host "Waiting for deployments…" -ForegroundColor Cyan
kubectl -n $Namespace rollout status deploy/juice-shop --timeout=300s | Out-Null
kubectl -n $Namespace rollout status deploy/zap --timeout=300s | Out-Null

Write-Host "Port-forwarding ZAP API to localhost:$LocalPort…" -ForegroundColor Cyan
$pf = Start-Process -PassThru -WindowStyle Hidden kubectl -ArgumentList @('-n', $Namespace, 'port-forward', 'svc/zap', "$LocalPort:8090")
Start-Sleep -Seconds 2
try {
  for ($i=0; $i -lt 60; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -Uri "$zapUrl/JSON/core/view/version/" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Seconds 2 }
  }

  Write-Host "Running scan via ZAP API…" -ForegroundColor Cyan
  $env:ZAP_URL = $zapUrl
  $env:ZAP_API_KEY = $ApiKey
  $env:TARGET = 'http://juice-shop:3000'
  bash (Join-Path $root 'zap-kb/scripts/scan-zap.sh') | Out-Null

  Write-Host "Building KB artifacts…" -ForegroundColor Cyan
  Push-Location (Join-Path $root 'zap-kb')
  try {
    New-Item -ItemType Directory -Force -Path 'out' | Out-Null
    $runId = "k8s-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    go run ./cmd/zap-kb -format entities -out out/entities.json `
      -zap-url $zapUrl -api-key $ApiKey -baseurl 'http://juice-shop:3000' `
      -include-traffic -traffic-scope first -traffic-max-bytes 2048 `
      -include-detection -detection-details summary `
      -scan-label $runId -site-label 'Juice Shop' -zap-base-url $zapUrl `
      -redact cookies,auth `
      -run-out out/run.json

    go run ./cmd/zap-kb -format obsidian -entities-in out/entities.json -obsidian-dir kb-new/obsidian -zap-base-url $zapUrl -scan-label $runId

    go run ./cmd/zap-kb -format both -out out/alerts.json -entities-in out/entities.json -zip-out out/kb.zip
  } finally { Pop-Location }
}
finally {
  if ($pf -and -not $pf.HasExited) { $pf.Kill() | Out-Null }
}

Write-Host "Artifacts ready: zap-kb/out/*.json and zap-kb/out/kb.zip; vault in zap-kb/kb-new/obsidian" -ForegroundColor Green
Write-Host "Stop demo: kubectl delete -f $($root)/examples/k8s/kb-demo.yaml" -ForegroundColor DarkGray

