<#
.SYNOPSIS
  Orchestrates the non-browser bookends of the Forgejo browse-and-triage
  pipeline: publishes findings as Forgejo issues (Stage 2) and, optionally,
  pulls the triaged status back into the KB (Stage 5). The browse-and-triage
  middle (Stages 3-4) is performed by the `forgejo-triager` Claude subagent in
  Chrome — this script prints the exact spawn instruction for it.

.DESCRIPTION
  See zap-kb/docs/forgejo-triage-pipeline.md for the full runbook.
  The Forgejo token is read from $env:FORGEJO_TOKEN (never passed on the command
  line, so it is not echoed). Run from anywhere; paths resolve to the repo.

.EXAMPLE
  $env:FORGEJO_TOKEN = '...'
  ./forgejo-triage.ps1 -ForgejoUrl http://localhost:3000 -Owner analyst -Repo security-findings
  # publishes, then prints the agent spawn line

.EXAMPLE
  ./forgejo-triage.ps1 -ForgejoUrl http://localhost:3000 -Owner analyst -Repo security-findings -Sync
  # after triage: pull mapped statuses back into the entities file
#>
[CmdletBinding()]
param(
    [string]$ForgejoUrl = $env:FORGEJO_URL,
    [string]$Owner      = $env:FORGEJO_OWNER,
    [string]$Repo       = $env:FORGEJO_REPO,
    [string]$Entities   = 'docs\data\entities.json',
    [ValidateSet('info','low','medium','high')] [string]$MinRisk = 'medium',
    [ValidateSet('recommend','apply')] [string]$Mode = 'recommend',
    [switch]$Wiki,
    [switch]$DryRun,        # preview which issues would be created
    [switch]$Sync,          # Stage 5: persist mapped status into the entities file
    [switch]$SkipPublish    # only print the agent instruction (+ -Sync if set)
)

$ErrorActionPreference = 'Stop'

function Invoke-ZapKb {
    param([string[]]$ArgList)
    $projRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    Push-Location $projRoot
    try {
        Write-Host ("go run ./cmd/zap-kb {0}" -f ($ArgList -join ' ')) -ForegroundColor DarkCyan
        & go run ./cmd/zap-kb @ArgList
        if ($LASTEXITCODE -ne 0) { throw "zap-kb exited with $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

# --- Validate inputs -------------------------------------------------------
foreach ($p in @(@{n='ForgejoUrl';v=$ForgejoUrl}, @{n='Owner';v=$Owner}, @{n='Repo';v=$Repo})) {
    if ([string]::IsNullOrWhiteSpace($p.v)) { throw "Missing -$($p.n) (or its FORGEJO_* env var)." }
}
if (-not $SkipPublish -and [string]::IsNullOrWhiteSpace($env:FORGEJO_TOKEN)) {
    throw 'Set $env:FORGEJO_TOKEN before publishing (write:issue,write:repository scope).'
}

$common = @('-forgejo-url', $ForgejoUrl, '-forgejo-owner', $Owner, '-forgejo-repo', $Repo)

# --- Stage 2: publish findings as issues -----------------------------------
if (-not $SkipPublish -and -not $Sync) {
    $argList = @('-entities-in', $Entities) + $common + @('-forgejo-min-risk', $MinRisk, '-forgejo-issues')
    if ($Wiki)   { $argList += '-forgejo-wiki' }
    if ($DryRun) { $argList += '-forgejo-dry-run' }
    Write-Host "`n[Stage 2] Publishing findings to $ForgejoUrl/$Owner/$Repo ..." -ForegroundColor Cyan
    Invoke-ZapKb -ArgList $argList
}

# --- Stage 4: hand off to the browser-driving agent ------------------------
Write-Host "`n[Stage 3-4] Connect the Claude-in-Chrome extension (logged in to $ForgejoUrl), then spawn:" -ForegroundColor Cyan
Write-Host ("  Use the forgejo-triager agent to triage the Forgejo board at {0}, owner {1}, repo {2}, mode {3}." -f $ForgejoUrl, $Owner, $Repo, $Mode) -ForegroundColor Green

# --- Stage 5: pull triaged status back into the KB -------------------------
if ($Sync) {
    $argList = @('-entities-in', $Entities) + $common + @('-forgejo-sync-kb-status')
    Write-Host "`n[Stage 5] Syncing mapped Forgejo status into $Entities ..." -ForegroundColor Cyan
    Invoke-ZapKb -ArgList $argList
}
