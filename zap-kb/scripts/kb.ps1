[CmdletBinding()]
param(
    [Parameter(Position=0)] [ValidateSet('init','ingest','publish','enrich','prune','all')] [string]$Task = 'init',
    [string]$Entities = 'docs\data\entities.json',
    [string]$Vault = 'docs\obsidian',
    [string]$ZapUrl = $env:ZAP_URL,
    [string]$ApiKey = $env:ZAP_API_KEY,
    [string]$BaseUrl = '',
    [int]$Count = 0,
    [switch]$AllPlugins,
    [string]$Plugins = '',
    [ValidateSet('links','summary')] [string]$Detection = 'links',
    [switch]$IncludeDetection = $true,
    [switch]$IncludeTraffic = $false,
    [ValidateSet('first','all')] [string]$TrafficScope = 'first',
    [int]$TrafficMax = 2048,
    [string]$GeneratedAt = '',
    [string]$PruneScan = '',
    [string]$PruneSite = ''
)

function Invoke-ZapKb {
    param([string[]]$ArgList)
    $projRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    Push-Location $projRoot
    try {
        $cmd = "go run ./cmd/zap-kb {0}" -f ($ArgList -join ' ')
        Write-Host $cmd -ForegroundColor DarkCyan
        Write-Verbose $cmd
        & go run ./cmd/zap-kb @ArgList
        if ($LASTEXITCODE -ne 0) { throw "zap-kb exited with $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

function New-KBEntities {
    param()
    $argList = @('-init','-format','entities','-out', $Entities)
    if ($AllPlugins) { $argList += '-all-plugins' }
    if ($Plugins -and -not $AllPlugins) { $argList += @('-plugins', $Plugins) }
    if ($IncludeDetection) { $argList += @('-include-detection','-detection-details', $Detection) }
    if ($GeneratedAt) { $argList += @('-generated-at', $GeneratedAt) }
    Invoke-ZapKb -ArgList $argList
}

function Ingest-ZAPAlerts {
    param()
    $argList = @('-format','entities','-out', $Entities)
    # Only merge with an existing entities file when it actually exists
    if (Test-Path -LiteralPath $Entities) {
        $argList += @('-entities-in', $Entities)
    }
    if ($ZapUrl) { $argList += @('-zap-url', $ZapUrl) }
    if ($ApiKey) { $argList += @('-api-key', $ApiKey) }
    if ($BaseUrl) { $argList += @('-baseurl', $BaseUrl) }
    if ($Count -gt 0) { $argList += @('-count', [string]$Count) }
    if ($IncludeTraffic) { $argList += @('-include-traffic','-traffic-scope', $TrafficScope, '-traffic-max-bytes', [string]$TrafficMax) }
    if ($GeneratedAt) { $argList += @('-generated-at', $GeneratedAt) }
    Invoke-ZapKb -ArgList $argList
}

function Publish-Obsidian {
    param()
    $argList = @('-format','obsidian','-obsidian-dir', $Vault, '-entities-in', $Entities)
    if ($IncludeDetection) { $argList += @('-include-detection','-detection-details', $Detection) }
    if ($GeneratedAt) { $argList += @('-generated-at', $GeneratedAt) }
    Invoke-ZapKb -ArgList $argList
}

function Enrich-Detection {
    param()
    $argList = @('-init','-format','entities','-out', $Entities, '-entities-in', $Entities, '-include-detection','-detection-details', $Detection)
    if ($AllPlugins) { $argList += '-all-plugins' }
    if ($Plugins -and -not $AllPlugins) { $argList += @('-plugins', $Plugins) }
    if ($GeneratedAt) { $argList += @('-generated-at', $GeneratedAt) }
    Invoke-ZapKb -ArgList $argList
}

function Prune-Run {
    param()
    $vaultDir = $Vault
    if (-not $vaultDir) { $vaultDir = 'docs\obsidian' }
    if (-not $PruneScan) { throw 'Provide -PruneScan (scan label) to prune' }
    $argList = @('-prune-scan', $PruneScan, '-prune-vault', $vaultDir)
    if ($PruneSite) { $argList += @('-prune-site', $PruneSite) }
    Invoke-ZapKb -ArgList $argList
}

switch ($Task) {
    'init'    { New-KBEntities }
    'ingest'  { Ingest-ZAPAlerts }
    'publish' { Publish-Obsidian }
    'enrich'  { Enrich-Detection }
    'all'     { New-KBEntities; Ingest-ZAPAlerts; Publish-Obsidian }
    'prune'   { Prune-Run }
}

Write-Host "Done ($Task)." -ForegroundColor Green
