<#
.SYNOPSIS
    Suburban-SOC - Four-Dashboard Deployment (Windows-native equivalent of deploy_dashboards.sh)

.DESCRIPTION
    Imports the executive / network / endpoint / data-quality dashboards plus the
    SOC navigation hub into Kibana, provisions the logstash-* data view, installs
    the Elastic Watchers, and syncs the enriched logstash.conf into the Docker
    mount before restarting Logstash.

.EXAMPLE
    .\scripts\setup\deploy_dashboards.ps1
    $env:KIBANA_URL = "http://192.168.1.50:5601"; .\deploy_dashboards.ps1
#>
[CmdletBinding()]
param(
    [string]$EsUrl     = "http://localhost:9200",
    [string]$KibanaUrl = "http://localhost:5601"
)

$ErrorActionPreference = "Stop"

# Allow environment overrides (parity with the bash script's ES_URL / KIBANA_URL).
if ($env:ES_URL)     { $EsUrl     = $env:ES_URL }
if ($env:KIBANA_URL) { $KibanaUrl = $env:KIBANA_URL }

$ScriptDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot      = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$ServerDir     = Join-Path $RepoRoot "configs\server"
$WatcherDir    = Join-Path $RepoRoot "rules\elastic_watcher"
$LogstashSrc   = Join-Path $RepoRoot "configs\logstash.conf"
$LogstashMount = Join-Path $RepoRoot "scripts\setup\configs\logstash\logstash.conf"

$Dashboards = @(
    "executive_dashboard.ndjson",
    "network_dashboard_v3.ndjson",
    "endpoint_dashboard.ndjson",
    "dataquality_dashboard.ndjson",
    "soc_navigation_hub.ndjson"
)

function Write-Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Write-Warn2($m){ Write-Host "    $m" -ForegroundColor Yellow }

# 1. Pre-flight ---------------------------------------------------------------
Write-Step "[1/6] Validating Elasticsearch at $EsUrl"
try { Invoke-RestMethod -Uri $EsUrl -TimeoutSec 10 | Out-Null; Write-Ok "Elasticsearch is up." }
catch { Write-Host "ERROR: Elasticsearch not reachable at $EsUrl. Is the stack up?" -ForegroundColor Red; exit 1 }

Write-Step "[2/6] Validating Kibana at $KibanaUrl"
try { Invoke-RestMethod -Uri "$KibanaUrl/api/status" -TimeoutSec 10 | Out-Null; Write-Ok "Kibana is up." }
catch { Write-Host "ERROR: Kibana not reachable at $KibanaUrl/api/status." -ForegroundColor Red; exit 1 }

# 2. Data view ----------------------------------------------------------------
Write-Step "[3/6] Ensuring 'logstash-pattern' data view exists"
try {
    $body = '{"attributes":{"title":"logstash-*","timeFieldName":"@timestamp"}}'
    Invoke-RestMethod -Method Post `
        -Uri "$KibanaUrl/api/saved_objects/index-pattern/logstash-pattern?overwrite=true" `
        -Headers @{ "kbn-xsrf" = "true" } -ContentType "application/json" -Body $body | Out-Null
    Write-Ok "logstash-pattern ready."
} catch { Write-Warn2 "WARN: data view create failed (may already exist): $($_.Exception.Message)" }

# 3. Import dashboards --------------------------------------------------------
Write-Step "[4/6] Importing dashboard bundles"
$imported = 0
foreach ($f in $Dashboards) {
    $path = Join-Path $ServerDir $f
    if (-not (Test-Path $path)) { Write-Warn2 "SKIP (missing): $f"; continue }
    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri "$KibanaUrl/api/saved_objects/_import?overwrite=true" `
            -Headers @{ "kbn-xsrf" = "true" } -Form @{ file = Get-Item $path }
        if ($resp.success) { Write-Ok "Imported $f"; $imported++ }
        else { Write-Host "    FAILED $f" -ForegroundColor Red }
    } catch { Write-Host "    FAILED $f : $($_.Exception.Message)" -ForegroundColor Red }
}

# 4. Watchers (best-effort) ---------------------------------------------------
Write-Step "[5/6] Installing Elastic Watchers"
$watchers = 0
if (Test-Path $WatcherDir) {
    foreach ($w in Get-ChildItem -Path $WatcherDir -Filter *.json) {
        $wid = $w.BaseName
        try {
            Invoke-RestMethod -Method Put -Uri "$EsUrl/_watcher/watch/$wid" `
                -ContentType "application/json" -Body (Get-Content $w.FullName -Raw) | Out-Null
            Write-Ok "Installed watcher $wid"; $watchers++
        } catch { Write-Warn2 "WARN: watcher $wid (Watcher may require a trial/Gold license)" }
    }
} else { Write-Warn2 "No watcher directory at $WatcherDir" }

# 5. Sync logstash.conf + restart --------------------------------------------
Write-Step "[6/6] Syncing logstash.conf to Docker mount + restarting Logstash"
if (Test-Path $LogstashSrc) {
    New-Item -ItemType Directory -Force -Path (Split-Path $LogstashMount) | Out-Null
    Copy-Item $LogstashSrc $LogstashMount -Force
    Write-Ok "Synced configs/logstash.conf -> Docker mount."
    $running = (docker ps --format "{{.Names}}" 2>$null) -contains "logstash"
    if ($running) { docker restart logstash | Out-Null; Write-Ok "Restarted Logstash container." }
    else { Write-Warn2 "NOTE: Logstash container not running - restart it manually." }
} else { Write-Warn2 "WARN: $LogstashSrc not found - skipped sync." }

# Summary ---------------------------------------------------------------------
Write-Host ""
Write-Host "=================== DEPLOYMENT SUMMARY ===================" -ForegroundColor Green
Write-Host ("  Dashboards imported : {0} / {1}" -f $imported, $Dashboards.Count)
Write-Host ("  Watchers installed  : {0}" -f $watchers)
Write-Host ("  Kibana              : {0}/app/dashboards" -f $KibanaUrl)
Write-Host "  Dashboard IDs       : executive-dashboard, network-dashboard-v3,"
Write-Host "                        endpoint-dashboard, dataquality-dashboard, soc-navigation-hub"
Write-Host "=========================================================" -ForegroundColor Green
