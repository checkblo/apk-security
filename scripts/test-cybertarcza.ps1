[CmdletBinding()]
param([switch]$SkipImageBuild)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

function Step([string]$Text) {
    Write-Host "`n[CyberTarcza] $Text" -ForegroundColor Cyan
}

Step "Sprawdzanie Docker Desktop"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Nie znaleziono Docker Desktop. Zainstaluj go, uruchom i ponow test."
}
docker info | Out-Null
docker compose version

Step "Walidacja docker-compose.yml"
docker compose config --quiet

if (-not $SkipImageBuild) {
    Step "Budowanie obrazu aplikacji bez publikowania"
    docker compose build --pull app
}

Step "Uruchamianie uslug"
& "$PSScriptRoot\start-cybertarcza.ps1" -NoBrowser

Step "Kontrola kontenerow"
docker compose ps
$AppId = docker compose ps -q app
$CaddyId = docker compose ps -q caddy
if (-not $AppId -or -not $CaddyId) { throw "Brakuje uruchomionego kontenera app lub caddy." }

$Health = docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" $AppId
if ($Health -ne "healthy") { throw "Kontener aplikacji nie jest healthy: $Health" }

Step "Test HTTPS i naglowkow"
$Headers = curl.exe --fail --silent --show-error --insecure --dump-header - --output NUL https://localhost:8443/
if ($LASTEXITCODE -ne 0) { throw "Test HTTPS nie powiodl sie." }
foreach ($Header in @("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy")) {
    if (($Headers -join "`n") -notmatch "(?im)^$Header\s*:") { throw "Brakuje naglowka: $Header" }
}

$HealthBody = curl.exe --fail --silent --show-error --insecure https://localhost:8443/healthz
if ($HealthBody -notmatch '"ok"\s*:\s*true') { throw "Endpoint /healthz nie potwierdzil gotowosci." }

Write-Host "`nWszystkie testy instalacji zaliczone." -ForegroundColor Green
Write-Host "Aplikacja: https://localhost:8443"
Write-Host "Logi: docker compose logs --tail 100"
