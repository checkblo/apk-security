[CmdletBinding()]
param([switch]$NoBrowser)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Nie znaleziono Docker Desktop. Zainstaluj i uruchom Docker Desktop, a potem ponow probe."
}
docker info | Out-Null
docker compose config --quiet

$null = New-Item -ItemType Directory -Force -Path "data", "caddy-data", "caddy-config", ".secrets"
if (-not (Test-Path ".secrets\hibp_api_key.txt")) {
    New-Item -ItemType File -Path ".secrets\hibp_api_key.txt" | Out-Null
}

Write-Host "Budowanie i uruchamianie CyberTarcza Local..." -ForegroundColor Cyan
docker compose up -d --build

$ready = $false
for ($attempt = 0; $attempt -lt 45; $attempt++) {
    Start-Sleep -Seconds 2
    try {
        $appId = docker compose ps -q app
        if (-not $appId) { continue }
        $status = docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" $appId
        if ($status -eq "healthy") {
            $ready = $true
            break
        }
    } catch {}
}

if (-not $ready) {
    docker compose ps
    docker compose logs --tail 100 app
    throw "Aplikacja nie osiagnela stanu healthy. Sprawdz: docker compose logs"
}

$httpsReady = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $health = curl.exe --fail --silent --insecure "https://localhost:8443/healthz" 2>$null
    if ($LASTEXITCODE -eq 0 -and $health -match '"ok"\s*:\s*true') {
        $httpsReady = $true
        break
    }
    Start-Sleep -Seconds 1
}
if (-not $httpsReady) {
    docker compose logs --tail 100 caddy
    throw "Kontrola HTTPS /healthz nie powiodla sie. Sprawdz: docker compose logs"
}

try {
    docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt "caddy-data\root.crt" | Out-Null
} catch {
    Write-Warning "Nie udalo sie pobrac lokalnego certyfikatu CA. Aplikacja dziala, ale przegladarka moze pokazac ostrzezenie."
}

Write-Host ""
Write-Host "CyberTarcza dziala pod adresem: https://localhost:8443" -ForegroundColor Green
Write-Host "Port jest dostepny tylko z tego komputera (127.0.0.1)." -ForegroundColor DarkGray
Write-Host "Pelny test instalacji: .\scripts\test-cybertarcza.ps1 -SkipImageBuild" -ForegroundColor DarkGray
if (Test-Path "caddy-data\root.crt") {
    Write-Host "Aby usunac ostrzezenie certyfikatu, uruchom jako administrator: .\scripts\trust-local-ca.ps1" -ForegroundColor Yellow
}

if (-not $NoBrowser) { Start-Process "https://localhost:8443" }
