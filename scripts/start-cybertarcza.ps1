[CmdletBinding()]
param([switch]$NoBrowser)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Nie znaleziono Docker Desktop. Zainstaluj i uruchom Docker Desktop, a potem ponow probe."
}

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
        $status = docker compose ps --format json | Out-String
        if ($status -match 'running|healthy') {
            $ready = $true
            break
        }
    } catch {}
}

if (-not $ready) {
    docker compose ps
    throw "Aplikacja nie osiagnela gotowosci. Sprawdz: docker compose logs"
}

try {
    docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt "caddy-data\root.crt" | Out-Null
} catch {
    Write-Warning "Nie udalo sie pobrac lokalnego certyfikatu CA. Aplikacja dziala, ale przegladarka moze pokazac ostrzezenie."
}

Write-Host ""
Write-Host "CyberTarcza dziala pod adresem: https://localhost:8443" -ForegroundColor Green
Write-Host "Port jest dostepny tylko z tego komputera (127.0.0.1)." -ForegroundColor DarkGray
if (Test-Path "caddy-data\root.crt") {
    Write-Host "Aby usunac ostrzezenie certyfikatu, uruchom jako administrator: .\scripts\trust-local-ca.ps1" -ForegroundColor Yellow
}

if (-not $NoBrowser) { Start-Process "https://localhost:8443" }
