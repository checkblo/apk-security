$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
docker compose down
Write-Host "CyberTarcza zostala zatrzymana. Zaszyfrowany sejf pozostaje w folderze data." -ForegroundColor Cyan
