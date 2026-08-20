[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"
$os = Get-CimInstance Win32_OperatingSystem
$docker = Get-Command docker
$wsl = Get-Command wsl
$virtualization = (Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled

Write-Host "CyberTarcza - kontrola wymagan" -ForegroundColor Cyan
Write-Host "Windows: $($os.Caption), build $($os.BuildNumber)"
Write-Host "Docker:  $(if ($docker) { 'znaleziony' } else { 'BRAK' })" -ForegroundColor $(if ($docker) { 'Green' } else { 'Yellow' })
Write-Host "WSL:     $(if ($wsl) { 'znaleziony' } else { 'BRAK' })" -ForegroundColor $(if ($wsl) { 'Green' } else { 'Yellow' })
Write-Host "Wirtualizacja firmware: $virtualization"
Write-Host ""
if (-not $docker) { Write-Host "Zainstaluj Docker Desktop z backendem WSL 2." -ForegroundColor Yellow }
if ($os.Caption -match "Windows 10") { Write-Host "Windows 10 bez ESU nie otrzymuje zwyklych aktualizacji zabezpieczen." -ForegroundColor Yellow }
