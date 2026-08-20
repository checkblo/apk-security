[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$CertificatePath = Join-Path $ProjectRoot "caddy-data\root.crt"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Uruchom PowerShell jako administrator. Ten krok dodaje wylacznie lokalny certyfikat CyberTarcza do magazynu zaufanych urzedow."
}
if (-not (Test-Path $CertificatePath)) {
    throw "Nie znaleziono certyfikatu. Najpierw uruchom .\scripts\start-cybertarcza.ps1"
}

$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
Write-Host "Certyfikat lokalny:" -ForegroundColor Cyan
Write-Host "  Podmiot: $($certificate.Subject)"
Write-Host "  SHA-256: $(([BitConverter]::ToString($certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256))).Replace('-', ':'))"
Write-Host "  Wazny do: $($certificate.NotAfter)"
Write-Host ""
$answer = Read-Host "Dodac ten certyfikat do zaufanych glownych urzedow tego komputera? (TAK/nie)"
if ($answer -cne "TAK") {
    Write-Host "Anulowano. Nie zmieniono magazynu certyfikatow." -ForegroundColor Yellow
    exit 1
}

Import-Certificate -FilePath $CertificatePath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Write-Host "Certyfikat dodany. Uruchom ponownie przegladarke i otworz https://localhost:8443" -ForegroundColor Green
