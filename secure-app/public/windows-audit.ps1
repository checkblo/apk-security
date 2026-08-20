# CyberTarcza Local - bezpieczny audyt tylko do odczytu
# Obsluguje Windows 10 i Windows 11 (Home, Pro, Enterprise, Education, IoT).
# Skrypt NIE zmienia ustawien, NIE wysyla danych i NIE wymaga polaczenia z internetem.

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:USERPROFILE "Desktop\CyberTarcza-Windows-Audit.json")
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

function Read-SafeValue {
    param([scriptblock]$Action, $Fallback = $null)
    try {
        $value = & $Action
        if ($null -eq $value) { return $Fallback }
        return $value
    } catch {
        return $Fallback
    }
}

function New-Check {
    param([string]$Id, [string]$Label, [string]$Status, [string]$Detail)
    [ordered]@{
        id = $Id
        label = $Label
        status = $Status
        detail = $Detail
    }
}

$os = Read-SafeValue { Get-CimInstance Win32_OperatingSystem }
$computer = Read-SafeValue { Get-CimInstance Win32_ComputerSystem }
$tpm = Read-SafeValue { Get-Tpm }
$defender = Read-SafeValue { Get-MpComputerStatus }
$defenderPreferences = Read-SafeValue { Get-MpPreference }
$firewall = @(Read-SafeValue { Get-NetFirewallProfile } @())
$bitlocker = @(Read-SafeValue { Get-BitLockerVolume } @())
$secureBoot = Read-SafeValue { Confirm-SecureBootUEFI } $null
$smb1 = Read-SafeValue { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol }
$rdpDenied = Read-SafeValue { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections }
$uac = Read-SafeValue { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA }
$updateService = Read-SafeValue { Get-Service wuauserv }

$systemDrive = $bitlocker | Where-Object { $_.MountPoint -eq $env:SystemDrive } | Select-Object -First 1
$firewallAllEnabled = $firewall.Count -gt 0 -and (@($firewall | Where-Object { -not $_.Enabled }).Count -eq 0)
$isWindows10 = $os -and $os.Caption -match "Windows 10"
$build = if ($os) { [int]$os.BuildNumber } else { 0 }
$windows10Supported = -not $isWindows10 -or $build -ge 19045

$checks = @()
$checks += New-Check "windows-version" "Wersja systemu" $(if ($os) { "info" } else { "unknown" }) $(if ($os) { "$($os.Caption), kompilacja $($os.BuildNumber)" } else { "Brak danych" })
$checks += New-Check "windows-support" "Wsparcie aktualizacjami" $(if ($isWindows10) { "warning" } elseif ($os) { "pass" } else { "unknown" }) $(if ($isWindows10) { "Windows 10 wymaga programu ESU albo migracji do Windows 11." } elseif ($os) { "System Windows 11 - sprawdz regularnie Windows Update." } else { "Nie rozpoznano systemu." })
$checks += New-Check "secure-boot" "Secure Boot" $(if ($secureBoot -eq $true) { "pass" } elseif ($secureBoot -eq $false) { "fail" } else { "unknown" }) $(if ($secureBoot -eq $true) { "Wlaczone" } elseif ($secureBoot -eq $false) { "Wylaczone" } else { "Niedostepne lub brak uprawnien" })
$checks += New-Check "tpm" "TPM" $(if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) { "pass" } elseif ($tpm -and $tpm.TpmPresent) { "warning" } else { "unknown" }) $(if ($tpm) { "Obecny: $($tpm.TpmPresent); gotowy: $($tpm.TpmReady); wlaczony: $($tpm.TpmEnabled)" } else { "Brak danych" })
$checks += New-Check "defender" "Microsoft Defender" $(if ($defender -and $defender.RealTimeProtectionEnabled -and $defender.AntivirusEnabled) { "pass" } elseif ($defender) { "warning" } else { "unknown" }) $(if ($defender) { "Antywirus: $($defender.AntivirusEnabled); ochrona czasu rzeczywistego: $($defender.RealTimeProtectionEnabled); sygnatury: $($defender.AntivirusSignatureLastUpdated)" } else { "Defender niedostepny lub uzywany jest inny antywirus." })
$checks += New-Check "firewall" "Zapora Windows" $(if ($firewallAllEnabled) { "pass" } elseif ($firewall.Count -gt 0) { "fail" } else { "unknown" }) $(if ($firewall.Count -gt 0) { (($firewall | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join "; ") } else { "Brak danych" })
$checks += New-Check "encryption" "Szyfrowanie dysku" $(if ($systemDrive -and $systemDrive.ProtectionStatus -eq "On") { "pass" } elseif ($systemDrive) { "warning" } else { "unknown" }) $(if ($systemDrive) { "Dysk $env:SystemDrive; ochrona: $($systemDrive.ProtectionStatus); szyfrowanie: $($systemDrive.EncryptionPercentage)%" } else { "BitLocker moze byc niedostepny w tej edycji. Sprawdz Ustawienia > Prywatnosc i zabezpieczenia > Szyfrowanie urzadzenia." })
$checks += New-Check "ransomware" "Kontrolowany dostep do folderow" $(if ($defenderPreferences -and $defenderPreferences.EnableControlledFolderAccess -eq 1) { "pass" } elseif ($defenderPreferences) { "warning" } else { "unknown" }) $(if ($defenderPreferences) { "Stan: $($defenderPreferences.EnableControlledFolderAccess) (1 = wlaczone)" } else { "Brak danych" })
$checks += New-Check "smb1" "Stary protokol SMB1" $(if ($smb1 -and $smb1.State -eq "Disabled") { "pass" } elseif ($smb1) { "warning" } else { "unknown" }) $(if ($smb1) { "Stan: $($smb1.State)" } else { "Brak danych" })
$checks += New-Check "rdp" "Pulpit zdalny" $(if ($rdpDenied -eq 1) { "pass" } elseif ($rdpDenied -eq 0) { "warning" } else { "unknown" }) $(if ($rdpDenied -eq 1) { "Wylaczony" } elseif ($rdpDenied -eq 0) { "Wlaczony - upewnij sie, ze jest potrzebny i ograniczony zapora." } else { "Brak danych" })
$checks += New-Check "uac" "Kontrola konta uzytkownika (UAC)" $(if ($uac -eq 1) { "pass" } elseif ($uac -eq 0) { "fail" } else { "unknown" }) $(if ($uac -eq 1) { "Wlaczona" } elseif ($uac -eq 0) { "Wylaczona" } else { "Brak danych" })
$checks += New-Check "windows-update" "Usluga Windows Update" $(if ($updateService -and $updateService.StartType -ne "Disabled") { "pass" } elseif ($updateService) { "fail" } else { "unknown" }) $(if ($updateService) { "Stan: $($updateService.Status); uruchamianie: $($updateService.StartType)" } else { "Brak danych" })

$report = [ordered]@{
    schema = 1
    tool = "CyberTarcza Windows Audit"
    readOnly = $true
    generatedAt = (Get-Date).ToUniversalTime().ToString("o")
    device = [ordered]@{
        manufacturer = if ($computer) { $computer.Manufacturer } else { $null }
        model = if ($computer) { $computer.Model } else { $null }
        os = if ($os) { $os.Caption } else { $null }
        build = if ($os) { $os.BuildNumber } else { $null }
        architecture = if ($os) { $os.OSArchitecture } else { $null }
    }
    checks = $checks
    privacy = "Raport nie zawiera hasel, kluczy odzyskiwania, numeru seryjnego ani adresu IP. Nic nie zostalo wyslane do internetu."
}

$json = $report | ConvertTo-Json -Depth 8
$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "CyberTarcza - audyt tylko do odczytu" -ForegroundColor Cyan
Write-Host "System: $($report.device.os) (build $($report.device.build))"
Write-Host ""
foreach ($check in $checks) {
    $color = switch ($check.status) { "pass" { "Green" } "fail" { "Red" } "warning" { "Yellow" } default { "DarkGray" } }
    Write-Host ("[{0}] {1}: {2}" -f $check.status.ToUpper(), $check.label, $check.detail) -ForegroundColor $color
}
Write-Host ""
Write-Host "Raport zapisano: $OutputPath" -ForegroundColor Cyan
Write-Host "Skrypt nie zmienil zadnych ustawien i nie wyslal danych." -ForegroundColor DarkGray
