<#
.SYNOPSIS
   The system must be configured to prevent IP source routing

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-25
    Last Modified   : 2025-07-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000025

.TESTED ON
    Date(s) Tested  : 2025-07-25
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG WN10-CC-000025.ps1
#>

## STIG ID: WN10-CC-000025
# Disable IP Source Routing (must be set to 2)
# Registry Path: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
# Value Name: DisableIPSourceRouting
# Value Type: REG_DWORD
# Expected Value: 2

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$valueName = 'DisableIPSourceRouting'
$expectedValue = 2

Write-Host "`n[+] Checking DisableIPSourceRouting setting..." -ForegroundColor Cyan

try {
    # Verify registry path exists
    if (-not (Test-Path $regPath)) {
        Write-Host "[-] Registry path not found. Attempting to create..." -ForegroundColor Yellow
        New-Item -Path $regPath -Force | Out-Null
    }

    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName

    # Audit logic
    if ($null -eq $currentValue) {
        Write-Host "[-] Registry value '$valueName' not found. Status: Non-Compliant" -ForegroundColor Yellow
        Write-Host "[*] Setting value to $expectedValue..." -ForegroundColor Cyan
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
    }
    elseif ($currentValue -ne $expectedValue) {
        Write-Host "[-] Value is $currentValue (Expected: $expectedValue). Status: Non-Compliant" -ForegroundColor Yellow
        Write-Host "[*] Remediating value..." -ForegroundColor Cyan
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord
    }
    else {
        Write-Host "[+] Registry value is correctly set. Status: Compliant" -ForegroundColor Green
    }

    # Final confirmation
    $confirmedValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName
    if ($confirmedValue -eq $expectedValue) {
        Write-Host "[+] Remediation confirmed. Value is now $expectedValue." -ForegroundColor Green
    } else {
        Write-Host "[!] Unexpected result after remediation. Please verify manually." -ForegroundColor Red
    }
}
catch {
    Write-Host "[!] Error occurred: $_" -ForegroundColor Red
}

