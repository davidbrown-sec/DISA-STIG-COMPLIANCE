<#
.SYNOPSIS
  Local drives must be prevented from sharing with Remote Desktop Session Hosts.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-25
    Last Modified   : 2025-07-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000275

.TESTED ON
    Date(s) Tested  : 2025-07-25
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG  WN10-CC-000275.ps1
#>
# STIG ID: WN10-CC-000275
# Purpose: Disable clipboard redirection in RDP
# Registry Path: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
# Value Name: fDisableCdm
# Value Type: REG_DWORD
# Expected Value: 1 (Disabled)

$regPath     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$valueName   = 'fDisableCdm'
$expectedVal = 1

Write-Host "`n[+] Checking clipboard redirection policy..." -ForegroundColor Cyan

try {
    # Create registry key if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "[-] Registry path not found. Creating it..." -ForegroundColor Yellow
        New-Item -Path $regPath -Force | Out-Null
    }

    $currentVal = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName

    # Evaluate compliance
    if ($null -eq $currentVal) {
        Write-Host "[-] '$valueName' not found. Status: Non-Compliant" -ForegroundColor Yellow
        Write-Host "[*] Setting value to $expectedVal..." -ForegroundColor Cyan
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedVal -Type DWord
    }
    elseif ($currentVal -ne $expectedVal) {
        Write-Host "[-] Value is $currentVal (Expected: $expectedVal). Status: Non-Compliant" -ForegroundColor Yellow
        Write-Host "[*] Remediating value..." -ForegroundColor Cyan
        Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedVal -Type DWord
    }
    else {
        Write-Host "[+] Value correctly set. Status: Compliant" -ForegroundColor Green
    }

    # Verify remediation
    $confirmedVal = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName
    if ($confirmedVal -eq $expectedVal) {
        Write-Host "[+] Final check passed. Value confirmed as $expectedVal." -ForegroundColor Green
    } else {
        Write-Host "[!] Value mismatch after remediation. Manual validation may be needed." -ForegroundColor Red
    }
}
catch {
    Write-Host "[!] Error during policy enforcement: $_" -ForegroundColor Red
}

