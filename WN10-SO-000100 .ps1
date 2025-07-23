<#
.SYNOPSIS
    The Windows SMB client must be configured to always perform SMB packet signing.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000100

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID-WN10-SO-000100).ps1 
#>

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$valueName = "RequireSecuritySignature"
$valueData = 1

if (Test-Path $regPath) {
    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData
        Write-Host "'$valueName' has been set successfully to $valueData." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set '$valueName'. Error: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Registry path '$regPath' not found." -ForegroundColor Yellow
}