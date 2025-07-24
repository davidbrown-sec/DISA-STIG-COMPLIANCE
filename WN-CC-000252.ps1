<#
.SYNOPSIS
    Printing over HTTP must be prevented.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-24
    Last Modified   : 2025-07-24
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000355

.TESTED ON
    Date(s) Tested  : 2025-07-24
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-CC-000252).ps1 
#>
# STIG ID: WN10-CC-000252
# Description: Ensures GameDVR is disabled via registry setting.
# This mitigates potential privacy concerns by preventing the recording of user sessions.

# PowerShell Script to remediate WN10-CC-000252
# This is not applicable for Windows 10 LTSC/B versions 1507 and 1607

# Define registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
$regName = "AllowGameDVR"
$desiredValue = 0

# Get current Windows version
$winVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

# Skip remediation for versions 1507 or 1607 (LTSC/B)
if ($winVersion -eq "1507" -or $winVersion -eq "1607") {
    Write-Host "Remediation not applicable for Windows version $winVersion."
    return
}

# Check if registry path exists
if (!(Test-Path $regPath)) {
    Write-Host "Registry path does not exist. Creating path..."
    New-Item -Path $regPath -Force | Out-Null
}

# Check if registry value exists and has correct setting
$currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

if ($null -eq $currentValue -or $currentValue -ne $desiredValue) {
    Write-Host "Setting registry value $regName to $desiredValue..."
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue
} else {
    Write-Host "Registry value $regName is already correctly set."
}

