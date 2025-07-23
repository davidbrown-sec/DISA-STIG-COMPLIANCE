<#
.SYNOPSIS
    This PowerShell script ensures that Windows 10 account lockout duration be configured to 15 minutes or greater.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000185 

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID-WN10-AC-000005).ps1 
#>

# Script Name: Set-NoAutorun.ps1
# Purpose: Disable AutoRun by setting NoAutorun registry value to 1

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoAutorun"
$valueData = 1

# Create the key if it doesn't exist
If (-Not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the value
Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type DWord

Write-Host "AutoRun disabled successfully by setting $valueName to $valueData in $registryPath"