<#
.SYNOPSIS
    This PowerShell script ensures that Windows 10 account lockout duration be configured to 15 minutes or greater.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-22
    Last Modified   : 2025-07-22
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 2025-07-22
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID-WN10-AC-000005).ps1 
#>

# Create temporary folder for config
$tempPath = "$env:SystemDrive\Temp"
if (-not (Test-Path $tempPath)) {
    New-Item -Path $tempPath -ItemType Directory | Out-Null
}

# Export current security settings
$cfgFile = "$tempPath\secpol.cfg"
secedit /export /cfg $cfgFile | Out-Null

# Replace LockoutDuration value with 20
(Get-Content $cfgFile) -replace 'LockoutDuration\s*=\s*\d+', 'LockoutDuration = 20' | Set-Content $cfgFile

# Apply the updated policy
secedit /configure /db secedit.sdb /cfg $cfgFile /quiet

# Optional cleanup
Remove-Item $cfgFile -Force

Write-Output "Account Lockout Duration set to 20 minutes