<#
.SYNOPSIS
    The Windows Remote Management (WinRM) client must not allow unencrypted traffic

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
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-CC-000335).ps1 
#>

# Define registry path and value
$# Remediation for WN10-CC-000335

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$valueName = "AllowUnencryptedTraffic"
$desiredValue = 0

# Check if the registry path exists; create it if it doesn't
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Host "Registry path created: $regPath"
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -Type DWord

Write-Host "Remediation complete: $valueName set to $desiredValue under $regPath"
