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
    STIG-ID         : WN10-CC-000350

.TESTED ON
    Date(s) Tested  : 2025-07-24
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-CC-000350).ps1 
#>

# Define registry path and value
try {
    # Define registry path and value name
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $valueName = "AllowUnencryptedTraffic"

    # Check and create the registry key if it doesn't exist
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path created: $registryPath"
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Attempt to set the registry value
    Set-ItemProperty -Path $registryPath -Name $valueName -Value 0 -Type DWord
    Write-Host "WinRM Service configured to block unencrypted traffic (WN10-CC-000350)."
}
catch {
    Write-Host "Error configuring WinRM Service:`n$($_.Exception.Message)"
}
