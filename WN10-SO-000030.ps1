<#
.SYNOPSIS
    Audit policy using subcategories must be enabled.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-24
    Last Modified   : 2025-07-24
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000030

.TESTED ON
    Date(s) Tested  : 2025-07-24
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-SO-000030).ps1 
#>
try {
    # Define registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $valueName = "SCENoApplyLegacyAuditPolicy"
    $desiredValue = 1

    # Check and create the registry key if it doesn't exist
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path created: $registryPath"
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set the required value
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord
    Write-Host "Audit policy subcategory enforcement enabled (WN10-SO-000030)."
}
catch {
    Write-Host "Error applying WN10-SO-000030:`n$($_.Exception.Message)"
}


