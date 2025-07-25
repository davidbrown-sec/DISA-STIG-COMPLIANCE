<#
.SYNOPSIS
   Remote Desktop Services must be configured with the client connection encryption set to the required level.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-24
    Last Modified   : 2025-07-24
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000290

.TESTED ON
    Date(s) Tested  : 2025-07-24
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-CC-000290).ps1 
#>
try {
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $valueName = "MinEncryptionLevel"
    $desiredValue = 3

    # Ensure the registry key exists
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path does not exist. Creating..."
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Retrieve current value (if it exists)
    $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName

    if ($currentValue -eq $desiredValue) {
        Write-Host "MinEncryptionLevel is already set to $desiredValue. No changes needed."
    }
    else {
        Write-Host "Updating MinEncryptionLevel from '$currentValue' to '$desiredValue'"
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord
    }
}
catch {
    Write-Host "Error applying WN10-CC-000290 remediation."
    Write-Host $_.Exception.Message
}



