<#
.SYNOPSIS
    The Windows Remote Management (WinRM) service must not use Basic authentication.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-24
    Last Modified   : 2025-07-24
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000345 

.TESTED ON
    Date(s) Tested  : 2025-07-24
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-CC-000345).ps1 
#>

try {
    # Define registry path and required value
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    $valueName = "AllowBasic"
    $desiredValue = 0

    # Create the registry key if it does not exist
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path created: $registryPath"
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Retrieve current value if it exists
    $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName

    # Compare and update if necessary
    if ($currentValue -eq $desiredValue) {
        Write-Host "$valueName is already set to $desiredValue. No changes needed."
    }
    else {
        Write-Host "Setting $valueName to $desiredValue"
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type DWord
        Write-Host "$valueName updated successfully."
    }
}
catch {
    Write-Host "Error applying WN10-CC-000345 remediation"
    Write-Host $_.Exception.Message
}

