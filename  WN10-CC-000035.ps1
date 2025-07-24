<#
.SYNOPSIS
    The system must be configured to ignore NetBIOS name release requests except from WINS servers.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :  WN10-CC-000035

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- WN10-CC-000035).ps1 
#>
## Target Registry Path and Value
try {
    # Define registry path and value
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
    $valueName = "NoNameReleaseOnDemand"
    $valueData = 1

    # Ensure the registry key exists
    if (-not (Test-Path $registryPath)) {
        Write-Warning "Registry path not found: $registryPath"
        return
    }

    # Get current value (if it exists)
    $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

    if ($null -eq $currentValue.$valueName) {
        # Value doesn't exist—create it
        New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType DWord -Force
        Write-Host "Registry value '$valueName' created with value $valueData." -ForegroundColor Green
    } else {
        # Value exists—update it
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData
        Write-Host "Registry value '$valueName' updated to $valueData." -ForegroundColor Cyan
    }
}
catch {
    Write-Error "An error occurred while modifying the registry: $_"
}
