<#
.SYNOPSIS
   The default autorun behavior must be configured to prevent autorun commands.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-25
    Last Modified   : 2025-07-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000185 

.TESTED ON
    Date(s) Tested  : 2025-07-25
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG WN10-CC-000185.ps1 
#>
# Define registry path and required configuration
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$valueName = 'NoAutorun'
$desiredValue = 1

try {
    # Create registry path if missing
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Retrieve current registry settings
    $currentValue = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

    # Check and apply remediation if necessary
    if ($null -eq $currentValue -or $currentValue[$valueName] -ne $desiredValue) {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -Type DWord
        Write-Host "Remediated: ${valueName} set to $desiredValue at $regPath"
    } else {
        Write-Host "Compliant: ${valueName} already set to $desiredValue"
    }
} catch {
    Write-Error "Error configuring ${valueName}: $_"
}




