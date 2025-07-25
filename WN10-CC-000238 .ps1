<#
.SYNOPSIS
   Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-25
    Last Modified   : 2025-07-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000238 

.TESTED ON
    Date(s) Tested  : 2025-07-25
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG WN10-CC-000238).ps1 
#>
# Define the registry location and desired configuration
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings'
$valueName = 'PreventCertErrorOverrides'
$desiredValue = 1  # Enforce certificate error overrides prevention

try {
    # Create the registry key if it doesn't exist
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Retrieve current registry settings from the defined path
    $currentValue = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

    # If the value is missing or set incorrectly, remediate it
    if ($null -eq $currentValue -or $currentValue[$valueName] -ne $desiredValue) {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -Type DWord
        Write-Host "Remediated: ${valueName} set to $desiredValue at $regPath"
    } else {
        # Value is already compliant
        Write-Host "Compliant: ${valueName} already set to $desiredValue"
    }
} catch {
    # Output error if remediation fails
    Write-Error "Error configuring ${valueName}: $_"
}



