<#
.SYNOPSIS
    Printing over HTTP must be prevented.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000110

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID: WN10-CC-000110).ps1 
#>
## Target Registry Path and Value
# STIG Remediation: WN10-CC-000110
# Description: Disable HTTP Printing to enhance security on the system

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableHTTPPrinting"
$expectedValue = 1

# Create the registry path if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Output "Created missing registry path: $registryPath"
}

# Retrieve current value
$currentValue = $null
try {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
} catch {}

# Compare and remediate
if ($currentValue -ne $expectedValue) {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $expectedValue -Type DWord
    Write-Output "Remediation applied: '$valueName' set to $expectedValue for STIG WN10-CC-000110."
} else {
    Write-Output "Already compliant: '$valueName' is correctly set to $expectedValue."
}
