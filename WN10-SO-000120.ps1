<#
.SYNOPSIS
    The Windows SMB server must be configured to always perform SMB packet signing.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000120

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID: WN10-SO-000120).ps1 
#>
## Target Registry Path and Value
# STIG ID: WN10-SO-000120
# Purpose: Ensure RequireSecuritySignature is enabled to prevent unauthenticated SMB sessions

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$valueName = "RequireSecuritySignature"
$expectedValue = 1

# Create the registry path if it's missing
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Output "Registry path created: $registryPath"
}

# Get current value (if any)
$currentValue = $null
try {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
} catch {}

# Remediate if needed
if ($currentValue -ne $expectedValue) {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $expectedValue -Type DWord
    Write-Output "Remediation applied: '$valueName' set to $expectedValue for STIG WN10-SO-000120."
} else {
    Write-Output "Already compliant: '$valueName' is correctly set to $expectedValue."
}
