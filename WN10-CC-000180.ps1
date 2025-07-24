<#
.SYNOPSIS
    Autoplay must be turned off for non-volume devices.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000180

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- WN10-CC-000180).ps1 
#>
## Target Registry Path and Value
# STIG ID: WN10-CC-000180 - Ensure 'NoAutoplayfornonVolume' is set to 1

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$valueName = "NoAutoplayfornonVolume"
$expectedValue = 1

# Create the registry path if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Output "Registry path created: $registryPath"
}

# Retrieve current value (if any)
$currentValue = $null
try {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
} catch {}

# Remediate if non-compliant
if ($currentValue -ne $expectedValue) {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $expectedValue -Type DWord
    Write-Output "STIG WN10-CC-000180: Remediated. '$valueName' set to $expectedValue."
} else {
    Write-Output "STIG WN10-CC-000180: Already compliant. '$valueName' is correctly set to $expectedValue."
}
