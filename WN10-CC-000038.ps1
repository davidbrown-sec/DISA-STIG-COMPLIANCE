<#
.SYNOPSIS
    WDigest Authentication must be disabled.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :  WN10-CC-000038

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- WN10-CC-000038).ps1 
#>
## Target Registry Path and Value
# STIG ID: WN10-CC-000038 - Enforce 'UseLogonCredential' registry setting

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest"
$valueName = "UseLogonCredential"
$expectedValue = 0

# Check if registry path exists; if not, create it
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    Write-Output "🛠️ Registry path created: $registryPath"
}

# Get current value (if it exists)
$currentValue = $null
try {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
} catch {}

# Compare and remediate if needed
if ($currentValue -ne $expectedValue) {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $expectedValue -Type DWord
    Write-Output "STIG WN10-CC-000038: 'UseLogonCredential' set to $expectedValue for compliance."
} else {
    Write-Output "STIG WN10-CC-000038: Already compliant. 'UseLogonCredential' is set to $expectedValue."