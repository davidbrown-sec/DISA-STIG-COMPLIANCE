<#
.SYNOPSIS
   The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-25
    Last Modified   : 2025-07-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000215

.TESTED ON
    Date(s) Tested  : 2025-07-25
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG WN10-SO-000215.ps1
#>

# Define target registry path and value details
$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
$ValueName = 'NoGPOListChanges'
$DesiredValue = 0

# Set NTLMMinClientSec to 0x20080000 to comply with Windows STIG requirement
# Ensures NTLM client minimum security settings are enforced

$RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$ValueName   = "NTLMMinClientSec"
$ExpectedValue = 0x20080000

try {
    # Check if the registry key exists
    if (-not (Test-Path $RegPath)) {
        Write-Output "Creating registry path: $RegPath"
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Get current value if it exists
    $CurrentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Output "'$ValueName' already set to expected value: 0x{0:X8}" -f $ExpectedValue
    } else {
        Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -Type DWord
        Write-Output "Set '$ValueName' to 0x{0:X8} successfully." -f $ExpectedValue
    }
}
catch {
    Write-Error "Failed to update '$ValueName' at $RegPath. Exception: $_"
}
