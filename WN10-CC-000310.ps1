<#
.SYNOPSIS
  Users must be prevented from changing installation options.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-25
    Last Modified   : 2025-07-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000310

.TESTED ON
    Date(s) Tested  : 2025-07-25
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG  WN10-CC-000310.ps1
#>
# Remediation for WN10-CC-000310 - Prevent user control over installs
# Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer
# Value Name: EnableUserControl
# Value Type: REG_DWORD
# Value Data: 0

$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
$ValueName = 'EnableUserControl'
$ExpectedValue = 0

# Ensure registry path exists
if (-not (Test-Path $RegPath)) {
    try {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Output "Created registry path: $RegPath"
    } catch {
        Write-Error "Failed to create registry path: $RegPath. $_"
    }
}

# Check current value
try {
    $CurrentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $ValueName
    if ($null -eq $CurrentValue) {
        # Value doesn't exist, create it
        New-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue -PropertyType DWord -Force | Out-Null
        Write-Output "Created registry value '$ValueName' with data '$ExpectedValue'."
    } elseif ($CurrentValue -ne $ExpectedValue) {
        # Value exists but is incorrect, update it
        Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ExpectedValue
        Write-Output "Updated registry value '$ValueName' to '$ExpectedValue'."
    } else {
        Write-Output "Registry value '$ValueName' already set correctly to '$ExpectedValue'. No action needed."
    }
} catch {
    Write-Error "Error accessing or modifying registry value '$ValueName'. $_"
}

