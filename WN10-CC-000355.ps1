<#
.SYNOPSIS
    Printing over HTTP must be prevented.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-24
    Last Modified   : 2025-07-24
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000355

.TESTED ON
    Date(s) Tested  : 2025-07-24
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-CC-000355).ps1 
#>
## Target Registry Path and Value
# STIG ID: WN10-CC-000355
# STIG Explanation:
# This setting controls the behavior of LAN Manager (LM) and NTLM authentication. 

# Begin error-handling block to catch and report any issues
# STIG ID: WN10-CC-000355
# Description: Ensures WinRM 'RunAs' functionality is disabled via registry setting.
# This mitigates potential privilege escalation or credential misuse by preventing accounts from using RunAs in remote management scenarios.

# Define registry path and value
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$valueName = "DisableRunAs"
$desiredValue = 1

# Check if the registry key exists
if (-not (Test-Path $registryPath)) {
    # Create the registry key
    New-Item -Path $registryPath -Force | Out-Null
    Write-Output "Registry path '$registryPath' did not exist and was created."
}

# Get the current value
$currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

# Set the value if it doesn't exist or is incorrect
if ($currentValue.$valueName -ne $desiredValue) {
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue
    Write-Output "Registry value '$valueName' set to $desiredValue."
} else {
    Write-Output "Registry value '$valueName' is already set correctly."
}


