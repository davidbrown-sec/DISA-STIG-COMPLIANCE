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
    STIG-ID         : WN10-SO-000205

.TESTED ON
    Date(s) Tested  : 2025-07-24
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG ID:WN10-SO-000205).ps1 
#>
## Target Registry Path and Value
# STIG ID: WN10-SO-000205
# STIG Explanation:
# This setting controls the behavior of LAN Manager (LM) and NTLM authentication. 

# Begin error-handling block to catch and report any issues
try {
    # Define the correct registry path using Registry:: prefix
    $lsaPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"

    # Check if the LSA key exists
    if (!(Test-Path $lsaPath)) {
        # Create LSA key if it doesn't exist
        New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" -Name "Lsa" -ErrorAction Stop
    }

    # Set the LmCompatibilityLevel to 5
    New-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -PropertyType DWord -Force -ErrorAction Stop

    # Confirmation message
    Write-Host "LmCompatibilityLevel successfully set to 5. System is now compliant with STIG ID WN10-SO-000205."
}
catch {
    # Error message if something goes wrong
    Write-Host "An error occurred: $($_.Exception.Message)"
}


