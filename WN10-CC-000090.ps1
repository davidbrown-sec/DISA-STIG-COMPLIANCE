<#
.SYNOPSIS
   Group Policy objects must be reprocessed even if they have not changed.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-25
    Last Modified   : 2025-07-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000090

.TESTED ON
    Date(s) Tested  : 2025-07-25
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093  

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID- # STIG WN10-CC-000090.ps1
#>

# Define target registry path and value details
$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
$ValueName = 'NoGPOListChanges'
$DesiredValue = 0

try {
    # Check if the registry path exists, create it if missing
    if (-not (Test-Path $RegPath)) {
        Write-Verbose "Registry path not found. Creating..."
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Attempt to read the current registry value, suppressing errors
    $currentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

    # If value is missing or set incorrectly, remediate
    if ($null -eq $currentValue -or $currentValue.$ValueName -ne $DesiredValue) {
        Write-Output "Remediating: Setting '$ValueName' to $DesiredValue..."
        
        # Set the desired value with proper type
        Set-ItemProperty -Path $RegPath -Name $ValueName -Value $DesiredValue -Type DWord
        
        Write-Output "Remediation complete."
    }
    else {
        # Value is already compliant
        Write-Output "Compliant: '$ValueName' is already set to $DesiredValue."
    }
}
catch {
    # Log unexpected errors during execution
    Write-Error "Error during remediation: $_"
}


