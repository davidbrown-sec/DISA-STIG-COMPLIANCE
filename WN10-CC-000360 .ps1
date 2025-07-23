<#
.SYNOPSIS
    The Windows Remote Management (WinRM) client must not use Digest authentication.

.NOTES
    Author          : David Brown
    LinkedIn        : linkedin.com/in/david-benton-brown/
    GitHub          : github.com/davidbrown-sec
    Date Created    : 2025-07-23
    Last Modified   : 2025-07-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000360

.TESTED ON
    Date(s) Tested  : 2025-07-23
    Tested By       : David Brown
    Systems Tested  : Windows 10 Pro Version 22H2
    PowerShell Ver. : 5.1.19041.6093 

.USAGE
    Put any usage instructions here.
    # Requires: Admin privileges
    Example syntax:
    PS C:\> .\__remediation_template(STID-ID-WN10-CC-000360).ps1 
#>
# Target: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client
# Value: AllowDigest = 0

# Define registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$valueName = "AllowDigest"
$expectedValue = 0

# Function to verify registry value
function Verify-RegistryValue {
    param ([string]$path, [string]$name, [int]$expected)
    try {
        $currentValue = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        return ($currentValue.$name -eq $expected)
    } catch {
        return $false
    }
}

try {
    # Ensure registry path exists
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set registry value
    Set-ItemProperty -Path $regPath -Name $valueName -Value $expectedValue -Type DWord

    # Verify value
    if (Verify-RegistryValue -path $regPath -name $valueName -expected $expectedValue) {
        Write-Output "✅ Registry updated and verified."
    } else {
        Write-Warning "⚠️ Registry value mismatch after update."
    }

} catch {
    $errorMsg = $_.Exception.Message
    Write-Error "❌ Failed to update registry: $errorMsg"
}