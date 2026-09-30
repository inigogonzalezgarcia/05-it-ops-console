<#
.SYNOPSIS
    Remote query used by the console: serial number, installed software or basic health.

.DESCRIPTION
    Called by app/services.py. Credentials arrive as JSON on stdin (never as
    arguments, which other users could read in the process list). The result is
    written as JSON to -OutFile instead of stdout, so warnings or module banners
    can never corrupt it.

    Empty credentials mean "use the identity of the account running the console".

.EXAMPLE
    '{"username":"","password":""}' | pwsh -File Get-DeviceInfo.ps1 -ComputerName WKS-1001 -Query serial -OutFile out.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$')] [string]$ComputerName,
    [Parameter(Mandatory)] [ValidateSet('serial', 'software', 'health')] [string]$Query,
    [Parameter(Mandatory)] [string]$OutFile
)

$ErrorActionPreference = 'Stop'

$input_json = [Console]::In.ReadToEnd()
$creds = if ($input_json) { $input_json | ConvertFrom-Json } else { $null }
$credential = $null
if ($creds -and $creds.username) {
    $secure = ConvertTo-SecureString $creds.password -AsPlainText -Force
    $credential = [pscredential]::new($creds.username, $secure)
}

# Get-CimInstance has no -Credential parameter: alternate credentials only work
# through a CIM session. (Get-WmiObject had -Credential, but it is gone in PowerShell 7.)
$sessionParams = @{ ComputerName = $ComputerName; OperationTimeoutSec = 30 }
if ($credential) { $sessionParams.Credential = $credential }

$result = @{}
$session = $null
try {
    switch ($Query) {
        'serial' {
            $session = New-CimSession @sessionParams
            $bios = Get-CimInstance -CimSession $session -ClassName Win32_BIOS
            $result.serial = $bios.SerialNumber.Trim()
        }
        'health' {
            $session = New-CimSession @sessionParams
            $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
            $cpu = Get-CimInstance -CimSession $session -ClassName Win32_Processor |
                Measure-Object -Property LoadPercentage -Average
            $disk = Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
            $result.cpu_percent = [int]$cpu.Average
            $result.free_disk_gb = [math]::Round($disk.FreeSpace / 1GB)
            $result.uptime_days = [int]((Get-Date) - $os.LastBootUpTime).TotalDays
        }
        'software' {
            # Win32_Product is avoided on purpose: querying it is slow and makes
            # Windows Installer re-validate every MSI package on the machine.
            $invokeParams = @{ ComputerName = $ComputerName }
            if ($credential) { $invokeParams.Credential = $credential }
            $apps = Invoke-Command @invokeParams -ScriptBlock {
                $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
                    ForEach-Object {
                        # Objects, not hashtables: Sort-Object -Unique compares hashtables
                        # by reference, so duplicates would survive.
                        [pscustomobject]@{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher }
                    }
            }
            $result.software = @($apps | Select-Object name, version, publisher |
                Sort-Object -Property name, version -Unique)
        }
    }
}
finally {
    if ($session) { Remove-CimSession $session }
}

$result | ConvertTo-Json -Depth 4 | Set-Content -Path $OutFile -Encoding UTF8
