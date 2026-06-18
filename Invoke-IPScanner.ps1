# Filename: Invoke-IPScanner.ps1
# Author: Gemini
# Date: 2026-06-03
# Version: 3.1.1

<#
.SYNOPSIS
    A high-performance, multithreaded IP scanner using PowerShell Runspaces.

.DESCRIPTION
    Scans ranges of IP addresses and/or CIDR subnets to identify active devices.
    You can mix -Range and -Subnet in a single execution.
    Performs post-scan OUI lookups for vendor identification.

.PARAMETER Range
    Defines specific ranges of IP addresses to scan. Accepts multiple strings.
    Format: "192.168.1.10-50" or "192.168.1.100-192.168.2.50"
    Special: Use "local" to automatically scan all active IPv4 interfaces.

.PARAMETER Subnet
    Defines CIDR blocks to scan. Accepts multiple strings.
    Example: "192.168.1.0/24", "10.0.0.0/24"

.PARAMETER TcpConnect
    Switch. Skips ICMP (Ping) and relies solely on TCP port connection.

.PARAMETER Ports
    An array of specific TCP ports to scan. Default is top 28 common ports.

.PARAMETER ListenOnly
    Switch. Only returns hosts that respond on the specified ports. Requires -Ports parameter.

.PARAMETER Threads
    Integer. Number of concurrent threads (Default: 64).

.PARAMETER OutputFormat
    String. "GridView", "Json", or "Object". 
    DEFAULT: "Object"

.PARAMETER Quiet
    Switch. Suppresses console output.

.PARAMETER UpdateOUI
    Switch. Forces a fresh download of the OUI database.

.EXAMPLE
    .\Invoke-IPScanner.ps1
    Auto-detects the local subnet and scans it, returning standard objects.

.EXAMPLE
    .\Invoke-IPScanner.ps1 -Subnet "192.168.1.0/24" -Range "10.0.0.50-60"
    Scans the entire 192.168.1.x subnet AND the specific 10.0.0.50-60 range simultaneously.

.EXAMPLE
    .\Invoke-IPScanner.ps1 -Range "local" -ListenOnly -Ports 80,443
    Scans all active network interfaces on the machine and only returns devices with port 80 or 443 open.

.EXAMPLE
    .\Invoke-IPScanner.ps1 -Subnet "192.168.50.0/24" -OutputFormat Json -Quiet | Set-Content scan_results.json
    Silently scans the network and saves the results directly to a JSON file.
#>

[CmdletBinding()]
Param(
    [Parameter()]
    [string[]]$Range,

    [Parameter()]
    [string[]]$Subnet,

    [switch]$TcpConnect,
    [switch]$UpdateOUI,
    [switch]$ListenOnly,

    [int[]]$Ports,
    [int]$Threads = 64,

    [ValidateSet("GridView", "Json", "Object")]
    [string]$OutputFormat = "Object",

    [switch]$Quiet
)

# --- 1. CONFIGURATION & HELPERS ---

# Explicit HTTPS URL to match modern IEEE server requirements
$OuiUrl = "https://standards-oui.ieee.org/oui/oui.txt"
$OuiCachePath = Join-Path $env:TEMP "oui_database.txt"

# Validate ListenOnly dependency
if ($ListenOnly -and -not $Ports) {
    Write-Error "The -ListenOnly flag requires a custom list of -Ports to be provided."
    return
}

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = "White")
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}

function Convert-IpToInt64 {
    param([string]$ip)
    [ipaddress]$ipAddr = $ip
    $bytes = $ipAddr.GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Convert-Int64ToIp {
    param([int64]$int)
    $bytes = [BitConverter]::GetBytes([uint32]$int)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    return ([ipaddress]$bytes).IPAddressToString
}

# --- 2. OUI / VENDOR LOGIC ---

function Get-OuiDatabase {
    $NeedDownload = $true
    if (Test-Path $OuiCachePath) {
        if ($UpdateOUI) { 
            $NeedDownload = $true 
        } elseif ((Get-Date) - (Get-Item $OuiCachePath).LastWriteTime -lt (New-TimeSpan -Days 30)) {
            $NeedDownload = $false
        }
    }

    if ($NeedDownload) {
        Write-Log "Downloading OUI Database (this happens once per month)..." -Color Yellow
        try {
            # Force PowerShell 5.1 security provider context to accept modern TLS ciphers
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            
            # Explicit use of basic parsing bypasses legacy Internet Explorer structural engine blocks
            Invoke-WebRequest -Uri $OuiUrl -OutFile $OuiCachePath -UseBasicParsing
            Write-Log "OUI Database updated successfully via HTTPS." -Color Green
        } catch {
            Write-Log "Failed to download OUI database. Error: $($_.Exception.Message)" -Color Red
        }
    }
}

function Parse-OuiDatabase {
    if (-not (Test-Path $OuiCachePath)) { return @{} }
    $Map = @{}
    Get-Content $OuiCachePath | Where-Object { $_ -match "\(hex\)" } | ForEach-Object {
        if ($_ -match "^([0-9A-F-]{8})\s+\(hex\)\s+(.+)$") {
            $Prefix = $matches[1].Replace("-", ":").Trim().Substring(0,8)
            $Vendor = $matches[2].Trim()
            if (-not $Map.ContainsKey($Prefix)) { $Map[$Prefix] = $Vendor }
        }
    }
    return $Map
}

# --- 3. DEFINE THE WORKER (Thread Logic) ---
$WorkerBlock = {
    Param($TargetIP, $PortsToScan, $MasterPortMap, $TcpConnect, $ListenOnly)

    function Get-MacInternal {
        param($IP)
        $ArpEntry = (arp -a $IP) -join "`n"
        if ($ArpEntry -match "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})") {
            return $matches[0].ToUpper() -replace "-", ":"
        }
        return $null
    }

    function Get-HostnameInternal {
        param($IP)
        try { return [System.Net.Dns]::GetHostEntry($IP).HostName } catch {}
        try {
            $NbtOutput = nbtstat -A $IP
            if ($NbtOutput -match "\s+([A-Za-z0-9-_]+)\s+<00>\s+UNIQUE") {
                return $matches[1].Trim()
            }
        } catch {}
        return $null
    }

    $IsAlive = $false
    if ($TcpConnect -or $ListenOnly) {
        $IsAlive = $true 
    } else {
        if (Test-Connection -ComputerName $TargetIP -Count 1 -Quiet) { $IsAlive = $true }
    }

    if ($IsAlive) {
        $HostName = Get-HostnameInternal -IP $TargetIP
        $Mac = Get-MacInternal -IP $TargetIP
        $DetectedPorts = @()

        foreach ($Port in $PortsToScan) {
            $Tcp = New-Object System.Net.Sockets.TcpClient
            $Con = $Tcp.BeginConnect($TargetIP, $Port, $null, $null)
            if ($Tcp.Connected -or $Con.AsyncWaitHandle.WaitOne(200, $false)) {
                try {
                    if ($Tcp.Connected) {
                        if ($MasterPortMap.ContainsKey($Port)) { 
                            $DetectedPorts += "$Port ($($MasterPortMap[$Port]))" 
                        } else { 
                            $DetectedPorts += "$Port" 
                        }
                    }
                    $Tcp.Close()
                } catch {}
            }
        }

        if (($TcpConnect -or $ListenOnly) -and $DetectedPorts.Count -eq 0) { return $null }

        return [PSCustomObject]@{
            IP     = $TargetIP
            Name   = $HostName
            MAC    = $Mac
            Vendor = ""
            Ports  = if ($DetectedPorts.Count -gt 0) { $DetectedPorts -join ", " } else { $null }
        }
    }
    return $null
}

# --- 4. PREPARE SCAN PARAMETERS ---

$MasterPortMap = @{
    20="FTP-Data"; 21="FTP"; 22="SSH"; 25="SMTP"; 53="DNS"; 67="DHCP";
    80="HTTP"; 110="POP3"; 113="Ident"; 123="NTP"; 135="RPC"; 143="IMAP"; 
    161="SNMP"; 443="HTTPS"; 445="SMB"; 631="IPP"; 993="IMAPS"; 995="POP3S"; 
    1433="MSSQL"; 3306="MySQL"; 3389="RDP"; 5432="PostgreSQL"; 5900="VNC/RFB";
    8000="HTTP-Alt"; 8080="HTTP-Proxy"; 8443="HTTPS-Alt"; 9050="Tor";
    9100="JetDirect"
}

if ($Ports) { $PortsToScan = $Ports | Sort-Object -Unique } 
else { $PortsToScan = $MasterPortMap.Keys | Sort-Object }

$IPList = @()
$SubnetToProcess = @()

# Handle -Range "local"
if ($Range -contains "local") {
    $Range = $Range | Where-Object { $_ -ne "local" }
    $LocalInterfaces = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' }
    foreach ($Interface in $LocalInterfaces) {
        $SubnetToProcess += "$($Interface.IPAddress)/$($Interface.PrefixLength)"
    }
}

# --- AUTO DETECT LOGIC ---
if (-not $Range -and -not $Subnet -and $SubnetToProcess.Count -eq 0) {
    $Interface = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1
    if ($Interface) {
        $Detected = "$($Interface.IPv4Address.IPAddress)/$($Interface.IPv4Address.PrefixLength)"
        Write-Log "Auto-detected Subnet: $Detected" -Color Cyan
        $SubnetToProcess += $Detected
    } else {
        Write-Error "Could not auto-detect network. Please specify -Range or -Subnet."
        return
    }
}

# Add explicitly passed subnets
if ($Subnet) { $SubnetToProcess += $Subnet }

# --- IP CALCULATION ---

# Process Subnets
foreach ($S in $SubnetToProcess) {
    try {
        $IP, $Prefix = $S.Split('/')
        $BaseInt = Convert-IpToInt64 $IP
        $MaskInt = [uint32]::MaxValue -shl (32 - [int]$Prefix)
        $NetworkInt = $BaseInt -band $MaskInt
        $BroadcastInt = $NetworkInt -bor (-bnot $MaskInt)
        
        Write-Log "Adding Subnet: $S" -Color Gray
        for ($i = $NetworkInt + 1; $i -lt $BroadcastInt; $i++) { 
            $IPList += Convert-Int64ToIp $i 
        }
    } catch { Write-Error "Invalid CIDR format: $S"; continue }
}

# Process Ranges
if ($Range) {
    foreach ($R in $Range) {
        if ($R -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$") {
            Write-Log "Adding Range: $R" -Color Gray
            $matches[2]..$matches[3] | ForEach-Object { $IPList += "$($matches[1])$_" }
        }
        elseif ($R -match "^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$") {
            Write-Log "Adding Range: $R" -Color Gray
            $Start = Convert-IpToInt64 $matches[1]; $End = Convert-IpToInt64 $matches[2]
            for ($i = $Start; $i -le $End; $i++) { $IPList += Convert-Int64ToIp $i }
        }
        else {
            Write-Error "Invalid Range format: $R"
        }
    }
}

# Remove duplicates
$IPList = $IPList | Select-Object -Unique

if ($IPList.Count -eq 0) {
    Write-Warning "No valid IPs found to scan."
    return
}

# --- 5. EXECUTE RUNSPACE POOL ---

Write-Log "Scanning $($IPList.Count) IPs with $Threads threads..." -Color Cyan

$Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
$Pool.Open()
$Tasks = @()

foreach ($TargetIP in $IPList) {
    $Pipeline = [PowerShell]::Create()
    $Pipeline.RunspacePool = $Pool
    [void]$Pipeline.AddScript($WorkerBlock)
    [void]$Pipeline.AddArgument($TargetIP)
    [void]$Pipeline.AddArgument($PortsToScan)
    [void]$Pipeline.AddArgument($MasterPortMap)
    [void]$Pipeline.AddArgument($TcpConnect)
    [void]$Pipeline.AddArgument($ListenOnly)
    $Tasks += [PSCustomObject]@{ Pipe = $Pipeline; Handle = $Pipeline.BeginInvoke() }
}

$RawResults = @()
$Done = 0; $Total = $Tasks.Count

while ($Tasks.Handle -ne $null) {
    $Completed = $Tasks | Where-Object { $_.Handle.IsCompleted }
    foreach ($Task in $Completed) {
        try {
            $Result = $Task.Pipe.EndInvoke($Task.Handle)
            if ($Result) { $RawResults += $Result }
        } catch {} finally {
            $Task.Pipe.Dispose(); $Task.Handle = $null
        }
        $Done++
        if (-not $Quiet) { Write-Progress -Activity "Scanning Network" -Status "Progress" -PercentComplete (($Done / $Total) * 100) }
    }
    Start-Sleep -Milliseconds 50
}
$Pool.Close(); $Pool.Dispose()

# --- 6. POST-PROCESSING (VENDOR LOOKUP & PROPER SORT) ---

# Resolve MAC Vendors
$MacsFound = $RawResults | Where-Object { $_.MAC -ne $null }

if ($MacsFound) {
    Write-Log "Resolving MAC Vendors..." -Color Cyan
    Get-OuiDatabase
    $OuiMap = Parse-OuiDatabase
    
    foreach ($Item in $RawResults) {
        if ($Item.MAC) {
            $Prefix = $Item.MAC.Substring(0, 8)
            if ($OuiMap.ContainsKey($Prefix)) {
                $Item.Vendor = $OuiMap[$Prefix]
            }
        }
    }
}

# Clean numerical sort using a trimmed version object structure.
# This avoids lexicographical layout issues without modifying output display format strings.
$FinalResults = $RawResults | Sort-Object { [Version]($_.IP.Trim()) }

# --- 7. OUTPUT ---

switch ($OutputFormat) {
    "GridView" { 
        $FinalResults | Select-Object IP, Name, MAC, Vendor, Ports | Out-GridView -Title "Scanner Results ($($FinalResults.Count) Found)" 
        Write-Log "Found $($FinalResults.Count) devices." -Color Green
    }
    "Json" { 
        $FinalResults | Select-Object IP, Name, MAC, Vendor, Ports | ConvertTo-Json -Depth 2 -Compress 
    }
    "Object" { 
        return ($FinalResults | Select-Object IP, Name, MAC, Vendor, Ports)
    }
}