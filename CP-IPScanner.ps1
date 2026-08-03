# ==============================================================================
# AUTHOR: Lucas IT Services (LITS)
# FILE: CP-IPScanner.ps1
# DESCRIPTION: Multithreaded IP Scanner with GUI or CLI interface
# Revision 2.0
# ==============================================================================

<#
.SYNOPSIS
    A high-performance, multithreaded IP scanner using PowerShell Runspaces.

.DESCRIPTION
    Scans ranges of IP addresses and/or CIDR subnets to identify active devices.
    Features an interactive web-based GUI with a strict reverse-watchdog fail-safe.

.PARAMETER Range
    Specifies one or more IP address ranges to scan.
    Supported formats:
    - Octet range: "192.168.1.1-50"
    - Full IP range: "10.0.0.1-10.0.0.254"

.PARAMETER Subnet
    Specifies one or more subnets in CIDR notation to scan (e.g., "192.168.1.0/24").

.PARAMETER TcpConnect
    If specified, skips initial ICMP ping checks and directly attempts TCP connect scans 
    on specified ports. Useful for networks blocking ICMP traffic.

.PARAMETER UpdateDatabases
    Forces an update of the locally cached IEEE OUI and IANA port mapping databases 
    from their upstream remote sources.

.PARAMETER Ports
    An array of target TCP ports to check on each discovered host.
    If omitted, defaults to standard infrastructure ports (20, 21, 22, 23, 25, 53, 80, 135, 161, 443, 445, 1433, 3306, 3389, 4433, 8000, 8080, 8443, 9443).

.PARAMETER Threads
    The maximum number of concurrent runspaces allocated to the scanning pool. Default is 64.

.PARAMETER GUI
    Launches the interactive web-based graphical user interface via a local HttpListener.

.PARAMETER OutputFormat
    Defines the output structure for CLI execution. Options:
    - "Object" (Default): Returns PSCustomObjects to the pipeline.
    - "GridView": Spawns an Out-GridView window displaying the results.
    - "Json": Returns raw compressed JSON text to stdout.

.PARAMETER Quiet
    Suppresses console progress output during CLI execution.

.EXAMPLE
    .\CP-IPScanner.ps1 -Subnet "192.168.1.0/24" -GUI
    Launches the web GUI pre-populated with the target subnet 192.168.1.0/24.

.EXAMPLE
    .\CP-IPScanner.ps1 -Range "10.0.10.1-100" -Ports 80,443,3389 -OutputFormat GridView
    Scans the specified range on ports 80, 443, and 3389 via CLI and displays the results in Out-GridView.
#>

[CmdletBinding(DefaultParameterSetName = 'CliStream')]
Param(
    [Parameter(ParameterSetName = 'CliStream')]
    [Parameter(ParameterSetName = 'GuiWindow')]
    [string[]]$Range,

    [Parameter(ParameterSetName = 'CliStream')]
    [Parameter(ParameterSetName = 'GuiWindow')]
    [string[]]$Subnet,

    [Parameter(ParameterSetName = 'CliStream')]
    [Parameter(ParameterSetName = 'GuiWindow')]
    [switch]$TcpConnect,

    [Parameter(ParameterSetName = 'CliStream')]
    [Parameter(ParameterSetName = 'GuiWindow')]
    [switch]$UpdateDatabases,

    [Parameter(ParameterSetName = 'CliStream')]
    [Parameter(ParameterSetName = 'GuiWindow')]
    [int[]]$Ports,

    [Parameter(ParameterSetName = 'GuiWindow')]
    [Parameter(ParameterSetName = 'CliStream')]
    [int]$Threads = 64,

    [Parameter(Mandatory = $false, ParameterSetName = 'GuiWindow')]
    [switch]$GUI,

    [Parameter(ParameterSetName = 'CliStream')]
    [ValidateSet("GridView", "Json", "Object")]
    [string]$OutputFormat = "Object",

    [Parameter(ParameterSetName = 'CliStream')]
    [switch]$Quiet
)

$AlwaysUseGUI = $True
$RunGUI = $GUI -or $AlwaysUseGUI

# Helper function to detect all active non-reserved network CIDRs across all interfaces
function Get-AutoDetectedSubnets {
    $DetectedSubnets = @()

    $IpAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
        $_.IPAddress -notlike "127.*" -and 
        $_.IPAddress -notlike "169.254.*" -and 
        $_.IPAddress -ne "0.0.0.0"
    }

    foreach ($Addr in $IpAddresses) {
        $Interface = Get-NetAdapter -InterfaceIndex $Addr.InterfaceIndex -ErrorAction SilentlyContinue
        if ($Interface -and $Interface.Status -eq "Up") {
            $IpStr = $Addr.IPAddress
            $Prefix = $Addr.PrefixLength
            if (-not $Prefix) { $Prefix = 24 }

            try {
                [ipaddress]$ipAddrObj = $IpStr
                $bytes = $ipAddrObj.GetAddressBytes()
                if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
                $ipInt = [BitConverter]::ToUInt32($bytes, 0)

                $maskInt = [uint32]::MaxValue -shl (32 - [int]$Prefix)
                $netInt = $ipInt -band $maskInt

                $netBytes = [BitConverter]::GetBytes([uint32]$netInt)
                if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($netBytes) }
                $netIp = ([ipaddress]$netBytes).IPAddressToString

                $Cidr = "$netIp/$Prefix"
                if ($DetectedSubnets -notcontains $Cidr) {
                    $DetectedSubnets += $Cidr
                }
            } catch {}
        }
    }

    if ($DetectedSubnets.Count -eq 0) {
        return @("192.168.1.0/24")
    }
    return $DetectedSubnets
}

# ==============================================================================
# 1. CORE SCANNING ENGINE
# ==============================================================================
function Invoke-CoreScannerEngine {
    [CmdletBinding()]
    Param(
        [string[]]$Range,
        [string[]]$Subnet,
        [switch]$TcpConnect,
        [switch]$UpdateDatabases,
        [int[]]$Ports,
        [int]$Threads = 64,
        [switch]$IsGuiRunning
    )

    $OuiUrl = "http://standards-oui.ieee.org/oui/oui.txt"
    $OuiCachePath = Join-Path $env:TEMP "oui_database.txt"
    $IanaUrl = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    $IanaCachePath = Join-Path $env:TEMP "iana_ports_database.csv"

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

    if (Test-Path $OuiCachePath) {
        if ($UpdateDatabases -or ((Get-Date) - (Get-Item $OuiCachePath).LastWriteTime -gt (New-TimeSpan -Days 30))) {
            try { Invoke-WebRequest -Uri $OuiUrl -OutFile $OuiCachePath -UseBasicParsing } catch {}
        }
    } else {
        try { Invoke-WebRequest -Uri $OuiUrl -OutFile $OuiCachePath -UseBasicParsing } catch {}
    }

    $OuiMap = @{}
    if (Test-Path $OuiCachePath) {
        Get-Content $OuiCachePath | Where-Object { $_ -match "\(hex\)" } | ForEach-Object {
            if ($_ -match "^([0-9A-F-]{8})\s+\(hex\)\s+(.+)$") {
                $Prefix = $matches[1].Replace("-", ":").Trim().Substring(0,8)
                $OuiMap[$Prefix] = $matches[2].Trim()
            }
        }
    }

    if (Test-Path $IanaCachePath) {
        if ($UpdateDatabases -or ((Get-Date) - (Get-Item $IanaCachePath).LastWriteTime -gt (New-TimeSpan -Days 30))) {
            try { Invoke-WebRequest -Uri $IanaUrl -OutFile $IanaCachePath -UseBasicParsing } catch {}
        }
    } else {
        try { Invoke-WebRequest -Uri $IanaUrl -OutFile $IanaCachePath -UseBasicParsing } catch {}
    }

    $MasterPortMap = @{
        20="FTP-Data"; 21="FTP"; 22="SSH"; 25="SMTP"; 53="DNS"; 80="HTTP"; 135="RPC"; 
        161="SNMP"; 443="HTTPS"; 445="SMB"; 1433="MSSQL"; 3306="MySQL"; 3389="RDP";
        4433="HTTPS-Alt"; 8000="HTTP-Alt"; 8080="HTTP-Proxy"; 8443="HTTPS-Alt"; 9443="HTTPS-Alt"
    }

    if (Test-Path $IanaCachePath) {
        try {
            $CsvData = Import-Csv -Path $IanaCachePath -ErrorAction SilentlyContinue
            foreach ($Row in $CsvData) {
                if ($Row.'Transport Protocol' -eq 'tcp' -and -not [string]::IsNullOrEmpty($Row.'Port Number') -and -not [string]::IsNullOrEmpty($Row.'Service Name')) {
                    if ($Row.'Port Number' -match '^\d+$') {
                        $PNum = [int]$Row.'Port Number'
                        if (-not $MasterPortMap.ContainsKey($PNum)) {
                            $MasterPortMap[$PNum] = $Row.'Service Name'
                        }
                    }
                }
            }
        } catch {}
    }
    
    $DefaultInfraPorts = @(20, 21, 22, 23, 25, 53, 80, 135, 161, 443, 445, 1433, 3306, 3389, 4433, 8000, 8080, 8443, 9443)
    $PortsToScan = if ($Ports) { $Ports | Sort-Object -Unique } else { $DefaultInfraPorts | Sort-Object }

    $WorkerBlock = {
        Param($TargetIP, $PortsToScan, $MasterPortMap, $TcpConnect)

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
                if ($NbtOutput -match "\s+([A-Za-z0-9-_]+)\s+<00>\s+UNIQUE") { return $matches[1].Trim() }
            } catch {}
            return $null
        }

        $IsAlive = $false
        if ($TcpConnect) { $IsAlive = $true } 
        else { if (Test-Connection -ComputerName $TargetIP -Count 1 -Quiet) { $IsAlive = $true } }

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
            if ($TcpConnect -and $DetectedPorts.Count -eq 0) { return $null }

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

    $IPList = @()
    foreach ($S in $Subnet) {
        try {
            $IP, $Prefix = $S.Split('/')
            $BaseInt = Convert-IpToInt64 $IP
            $MaskInt = [uint32]::MaxValue -shl (32 - [int]$Prefix)
            $NetworkInt = $BaseInt -band $MaskInt
            $BroadcastInt = $NetworkInt -bor (-bnot $MaskInt)
            for ($i = $NetworkInt + 1; $i -lt $BroadcastInt; $i++) { $IPList += Convert-Int64ToIp $i }
        } catch { continue }
    }
    foreach ($R in $Range) {
        if ($R -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$") {
            $matches[2]..$matches[3] | ForEach-Object { $IPList += "$($matches[1])$_" }
        }
        elseif ($R -match "^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$") {
            $Start = Convert-IpToInt64 $matches[1]; $End = Convert-IpToInt64 $matches[2]
            for ($i = $Start; $i -le $End; $i++) { $IPList += Convert-Int64ToIp $i }
        }
    }
    $IPList = $IPList | Select-Object -Unique
    if ($IPList.Count -eq 0) { return @() }

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
        $Tasks += [PSCustomObject]@{ Pipe = $Pipeline; Handle = $Pipeline.BeginInvoke(); Completed = $false }
    }

    $RawResults = @()
    $Done = 0; $Total = $Tasks.Count

    while ($Done -lt $Total) {
        $Pending = $Tasks | Where-Object { -not $_.Completed -and $_.Handle.IsCompleted }
        foreach ($Task in $Pending) {
            try {
                $Result = $Task.Pipe.EndInvoke($Task.Handle)
                if ($Result) { $RawResults += $Result }
            } catch {} finally { 
                $Task.Pipe.Dispose()
                $Task.Completed = $true
            }
            $Done++
            if (-not $IsGuiRunning -and -not $Quiet) { 
                Write-Progress -Activity "Scanning Network" -Status "Progress" -PercentComplete (($Done / $Total) * 100) 
            }
        }
        
        if ($IsGuiRunning -and $IsWindows) { 
            if ([Type]::GetType("System.Windows.Forms.Application, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")) {
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
        Start-Sleep -Milliseconds 20
    }
    $Pool.Close(); $Pool.Dispose()

    foreach ($Item in $RawResults) {
        if ($Item.MAC) {
            $Prefix = $Item.MAC.Substring(0, 8)
            if ($OuiMap.ContainsKey($Prefix)) { $Item.Vendor = $OuiMap[$Prefix] }
        }
    }

    return $RawResults | Sort-Object { [int[]]($_.IP -split '\.') }
}

# ==============================================================================
# 2. RUNTIME CONDITIONAL BLOCK
# ==============================================================================
if ($RunGUI) {
    $TempSocket = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $TempSocket.Start()
    $Port = ($TempSocket.LocalEndpoint -as [System.Net.IPEndPoint]).Port
    $TempSocket.Stop()

    $Listener = [System.Net.HttpListener]::new()
    $Listener.Prefixes.Add("http://localhost:$Port/")
    
    try {
        $Listener.Start()
        
        $AutoSubnets = Get-AutoDetectedSubnets
        $DefaultTarget = $AutoSubnets -join ', '

        if ($Subnet) { $DefaultTarget = $Subnet -join ', ' }
        elseif ($Range) { $DefaultTarget = $Range -join ', ' }

        $DefaultPortsText = if ($Ports) { $Ports -join ', ' } else { "20, 21, 22, 23, 25, 53, 80, 135, 161, 443, 445, 1433, 3306, 3389, 4433, 8000, 8080, 8443, 9443" }
        $TcpChecked = if ($TcpConnect) { "checked" } else { "" }
        $DbChecked = if ($UpdateDatabases) { "checked" } else { "" }

        Write-Host "GUI active at http://localhost:$Port" -ForegroundColor Cyan
        if ($IsWindows -or $env:OS -like "*Windows*") {
            Start-Process "http://localhost:$Port"
        } elseif ($IsMacOS) {
            open "http://localhost:$Port"
        } elseif ($IsLinux) {
            xdg-open "http://localhost:$Port"
        }

        $Running = $true
        $LastWatchdogTick = [DateTime]::Now

        while ($Running -and $Listener.IsListening) {
            $ContextAsyncResult = $Listener.BeginGetContext($null, $null)
            
            while (-not $ContextAsyncResult.IsCompleted -and $Running -and $Listener.IsListening) {
                if (([DateTime]::Now - $LastWatchdogTick).TotalMilliseconds -gt 2000) {
                    Write-Host "Watchdog timeout crossed (5s limit exceeded). Terminating." -ForegroundColor Red
                    $Running = $false
                    break
                }
                Start-Sleep -Milliseconds 25
            }

            if (-not $Running) { break }

            $Context = $Listener.EndGetContext($ContextAsyncResult)
            $Request = $Context.Request
            $Response = $Context.Response

            if ($Request.Url.AbsolutePath -eq '/heartbeat') {
                $LastWatchdogTick = [DateTime]::Now
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes("ok")
                $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
            } elseif ($Request.HttpMethod -eq 'GET') {
                $LastWatchdogTick = [DateTime]::Now
                $Html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>LITS Network Scanner</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 50 50'><path fill='%230078d4' fill-rule='evenodd' d='M 25 0 A 24.999868 25.000025 0 0 0 0 25 A 24.999868 25.000025 0 0 0 25 50 A 24.999868 25.000025 0 0 0 50 25 A 24.999868 25.000025 0 0 0 25 0 z M 25 6.9960938 A 18.000229 18.000229 0 0 1 43 24.996094 A 18.000229 18.000229 0 0 1 25 42.996094 A 18.000229 18.000229 0 0 1 7 24.996094 A 18.000229 18.000229 0 0 1 25 6.9960938 z M 21.496094 12 A 0.5 0.5 0 0 0 20.996094 12.5 L 20.996094 25.701172 A 0.5 0.5 0 0 1 20.496094 26.201172 L 11.998047 11.998047 26.201172 A 0.18766001 0.18766001 0 0 0 11.875 26.529297 L 24.623047 37.669922 A 0.57222682 0.57222682 0 0 0 25.376953 37.669922 L 38.123047 26.529297 A 0.18768046 0.18768046 0 0 0 38 26.201172 L 29.5 26.201172 A 0.5 0.5 0 0 1 29 25.701172 L 29 12.5 A 0.5 0.5 0 0 0 28.5 12 L 21.496094 12 z'/></svg>">
    <style>
        :root {
            --bg-main: #121214;
            --bg-panel: #1a1a1e;
            --bg-input: #26262b;
            --border-color: #323238;
            --text-main: #e1e1e6;
            --text-muted: #a8a8b3;
            --accent: #0078d4;
            --accent-hover: #005a9e;
            --danger: #f75a68;
            --table-stripe: #202024;
        }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background-color: var(--bg-main);
            color: var(--text-main);
            padding: 30px; 
            margin: 0;
            line-height: 1.5; 
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .panel {
            background-color: var(--bg-panel);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        }
        .header-title {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-top: 0; 
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
        }
        .header-title svg {
            width: 32px;
            height: 32px;
            flex-shrink: 0;
        }
        h2 { 
            margin: 0;
            font-weight: 600;
            color: #fff;
            font-size: 24px;
        }
        .form-group {
            margin-bottom: 16px;
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-muted);
        }
        input[type="text"] { 
            width: 100%; 
            box-sizing: border-box;
            padding: 10px 14px; 
            background-color: var(--bg-input);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-main);
            font-size: 15px;
            transition: border-color 0.2s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: var(--accent);
        }
        .checkbox-group {
            display: flex;
            gap: 24px;
            margin: 20px 0;
        }
        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            font-size: 14px;
            color: var(--text-main);
        }
        .checkbox-label input {
            cursor: pointer;
            accent-color: var(--accent);
            width: 16px;
            height: 16px;
        }
        button { 
            padding: 10px 20px; 
            font-size: 14px;
            font-weight: 600;
            border-radius: 6px;
            border: none;
            cursor: pointer; 
            transition: background-color 0.2s, transform 0.1s;
        }
        button:active {
            transform: scale(0.98);
        }
        .btn-primary {
            background-color: var(--accent);
            color: #fff;
        }
        .btn-primary:hover {
            background-color: var(--accent-hover);
        }
        .btn-secondary {
            background-color: var(--bg-input);
            color: var(--text-main);
            border: 1px solid var(--border-color);
        }
        .btn-secondary:hover {
            background-color: var(--border-color);
        }
        .table-responsive {
            overflow-x: auto;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            font-size: 14px;
            background-color: var(--bg-panel);
        }
        th, td { 
            padding: 12px 16px; 
            text-align: left; 
            border-bottom: 1px solid var(--border-color);
        }
        th { 
            background-color: #202024; 
            color: #fff;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }
        th:hover {
            background-color: #2a2a30;
        }
        tr:nth-child(even) td { 
            background-color: var(--table-stripe); 
        }
        tr:hover td {
            background-color: #29292e;
        }
        td a {
            color: var(--accent);
            text-decoration: none;
        }
        td a:hover {
            text-decoration: underline;
        }
        .copyable-link {
            cursor: pointer;
        }
        .copyable-link:hover {
            text-decoration: underline;
        }
        .copy-note {
            font-size: 11px;
            color: #4caf50;
            margin-left: 4px;
            font-weight: bold;
        }
        .offline-banner { 
            color: #fff; 
            background-color: var(--danger); 
            padding: 16px; 
            margin-bottom: 24px; 
            border-radius: 6px; 
            font-weight: 600; 
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .hidden { 
            display: none !important; 
        }
        .status-msg {
            font-weight: 500;
            color: var(--text-muted);
            padding: 12px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .spinner {
            width: 18px;
            height: 18px;
            border: 2px solid var(--border-color);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .action-bar {
            margin-top: 16px;
            display: flex;
            justify-content: flex-end;
        }
    </style>
</head>
<body>
    <div class="container">
        <div id="status-container"></div>
        
        <div id="controls-wrapper" class="panel">
            <div class="header-title">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 50 50" width="100%" height="100%">
                    <path 
                        fill="var(--accent)" 
                        fill-rule="evenodd" 
                        d="M 25 0 A 24.999868 25.000025 0 0 0 0 25 A 24.999868 25.000025 0 0 0 25 50 A 24.999868 25.000025 0 0 0 50 25 A 24.999868 25.000025 0 0 0 25 0 z M 25 6.9960938 A 18.000229 18.000229 0 0 1 43 24.996094 A 18.000229 18.000229 0 0 1 25 42.996094 A 18.000229 18.000229 0 0 1 7 24.996094 A 18.000229 18.000229 0 0 1 25 6.9960938 z M 21.496094 12 A 0.5 0.5 0 0 0 20.996094 12.5 L 20.996094 25.701172 A 0.5 0.5 0 0 1 20.496094 26.201172 L 11.998047 26.201172 A 0.18766001 0.18766001 0 0 0 11.875 26.529297 L 24.623047 37.669922 A 0.57222682 0.57222682 0 0 0 25.376953 37.669922 L 38.123047 26.529297 A 0.18768046 0.18768046 0 0 0 38 26.201172 L 29.5 26.201172 A 0.5 0.5 0 0 1 29 25.701172 L 29 12.5 A 0.5 0.5 0 0 0 28.5 12 L 21.496094 12 z" 
                    />
                </svg>
                <h2>LITS Network Scanner</h2>
            </div>
            <div class="form-group">
                <label for="t">Scan Targets (CIDR or Ranges comma-separated)</label>
                <input type="text" id="t" value="$DefaultTarget">
            </div>
            <div class="form-group">
                <label for="p">Target Ports</label>
                <input type="text" id="p" value="$DefaultPortsText">
            </div>
            <div class="checkbox-group">
                <label class="checkbox-label">
                    <input type="checkbox" id="tcp" $TcpChecked>
                    TCP Connect Method Only
                </label>
                <label class="checkbox-label">
                    <input type="checkbox" id="upd" $DbChecked>
                    Force DB Cache Reload
                </label>
            </div>
            <button id="btn-scan" class="btn-primary" onclick="s()">Execute Scan</button>
        </div>
        
        <div id="r"></div>
    </div>

    <script>
        let lastRes = [];
        let sortCol = 'IP';
        let sortAsc = true;
        
        function setOfflineUI(message) {
            document.getElementById('controls-wrapper').classList.add('hidden');
            const resDiv = document.getElementById('r');
            const expBtn = resDiv.querySelector('button');
            if(expBtn) expBtn.remove();
            
            document.getElementById('status-container').innerHTML = '<div class="offline-banner">' + message + '</div>';
        }

        function checkBackend() {
            fetch('/heartbeat')
                .catch(() => {
                    setOfflineUI('Backend connection lost. The browser session has been terminated.');
                });
        }

        setInterval(checkBackend, 100);

        document.addEventListener('visibilitychange', function() {
            if (!document.hidden) {
                checkBackend();
            }
        });

        function ipToInt(ip) {
            if (!ip) return 0;
            const parts = ip.split('.').map(Number);
            return ((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
        }

        function makeCopyable(text) {
            if (!text) return '';
            const safeText = ('' + text).replace(/'/g, "\\'").replace(/"/g, '&quot;');
            return '<a class="copyable-link" onclick="copyToClipboard(\'' + safeText + '\', this)">' + text + '</a>';
        }

        function copyToClipboard(text, elem) {
            navigator.clipboard.writeText(text).then(function() {
                let existing = elem.querySelector('.copy-note');
                if (!existing) {
                    let note = document.createElement('span');
                    note.className = 'copy-note';
                    note.innerText = ' (Copied!)';
                    elem.appendChild(note);
                    setTimeout(function() {
                        note.remove();
                    }, 2000);
                }
            });
        }

        function formatPorts(portsStr, ip) {
            if (!portsStr) return '';
            const ports = portsStr.split(', ');
            return ports.map(function(entry) {
                const match = entry.match(/^(\d+)(?:\s*\((.*?)\))?$/);
                if (!match) return makeCopyable(entry);
                const portNum = parseInt(match[1], 10);
                const serviceName = match[2] || '';

                let proto = null;
                if (portNum === 21) proto = 'ftp';
                else if (portNum === 80 || portNum === 8000 || portNum === 8080) proto = 'http';
                else if (portNum === 443 || portNum === 4433 || portNum === 8443 || portNum === 9443) proto = 'https';

                if (proto) {
                    const label = serviceName ? portNum + ' (' + serviceName + ')' : '' + portNum;
                    return '<a href="' + proto + '://' + ip + ':' + portNum + '" target="_blank" rel="noopener noreferrer">' + label + '</a>';
                }
                return makeCopyable(entry);
            }).join(', ');
        }

        function sortData(col) {
            if (sortCol === col) {
                sortAsc = !sortAsc;
            } else {
                sortCol = col;
                sortAsc = true;
            }
            renderTable();
        }

        function renderTable() {
            if (!lastRes || lastRes.length === 0) return;

            lastRes.sort((a, b) => {
                let valA = a[sortCol] || '';
                let valB = b[sortCol] || '';
                let res = 0;

                if (sortCol === 'IP') {
                    res = ipToInt(valA) - ipToInt(valB);
                } else {
                    res = valA.toString().localeCompare(valB.toString(), undefined, {numeric: true, sensitivity: 'base'});
                }
                return sortAsc ? res : -res;
            });

            const getArrow = (col) => {
                if (sortCol !== col) return '';
                return sortAsc ? ' &#9650;' : ' &#9660;';
            };

            let html = '<div class="panel"><h2>Scan Mappings (' + lastRes.length + ' Active Elements)</h2><div class="table-responsive"><table><tr>';
            html += '<th onclick="sortData(\'IP\')">IP Target' + getArrow('IP') + '</th>';
            html += '<th onclick="sortData(\'Name\')">Dns Name/NetBIOS' + getArrow('Name') + '</th>';
            html += '<th onclick="sortData(\'MAC\')">Hardware MAC' + getArrow('MAC') + '</th>';
            html += '<th onclick="sortData(\'Vendor\')">NIC Vendor' + getArrow('Vendor') + '</th>';
            html += '<th onclick="sortData(\'Ports\')">Active Ports' + getArrow('Ports') + '</th></tr>';

            lastRes.forEach(i => {
                const formattedPorts = formatPorts(i.Ports, i.IP);
                html += '<tr><td>'+makeCopyable(i.IP || '')+'</td><td>'+makeCopyable(i.Name || '')+'</td><td>'+makeCopyable(i.MAC || '')+'</td><td>'+makeCopyable(i.Vendor || '')+'</td><td>'+formattedPorts+'</td></tr>';
            });

            document.getElementById('r').innerHTML = html + '</table></div><div class="action-bar"><button class="btn-secondary" onclick="exp()">Export CSV</button></div></div>';
        }

        function s(){
            document.getElementById('r').innerHTML = '<div class="status-msg"><div class="spinner"></div>Scanning target infrastructure... please wait.</div>';
            fetch('/', {
                method: 'POST', 
                body: JSON.stringify({
                    t: document.getElementById('t').value, 
                    p: document.getElementById('p').value, 
                    tcp: document.getElementById('tcp').checked, 
                    f: document.getElementById('upd').checked
                })
            })
            .then(res => {
                if(!res.ok) throw new Error();
                return res.json();
            })
            .then(data => {
                lastRes = data;
                sortCol = 'IP';
                sortAsc = true;
                renderTable();
            })
            .catch(() => {
                setOfflineUI('Scan execution failed. The backend server has dropped offline.');
            });
        }
        
        function exp(){
            if (!lastRes || lastRes.length === 0) return;
            
            const headers = ['IP', 'Name', 'MAC', 'Vendor', 'Ports'];
            const csvRows = [headers.join(',')];
            
            lastRes.forEach(item => {
                const values = headers.map(header => {
                    const val = item[header] || '';
                    const escaped = ('' + val).replace(/"/g, '""');
                    return '"' + escaped + '"';
                });
                csvRows.push(values.join(','));
            });
            
            const blob = new Blob([csvRows.join('\n')], {type: 'text/csv;charset=utf-8;'});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'scan_results.csv';
            a.click();
        }
    </script>
</body>
</html>
"@
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes($Html)
                $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
            } else {
                $Reader = [System.IO.StreamReader]::new($Request.InputStream)
                $Data = $Reader.ReadToEnd() | ConvertFrom-Json
                
                $PortArray = @()
                if ($Data.p) {
                    $PortArray = ($Data.p -split ',') | ForEach-Object { [int]$_.Trim() }
                }

                $PassedTargets = ($Data.t -split ',') | ForEach-Object { $_.Trim() }
                $TargetSubnets = @(); $TargetRanges = @()

                foreach ($Target in $PassedTargets) {
                    if ($Target -match '/') { $TargetSubnets += $Target }
                    else { $TargetRanges += $Target }
                }

                $Results = Invoke-CoreScannerEngine -Subnet $TargetSubnets -Range $TargetRanges -Ports $PortArray -TcpConnect:$Data.tcp -UpdateDatabases:$Data.f -IsGuiRunning:$true
                
                $LastWatchdogTick = [DateTime]::Now
                $Json = $Results | ConvertTo-Json
                $Buffer = [System.Text.Encoding]::UTF8.GetBytes($Json)
                $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)
            }
            $Response.Close()
        }
    } finally {
        $Listener.Stop()
        $Listener.Close()
        Write-Host "Scan session complete. Watchdog terminated backend listener cleanly." -ForegroundColor Yellow
    }
} else {
    # --- Standard CLI Execution Pathway ---
    if (-not $Range -and -not $Subnet) {
        $Subnet = Get-AutoDetectedSubnets
        if (-not $Quiet) { Write-Host "Auto-detected Subnets: $($Subnet -join ', ')" -ForegroundColor Cyan }
    }

    $CliParams = @{
        Range           = $Range
        Subnet          = $Subnet
        TcpConnect      = $TcpConnect
        UpdateDatabases = $UpdateDatabases
        Ports           = $Ports
        Threads         = $Threads
        IsGuiRunning    = $false
    }

    $FinalResults = Invoke-CoreScannerEngine @CliParams

    switch ($OutputFormat) {
        "GridView" { 
            $FinalResults | Select-Object IP, Name, MAC, Vendor, Ports | Out-GridView -Title "Scanner Results ($($FinalResults.Count) Found)" 
        }
        "Json" { 
            $FinalResults | Select-Object IP, Name, MAC, Vendor, Ports | ConvertTo-Json -Depth 2 -Compress 
        }
        "Object" { 
            return ($FinalResults | Select-Object IP, Name, MAC, Vendor, Ports)
        }
    }
}