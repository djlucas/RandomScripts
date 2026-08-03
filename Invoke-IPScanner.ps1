# ==============================================================================
# AUTHOR: Lucas IT Services (LITS)
# FILE: Invoke-IPScanner.ps1
# DESCRIPTION: Multithreaded IP Scanner with GUI or CLI interface
# Revision 4.6
# ==============================================================================

<#
.SYNOPSIS
    A high-performance, multithreaded IP scanner using PowerShell Runspaces.

.DESCRIPTION
    Scans ranges of IP addresses and/or CIDR subnets to identify active devices.
    You can mix -Range and -Subnet in a single execution.
    Performs post-scan OUI lookups for vendor identification.
    Features an optional built-in WinForms GUI interface.

    CONFLICTING PARAMETERS:
    - The -GUI switch cannot be combined with -Quiet or -OutputFormat. 
    - Output formatting and silent switches are strictly reserved for CLI stream piping.

.PARAMETER Range
    Defines specific ranges of IP addresses to scan. Accepts multiple strings.
    Format: "192.168.1.10-50" or "192.168.1.100-192.168.2.50"

.PARAMETER Subnet
    Defines CIDR blocks to scan. Accepts multiple strings.
    Example: "192.168.1.0/24", "10.0.0.0/24"

.PARAMETER TcpConnect
    Switch. Skips ICMP (Ping) and relies solely on TCP port connection.

.PARAMETER Ports
    An array of specific TCP ports to scan. Default is top common infrastructure ports.

.PARAMETER Threads
    Integer. Number of concurrent threads (Default: 64).

.PARAMETER OutputFormat
    String. "GridView", "Json", or "Object". 
    DEFAULT: "Object"
    (Exclusive to CLI Engine Execution pathway)

.PARAMETER Quiet
    Switch. Suppresses console output and progress bar metrics.
    (Exclusive to CLI Engine Execution pathway)

.PARAMETER UpdateDatabases
    Switch. Forces a fresh download of both the IEEE OUI and IANA port databases.

.PARAMETER GUI
    Switch. Launches the interactive WinForms graphical user interface.
    When this switch is used, text parameters are optional and used as GUI defaults.

.EXAMPLE
    .\Invoke-IPScanner.ps1
    Auto-detects the local subnet and scans it, returning standard objects.
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

    [Parameter(ParameterSetName = 'CliStream')]
    [Parameter(ParameterSetName = 'GuiWindow')]
    [int]$Threads = 64,

    # Strictly Exclusive to the GUI Pathway
    [Parameter(Mandatory = $false, ParameterSetName = 'GuiWindow')]
    [switch]$GUI,

    # Strictly Exclusive to the CLI Pathway
    [Parameter(ParameterSetName = 'CliStream')]
    [ValidateSet("GridView", "Json", "Object")]
    [string]$OutputFormat = "Object",

    [Parameter(ParameterSetName = 'CliStream')]
    [switch]$Quiet
)

$AlwaysUseGUI = $false

# Determine if GUI should run based on switch or constant
$RunGUI = $GUI -or $AlwaysUseGUI

# ==============================================================================
# GLOBAL HELPER FUNCTIONS
# ==============================================================================
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

                $maskInt = if ($Prefix -eq 0) { 0 } else { [uint32]::MaxValue -shl (32 - [int]$Prefix) }
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

    # --- Data Source Sync Definitions ---
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

    # --- IEEE OUI Cache Verification ---
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

    # --- IANA Ports Cache Verification ---
    if (Test-Path $IanaCachePath) {
        if ($UpdateDatabases -or ((Get-Date) - (Get-Item $IanaCachePath).LastWriteTime -gt (New-TimeSpan -Days 30))) {
            try { Invoke-WebRequest -Uri $IanaUrl -OutFile $IanaCachePath -UseBasicParsing } catch {}
        }
    } else {
        try { Invoke-WebRequest -Uri $IanaUrl -OutFile $IanaCachePath -UseBasicParsing } catch {}
    }

    # Baseline core map for high-speed mapping fallbacks
    $MasterPortMap = @{
        20="FTP-Data"; 21="FTP"; 22="SSH"; 25="SMTP"; 53="DNS"; 80="HTTP"; 135="RPC"; 
        161="SNMP"; 443="HTTPS"; 445="SMB"; 1433="MSSQL"; 3306="MySQL"; 3389="RDP";
        4433="HTTPS-Alt"; 8000="HTTP-Alt"; 8080="HTTP-Proxy"; 8443="HTTPS-Alt"; 9443="HTTPS-Alt"
    }

    # Parse IANA CSV into Master Map dictionary if available
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
    
    # Standard baseline target ports used when no custom overrides are defined via CLI or GUI
    $DefaultInfraPorts = @(20, 21, 22, 23, 25, 53, 80, 135, 161, 443, 445, 1433, 3306, 3389, 4433, 8000, 8080, 8443, 9443)
    $PortsToScan = if ($Ports) { $Ports | Sort-Object -Unique } else { $DefaultInfraPorts | Sort-Object }

    # --- Worker Thread Script Block ---
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

    # --- IP Targeted Boundary Allocations ---
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

    # --- Runspace Orchestration Loop ---
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

    # Tracking completion natively via explicit counter boundaries to prevent array deadlocks
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
        if ($IsGuiRunning) { [System.Windows.Forms.Application]::DoEvents() }
        Start-Sleep -Milliseconds 20
    }
    $Pool.Close(); $Pool.Dispose()

    # --- Append Hardware Vendors ---
    foreach ($Item in $RawResults) {
        if ($Item.MAC) {
            $Prefix = $Item.MAC.Substring(0, 8)
            if ($OuiMap.ContainsKey($Prefix)) { $Item.Vendor = $OuiMap[$Prefix] }
        }
    }

    return $RawResults | Sort-Object { [Version]$_.IP }
}

# ==============================================================================
# 2. RUNTIME CONDITIONAL BLOCK
# ==============================================================================
if ($RunGUI) {
    # --- GUI Execution Pathway ---
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Lucas IT - Network Scanner"
    $form.Size = New-Object System.Drawing.Size(750, 600)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false

    $lblTarget = New-Object System.Windows.Forms.Label
    $lblTarget.Text = "Target Networks / Ranges (Comma separated):"
    $lblTarget.Location = New-Object System.Drawing.Point(20, 15)
    $lblTarget.Size = New-Object System.Drawing.Size(300, 20)
    $form.Controls.Add($lblTarget)

    $txtTarget = New-Object System.Windows.Forms.TextBox
    $txtTarget.Location = New-Object System.Drawing.Point(20, 38)
    $txtTarget.Size = New-Object System.Drawing.Size(430, 20)

    # --- Fixed Layout Initialization Conditionals ---
    if ($Subnet -and $Range) {
        $txtTarget.Text = "$($Subnet -join ', '), $($Range -join ', ')"
    }
    elseif ($Subnet) { 
        $txtTarget.Text = $Subnet -join ", " 
    }
    elseif ($Range) { 
        $txtTarget.Text = $Range -join ", " 
    }
    else {
        $txtTarget.Text = (Get-AutoDetectedSubnets) -join ", "
    }
    $form.Controls.Add($txtTarget)

    # --- Configuration Panel Container ---
    $grpOptions = New-Object System.Windows.Forms.GroupBox
    $grpOptions.Text = "Scan Configurations"
    $grpOptions.Location = New-Object System.Drawing.Point(470, 15)
    $grpOptions.Size = New-Object System.Drawing.Size(245, 130)
    $form.Controls.Add($grpOptions)

    $chkTcpConnect = New-Object System.Windows.Forms.CheckBox
    $chkTcpConnect.Text = "TCP Connect Method Only"
    $chkTcpConnect.Location = New-Object System.Drawing.Point(15, 22)
    $chkTcpConnect.Size = New-Object System.Drawing.Size(200, 20)
    $chkTcpConnect.Checked = $TcpConnect
    $grpOptions.Controls.Add($chkTcpConnect)

    $chkUpdateDatabases = New-Object System.Windows.Forms.CheckBox
    $chkUpdateDatabases.Text = "Force DB Cache Reload"
    $chkUpdateDatabases.Location = New-Object System.Drawing.Point(15, 45)
    $chkUpdateDatabases.Size = New-Object System.Drawing.Size(200, 20)
    $chkUpdateDatabases.Checked = $UpdateDatabases
    $grpOptions.Controls.Add($chkUpdateDatabases)

    # --- Inline Port Selection Controls ---
    $lblPortsInput = New-Object System.Windows.Forms.Label
    $lblPortsInput.Text = "Target TCP Ports (Comma separated):"
    $lblPortsInput.Location = New-Object System.Drawing.Point(15, 73)
    $lblPortsInput.Size = New-Object System.Drawing.Size(215, 15)
    $lblPortsInput.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $grpOptions.Controls.Add($lblPortsInput)

    $txtPortsInput = New-Object System.Windows.Forms.TextBox
    $txtPortsInput.Location = New-Object System.Drawing.Point(15, 91)
    $txtPortsInput.Size = New-Object System.Drawing.Size(215, 20)
    $txtPortsInput.Text = if ($Ports) { $Ports -join ", " } else { "20, 21, 22, 23, 25, 53, 80, 135, 161, 443, 445, 1433, 3306, 3389, 4433, 8000, 8080, 8443, 9443" }
    $grpOptions.Controls.Add($txtPortsInput)

    $btnScan = New-Object System.Windows.Forms.Button
    $btnScan.Text = "Execute Scan"
    $btnScan.Location = New-Object System.Drawing.Point(20, 95)
    $btnScan.Size = New-Object System.Drawing.Size(130, 30)
    $btnScan.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($btnScan)

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text = "Engine Ready."
    $lblStatus.Location = New-Object System.Drawing.Point(160, 103)
    $lblStatus.Size = New-Object System.Drawing.Size(300, 20)
    $lblStatus.ForeColor = [System.Drawing.Color]::Gray
    $form.Controls.Add($lblStatus)

    $lvResults = New-Object System.Windows.Forms.ListView
    $lvResults.Location = New-Object System.Drawing.Point(20, 160)
    $lvResults.Size = New-Object System.Drawing.Size(695, 380)
    $lvResults.View = [System.Windows.Forms.View]::Details
    $lvResults.FullRowSelect = $true
    $lvResults.GridLines = $true

    [void]$lvResults.Columns.Add("IP Target", 110)
    [void]$lvResults.Columns.Add("Dns Name/NetBIOS", 160)
    [void]$lvResults.Columns.Add("Hardware MAC", 130)
    [void]$lvResults.Columns.Add("NIC Vendor", 160)
    [void]$lvResults.Columns.Add("Active Ports", 110)
    $form.Controls.Add($lvResults)

    # --- Right-Click Context Menu Implementation ---
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

    $menuCopyIP = $contextMenu.Items.Add("Copy IP Address")
    $menuCopyIP.Add_Click({
        if ($lvResults.SelectedItems.Count -gt 0) {
            $ip = $lvResults.SelectedItems[0].Text
            if (-not [string]::IsNullOrWhiteSpace($ip)) {
                [System.Windows.Forms.Clipboard]::SetText($ip)
                $lblStatus.Text = "Copied IP ($ip) to clipboard."
                $lblStatus.ForeColor = [System.Drawing.Color]::Green
            }
        }
    })

    $menuCopyMAC = $contextMenu.Items.Add("Copy MAC Address")
    $menuCopyMAC.Add_Click({
        if ($lvResults.SelectedItems.Count -gt 0) {
            $mac = $lvResults.SelectedItems[0].SubItems[2].Text
            if (-not [string]::IsNullOrWhiteSpace($mac)) {
                [System.Windows.Forms.Clipboard]::SetText($mac)
                $lblStatus.Text = "Copied MAC ($mac) to clipboard."
                $lblStatus.ForeColor = [System.Drawing.Color]::Green
            }
        }
    })

    $menuCopyPorts = $contextMenu.Items.Add("Copy Active Ports")
    $menuCopyPorts.Add_Click({
        if ($lvResults.SelectedItems.Count -gt 0) {
            $ports = $lvResults.SelectedItems[0].SubItems[4].Text
            if (-not [string]::IsNullOrWhiteSpace($ports)) {
                [System.Windows.Forms.Clipboard]::SetText($ports)
                $lblStatus.Text = "Copied ports ($ports) to clipboard."
                $lblStatus.ForeColor = [System.Drawing.Color]::Green
            }
        }
    })

    [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

    $menuOpenHTTP = $contextMenu.Items.Add("Open HTTP (Browser)")
    $menuOpenHTTP.Add_Click({
        if ($lvResults.SelectedItems.Count -gt 0) {
            $ip = $lvResults.SelectedItems[0].Text
            if (-not [string]::IsNullOrWhiteSpace($ip)) { Start-Process "http://$ip" }
        }
    })

    $menuOpenHTTPS = $contextMenu.Items.Add("Open HTTPS (Browser)")
    $menuOpenHTTPS.Add_Click({
        if ($lvResults.SelectedItems.Count -gt 0) {
            $ip = $lvResults.SelectedItems[0].Text
            if (-not [string]::IsNullOrWhiteSpace($ip)) { Start-Process "https://$ip" }
        }
    })

    $lvResults.ContextMenuStrip = $contextMenu

    # --- Column Header Sorting Implementation ---
    $script:sortColumn = -1
    $script:sortAscending = $true

    $lvResults.Add_ColumnClick({
        param($sender, $e)
        if ($lvResults.Items.Count -le 1) { return }

        if ($script:sortColumn -eq $e.Column) {
            $script:sortAscending = -not $script:sortAscending
        } else {
            $script:sortColumn = $e.Column
            $script:sortAscending = $true
        }

        $lvResults.BeginUpdate()
        
        # Cast to array explicitly to prevent unrolling issues
        $rawItems = @($lvResults.Items)
        $lvResults.Items.Clear()

        $sortedItems = @($rawItems | Sort-Object -Property @{
            Expression = {
                $val = $_.SubItems[$e.Column].Text
                if ($e.Column -eq 0) {
                    try { [version]$val } catch { $val }
                } else {
                    $val
                }
            }
            Descending = (-not $script:sortAscending)
        })

        if ($sortedItems.Count -gt 0) {
            $typedItems = [System.Windows.Forms.ListViewItem[]]$sortedItems
            $lvResults.Items.AddRange($typedItems)
        }

        $lvResults.EndUpdate()
    })

    $btnScan.Add_Click({
        $lvResults.Items.Clear()
        $Inputs = $txtTarget.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        
        if ($Inputs.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a target range or subnet.", "Validation Alert", "OK", "Warning")
            return
        }

        # --- Runtime Dynamic Port Parsing Validation Loop ---
        $SelectedPorts = @()
        if (-not [string]::IsNullOrWhiteSpace($txtPortsInput.Text)) {
            $ParsedPorts = $txtPortsInput.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
            if ($ParsedPorts) { $SelectedPorts = $ParsedPorts }
        }

        $btnScan.Enabled = $false
        $txtTarget.Enabled = $false
        $grpOptions.Enabled = $false
        $lblStatus.Text = "Deploying runspace parameters..."
        $lblStatus.ForeColor = [System.Drawing.Color]::DarkGoldenrod
        $form.Refresh()

        $GUISubnets = @()
        $GUIRanges = @()
        foreach ($Entry in $Inputs) {
            if ($Entry -like "*/*") { $GUISubnets += $Entry } else { $GUIRanges += $Entry }
        }

        try {
            $lblStatus.Text = "Engine scanning network..."
            $form.Refresh()

            # Using parameter splatting to bypass line continuation backtick parsing errors entirely
            $EngineParams = @{
                Subnet          = $GUISubnets
                Range           = $GUIRanges
                TcpConnect      = [bool]$chkTcpConnect.Checked
                UpdateDatabases = [bool]$chkUpdateDatabases.Checked
                Ports           = $SelectedPorts
                Threads         = $Threads
                IsGuiRunning    = $true
            }

            $OutputObjects = Invoke-CoreScannerEngine @EngineParams

            if ($null -ne $OutputObjects -and $OutputObjects.Count -gt 0) {
                foreach ($Device in $OutputObjects) {
                    $Item = New-Object System.Windows.Forms.ListViewItem($Device.IP)
                    [void]$Item.SubItems.Add(([string]$Device.Name))
                    [void]$Item.SubItems.Add(([string]$Device.MAC))
                    [void]$Item.SubItems.Add(([string]$Device.Vendor))
                    [void]$Item.SubItems.Add(([string]$Device.Ports))
                    [void]$lvResults.Items.Add($Item)
                }
                $lblStatus.Text = "Completed successfully. Discovered $($lvResults.Items.Count) hosts."
                $lblStatus.ForeColor = [System.Drawing.Color]::Green
            } else {
                $lblStatus.Text = "Finished. Zero responsive nodes found."
                $lblStatus.ForeColor = [System.Drawing.Color]::Blue
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Execution faulted: `n $_", "Engine Exception", "OK", "Error")
            $lblStatus.Text = "Execution aborted on fault."
            $lblStatus.ForeColor = [System.Drawing.Color]::Red
        } finally {
            $btnScan.Enabled = $true
            $txtTarget.Enabled = $true
            $grpOptions.Enabled = $true
        }
    })

    $form.ShowDialog() | Out-Null

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