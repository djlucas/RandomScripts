<#
.SYNOPSIS
    Advanced Ping/STUN wrapper that calculates network jitter and latency statistics.

.DESCRIPTION
    By default, sends ICMP echo requests to a target and calculates the variance
    between successive responses (Jitter).

    When -Stun is specified, sends STUN Binding Requests over UDP instead of ICMP
    and measures the round-trip time of each STUN transaction.

    Includes color-coded thresholds for RTT and Jitter.

.PARAMETER Target
    The hostname or IP address to test. [Default: google.com]

    The special target "help" displays full help for the script.

.PARAMETER Count
    The number of requests to send. [Default: 100]

.PARAMETER Interval
    Wait time in seconds between requests. [Default: 1]

.PARAMETER Continuous
    If specified, tests indefinitely until CTRL+C is pressed.

.PARAMETER Stun
    Use UDP STUN Binding Requests instead of ICMP echo requests.

.PARAMETER StunPort
    UDP port to use for STUN requests. [Default: 3478]

.PARAMETER 4
    Force IPv4 resolution.

.PARAMETER 6
    Force IPv6 resolution.

.PARAMETER PWarn
    RTT threshold in ms for yellow warning. [Default: 100]

.PARAMETER PErr
    RTT threshold in ms for red alert. [Default: 130]

.PARAMETER JWarn
    Jitter threshold in ms for yellow warning. [Default: 10]

.PARAMETER JErr
    Jitter threshold in ms for red alert. [Default: 30]

.PARAMETER Help
    Displays this help message.

.EXAMPLE
    .\myping.ps1 -Target "8.8.8.8" -Count 10 -PWarn 50 -JWarn 5

.EXAMPLE
    .\myping.ps1 -Stun worldaz.tr.teams.microsoft.com

    Sends STUN Binding Requests to worldaz.tr.teams.microsoft.com on UDP port 3478.

.EXAMPLE
    .\myping.ps1 -Target "stun.example.com" -Stun -StunPort 5349 -Count 20

    Sends STUN Binding Requests to UDP port 5349.

.EXAMPLE
    .\myping.ps1 -Help

    Displays full help.

.EXAMPLE
    .\myping.ps1 help

    Displays full help.
#>

param (
    [Parameter(Position=0)]
    [string]$Target = "google.com",

    [Parameter(Position=1)]
    [int]$Count = 100,

    [int]$Interval = 1,

    [switch]$Continuous,
    [switch]$Stun,

    [ValidateRange(1, 65535)]
    [int]$StunPort = 3478,

    [switch]$4,
    [switch]$6,
    [switch]$Help,

    [int]$PWarn = 100,
    [int]$PErr  = 130,
    [int]$JWarn = 10,
    [int]$JErr  = 30
)

if ($Help -or $Target -eq "help") {
    Get-Help $PSCommandPath -Full
    return
}

$timeout = 2000

if (-not $Stun) {
    $pingSender = New-Object System.Net.NetworkInformation.Ping
}

# Resolve IP address
try {
    $ipAddresses = [System.Net.Dns]::GetHostAddresses($Target)

    if ($4) {
        $resolvedIp = $ipAddresses |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            Select-Object -First 1

        if (-not $resolvedIp) {
            throw "No IPv4 address found for $Target"
        }
    }
    elseif ($6) {
        $resolvedIp = $ipAddresses |
            Where-Object { $_.AddressFamily -eq 'InterNetworkV6' } |
            Select-Object -First 1

        if (-not $resolvedIp) {
            throw "No IPv6 address found for $Target"
        }
    }
    else {
        $resolvedIp = $ipAddresses[0]
    }

    $ipString = $resolvedIp.IPAddressToString

    $displayTarget = if ($Target -eq $ipString) {
        $ipString
    }
    else {
        "$Target ($ipString)"
    }
}
catch {
    Write-Host "Error: Failed to resolve $Target : $($_.Exception.Message)" -ForegroundColor Red
    return
}

$rttStats = @{
    Min      = [double]::MaxValue
    Max      = 0
    Sum      = 0
    Received = 0
    Sent     = 0
}

$jitStats = @{
    Min   = [double]::MaxValue
    Max   = 0
    Sum   = 0
    Count = 0
}

$previousRtt = $null
$startTime = Get-Date

$packetDisplay = if ($Continuous) {
    "infinite"
}
else {
    "$Count"
}

if ($Stun) {
    Write-Host "`nSTUN testing $displayTarget`:$StunPort with $packetDisplay requests:" -ForegroundColor Cyan
}
else {
    Write-Host "`nPinging $displayTarget with $packetDisplay packets:" -ForegroundColor Cyan
}

Write-Host "Thresholds: Ping (W:$PWarn/E:$PErr) | Jitter (W:$JWarn/E:$JErr)" -ForegroundColor DarkGray
Write-Host ("{0,-10} | {1,-5} | {2,-12} | {3,-12} | {4,-12}" -f "Time", "Seq", "RTT (ms)", "Jitter (ms)", "Avg Jitter")
Write-Host ("-" * 65)

try {
    for ($i = 1; ($i -le $Count) -or $Continuous; $i++) {
        $rttStats.Sent++
        $timestamp = Get-Date -Format "HH:mm:ss"
        $success = $false

        try {
            if ($Stun) {
                # STUN Binding Request
                $transactionId = New-Object byte[] 12
                [System.Security.Cryptography.RandomNumberGenerator]::Fill($transactionId)

                $request = New-Object byte[] 20

                $request[0] = 0x00
                $request[1] = 0x01
                $request[2] = 0x00
                $request[3] = 0x00

                $request[4] = 0x21
                $request[5] = 0x12
                $request[6] = 0xA4
                $request[7] = 0x42

                [Array]::Copy($transactionId, 0, $request, 8, 12)

                $socket = [System.Net.Sockets.Socket]::new(
                    $resolvedIp.AddressFamily,
                    [System.Net.Sockets.SocketType]::Dgram,
                    [System.Net.Sockets.ProtocolType]::Udp
                )

                try {
                    $socket.ReceiveTimeout = $timeout

                    $endpoint = [System.Net.IPEndPoint]::new(
                        $resolvedIp,
                        $StunPort
                    )

                    $socket.Connect($endpoint)

                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                    [void]$socket.Send($request)

                    $response = New-Object byte[] 2048
                    $received = $socket.Receive($response)

                    $stopwatch.Stop()

                    if ($received -lt 20) {
                        throw "Invalid STUN response"
                    }

                    if (
                        $response[4] -ne 0x21 -or
                        $response[5] -ne 0x12 -or
                        $response[6] -ne 0xA4 -or
                        $response[7] -ne 0x42
                    ) {
                        throw "Invalid STUN magic cookie"
                    }

                    for ($x = 0; $x -lt 12; $x++) {
                        if ($response[8 + $x] -ne $transactionId[$x]) {
                            throw "STUN transaction ID mismatch"
                        }
                    }

                    $curr = [Math]::Round(
                        $stopwatch.Elapsed.TotalMilliseconds,
                        2
                    )

                    $success = $true
                }
                finally {
                    if ($socket) {
                        $socket.Dispose()
                    }
                }
            }
            else {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                $reply = $pingSender.Send($resolvedIp, $timeout)

                $stopwatch.Stop()

                if ($reply.Status -eq "Success") {
                    $curr = [Math]::Round(
                        $stopwatch.Elapsed.TotalMilliseconds,
                        2
                    )

                    $success = $true
                }
                else {
                    Write-Host (
                        "{0,-10} | {1,-5} | {2,-12}" -f
                        $timestamp,
                        $i,
                        "Status: $($reply.Status)"
                    ) -ForegroundColor Gray

                    $previousRtt = $null
                }
            }

            if ($success) {
                $rttStats.Received++

                if ($curr -lt $rttStats.Min) {
                    $rttStats.Min = $curr
                }

                if ($curr -gt $rttStats.Max) {
                    $rttStats.Max = $curr
                }

                $rttStats.Sum += $curr

                $instantJitValue = 0
                $displayRtt = "{0:F2} ms" -f $curr
                $displayJitter = "---"
                $displayAvgJit = "---"

                if ($null -ne $previousRtt) {
                    $instantJitValue = [Math]::Round(
                        [Math]::Abs($curr - $previousRtt),
                        2
                    )

                    $jitStats.Count++
                    $jitStats.Sum += $instantJitValue

                    if ($instantJitValue -lt $jitStats.Min) {
                        $jitStats.Min = $instantJitValue
                    }

                    if ($instantJitValue -gt $jitStats.Max) {
                        $jitStats.Max = $instantJitValue
                    }

                    $displayJitter = "{0:F2} ms" -f $instantJitValue
                    $displayAvgJit = "{0:F2} ms" -f ($jitStats.Sum / $jitStats.Count)
                }

                $rowColor = "White"

                if ($curr -ge $PErr -or $instantJitValue -ge $JErr) {
                    $rowColor = "Red"
                }
                elseif ($curr -ge $PWarn -or $instantJitValue -ge $JWarn) {
                    $rowColor = "Yellow"
                }

                Write-Host (
                    "{0,-10} | {1,-5} | {2,-12} | {3,-12} | {4,-12}" -f
                    $timestamp,
                    $i,
                    $displayRtt,
                    $displayJitter,
                    $displayAvgJit
                ) -ForegroundColor $rowColor

                $previousRtt = $curr
            }
        }
        catch {
            if ($Stun) {
                $errorText = if (
                    $_.Exception -is [System.Net.Sockets.SocketException] -and
                    $_.Exception.SocketErrorCode -eq 'TimedOut'
                ) {
                    "STUN timeout"
                }
                else {
                    "STUN error"
                }

                Write-Host (
                    "{0,-10} | {1,-5} | {2,-12}" -f
                    $timestamp,
                    $i,
                    $errorText
                ) -ForegroundColor Gray
            }
            else {
                Write-Host (
                    "{0,-10} | {1,-5} | {2,-12}" -f
                    $timestamp,
                    $i,
                    "Error: Failed"
                ) -ForegroundColor Gray
            }

            $previousRtt = $null
        }

        if (($i -lt $Count) -or $Continuous) {
            Start-Sleep -Seconds $Interval
        }
    }
}
finally {
    $endTime = Get-Date
    $duration = $endTime - $startTime

    $lost = $rttStats.Sent - $rttStats.Received

    $lossPercent = if ($rttStats.Sent -gt 0) {
        [Math]::Round(
            ($lost / $rttStats.Sent) * 100,
            1
        )
    }
    else {
        0
    }

    $statType = if ($Stun) {
        "STUN"
    }
    else {
        "Ping"
    }

    Write-Host "`n--- $statType Statistics for $Target ---" -ForegroundColor Cyan
    Write-Host "Packets: Sent = $($rttStats.Sent), Received = $($rttStats.Received), Lost = $lost ($lossPercent% loss)"
    Write-Host "Approximate duration: $([int]$duration.TotalSeconds) seconds"

    if ($rttStats.Received -gt 0) {
        $finalAvgRtt = $rttStats.Sum / $rttStats.Received

        $finalAvgJit = if ($jitStats.Count -gt 0) {
            $jitStats.Sum / $jitStats.Count
        }
        else {
            0
        }

        $minRttDisplay = if ($rttStats.Min -eq [double]::MaxValue) {
            0
        }
        else {
            $rttStats.Min
        }

        $minJitDisplay = if ($jitStats.Min -eq [double]::MaxValue) {
            0
        }
        else {
            $jitStats.Min
        }

        Write-Host "`n--- Round Trip Time (RTT) ---"
        Write-Host (
            "Min = {0:F2}ms, Max = {1:F2}ms, Avg = {2:F2} ms" -f
            $minRttDisplay,
            $rttStats.Max,
            $finalAvgRtt
        )

        Write-Host "`n--- Jitter (Successive Delta) ---"
        Write-Host (
            "Min = {0:F2}ms, Max = {1:F2}ms, Avg = {2:F2} ms" -f
            $minJitDisplay,
            $jitStats.Max,
            $finalAvgJit
        )
    }

    Write-Host ""
}
