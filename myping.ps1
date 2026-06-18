<#
.SYNOPSIS
    Advanced Ping wrapper that calculates network jitter and latency statistics.

.DESCRIPTION
    Sends ICMP echo requests to a target and calculates the variance between 
    successive responses (Jitter). Includes color-coded thresholds for RTT and Jitter.

.PARAMETER Target
    The hostname or IP address to ping. [Default: google.com]

.PARAMETER Count
    The number of echo requests to send. [Default: 100]

.PARAMETER Interval
    Wait time in seconds between pings. [Default: 1]

.PARAMETER Continuous
    If specified, pings indefinitely until CTRL+C is pressed.

.PARAMETER 4
    Force IPv4 resolution.

.PARAMETER 6
    Force IPv6 resolution.

.PARAMETER PWarn
    RTT (Ping) threshold in ms for yellow warning. [Default: 100]

.PARAMETER PErr
    RTT (Ping) threshold in ms for red alert. [Default: 130]

.PARAMETER JWarn
    Jitter threshold in ms for yellow warning. [Default: 10]

.PARAMETER JErr
    Jitter threshold in ms for red alert. [Default: 30]

.PARAMETER Help
    Displays this help message.

.EXAMPLE
    .\myping.ps1 -Target "8.8.8.8" -Count 10 -PWarn 50 -JWarn 5
#>

param (
    [Parameter(Position=0)]
    [string]$Target = "google.com",

    [Parameter(Position=1)]
    [int]$Count = 100,

    [int]$Interval = 1,

    [switch]$Continuous,
    [switch]$4,
    [switch]$6,
    [switch]$Help,

    [int]$PWarn = 100,
    [int]$PErr  = 130,
    [int]$JWarn = 10,
    [int]$JErr  = 30
)

if ($Help) {
    Get-Help $PSCommandPath -Full
    return
}

$pingSender = New-Object System.Net.NetworkInformation.Ping
$timeout = 2000 

# Resolve IP Address and determine display format
try {
    $ipAddresses = [System.Net.Dns]::GetHostAddresses($Target)
    if ($4) {
        $resolvedIp = $ipAddresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if (-not $resolvedIp) { throw "No IPv4 address found for $Target" }
    }
    elseif ($6) {
        $resolvedIp = $ipAddresses | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' } | Select-Object -First 1
        if (-not $resolvedIp) { throw "No IPv6 address found for $Target" }
    }
    else {
        $resolvedIp = $ipAddresses[0]
    }

    $ipString = $resolvedIp.IPAddressToString
    # Logic: If the Target passed in is exactly the same as the resolved IP, don't show twice
    $displayTarget = if ($Target -eq $ipString) { $ipString } else { "$Target ($ipString)" }

}
catch {
    Write-Host "Error: Failed to resolve $Target : $($_.Exception.Message)" -ForegroundColor Red
    return
}

$rttStats = @{ Min = [double]::MaxValue; Max = 0; Sum = 0; Received = 0; Sent = 0 }
$jitStats = @{ Min = [double]::MaxValue; Max = 0; Sum = 0; Count = 0 }
$previousRtt = $null
$startTime = Get-Date

$packetDisplay = if($Continuous) { "infinite" } else { "$Count" }
Write-Host "`nPinging $displayTarget with $packetDisplay packets:" -ForegroundColor Cyan
Write-Host "Thresholds: Ping (W:$PWarn/E:$PErr) | Jitter (W:$JWarn/E:$JErr)" -ForegroundColor DarkGray
Write-Host ("{0,-10} | {1,-5} | {2,-12} | {3,-12} | {4,-12}" -f "Time", "Seq", "RTT (ms)", "Jitter (ms)", "Avg Jitter")
Write-Host ("-" * 65)

try {
    for ($i = 1; ($i -le $Count) -or $Continuous; $i++) {
        $rttStats.Sent++
        $timestamp = Get-Date -Format "HH:mm:ss"
        
        try {
            $reply = $pingSender.Send($resolvedIp, $timeout)
            
            if ($reply.Status -eq "Success") {
                $curr = [double]$reply.RoundtripTime
                $rttStats.Received++
                
                if ($curr -lt $rttStats.Min) { $rttStats.Min = $curr }
                if ($curr -gt $rttStats.Max) { $rttStats.Max = $curr }
                $rttStats.Sum += $curr

                $instantJitValue = 0
                $displayJitter = "---"
                $displayAvgJit = "---"

                if ($null -ne $previousRtt) {
                    $instantJitValue = [Math]::Abs($curr - $previousRtt)
                    $jitStats.Count++
                    $jitStats.Sum += $instantJitValue
                    if ($instantJitValue -lt $jitStats.Min) { $jitStats.Min = $instantJitValue }
                    if ($instantJitValue -gt $jitStats.Max) { $jitStats.Max = $instantJitValue }

                    $displayJitter = "$instantJitValue ms"
                    $displayAvgJit = "$([Math]::Round($jitStats.Sum / $jitStats.Count, 2)) ms"
                }

                $rowColor = "White"
                if ($curr -ge $PErr -or $instantJitValue -ge $JErr) { $rowColor = "Red" }
                elseif ($curr -ge $PWarn -or $instantJitValue -ge $JWarn) { $rowColor = "Yellow" }

                Write-Host ("{0,-10} | {1,-5} | {2,-12} | {3,-12} | {4,-12}" -f $timestamp, $i, "$curr ms", $displayJitter, $displayAvgJit) -ForegroundColor $rowColor
                $previousRtt = $curr
            }
            else {
                Write-Host ("{0,-10} | {1,-5} | {2,-12}" -f $timestamp, $i, "Status: $($reply.Status)") -ForegroundColor Gray
                $previousRtt = $null 
            }
        }
        catch {
            Write-Host ("{0,-10} | {1,-5} | {2,-12}" -f $timestamp, $i, "Error: Failed") -ForegroundColor Gray
            $previousRtt = $null
        }
        
        if (($i -lt $Count) -or $Continuous) { Start-Sleep -Seconds $Interval }
    }
}
finally {
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    $lost = $rttStats.Sent - $rttStats.Received
    $lossPercent = if ($rttStats.Sent -gt 0) { [Math]::Round(($lost / $rttStats.Sent) * 100, 1) } else { 0 }
    
    Write-Host "`n--- Ping Statistics for $Target ---" -ForegroundColor Cyan
    Write-Host "Packets: Sent = $($rttStats.Sent), Received = $($rttStats.Received), Lost = $lost ($lossPercent% loss)"
    Write-Host "Approximate duration: $([int]$duration.TotalSeconds) seconds"
    
    if ($rttStats.Received -gt 0) {
        $finalAvgRtt = [Math]::Round($rttStats.Sum / $rttStats.Received, 2)
        $finalAvgJit = if ($jitStats.Count -gt 0) { [Math]::Round($jitStats.Sum / $jitStats.Count, 2) } else { 0 }

        $minRttDisplay = if($rttStats.Min -eq [double]::MaxValue) { 0 } else { $rttStats.Min }
        $minJitDisplay = if($jitStats.Min -eq [double]::MaxValue) { 0 } else { $jitStats.Min }

        Write-Host "`n--- Round Trip Time (RTT) ---"
        Write-Host "Min = $($minRttDisplay)ms, Max = $($rttStats.Max)ms, Avg = $finalAvgRtt ms"
        
        Write-Host "`n--- Jitter (Successive Delta) ---"
        Write-Host "Min = $($minJitDisplay)ms, Max = $($jitStats.Max)ms, Avg = $finalAvgJit ms"
    }
    Write-Host ""
}