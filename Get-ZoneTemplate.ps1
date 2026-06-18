<#
.SYNOPSIS
    Generates a BIND-compatible DNS zone template by harvesting public records.
.DESCRIPTION
    PS 5.1/7.x Compatible. Ensures SOA and $TTL are prioritized at the top.
#>

param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Domain,
    [Parameter(Mandatory=$false)]
    [string]$Path,
    [Parameter(Mandatory=$false)]
    [string]$Server,
    [Parameter(Mandatory=$false)]
    [int]$Throttle = 500
)

function Invoke-DnsQuery {
    param([string]$Name, [string[]]$Type)
    $found = @()
    foreach ($t in $Type) {
        try {
            $p = @{ Name = $Name; Type = $t; ErrorAction = 'SilentlyContinue' }
            if ($Server) { $p.Server = $Server }
            $res = Resolve-DnsName @p
            if ($res) { 
                foreach($r in $res) { if($r.Section -eq "Answer") { $found += $r } }
            }
        } catch {}
    }
    return $found
}

# 1. INITIAL HARVEST & FINGERPRINTING
Write-Host "Fetching Infrastructure for $Domain..." -ForegroundColor Gray
$soaRecords = Invoke-DnsQuery -Name $Domain -Type @("SOA")
$mxRecords  = Invoke-DnsQuery -Name $Domain -Type @("MX")
$txtRecords = Invoke-DnsQuery -Name $Domain -Type @("TXT")
$nsRecords  = Invoke-DnsQuery -Name $Domain -Type @("NS")

$mxStr = if ($mxRecords) { ($mxRecords.Exchange -join " ").ToLower() } else { "" }
$txtStr = if ($txtRecords) { ($txtRecords.Strings -join " ").ToLower() } else { "" }

# 2. TEMPLATE HEADER
$template = @()
$template += "; #############################################################################"
$template += "; # !!!!!!!!!!!!!!!!!!!!!!!!!!! CRITICAL WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!! #"
$template += "; #############################################################################"
$template += "; # THIS IS AN INCOMPLETE, HARVESTED DNS ZONE TEMPLATE.                      #"
$template += "; # IT WAS GENERATED VIA PUBLIC DISCOVERY AND BRUTE-FORCE.                   #"
$template += "; #                                                                           #"
$template += "; # 1. THIS FILE MUST BE MANUALLY VALIDATED AGAINST THE SOURCE REGISTRAR.     #"
$template += "; # 2. HIDDEN, INTERNAL, OR NON-STANDARD RECORDS ARE LIKELY MISSING.         #"
$template += "; # 3. DO NOT IMPORT THIS INTO PRODUCTION WITHOUT A LINE-BY-LINE AUDIT.       #"
$template += "; #############################################################################"
$template += ""
$template += "; Domain: $Domain"
$template += "; Generated: $(Get-Date)"
$template += "`$ORIGIN $($Domain)."

# 3. TOP-LEVEL SOA & TTL (Fixed for PS 5.1)
if ($soaRecords) {
    $s = $soaRecords[0]
    
    # PS 5.1 sometimes uses different property names or hides them. 
    # We'll use a fall-through logic to ensure we get numbers.
    $refresh = if ($s.RefreshInterval) { $s.RefreshInterval } else { 28800 }
    $retry   = if ($s.RetryInterval) { $s.RetryInterval } else { 7200 }
    $expire  = if ($s.ExpireLimit) { $s.ExpireLimit } else { 604800 }
    $minTTL  = if ($s.MinimumTtl) { $s.MinimumTtl } else { 3600 }

    $template += "`$TTL $minTTL"
    $template += "{0,-25} IN  SOA   {1}. {2}. (" -f "@", $s.PrimaryServer.TrimEnd('.'), $s.Administrator.TrimEnd('.')
    $template += "                          $($s.SerialNumber) ; serial"
    $template += "                          $refresh ; refresh"
    $template += "                          $retry ; retry"
    $template += "                          $expire ; expire"
    $template += "                          $minTTL ; minimum )"
} else {
    $template += "`$TTL 3600"
    $template += "; SOA lookup failed - manual entry required"
}

# 4. ROOT INFRASTRUCTURE
if ($nsRecords) { foreach ($n in $nsRecords) { $template += "{0,-25} IN  NS    {1}." -f "@", $n.NameHost.TrimEnd('.') } }
if ($mxRecords) { foreach ($m in $mxRecords) { $template += "{0,-25} IN  MX    {1} {2}." -f "@", $m.Preference, $m.Exchange.TrimEnd('.') } }
if ($txtRecords) { foreach ($t in $txtRecords) { if ($t.Strings) { $template += "{0,-25} IN  TXT   `"{1}`"" -f "@", ($t.Strings -join ' ') } } }
$template += ""

# 5. SUBDOMAIN HARVEST
$subdomains = @("www", "mail", "ftp", "dev", "api", "portal", "test", "m", "blog", "vpn", "remote", "ssh", "secure", "app", "cloud", "smtp", "pop", "imap", "webmail", "ns1", "ns2", "support", "help", "billing", "client", "member", "status", "git", "wiki", "docs", "static", "admin", "panel", "web")
if ($mxStr -match "outlook.com" -or $txtStr -match "outlook.com") { $subdomains += @("autodiscover", "lyncdiscover", "msoid") }
if ($mxStr -match "barracuda" -or $txtStr -match "barracuda") { $subdomains += @("ess", "barracuda") }
if ($txtStr -match "avanan") { $subdomains += @("avanan-verification", "avanan") }

$selectors = @("selector1", "default", "mail", "k1", "google", "sig1", "sig2")
$srvList   = @("_sip._tls", "_sipfederationtls._tcp", "_autodiscover._tcp", "_xmpp-server._tcp")
$verif     = @("_amazonses", "_dmarc")
$allTasks = ($subdomains | Select-Object -Unique) + $selectors + $srvList + $verif

Write-Host "Harvesting $($allTasks.Count) records..." -ForegroundColor Cyan
$counter = 0
foreach ($item in $allTasks) {
    $counter++
    Write-Progress -Activity "Scanning $Domain" -Status "Checking: $item" -PercentComplete (($counter / $allTasks.Count) * 100)
    $target = if ($selectors -contains $item) { "$item._domainkey.$Domain" } else { "$item.$Domain" }
    $results = Invoke-DnsQuery -Name $target -Type @("CNAME","A","AAAA","TXT","SRV")
    if ($results) {
        $cname = $results | Where-Object { $_.Type -eq "CNAME" }
        if ($cname) { $template += "{0,-25} IN  CNAME {1}." -f $item, $cname[0].NameHost.TrimEnd('.'); continue }
        foreach ($r in $results) {
            $val = switch ($r.Type) {
                "A"     { $r.IPAddress }
                "AAAA"  { $r.IP6Address }
                "TXT"   { "`"$($r.Strings -join ' ')`"" }
                "SRV"   { "$($r.Priority) $($r.Weight) $($r.Port) $($r.Target.TrimEnd('.'))." }
            }
            if ($val) { $template += "{0,-25} IN  {1,-5} {2}" -f $item, $r.Type, $val }
        }
    }
    Start-Sleep -Milliseconds $Throttle
}

# 6. OUTPUT
if ($Path) { $template | Out-File $Path; Write-Host "Saved to $Path" -ForegroundColor Green }
else { $template | ForEach-Object { Write-Output $_ } }