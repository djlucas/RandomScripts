<#
.SYNOPSIS
    Audits file paths for SharePoint Online migration compatibility.

.DESCRIPTION
    Calculates path length violations for migrations. Automatically handles 
    SPOUrlLibrary construction from SPOUrlRoot and the LocalPath folder name.
    Does not prompt for SPOUrlLibrary.

.PARAMETER LocalPath
    The source directory on disk (e.g., D:\Data). 

.PARAMETER LocalSyncRoot
    The predicted local path on a user machine (e.g., C:\Users\User\OneDrive - Co).

.PARAMETER SPOUrlRoot
    The base site URL. Required if SPOUrlLibrary is not provided.

.PARAMETER SPOUrlLibrary
    The specific library URL. If omitted, this is automatically computed using 
    SPOUrlRoot and the leaf folder name of the LocalPath.

.PARAMETER MaxSPOPath
    Total URL length limit (Default 400).

.PARAMETER MaxSegment
    Individual file/folder name length limit (Default 255).

.PARAMETER MaxLocalPath
    Windows MAX_PATH limit (Default 260).

.EXAMPLE
    .\AuditPaths.ps1 `
        -LocalPath "D:\Data" `
        -LocalSyncRoot "C:\Users\FirstLast\OneDrive - My Company Name" `
        -SPOUrlRoot "https://tenant.sharepoint.com/sites/SiteName" `
        -MaxLocalPath 260
    
    This command runs the audit by defining the source, the sync root for a specific 
    user/company profile, and the site root, using backticks for multi-line readability.
#>

Param(
    [Parameter(Mandatory=$false)][string]$LocalPath,
    [Parameter(Mandatory=$false)][string]$LocalSyncRoot,
    [Parameter(Mandatory=$false)][string]$SPOUrlRoot,
    [Parameter(Mandatory=$false)][string]$SPOUrlLibrary,
    [Parameter(Mandatory=$false)][int]$MaxSPOPath = 400,
    [Parameter(Mandatory=$false)][int]$MaxSegment = 255,
    [Parameter(Mandatory=$false)][int]$MaxLocalPath = 260
)

function Get-MisingParam {
    param($Var, $Prompt)
    if (-not $Var) { return Read-Host $Prompt }
    return $Var
}

# 1. Mandatory Local Inputs
$LocalPath     = Get-MisingParam $LocalPath "Enter Source LocalPath (e.g., D:\Data)"
$LocalSyncRoot = Get-MisingParam $LocalSyncRoot "Enter Local Sync Root (e.g., C:\Users\FirstLast\OneDrive - My Company Name)"

# 2. Optimized SPO Logic
if (-not $SPOUrlLibrary) {
    if (-not $SPOUrlRoot) {
        $SPOUrlRoot = Read-Host "SPO URL not provided. Enter SPOUrlRoot (e.g., https://tenant.sharepoint.com/sites/Site)"
    }
    
    $FolderName = (Split-Path $LocalPath -Leaf)
    $SPOUrlLibrary = "$($SPOUrlRoot.TrimEnd('/'))/$FolderName"
}

# Normalize LocalPath for prefix stripping
$LocalPath = $LocalPath.TrimEnd('\')
$SourceBaseLen = $LocalPath.Length + 1 

$OutputFile = "Migration_Audit_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$Results = [System.Collections.Generic.List[PSObject]]::new()

Write-Host "`n--- Starting Migration Audit ---" -ForegroundColor Cyan
Write-Host "Local Source:    $LocalPath"
Write-Host "Target Library:  $SPOUrlLibrary"
Write-Host "Local Sync Root: $LocalSyncRoot" -ForegroundColor Gray

try {
    $Files = [System.IO.Directory]::EnumerateFileSystemEntries($LocalPath, "*", [System.IO.SearchOption]::AllDirectories)

    foreach ($FilePath in $Files) {
        $ItemName = [System.IO.Path]::GetFileName($FilePath)
        
        # Strip LocalPath prefix
        $RelativePath = $FilePath.Substring($SourceBaseLen)
        
        # 1. Segment Check
        $ElementLen = $ItemName.Length
        
        # 2. Local Sync Path Check (MAX_PATH)
        $PredictedLocalPath = Join-Path -Path $LocalSyncRoot -ChildPath $RelativePath
        $LocalLen = $PredictedLocalPath.Length
        
        # 3. SPO URL Check (URL Encoded)
        $UrlPath = $RelativePath.Replace('\', '/')
        $EncodedRelative = [uri]::EscapeDataString($UrlPath).Replace('%2F', '/')
        $FullSPOUrl = "$($SPOUrlLibrary.TrimEnd('/'))/$EncodedRelative"
        $SPOLen = $FullSPOUrl.Length

        # Violation Logic
        if ($LocalLen -ge $MaxLocalPath -or $SPOLen -ge $MaxSPOPath -or $ElementLen -ge $MaxSegment) {
            $Flags = @()
            if ($LocalLen -ge $MaxLocalPath)  { $Flags += "LOCAL_LIMIT" }
            if ($SPOLen -ge $MaxSPOPath)    { $Flags += "SPO_LIMIT" }
            if ($ElementLen -ge $MaxSegment) { $Flags += "SEGMENT_LIMIT" }

            $Results.Add([PSCustomObject]@{
                FileName     = $ItemName
                Issue        = $Flags -join "|"
                LocalLength  = $LocalLen
                SPOLength    = $SPOLen
                SegmentLen   = $ElementLen
                SourcePath   = $FilePath
            })
        }
    }

    if ($Results.Count -gt 0) {
        $Results | Export-Csv -Path $OutputFile -NoTypeInformation
        Write-Host "`n[!] Audit Complete: $($Results.Count) violations found." -ForegroundColor Yellow
        Write-Host "Log: $OutputFile" -ForegroundColor White
    } else {
        Write-Host "`n[+] Audit Complete: No violations found." -ForegroundColor Green
    }
} catch {
    Write-Error "Migration Audit Failed: $($_.Exception.Message)"
}