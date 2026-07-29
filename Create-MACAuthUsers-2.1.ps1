<#
.SYNOPSIS
    Automates provisioning of MAC addresses, AD Security Groups, Password Policies, 
    and generates an NPS-ready Network Policy configuration file.
.DESCRIPTION
    This script accepts a numerical VLAN ID, reads a text file of MAC addresses, 
    ensures the associated AD Group exists, configures a Fine-Grained Password Policy,
    provisions the accounts, and outputs an NPS XML configuration template. 
    Version 2.1 introduces a force flag to overwrite existing account passwords for hardware migrations.
.PARAMETER VlanId
    The numeric ID of the target VLAN. This determines the default source file path,
    the group name, and the embedded RADIUS VLAN attributes.
.PARAMETER Format
    Optional. Specifies the case format for the AD identities. 'Upper' or 'Lower'. Defaults to 'Upper'.
.PARAMETER TargetOU
    Optional. A simple OU name (e.g., "MAC-Auth") or full DN. Defaults to "MAC-Devices" at root.
.PARAMETER GroupName
    Optional. Explicit name for the Active Directory Security Group. Defaults to 'VLAN-[VlanId]'.
.PARAMETER DomainSuffix
    Optional. The UPN domain suffix used for the account identities. Defaults to current domain.
.PARAMETER FilePath
    Optional. Path to the input text file. Defaults to 'C:\Input\MAC-[VlanId].txt'.
.PARAMETER NpsXmlOutput
    Optional. Path to save the generated NPS Configuration XML template. Defaults to 'C:\Input\NPS-VLAN-[VlanId].xml'.
.PARAMETER ForcePasswordUpdate
    Optional Switch. Forcefully updates the sAMAccountName visual case and resets the password 
    hash of existing accounts to match the currently specified format (Upper/Lower).
.EXAMPLE
    .\Create-MACAuthUsers.ps1 -VlanId 20
    Runs dynamically using uppercase normalization. Skips existing users safely.
.EXAMPLE
    .\Create-MACAuthUsers.ps1 -VlanId 20 -Format Lower -ForcePasswordUpdate
    Forces all accounts found in MAC-20.txt (existing and new) to use lowercase identities and passwords.
#>

#################################################################################
# SCRIPT HEADER
# Module Name:  Create-MACAuthUsers.ps1
# Description:  All-In-One automated UniFi MAB AD & NPS provisioning pipeline.
# Author:       System Administrator
# Date Created: May 2026
# Version:      2.1 (Added Force Password Reset Logic)
#################################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Enter the numerical VLAN ID (e.g., 20)")]
    [ValidateScript({$_ -match '^\d+$'})]
    [int]$VlanId,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Upper", "Lower")]
    [string]$Format = "Upper",

    [Parameter(Mandatory=$false)]
    [string]$TargetOU = "MAC-Devices",

    [Parameter(Mandatory=$false)]
    [string]$GroupName = "VLAN-$VlanId",

    [Parameter(Mandatory=$false)]
    [string]$DomainSuffix = $env:USERDNSDOMAIN,

    [Parameter(Mandatory=$false)]
    [string]$FilePath = "C:\Input\MAC-$VlanId.txt",

    [Parameter(Mandatory=$false)]
    [string]$NpsXmlOutput = "C:\Input\NPS-VLAN-$VlanId.xml",

    [Parameter(Mandatory=$false)]
    [switch]$ForcePasswordUpdate
)

# 1. Resolve File Paths Safely
$ResolvedFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
$ResolvedXmlPath  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($NpsXmlOutput)

# 2. Smart OU Format Detection (Convert simple name to full Distinguished Name if needed)
$RootDN = ([adsi]'LDAP://RootDSE').defaultNamingContext
if ($TargetOU -notmatch '^OU=.*,DC=.*') {
    $CleanOUName = $TargetOU.Replace("OU=","").Replace("ou=","")
    $TargetOU = "OU=$CleanOUName,$RootDN"
}

# 3. Validate input file existence before processing
if (-not (Test-Path -Path $ResolvedFilePath)) {
    Write-Error "The expected source file was not found: $ResolvedFilePath"
    exit
}

# 4. Check and auto-create the Security Group if it doesn't exist
if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'")) {
    
    # Ensure the parent TargetOU exists before making the group
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetOU'")) {
        $OUName = ($TargetOU -split ',').Replace("OU=","")
        $OUParent = $TargetOU.Substring($TargetOU.IndexOf(',') + 1)
        New-ADOrganizationalUnit -Name $OUName -Path $OUParent
        Write-Host "Created base Organizational Unit: $TargetOU" -ForegroundColor LightCyan
    }

    New-ADGroup -Name $GroupName -GroupScope Global -GroupCategory Security -Path $TargetOU
    Write-Host "Created new Active Directory Security Group: $GroupName in $TargetOU" -ForegroundColor Cyan
}

# 5. Provision Fine-Grained Password Policy for MAB Security (If missing)
$PsoName = "MAB-Policy-$GroupName"
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$PsoName'")) {
    New-ADFineGrainedPasswordPolicy -Name $PsoName `
                                    -Precedence 10 `
                                    -ComplexityEnabled $false `
                                    -MinPasswordLength 12 `
                                    -ReversibleEncryptionEnabled $true `
                                    -PasswordHistoryCount 0 `
                                    -LockoutThreshold 0
    Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects $GroupName
    Write-Host "Created and assigned Fine-Grained Password Policy: $PsoName" -ForegroundColor LightMagenta
}

# 6. Read the file, clean spaces, drop blank lines, and skip lines starting with '#'
$MacList = Get-Content -Path $ResolvedFilePath | 
           ForEach-Object { $_.Trim() } | 
           Where-Object { $_ -and ($_ -notmatch '^#') }

# 7. Process each MAC address sequentially
foreach ($RawMac in $MacList) {
    
    $CleanedMac = $RawMac.Replace(":", "").Replace("-", "")
    if ($Format -eq "Upper") { $CleanedMac = $CleanedMac.ToUpper() } else { $CleanedMac = $CleanedMac.ToLower() }
    
    $UserExists = Get-ADUser -Filter "SamAccountName -eq '$CleanedMac'"
    
    if ($UserExists) {
        # Active Directory handles logons case-insensitively, but we align properties for consistency
        Set-ADUser -Identity $CleanedMac -SamAccountName $CleanedMac -UserPrincipalName "$CleanedMac@$DomainSuffix"
        
        if ($ForcePasswordUpdate) {
            Write-Host "Force updating password format for existing account: $CleanedMac" -ForegroundColor Yellow
            $SecurePassword = ConvertTo-SecureString $CleanedMac -AsPlainText -Force
            Set-ADAccountPassword -Identity $CleanedMac -NewPassword $SecurePassword -Reset $false
        } else {
            Write-Host "Account $CleanedMac already exists. Validating group membership..." -ForegroundColor Yellow
        }
        
        Add-ADGroupMember -Identity $GroupName -Members $CleanedMac -ErrorAction SilentlyContinue
        continue
    }

    # 8. Provision entirely new accounts if they don't exist
    $SecurePassword = ConvertTo-SecureString $CleanedMac -AsPlainText -Force

    New-ADUser -Name $CleanedMac `
               -SamAccountName $CleanedMac `
               -UserPrincipalName "$CleanedMac@$DomainSuffix" `
               -AccountPassword $SecurePassword `
               -Path $TargetOU `
               -Enabled $true `
               -PasswordNeverExpires $true

    $UserDN = (Get-ADUser -Identity $CleanedMac).DistinguishedName
    $UserObj = [ADSI]"LDAP://$UserDN"
    $UserObj.Put("userParameters", [byte[]](0x01, 0x00, 0x00, 0x00))
    $UserObj.SetInfo()

    Set-ADAccountPassword -Identity $CleanedMac -NewPassword $SecurePassword -Reset $false
    Add-ADGroupMember -Identity $GroupName -Members $CleanedMac
    Write-Host "Successfully provisioned and mapped to $GroupName: $CleanedMac" -ForegroundColor Green
}

# 9. Dynamic NPS Configuration Template Builder
$NetbiosDomain = (Get-ADDomain).NetBIOSName
$XmlPayload = @"
<?xml version="1.0" encoding="utf-8"?>
<NpsConfiguration Version="1">
  <NetworkPolicies>
    <NetworkPolicy Name="UniFi-MAB-VLAN$VlanId" State="1">
      <Conditions>
        <Condition Name="User-Groups">
          <Value>$NetbiosDomain\$GroupName</Value>
        </Condition>
        <Condition Name="NAS-Port-Type">
          <Value>0x00000013 0x00000006</Value>
        </Condition>
      </Conditions>
      <Profiles>
        <Profile Name="UniFi-MAB-VLAN$VlanId">
          <Attributes>
            <Attribute Id="0x0000000d" Type="1" Name="Tunnel-Type"><Value>13</Value></Attribute>
            <Attribute Id="0x00000006" Type="1" Name="Tunnel-Medium-Type"><Value>6</Value></Attribute>
            <Attribute Id="0x00000051" Type="1" Name="Tunnel-Private-Group-ID"><Value>$VlanId</Value></Attribute>
          </Attributes>
        </Profile>
      </Profiles>
    </NetworkPolicy>
  </NetworkPolicies>
</NpsConfiguration>
"@

$XmlPayload | Out-File -FilePath $ResolvedXmlPath -Encoding utf8 -Force
Write-Host "Generated matching NPS Policy template XML file at: $ResolvedXmlPath" -ForegroundColor LightGreen
Write-Host "Apply with: Import-NpsConfiguration -Path $ResolvedXmlPath"
