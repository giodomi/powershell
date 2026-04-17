<#
.SYNOPSIS
    Exports NSX-T 4.x Distributed Firewall (DFW) and Gateway Firewall (GFW) rules to Excel/CSV.

.DESCRIPTION
    Connects to NSX-T Manager via the Policy REST API and exports:
      - All DFW security policies + rules (all categories)
      - All GFW policies + rules for every Tier-0 and Tier-1 gateway

    Authentication uses session cookies (POST /api/session/create) — required for NSX-T 4.x.
    Automatic cursor-based pagination handles environments with large rule counts.

.PARAMETER NSXManager
    FQDN or IP of the NSX-T Manager  (e.g. "192.168.1.10" or "nsxmgr.lab.local")

.PARAMETER Username
    NSX-T username (default: admin)

.PARAMETER Password
    Password. If omitted you are prompted securely at runtime.

.PARAMETER OutputPath
    Folder for output files (default: current directory)

.PARAMETER OutputFormat
    "Excel" | "CSV" | "Both"  (default: Excel)
    Excel requires the ImportExcel module — the script tries to install it automatically.

.PARAMETER SkipCertificateCheck
    Bypass TLS certificate validation (self-signed certs in lab/dev environments)

.EXAMPLE
    .\Export-NSXFirewallRules.ps1 -NSXManager 192.168.1.10 -SkipCertificateCheck

.EXAMPLE
    .\Export-NSXFirewallRules.ps1 -NSXManager nsxmgr.corp.local -OutputFormat Both -OutputPath C:\Exports

.NOTES
    PowerShell 5.1+ supported; 7+ recommended.
    NSX-T 3.x / 4.x  (tested on 4.2.x)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]  [string]$NSXManager,
    [Parameter(Mandatory=$false)] [string]$Username = "admin",
    [Parameter(Mandatory=$false)] [string]$Password,
    [Parameter(Mandatory=$false)] [string]$OutputPath = (Get-Location).Path,
    [Parameter(Mandatory=$false)] [ValidateSet("Excel","CSV","Both")] [string]$OutputFormat = "Excel",
    [Parameter(Mandatory=$false)] [switch]$SkipCertificateCheck
)

# ---------------------------------------------------------------------------
# Strict mode OFF — avoids "property not found" on null PSCustomObject members
# from ConvertFrom-Json. We do our own null-safety instead.
# ---------------------------------------------------------------------------
Set-StrictMode -Off
$ErrorActionPreference = "Stop"

# ── TLS bypass (PS 5.1) ────────────────────────────────────────────────────
if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 7) {
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint s, X509Certificate c,
        WebRequest r, int p) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [System.Net.ServicePointManager]::SecurityProtocol  =
        [System.Net.SecurityProtocolType]::Tls12 -bor
        [System.Net.SecurityProtocolType]::Tls11
}

# ===========================================================================
# UTILITY
# ===========================================================================

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $color = switch ($Level) {
        "WARN"    {"Yellow"} "ERROR" {"Red"} "SUCCESS" {"Green"} default {"Cyan"}
    }
    Write-Host "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][$Level] $Msg" -ForegroundColor $color
}

# Safe array wrap: always returns a real [array], never $null
# This is the core fix — every property from ConvertFrom-Json that might be
# $null, a single object, or an array gets run through this.
function Coerce-Array {
    param($Value)
    if ($null -eq $Value)      { return @() }
    if ($Value -is [array])    { return $Value }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value)
    }
    return @($Value)   # single object → one-element array
}

# ===========================================================================
# AUTHENTICATION  (session cookie + XSRF token)
# ===========================================================================

function Connect-NSX {
    param([string]$Base, [string]$User, [string]$Pass, [bool]$SkipCert)

    Write-Log "Authenticating to $Base as '$User' ..."

    $sp = @{
        Uri             = "$Base/api/session/create"
        Method          = "POST"
        Body            = "j_username=$([uri]::EscapeDataString($User))&j_password=$([uri]::EscapeDataString($Pass))"
        ContentType     = "application/x-www-form-urlencoded"
        SessionVariable = "ws"
        UseBasicParsing = $true
    }
    if ($SkipCert -and $PSVersionTable.PSVersion.Major -ge 7) { $sp.SkipCertificateCheck = $true }

    try   { $r = Invoke-WebRequest @sp }
    catch {
        $c = try { $_.Exception.Response.StatusCode.value__ } catch { "?" }
        Write-Log "Login failed (HTTP $c): $($_.Exception.Message)" "ERROR"; throw
    }

    $xsrf = $r.Headers["x-xsrf-token"]
    if ($xsrf -is [array]) { $xsrf = $xsrf[0] }
    if (-not $xsrf) { Write-Log "x-xsrf-token missing — calls may fail." "WARN"; $xsrf = "" }

    Write-Log "Session established." "SUCCESS"
    return @{ WS = $ws; XSRF = $xsrf; Base = $Base }
}

function Disconnect-NSX {
    param([hashtable]$S, [bool]$SkipCert)
    try {
        $sp = @{ Uri="$($S.Base)/api/session/destroy"; Method="POST"
                 WebSession=$S.WS; Headers=@{"x-xsrf-token"=$S.XSRF}; UseBasicParsing=$true }
        if ($SkipCert -and $PSVersionTable.PSVersion.Major -ge 7) { $sp.SkipCertificateCheck = $true }
        Invoke-WebRequest @sp | Out-Null
        Write-Log "Session closed."
    } catch { Write-Log "Could not close session: $($_.Exception.Message)" "WARN" }
}

# ===========================================================================
# API CALL WRAPPER  — GET with automatic cursor pagination
# ===========================================================================

function Invoke-NSX {
    param(
        [string]$EP,
        [hashtable]$S,
        [bool]$SkipCert,
        [int]$PgSz = 1000,
        [switch]$NoPagination   # use for endpoints that reject ?page_size (e.g. gateway-firewall)
    )

    $all = [System.Collections.Generic.List[object]]::new()

    # Some endpoints (gateway-firewall) return 400 if any query string is appended.
    # For those, call the URL bare and do a single request only.
    $url    = if ($NoPagination) { "$($S.Base)$EP" } else { "$($S.Base)$EP`?page_size=$PgSz" }
    $cursor = $null

    do {
        $sp = @{ Uri=$url; Method="GET"; WebSession=$S.WS
                 Headers=@{"x-xsrf-token"=$S.XSRF}; UseBasicParsing=$true }
        if ($SkipCert -and $PSVersionTable.PSVersion.Major -ge 7) { $sp.SkipCertificateCheck = $true }

        try   { $resp = (Invoke-WebRequest @sp).Content | ConvertFrom-Json }
        catch {
            $c = try { $_.Exception.Response.StatusCode.value__ } catch { 0 }
            if ($c -eq 404) { Write-Log "404 skipped: $url" "WARN"; return ,@() }
            Write-Log "API error [$url]: $($_.Exception.Message)" "ERROR"; throw
        }

        # Collect items — endpoint-dependent property name
        $items = if     ($null -ne $resp.results) { Coerce-Array $resp.results }
                 elseif ($null -ne $resp.rules)    { Coerce-Array $resp.rules }
                 elseif ($resp -is [array])         { $resp }
                 else                               { @($resp) }

        foreach ($i in $items) { if ($null -ne $i) { $all.Add($i) } }

        # Only follow cursor if pagination is enabled for this endpoint
        $cursor = $null
        if (-not $NoPagination -and $null -ne $resp.cursor -and $resp.cursor -ne "") {
            $cursor = $resp.cursor
            $url = "$($S.Base)$EP`?page_size=$PgSz&cursor=$cursor"
        }

    } while ($cursor)

    return ,$all.ToArray()
}

# ===========================================================================
# PATH → DISPLAY NAME  (cached)
# ===========================================================================

function Resolve-Paths {
    param($Paths, [hashtable]$S, [hashtable]$Cache, [bool]$SkipCert)

    $arr = Coerce-Array $Paths
    if ($arr.Count -eq 0) { return "ANY" }

    $names = foreach ($p in $arr) {
        if ([string]::IsNullOrWhiteSpace($p) -or $p -eq "ANY") { "ANY"; continue }

        if ($Cache.ContainsKey($p)) { $Cache[$p]; continue }

        $name = try {
            $sp = @{ Uri="$($S.Base)/policy/api/v1$p"; Method="GET"
                     WebSession=$S.WS; Headers=@{"x-xsrf-token"=$S.XSRF}; UseBasicParsing=$true }
            if ($SkipCert -and $PSVersionTable.PSVersion.Major -ge 7) { $sp.SkipCertificateCheck = $true }
            $obj = (Invoke-WebRequest @sp).Content | ConvertFrom-Json
            if ($null -ne $obj -and $obj.display_name) { $obj.display_name }
            else { ($p -split "/")[-1] }
        } catch { ($p -split "/")[-1] }

        $Cache[$p] = $name
        $name
    }

    return (($names | Where-Object { $_ }) -join ", ")
}

function Format-Svc {
    param($Entries)
    $arr = Coerce-Array $Entries
    if ($arr.Count -eq 0) { return "ANY" }

    ($arr | ForEach-Object {
        $rt = if ($_.resource_type) { $_.resource_type } else { "" }
        switch ($rt) {
            "L4PortSetServiceEntry"  {
                $ports = if ($null -ne $_.destination_ports) {
                    (Coerce-Array $_.destination_ports) -join ","
                } else { "Any" }
                "$($_.l4_protocol):$ports"
            }
            "ICMPTypeServiceEntry"   { "ICMP(type=$($_.icmp_type))" }
            "IPProtocolServiceEntry" { "IP(proto=$($_.protocol_number))" }
            default { if ($rt) { $rt } else { "Unknown" } }
        }
    }) -join " | "
}

# ===========================================================================
# RULE  →  FLAT ROW
# ===========================================================================

function Flatten-Rule {
    param(
        $Rule,
        [string]$PolName, [string]$PolCat, [string]$PolID,
        [string]$FWType,  [string]$GwName, [string]$GwType,
        [hashtable]$S, [hashtable]$Cache, [bool]$SkipCert
    )

    $ra = @{ S=$S; Cache=$Cache; SkipCert=$SkipCert }

    $src = Resolve-Paths -Paths $Rule.source_groups      @ra
    $dst = Resolve-Paths -Paths $Rule.destination_groups @ra

    $svcArr = Coerce-Array $Rule.services
    $svc = if ($svcArr.Count -gt 0 -and $svcArr[0] -ne "ANY") {
               ($svcArr | ForEach-Object {
                   if ($_ -eq "ANY") { "ANY" } else { Resolve-Paths -Paths @($_) @ra }
               }) -join ", "
           } elseif ((Coerce-Array $Rule.service_entries).Count -gt 0) {
               Format-Svc -Entries $Rule.service_entries
           } else { "ANY" }

    $scopeArr = Coerce-Array $Rule.scope
    $applied = if ($scopeArr.Count -gt 0 -and $scopeArr[0] -ne "ANY") {
                   Resolve-Paths -Paths $scopeArr @ra
               } elseif ($FWType -eq "DFW") { "DFW (All)" }
               else { $GwName }

    [PSCustomObject][ordered]@{
        "Firewall Type"   = $FWType
        "Gateway"         = if ($GwName) { $GwName } else { "N/A" }
        "Gateway Type"    = if ($GwType) { $GwType } else { "N/A" }
        "Policy Name"     = $PolName
        "Policy ID"       = $PolID
        "Category"        = $PolCat
        "Rule Name"       = if ($Rule.display_name)   { $Rule.display_name }   else { "" }
        "Rule ID"         = if ($Rule.id)              { $Rule.id }             else { "" }
        "Sequence Number" = if ($null -ne $Rule.sequence_number) { $Rule.sequence_number } else { "" }
        "Source"          = $src
        "Destination"     = $dst
        "Services"        = $svc
        "Action"          = if ($Rule.action)          { $Rule.action }         else { "" }
        "Direction"       = if ($Rule.direction)       { $Rule.direction }      else { "IN_OUT" }
        "IP Protocol"     = if ($Rule.ip_protocol)     { $Rule.ip_protocol }    else { "IPV4_IPV6" }
        "Applied To"      = $applied
        "Logged"          = if ($Rule.logged)           { "Yes" }               else { "No" }
        "Disabled"        = if ($Rule.disabled)         { "Yes" }               else { "No" }
        "Notes"           = if ($Rule.notes)            { $Rule.notes }         else { "" }
        "Tags"            = if ($null -ne $Rule.tags) {
                                (Coerce-Array $Rule.tags |
                                 ForEach-Object { "$($_.scope):$($_.tag)" }) -join ", "
                            } else { "" }
    }
}

# ===========================================================================
# MAIN
# ===========================================================================

# Password
if (-not $Password) {
    $ss       = Read-Host "Password for $Username@$NSXManager" -AsSecureString
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss))
}

$base     = "https://$NSXManager"
$skipCert = [bool]$SkipCertificateCheck

# ImportExcel check
if ($OutputFormat -in @("Excel","Both")) {
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Log "ImportExcel not found — trying to install..." "WARN"
        try   { Install-Module ImportExcel -Scope CurrentUser -Force -SkipPublisherCheck
                Import-Module ImportExcel }
        catch { Write-Log "ImportExcel install failed — switching to CSV." "WARN"
                $OutputFormat = "CSV" }
    } else { Import-Module ImportExcel -ErrorAction SilentlyContinue }
}

# Connect
$S = Connect-NSX -Base $base -User $Username -Pass $Password -SkipCert $skipCert

$cache   = @{}
$dfwRows = [System.Collections.Generic.List[object]]::new()
$gfwRows = [System.Collections.Generic.List[object]]::new()

try {

    # ── DFW ─────────────────────────────────────────────────────────────────
    Write-Log "=== Distributed Firewall ==="
    $policies = Invoke-NSX -EP "/policy/api/v1/infra/domains/default/security-policies" -S $S -SkipCert $skipCert
    Write-Log "Found $(($policies).Count) DFW security policies."

    foreach ($pol in $policies) {
        $cat = if ($pol.category) { $pol.category } else { "Application" }
        Write-Log "  Policy: '$($pol.display_name)' [$cat]"

        $rules = Invoke-NSX -EP "/policy/api/v1/infra/domains/default/security-policies/$($pol.id)/rules" -S $S -SkipCert $skipCert
        Write-Log "    -> $(($rules).Count) rules"

        foreach ($r in $rules) {
            $dfwRows.Add((Flatten-Rule -Rule $r -PolName $pol.display_name -PolCat $cat -PolID $pol.id `
                -FWType "DFW" -GwName "" -GwType "" -S $S -Cache $cache -SkipCert $skipCert))
        }
    }

    # ── GFW Tier-0 ──────────────────────────────────────────────────────────
    Write-Log "=== Gateway Firewall — Tier-0 ==="
    $t0s = Invoke-NSX -EP "/policy/api/v1/infra/tier-0s" -S $S -SkipCert $skipCert
    Write-Log "Found $(($t0s).Count) Tier-0 gateways."

    foreach ($gw in $t0s) {
        Write-Log "  Tier-0: '$($gw.display_name)'"
        $pols = Invoke-NSX -EP "/policy/api/v1/infra/tier-0s/$($gw.id)/gateway-firewall" -S $S -SkipCert $skipCert -NoPagination
        foreach ($pol in $pols) {
            $cat   = if ($pol.category) { $pol.category } else { "Default" }
            $rules = Coerce-Array $pol.rules
            Write-Log "    Policy '$($pol.display_name)': $($rules.Count) rules"
            foreach ($r in $rules) {
                $gfwRows.Add((Flatten-Rule -Rule $r -PolName $pol.display_name -PolCat $cat -PolID $pol.id `
                    -FWType "GFW" -GwName $gw.display_name -GwType "Tier-0" -S $S -Cache $cache -SkipCert $skipCert))
            }
        }
    }

    # ── GFW Tier-1 ──────────────────────────────────────────────────────────
    Write-Log "=== Gateway Firewall — Tier-1 ==="
    $t1s = Invoke-NSX -EP "/policy/api/v1/infra/tier-1s" -S $S -SkipCert $skipCert
    Write-Log "Found $(($t1s).Count) Tier-1 gateways."

    foreach ($gw in $t1s) {
        Write-Log "  Tier-1: '$($gw.display_name)'"
        $pols = Invoke-NSX -EP "/policy/api/v1/infra/tier-1s/$($gw.id)/gateway-firewall" -S $S -SkipCert $skipCert -NoPagination
        foreach ($pol in $pols) {
            $cat   = if ($pol.category) { $pol.category } else { "Default" }
            $rules = Coerce-Array $pol.rules
            Write-Log "    Policy '$($pol.display_name)': $($rules.Count) rules"
            foreach ($r in $rules) {
                $gfwRows.Add((Flatten-Rule -Rule $r -PolName $pol.display_name -PolCat $cat -PolID $pol.id `
                    -FWType "GFW" -GwName $gw.display_name -GwType "Tier-1" -S $S -Cache $cache -SkipCert $skipCert))
            }
        }
    }

} finally {
    Disconnect-NSX -S $S -SkipCert $skipCert
}

# Summary
$nDFW = $dfwRows.Count
$nGFW = $gfwRows.Count
Write-Log "=== Done: $nDFW DFW rules | $nGFW GFW rules ===" "SUCCESS"
if ($nDFW -eq 0 -and $nGFW -eq 0) { Write-Log "No rules found." "WARN"; exit 0 }

# Output path
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
$ts      = Get-Date -Format "yyyyMMdd_HHmmss"
$safeMgr = $NSXManager -replace "[^a-zA-Z0-9_\-]","_"
$base2   = Join-Path $OutputPath "NSX_FW_Export_${safeMgr}_${ts}"

# ── Excel ────────────────────────────────────────────────────────────────────
if ($OutputFormat -in @("Excel","Both")) {
    $xlsx = "$base2.xlsx"
    $xs   = @{ AutoSize=$true; BoldTopRow=$true; FreezeTopRow=$true; AutoFilter=$true }

    @(
        [PSCustomObject]@{ Item="NSX Manager";   Value=$NSXManager }
        [PSCustomObject]@{ Item="Export Date";   Value=(Get-Date -f "yyyy-MM-dd HH:mm:ss") }
        [PSCustomObject]@{ Item="DFW Rules";     Value=$nDFW }
        [PSCustomObject]@{ Item="GFW Rules";     Value=$nGFW }
        [PSCustomObject]@{ Item="Total Rules";   Value=($nDFW+$nGFW) }
    ) | Export-Excel -Path $xlsx -WorksheetName "Summary" `
        -AutoSize -BoldTopRow -FreezeTopRow -TableName "Summary" -TableStyle Medium9

    if ($nDFW -gt 0) {
        $dfwRows | Export-Excel -Path $xlsx -WorksheetName "Distributed Firewall" `
            @xs -TableName "DFWRules" -TableStyle Medium2
    }
    if ($nGFW -gt 0) {
        $gfwRows | Export-Excel -Path $xlsx -WorksheetName "Gateway Firewall" `
            @xs -TableName "GFWRules" -TableStyle Medium4
    }

    $combined = @($dfwRows.ToArray()) + @($gfwRows.ToArray())
    $combined | Export-Excel -Path $xlsx -WorksheetName "All Rules" `
        @xs -TableName "AllRules" -TableStyle Medium6

    Write-Log "Excel: $xlsx" "SUCCESS"
}

# ── CSV ───────────────────────────────────────────────────────────────────────
if ($OutputFormat -in @("CSV","Both")) {
    if ($nDFW -gt 0) {
        $dfwRows | Export-Csv "$base2`_DFW.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "DFW CSV: $base2`_DFW.csv" "SUCCESS"
    }
    if ($nGFW -gt 0) {
        $gfwRows | Export-Csv "$base2`_GFW.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "GFW CSV: $base2`_GFW.csv" "SUCCESS"
    }
    $combined2 = @($dfwRows.ToArray()) + @($gfwRows.ToArray())
    $combined2 | Export-Csv "$base2`_ALL.csv" -NoTypeInformation -Encoding UTF8
    Write-Log "Combined CSV: $base2`_ALL.csv" "SUCCESS"
}

Write-Log "=== Export complete ===" "SUCCESS"
