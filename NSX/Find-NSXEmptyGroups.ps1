<#
.SYNOPSIS
    Finds all EMPTY NSX-T Security Groups and reports where they are used in
    Distributed Firewall (DFW) and Gateway Firewall (GFW) rules. Exports to Excel/CSV.

.DESCRIPTION
    OPTIMIZED for NSX-T Manager API rate limits (default ~100 req/s per client,
    plus concurrency caps). API call reduction strategies:

      * Groups with NO expression are classified empty with ZERO API calls
        (no definition = empty by definition).
      * Groups that only contain static path/IP expressions are evaluated from
        the expression itself where possible (no member API calls).
      * For remaining groups, member endpoints are queried with SHORT-CIRCUIT:
        as soon as any member type returns > 0, the group is known non-empty
        and the remaining member types are skipped.
        -> Populated groups typically cost 1 API call instead of 5.
      * Automatic retry with exponential backoff on HTTP 429 / 503 / timeouts.
      * Optional -ThrottleMs delay between API calls.

    Steps performed:
      1. Retrieves all Security Groups from /infra/domains/default/groups
      2. Classifies each group as empty/non-empty with minimal API usage
      3. Cross-references empty groups against every DFW rule and every
         Tier-0/Tier-1 Gateway Firewall rule (Source / Destination / Applied To)
      4. Exports: "Summary" + "Empty Groups" + "Rule Usage" sheets (or CSVs)

.PARAMETER NSXManager
    FQDN or IP of the NSX-T Manager

.PARAMETER Username
    NSX-T username (default: admin)

.PARAMETER Password
    Password. Prompted securely if omitted.

.PARAMETER OutputPath
    Folder for output files (default: current directory)

.PARAMETER OutputFormat
    "Excel" | "CSV" | "Both"  (default: Excel)

.PARAMETER SkipCertificateCheck
    Bypass TLS certificate validation (self-signed certs)

.PARAMETER ThrottleMs
    Milliseconds to sleep between API calls (default: 50 = max ~20 req/s,
    well under the NSX default limit). Set 0 to disable.

.PARAMETER TimeoutSec
    Per-request HTTP timeout in seconds (default: 60)

.EXAMPLE
    .\Find-NSXEmptyGroups.ps1 -NSXManager 192.168.1.10 -SkipCertificateCheck

.EXAMPLE
    # Slower but gentler on a busy manager:
    .\Find-NSXEmptyGroups.ps1 -NSXManager nsxmgr.corp.local -ThrottleMs 200 -SkipCertificateCheck

.NOTES
    PowerShell 5.1+ supported; 7+ recommended.
    NSX-T 3.x / 4.x  (tested logic against 4.2.x Policy API)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]  [string]$NSXManager,
    [Parameter(Mandatory=$false)] [string]$Username = "admin",
    [Parameter(Mandatory=$false)] [string]$Password,
    [Parameter(Mandatory=$false)] [string]$OutputPath = (Get-Location).Path,
    [Parameter(Mandatory=$false)] [ValidateSet("Excel","CSV","Both")] [string]$OutputFormat = "Excel",
    [Parameter(Mandatory=$false)] [switch]$SkipCertificateCheck,
    [Parameter(Mandatory=$false)] [int]$ThrottleMs = 50,
    [Parameter(Mandatory=$false)] [int]$TimeoutSec = 60
)

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
        "WARN" {"Yellow"} "ERROR" {"Red"} "SUCCESS" {"Green"} default {"Cyan"}
    }
    Write-Host "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')][$Level] $Msg" -ForegroundColor $color
}

function Coerce-Array {
    param($Value)
    if ($null -eq $Value)   { return @() }
    if ($Value -is [array]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value)
    }
    return @($Value)
}

# Global API call counter (reported at the end)
$script:ApiCallCount = 0

# ===========================================================================
# LOW-LEVEL HTTP  — single place for throttle + retry/backoff + timeout
# ===========================================================================

function Invoke-NSXRequest {
    <#
      Wraps Invoke-WebRequest with:
        - throttle delay        (respects NSX rate limits)
        - retry with backoff    (429 / 503 / timeouts, up to 4 attempts)
        - request timeout
      Returns parsed JSON object, or throws after final attempt.
      404 is returned as $null (caller decides).
    #>
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$S,
        [bool]$SkipCert
    )

    if ($ThrottleMs -gt 0) { Start-Sleep -Milliseconds $ThrottleMs }

    $maxAttempts = 4
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {

        $sp = @{
            Uri             = $Uri
            Method          = $Method
            WebSession      = $S.WS
            Headers         = @{ "x-xsrf-token" = $S.XSRF }
            UseBasicParsing = $true
            TimeoutSec      = $TimeoutSec
        }
        if ($SkipCert -and $PSVersionTable.PSVersion.Major -ge 7) { $sp.SkipCertificateCheck = $true }

        try {
            $script:ApiCallCount++
            $raw = Invoke-WebRequest @sp
            if ([string]::IsNullOrWhiteSpace($raw.Content)) { return $null }
            return ($raw.Content | ConvertFrom-Json)
        }
        catch {
            $code = try { $_.Exception.Response.StatusCode.value__ } catch { 0 }
            $msg  = $_.Exception.Message

            if ($code -eq 404) { return $null }

            $isRetryable = ($code -eq 429) -or ($code -eq 503) -or
                           ($msg -match "timed out|timeout|The operation has timed out")

            if ($isRetryable -and $attempt -lt $maxAttempts) {
                $wait = [math]::Pow(2, $attempt)   # 2s, 4s, 8s
                Write-Log "Retryable error (HTTP $code) on attempt $attempt — waiting ${wait}s: $Uri" "WARN"
                Start-Sleep -Seconds $wait
                continue
            }

            throw
        }
    }
}

# ===========================================================================
# AUTHENTICATION  (session cookie + XSRF token — required on NSX-T 4.x)
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
        TimeoutSec      = $TimeoutSec
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
                 WebSession=$S.WS; Headers=@{"x-xsrf-token"=$S.XSRF}
                 UseBasicParsing=$true; TimeoutSec=$TimeoutSec }
        if ($SkipCert -and $PSVersionTable.PSVersion.Major -ge 7) { $sp.SkipCertificateCheck = $true }
        Invoke-WebRequest @sp | Out-Null
        Write-Log "Session closed."
    } catch { Write-Log "Could not close session: $($_.Exception.Message)" "WARN" }
}

# ===========================================================================
# API HELPERS
# ===========================================================================

function Invoke-NSX {
    # Paginated GET returning all results
    param(
        [string]$EP,
        [hashtable]$S,
        [bool]$SkipCert,
        [int]$PgSz = 1000,
        [switch]$NoPagination
    )

    $all = [System.Collections.Generic.List[object]]::new()
    $url    = if ($NoPagination) { "$($S.Base)$EP" } else { "$($S.Base)$EP`?page_size=$PgSz" }
    $cursor = $null

    do {
        $resp = Invoke-NSXRequest -Uri $url -S $S -SkipCert $SkipCert
        if ($null -eq $resp) { return ,@() }   # 404 or empty body

        $items = if     ($null -ne $resp.results) { Coerce-Array $resp.results }
                 elseif ($null -ne $resp.rules)    { Coerce-Array $resp.rules }
                 elseif ($resp -is [array])         { $resp }
                 else                               { @($resp) }

        foreach ($i in $items) { if ($null -ne $i) { $all.Add($i) } }

        $cursor = $null
        if (-not $NoPagination -and $null -ne $resp.cursor -and $resp.cursor -ne "") {
            $cursor = $resp.cursor
            $url = "$($S.Base)$EP`?page_size=$PgSz&cursor=$cursor"
        }
    } while ($cursor)

    return ,$all.ToArray()
}

function Get-NSXMemberCount {
    # Fast count: page_size=1 + result_count. 404 -> 0.
    param([string]$EP, [hashtable]$S, [bool]$SkipCert)

    try {
        $resp = Invoke-NSXRequest -Uri "$($S.Base)$EP`?page_size=1" -S $S -SkipCert $SkipCert
        if ($null -eq $resp) { return 0 }
        if ($null -ne $resp.result_count) { return [int]$resp.result_count }
        return (Coerce-Array $resp.results).Count
    }
    catch {
        # 400 -> retry without query string (some endpoints reject params)
        try {
            $resp = Invoke-NSXRequest -Uri "$($S.Base)$EP" -S $S -SkipCert $SkipCert
            if ($null -eq $resp) { return 0 }
            if ($null -ne $resp.result_count) { return [int]$resp.result_count }
            return (Coerce-Array $resp.results).Count
        } catch {
            Write-Log "Member count failed [$EP] — assuming 0: $($_.Exception.Message)" "WARN"
            return 0
        }
    }
}

# ===========================================================================
# GROUP EMPTINESS CLASSIFICATION  — minimal API calls
# ===========================================================================

function Test-GroupEmpty {
    <#
      Returns a hashtable: @{ IsEmpty = $bool; ApiCalls = n; DefType = "..."; Counts = @{} }

      Strategy (cheapest first):
        A) No expression at all                       -> EMPTY, 0 calls
        B) Expression contains ONLY static entries
           (PathExpression / IPAddressExpression /
            MACAddressExpression / ExternalIDExpression)
           with non-empty member lists                -> NOT empty, 0 calls
           with all lists empty                       -> EMPTY, 0 calls
        C) Anything dynamic (Condition, NestedGroup,
           mixed expressions)                         -> member API checks with
                                                          SHORT-CIRCUIT on first hit
    #>
    param($Group, [hashtable]$S, [bool]$SkipCert)

    $exprArr = Coerce-Array $Group.expression
    $result  = @{ IsEmpty = $false; DefType = ""; Counts = [ordered]@{} }

    # ── A) No expression → empty by definition, zero API calls ──────────────
    if ($exprArr.Count -eq 0) {
        $result.IsEmpty = $true
        $result.DefType = "No expression (empty definition)"
        return $result
    }

    $exprTypes = @($exprArr | ForEach-Object {
        if ($_.resource_type) { $_.resource_type } else { "Unknown" }
    } | Select-Object -Unique)
    $result.DefType = ($exprTypes -join ", ")

    # ── B) Purely static expressions → evaluate locally, zero API calls ─────
    $staticTypes  = @("PathExpression","IPAddressExpression","MACAddressExpression","ExternalIDExpression")
    $conjunction  = @("ConjunctionOperator")
    $onlyStatic   = $true
    foreach ($t in $exprTypes) {
        if ($t -notin ($staticTypes + $conjunction)) { $onlyStatic = $false; break }
    }

    if ($onlyStatic) {
        $staticMemberCount = 0
        foreach ($e in $exprArr) {
            switch ($e.resource_type) {
                "PathExpression"        { $staticMemberCount += (Coerce-Array $e.paths).Count }
                "IPAddressExpression"   { $staticMemberCount += (Coerce-Array $e.ip_addresses).Count }
                "MACAddressExpression"  { $staticMemberCount += (Coerce-Array $e.mac_addresses).Count }
                "ExternalIDExpression"  { $staticMemberCount += (Coerce-Array $e.external_ids).Count }
            }
        }
        $result.Counts["Static entries"] = $staticMemberCount
        $result.IsEmpty = ($staticMemberCount -eq 0)
        return $result
    }

    # ── C) Dynamic / mixed → member API checks with short-circuit ───────────
    # Ordered by likelihood of membership: VMs first, then IPs, then the rest.
    $memberTypes = @(
        @{ Name = "VMs";           Suffix = "/members/virtual-machines" }
        @{ Name = "IP Addresses";  Suffix = "/members/ip-addresses" }
        @{ Name = "Segment Ports"; Suffix = "/members/segment-ports" }
        @{ Name = "Segments";      Suffix = "/members/segments" }
        @{ Name = "VIFs";          Suffix = "/members/vifs" }
    )

    foreach ($mt in $memberTypes) {
        $ep = "/policy/api/v1/infra/domains/default/groups/$($Group.id)$($mt.Suffix)"
        $c  = Get-NSXMemberCount -EP $ep -S $S -SkipCert $SkipCert
        $result.Counts[$mt.Name] = $c

        if ($c -gt 0) {
            # SHORT-CIRCUIT: group is populated, skip remaining member types
            $result.IsEmpty = $false
            return $result
        }
    }

    $result.IsEmpty = $true
    return $result
}

# ===========================================================================
# MAIN
# ===========================================================================

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

$S = Connect-NSX -Base $base -User $Username -Pass $Password -SkipCert $skipCert

$emptyGroups = [System.Collections.Generic.List[object]]::new()
$usageRows   = [System.Collections.Generic.List[object]]::new()
$groups      = @()

try {

    # ── 1. ALL SECURITY GROUPS  (1 call per 1000 groups) ────────────────────
    Write-Log "=== Step 1: Retrieving all Security Groups ==="
    $groups = Invoke-NSX -EP "/policy/api/v1/infra/domains/default/groups" -S $S -SkipCert $skipCert
    Write-Log "Found $(($groups).Count) total Security Groups."

    # ── 2. CLASSIFY EMPTY GROUPS (minimal API calls) ────────────────────────
    Write-Log "=== Step 2: Classifying groups (static analysis first, API only when needed) ==="

    $idx = 0; $skippedApi = 0
    foreach ($g in $groups) {
        $idx++
        $gID   = $g.id
        $gName = if ($g.display_name) { $g.display_name } else { $gID }
        $gPath = if ($g.path) { $g.path } else { "/infra/domains/default/groups/$gID" }

        Write-Progress -Activity "Classifying groups" `
            -Status "$idx / $(($groups).Count) — $gName" `
            -PercentComplete ([int](($idx / [math]::Max(($groups).Count,1)) * 100))

        $callsBefore = $script:ApiCallCount
        $check = Test-GroupEmpty -Group $g -S $S -SkipCert $skipCert
        if ($script:ApiCallCount -eq $callsBefore) { $skippedApi++ }

        if ($check.IsEmpty) {
            Write-Log "  EMPTY: '$gName'  [$($check.DefType)]" "WARN"

            $countsStr = (($check.Counts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; ")

            $emptyGroups.Add([PSCustomObject][ordered]@{
                "Group Name"      = $gName
                "Group ID"        = $gID
                "Group Path"      = $gPath
                "Definition Type" = $check.DefType
                "Member Checks"   = if ($countsStr) { $countsStr } else { "none needed" }
                "Used In Rules"   = 0
                "Description"     = if ($g.description) { $g.description } else { "" }
                "Tags"            = if ($null -ne $g.tags) {
                                        (Coerce-Array $g.tags |
                                         ForEach-Object { "$($_.scope):$($_.tag)" }) -join ", "
                                    } else { "" }
            })
        }
    }
    Write-Progress -Activity "Classifying groups" -Completed

    Write-Log "Found $($emptyGroups.Count) EMPTY groups. ($skippedApi of $(($groups).Count) groups classified with ZERO API calls)" "SUCCESS"

    if ($emptyGroups.Count -eq 0) {
        Write-Log "No empty groups — nothing to cross-reference. Exiting." "SUCCESS"
        exit 0
    }

    # Fast lookup: group path → row object
    $emptyByPath = @{}
    foreach ($eg in $emptyGroups) { $emptyByPath[$eg."Group Path"] = $eg }

    # ── 3. CROSS-REFERENCE AGAINST FIREWALL RULES ───────────────────────────
    Write-Log "=== Step 3: Cross-referencing against firewall rules ==="

    function Test-RuleUsage {
        param($Rule, [string]$FWType, [string]$GwName, [string]$GwType,
              [string]$PolName, [string]$PolID)

        $fields = @(
            @{ Label = "Source";      Values = Coerce-Array $Rule.source_groups }
            @{ Label = "Destination"; Values = Coerce-Array $Rule.destination_groups }
            @{ Label = "Applied To";  Values = Coerce-Array $Rule.scope }
        )

        foreach ($f in $fields) {
            foreach ($v in $f.Values) {
                if ($null -ne $v -and $emptyByPath.ContainsKey($v)) {
                    $eg = $emptyByPath[$v]
                    $eg."Used In Rules" = [int]$eg."Used In Rules" + 1

                    $usageRows.Add([PSCustomObject][ordered]@{
                        "Group Name"            = $eg."Group Name"
                        "Group Path"            = $v
                        "Used As"               = $f.Label
                        "Firewall Type"         = $FWType
                        "Gateway"               = if ($GwName) { $GwName } else { "N/A" }
                        "Gateway Type"          = if ($GwType) { $GwType } else { "N/A" }
                        "Policy Name"           = $PolName
                        "Policy ID"             = $PolID
                        "Rule Name"             = if ($Rule.display_name) { $Rule.display_name } else { "" }
                        "Rule ID (NSX Manager)" = if ($null -ne $Rule.rule_id) { $Rule.rule_id } else { "" }
                        "Rule Policy ID"        = if ($Rule.id) { $Rule.id } else { "" }
                        "Rule Action"           = if ($Rule.action) { $Rule.action } else { "" }
                        "Rule Disabled"         = if ($Rule.disabled) { "Yes" } else { "No" }
                    })
                }
            }
        }
    }

    # 3a. DFW — NOTE: rules are embedded when fetching policies one by one,
    # but the collection endpoint doesn't include them; we still need one call
    # per policy for its rules. This is unavoidable but bounded by policy count.
    Write-Log "  Scanning Distributed Firewall rules..."
    $policies = Invoke-NSX -EP "/policy/api/v1/infra/domains/default/security-policies" -S $S -SkipCert $skipCert
    foreach ($pol in $policies) {
        $rules = Invoke-NSX -EP "/policy/api/v1/infra/domains/default/security-policies/$($pol.id)/rules" -S $S -SkipCert $skipCert
        foreach ($r in $rules) {
            Test-RuleUsage -Rule $r -FWType "DFW" -GwName "" -GwType "" `
                -PolName $pol.display_name -PolID $pol.id
        }
    }

    # 3b. GFW Tier-0  (1 aggregated call per gateway — includes all rules)
    Write-Log "  Scanning Gateway Firewall rules (Tier-0)..."
    $t0s = Invoke-NSX -EP "/policy/api/v1/infra/tier-0s" -S $S -SkipCert $skipCert
    foreach ($gw in $t0s) {
        $pols = Invoke-NSX -EP "/policy/api/v1/infra/tier-0s/$($gw.id)/gateway-firewall" -S $S -SkipCert $skipCert -NoPagination
        foreach ($pol in $pols) {
            foreach ($r in (Coerce-Array $pol.rules)) {
                Test-RuleUsage -Rule $r -FWType "GFW" -GwName $gw.display_name -GwType "Tier-0" `
                    -PolName $pol.display_name -PolID $pol.id
            }
        }
    }

    # 3c. GFW Tier-1
    Write-Log "  Scanning Gateway Firewall rules (Tier-1)..."
    $t1s = Invoke-NSX -EP "/policy/api/v1/infra/tier-1s" -S $S -SkipCert $skipCert
    foreach ($gw in $t1s) {
        $pols = Invoke-NSX -EP "/policy/api/v1/infra/tier-1s/$($gw.id)/gateway-firewall" -S $S -SkipCert $skipCert -NoPagination
        foreach ($pol in $pols) {
            foreach ($r in (Coerce-Array $pol.rules)) {
                Test-RuleUsage -Rule $r -FWType "GFW" -GwName $gw.display_name -GwType "Tier-1" `
                    -PolName $pol.display_name -PolID $pol.id
            }
        }
    }

} finally {
    Disconnect-NSX -S $S -SkipCert $skipCert
}

# ── Summary ──────────────────────────────────────────────────────────────────
$nEmpty      = $emptyGroups.Count
$nUsed       = @($emptyGroups | Where-Object { [int]$_."Used In Rules" -gt 0 }).Count
$nUnused     = $nEmpty - $nUsed
$nReferences = $usageRows.Count

Write-Log "=== Results ===" "SUCCESS"
Write-Log "  Total API calls made:          $($script:ApiCallCount)" "INFO"
Write-Log "  Empty groups total:            $nEmpty" "SUCCESS"
Write-Log "  Empty groups USED in rules:    $nUsed   <-- rules matching nothing; review!" "WARN"
Write-Log "  Empty groups NOT used at all:  $nUnused <-- cleanup candidates" "SUCCESS"
Write-Log "  Total rule references found:   $nReferences" "SUCCESS"

# ── Output ───────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
$ts      = Get-Date -Format "yyyyMMdd_HHmmss"
$safeMgr = $NSXManager -replace "[^a-zA-Z0-9_\-]","_"
$base2   = Join-Path $OutputPath "NSX_EmptyGroups_${safeMgr}_${ts}"

# Excel
if ($OutputFormat -in @("Excel","Both")) {
    $xlsx = "$base2.xlsx"
    $xs   = @{ AutoSize=$true; BoldTopRow=$true; FreezeTopRow=$true; AutoFilter=$true }

    @(
        [PSCustomObject]@{ Item="NSX Manager";                 Value=$NSXManager }
        [PSCustomObject]@{ Item="Export Date";                 Value=(Get-Date -f "yyyy-MM-dd HH:mm:ss") }
        [PSCustomObject]@{ Item="Total Groups Scanned";        Value=(Coerce-Array $groups).Count }
        [PSCustomObject]@{ Item="Empty Groups";                Value=$nEmpty }
        [PSCustomObject]@{ Item="Empty Groups Used In Rules";  Value=$nUsed }
        [PSCustomObject]@{ Item="Empty Groups Not Used";       Value=$nUnused }
        [PSCustomObject]@{ Item="Total Rule References";       Value=$nReferences }
        [PSCustomObject]@{ Item="Total API Calls";             Value=$script:ApiCallCount }
    ) | Export-Excel -Path $xlsx -WorksheetName "Summary" `
        -AutoSize -BoldTopRow -FreezeTopRow -TableName "Summary" -TableStyle Medium9

    $emptyGroups | Export-Excel -Path $xlsx -WorksheetName "Empty Groups" `
        @xs -TableName "EmptyGroups" -TableStyle Medium2

    if ($nReferences -gt 0) {
        $usageRows | Export-Excel -Path $xlsx -WorksheetName "Rule Usage" `
            @xs -TableName "RuleUsage" -TableStyle Medium4
    }

    Write-Log "Excel: $xlsx" "SUCCESS"
}

# CSV
if ($OutputFormat -in @("CSV","Both")) {
    $emptyGroups | Export-Csv "$base2`_EmptyGroups.csv" -NoTypeInformation -Encoding UTF8
    Write-Log "Empty groups CSV: $base2`_EmptyGroups.csv" "SUCCESS"

    if ($nReferences -gt 0) {
        $usageRows | Export-Csv "$base2`_RuleUsage.csv" -NoTypeInformation -Encoding UTF8
        Write-Log "Rule usage CSV: $base2`_RuleUsage.csv" "SUCCESS"
    }
}

Write-Log "=== Done ===" "SUCCESS"
