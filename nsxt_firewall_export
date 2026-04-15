<#
.SYNOPSIS
    Exports NSX-T 4.x Distributed Firewall (DFW) and Gateway Firewall (GFW) rules to Excel/CSV.

.DESCRIPTION
    Connects to an NSX-T Manager via REST API (Policy API v1) and retrieves:
      - All Distributed Firewall security policies and rules (all categories)
      - All Gateway Firewall policies and rules for every Tier-0 and Tier-1 gateway
    Output is saved as a multi-sheet .xlsx file (requires ImportExcel module) and/or CSV files.

.PARAMETER NSXManager
    FQDN or IP address of the NSX-T Manager (e.g. "nsxmgr.lab.local" or "192.168.1.10")

.PARAMETER Username
    NSX-T Manager username (default: admin)

.PARAMETER Password
    NSX-T Manager password. If omitted, you will be prompted securely.

.PARAMETER OutputPath
    Directory where output files will be saved (default: current directory)

.PARAMETER OutputFormat
    Output format: "Excel", "CSV", or "Both" (default: "Excel")

.PARAMETER SkipCertificateCheck
    Ignore TLS certificate errors (useful for self-signed certs in lab environments)

.EXAMPLE
    .\Export-NSXFirewallRules.ps1 -NSXManager "192.168.1.10" -Username admin -SkipCertificateCheck

.EXAMPLE
    .\Export-NSXFirewallRules.ps1 -NSXManager nsxmgr.lab.local -OutputFormat Both -OutputPath C:\Exports

.NOTES
    Requires PowerShell 7+ (for -SkipCertificateCheck on Invoke-RestMethod).
    For Excel output: Install-Module -Name ImportExcel
    NSX-T API: Policy API v1 (compatible with NSX-T 3.x and 4.x)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NSXManager,

    [Parameter(Mandatory = $false)]
    [string]$Username = "admin",

    [Parameter(Mandatory = $false)]
    [string]$Password,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Excel", "CSV", "Both")]
    [string]$OutputFormat = "Excel",

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        default   { "Cyan" }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
}

function Get-BasicAuthHeader {
    param([string]$User, [string]$Pass)
    $pair = "${User}:${Pass}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $b64 = [Convert]::ToBase64String($bytes)
    return @{ Authorization = "Basic $b64"; "Content-Type" = "application/json" }
}

function Invoke-NSXApi {
    <#
    .SYNOPSIS Wrapper around Invoke-RestMethod with pagination support.
    Returns all results by following the cursor automatically.
    #>
    param(
        [string]$Endpoint,
        [hashtable]$Headers,
        [string]$BaseUrl,
        [switch]$SkipCert,
        [int]$PageSize = 1000
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $url = "${BaseUrl}${Endpoint}?page_size=${PageSize}"

    do {
        try {
            $splat = @{
                Uri     = $url
                Method  = "GET"
                Headers = $Headers
            }
            if ($SkipCert) { $splat["SkipCertificateCheck"] = $true }

            $response = Invoke-RestMethod @splat

            # Collect results — different endpoints use different property names
            $items = if ($response.PSObject.Properties.Name -contains "results") {
                $response.results
            } elseif ($response.PSObject.Properties.Name -contains "rules") {
                $response.rules
            } else {
                # Single object or gateway-firewall flat list
                if ($response -is [array]) { $response } else { @($response) }
            }

            if ($items) { $allResults.AddRange([object[]]$items) }

            # Follow cursor for pagination
            if ($response.PSObject.Properties.Name -contains "cursor" -and $response.cursor) {
                $cursor = $response.cursor
                $url = "${BaseUrl}${Endpoint}?page_size=${PageSize}&cursor=${cursor}"
            } else {
                $cursor = $null
            }
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 404) {
                Write-Log "404 Not Found: $url — skipping." "WARN"
                return @()
            }
            throw
        }
    } while ($cursor)

    return $allResults.ToArray()
}

function Resolve-NSXPath {
    <#
    .SYNOPSIS Converts an NSX policy path like /infra/services/HTTPS to a friendly display name.
    Uses a simple cache to avoid redundant API calls.
    #>
    param(
        [string[]]$Paths,
        [hashtable]$Headers,
        [string]$BaseUrl,
        [hashtable]$Cache,
        [switch]$SkipCert
    )

    if (-not $Paths -or $Paths.Count -eq 0) { return "ANY" }

    $resolved = foreach ($p in $Paths) {
        if ($p -eq "ANY" -or $p -eq "") { "ANY"; continue }

        if ($Cache.ContainsKey($p)) {
            $Cache[$p]; continue
        }

        try {
            $apiPath = "/policy/api/v1" + $p
            $splat = @{ Uri = "${BaseUrl}${apiPath}"; Method = "GET"; Headers = $Headers }
            if ($SkipCert) { $splat["SkipCertificateCheck"] = $true }
            $obj = Invoke-RestMethod @splat
            $name = if ($obj.display_name) { $obj.display_name } else { $p }
            $Cache[$p] = $name
            $name
        }
        catch {
            # Can't resolve – return the raw path's last segment as fallback
            $fallback = ($p -split "/")[-1]
            $Cache[$p] = $fallback
            $fallback
        }
    }

    return ($resolved -join ", ")
}

function Format-Services {
    param([array]$ServiceEntries)
    if (-not $ServiceEntries -or $ServiceEntries.Count -eq 0) { return "ANY" }

    $parts = foreach ($svc in $ServiceEntries) {
        switch ($svc.resource_type) {
            "L4PortSetServiceEntry" {
                $proto = $svc.l4_protocol
                $dstPorts = if ($svc.destination_ports) { $svc.destination_ports -join "," } else { "Any" }
                "${proto}:${dstPorts}"
            }
            "ICMPTypeServiceEntry" {
                "ICMP(type=$($svc.icmp_type))"
            }
            "IPProtocolServiceEntry" {
                "IP:$($svc.protocol_number)"
            }
            default {
                $svc.resource_type
            }
        }
    }
    return ($parts -join " | ")
}

function ConvertTo-FlatRule {
    <#
    .SYNOPSIS Converts a raw NSX rule object into a flat hashtable suitable for CSV/Excel export.
    #>
    param(
        [object]$Rule,
        [string]$PolicyName,
        [string]$PolicyCategory,
        [string]$PolicyID,
        [string]$FirewallType,          # "DFW" or "GFW"
        [string]$GatewayName,           # Only for GFW
        [string]$GatewayType,           # "Tier-0" / "Tier-1"
        [hashtable]$Headers,
        [string]$BaseUrl,
        [hashtable]$PathCache,
        [switch]$SkipCert
    )

    $commonSplat = @{
        Headers  = $Headers
        BaseUrl  = $BaseUrl
        Cache    = $PathCache
        SkipCert = $SkipCert
    }

    $sources      = Resolve-NSXPath -Paths $Rule.source_groups      @commonSplat
    $destinations = Resolve-NSXPath -Paths $Rule.destination_groups  @commonSplat

    # Services: either path references or inline service entries
    $serviceStr = if ($Rule.services -and $Rule.services.Count -gt 0 -and $Rule.services[0] -ne "ANY") {
        $svcNames = foreach ($svcPath in $Rule.services) {
            if ($svcPath -eq "ANY") { "ANY" }
            else {
                if ($PathCache.ContainsKey($svcPath)) { $PathCache[$svcPath] }
                else {
                    try {
                        $splat = @{ Uri = "${BaseUrl}/policy/api/v1${svcPath}"; Method = "GET"; Headers = $Headers }
                        if ($SkipCert) { $splat["SkipCertificateCheck"] = $true }
                        $svcObj = Invoke-RestMethod @splat
                        $name = $svcObj.display_name
                        $PathCache[$svcPath] = $name
                        $name
                    } catch { ($svcPath -split "/")[-1] }
                }
            }
        }
        $svcNames -join ", "
    } elseif ($Rule.service_entries -and $Rule.service_entries.Count -gt 0) {
        Format-Services -ServiceEntries $Rule.service_entries
    } else {
        "ANY"
    }

    $appliedTo = if ($Rule.scope -and $Rule.scope.Count -gt 0 -and $Rule.scope[0] -ne "ANY") {
        Resolve-NSXPath -Paths $Rule.scope @commonSplat
    } else { "DFW" }

    [ordered]@{
        "Firewall Type"      = $FirewallType
        "Gateway"            = if ($GatewayName) { $GatewayName } else { "N/A" }
        "Gateway Type"       = if ($GatewayType) { $GatewayType } else { "N/A" }
        "Policy Name"        = $PolicyName
        "Policy ID"          = $PolicyID
        "Category"           = $PolicyCategory
        "Rule Name"          = $Rule.display_name
        "Rule ID"            = $Rule.id
        "Sequence Number"    = $Rule.sequence_number
        "Source"             = $sources
        "Destination"        = $destinations
        "Services"           = $serviceStr
        "Action"             = $Rule.action
        "Direction"          = if ($Rule.direction) { $Rule.direction } else { "IN_OUT" }
        "IP Protocol"        = if ($Rule.ip_protocol) { $Rule.ip_protocol } else { "IPV4_IPV6" }
        "Applied To"         = $appliedTo
        "Logged"             = if ($Rule.logged) { "Yes" } else { "No" }
        "Disabled"           = if ($Rule.disabled) { "Yes" } else { "No" }
        "Notes"              = if ($Rule.notes) { $Rule.notes } else { "" }
        "Tags"               = if ($Rule.tags) { ($Rule.tags | ForEach-Object { "$($_.scope):$($_.tag)" }) -join ", " } else { "" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

# ── Password prompt ──────────────────────────────────────────────────────────
if (-not $Password) {
    $secPass = Read-Host "Enter password for $Username@$NSXManager" -AsSecureString
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
    )
}

$baseUrl = "https://${NSXManager}"
$headers = Get-BasicAuthHeader -User $Username -Pass $Password
$skipCert = $SkipCertificateCheck.IsPresent

# ── Check ImportExcel if needed ──────────────────────────────────────────────
if ($OutputFormat -in @("Excel", "Both")) {
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Log "ImportExcel module not found. Attempting install..." "WARN"
        try {
            Install-Module -Name ImportExcel -Scope CurrentUser -Force -SkipPublisherCheck
            Import-Module ImportExcel
        } catch {
            Write-Log "Could not install ImportExcel. Falling back to CSV only." "WARN"
            $OutputFormat = "CSV"
        }
    } else {
        Import-Module ImportExcel -ErrorAction SilentlyContinue
    }
}

# Shared path resolution cache (avoids redundant API calls)
$pathCache = @{}

$allDFWRows  = [System.Collections.Generic.List[object]]::new()
$allGFWRows  = [System.Collections.Generic.List[object]]::new()

# ── 1. DISTRIBUTED FIREWALL ─────────────────────────────────────────────────
Write-Log "=== Fetching Distributed Firewall Rules ==="

$dfwPolicies = Invoke-NSXApi `
    -Endpoint "/policy/api/v1/infra/domains/default/security-policies" `
    -Headers $headers -BaseUrl $baseUrl -SkipCert:$skipCert

Write-Log "Found $($dfwPolicies.Count) DFW security policies."

foreach ($policy in $dfwPolicies) {
    $policyName = $policy.display_name
    $policyID   = $policy.id
    $category   = if ($policy.category) { $policy.category } else { "Application" }

    Write-Log "  Processing DFW policy: '$policyName' (Category: $category)"

    $rules = Invoke-NSXApi `
        -Endpoint "/policy/api/v1/infra/domains/default/security-policies/${policyID}/rules" `
        -Headers $headers -BaseUrl $baseUrl -SkipCert:$skipCert

    Write-Log "    → $($rules.Count) rules found."

    foreach ($rule in $rules) {
        $row = ConvertTo-FlatRule `
            -Rule $rule `
            -PolicyName $policyName `
            -PolicyCategory $category `
            -PolicyID $policyID `
            -FirewallType "DFW" `
            -GatewayName "" `
            -GatewayType "" `
            -Headers $headers `
            -BaseUrl $baseUrl `
            -PathCache $pathCache `
            -SkipCert:$skipCert
        $allDFWRows.Add([PSCustomObject]$row)
    }
}

# ── 2. GATEWAY FIREWALL — Tier-0 ────────────────────────────────────────────
Write-Log "=== Fetching Gateway Firewall Rules (Tier-0) ==="

$tier0s = Invoke-NSXApi `
    -Endpoint "/policy/api/v1/infra/tier-0s" `
    -Headers $headers -BaseUrl $baseUrl -SkipCert:$skipCert

Write-Log "Found $($tier0s.Count) Tier-0 gateways."

foreach ($t0 in $tier0s) {
    $gwName = $t0.display_name
    $gwID   = $t0.id
    Write-Log "  Processing Tier-0: '$gwName'"

    # gateway-firewall returns a flat list of policy objects with embedded rules
    $gwPolicies = Invoke-NSXApi `
        -Endpoint "/policy/api/v1/infra/tier-0s/${gwID}/gateway-firewall" `
        -Headers $headers -BaseUrl $baseUrl -SkipCert:$skipCert

    foreach ($gfwPolicy in $gwPolicies) {
        $policyName = $gfwPolicy.display_name
        $policyID   = $gfwPolicy.id
        $category   = if ($gfwPolicy.category) { $gfwPolicy.category } else { "Default" }
        $rules      = if ($gfwPolicy.rules) { $gfwPolicy.rules } else { @() }

        Write-Log "    Policy: '$policyName' — $($rules.Count) rules"

        foreach ($rule in $rules) {
            $row = ConvertTo-FlatRule `
                -Rule $rule `
                -PolicyName $policyName `
                -PolicyCategory $category `
                -PolicyID $policyID `
                -FirewallType "GFW" `
                -GatewayName $gwName `
                -GatewayType "Tier-0" `
                -Headers $headers `
                -BaseUrl $baseUrl `
                -PathCache $pathCache `
                -SkipCert:$skipCert
            $allGFWRows.Add([PSCustomObject]$row)
        }
    }
}

# ── 3. GATEWAY FIREWALL — Tier-1 ────────────────────────────────────────────
Write-Log "=== Fetching Gateway Firewall Rules (Tier-1) ==="

$tier1s = Invoke-NSXApi `
    -Endpoint "/policy/api/v1/infra/tier-1s" `
    -Headers $headers -BaseUrl $baseUrl -SkipCert:$skipCert

Write-Log "Found $($tier1s.Count) Tier-1 gateways."

foreach ($t1 in $tier1s) {
    $gwName = $t1.display_name
    $gwID   = $t1.id
    Write-Log "  Processing Tier-1: '$gwName'"

    $gwPolicies = Invoke-NSXApi `
        -Endpoint "/policy/api/v1/infra/tier-1s/${gwID}/gateway-firewall" `
        -Headers $headers -BaseUrl $baseUrl -SkipCert:$skipCert

    foreach ($gfwPolicy in $gwPolicies) {
        $policyName = $gfwPolicy.display_name
        $policyID   = $gfwPolicy.id
        $category   = if ($gfwPolicy.category) { $gfwPolicy.category } else { "Default" }
        $rules      = if ($gfwPolicy.rules) { $gfwPolicy.rules } else { @() }

        Write-Log "    Policy: '$policyName' — $($rules.Count) rules"

        foreach ($rule in $rules) {
            $row = ConvertTo-FlatRule `
                -Rule $rule `
                -PolicyName $policyName `
                -PolicyCategory $category `
                -PolicyID $policyID `
                -FirewallType "GFW" `
                -GatewayName $gwName `
                -GatewayType "Tier-1" `
                -Headers $headers `
                -BaseUrl $baseUrl `
                -PathCache $pathCache `
                -SkipCert:$skipCert
            $allGFWRows.Add([PSCustomObject]$row)
        }
    }
}

# Summary
$totalDFW = $allDFWRows.Count
$totalGFW = $allGFWRows.Count
Write-Log "=== Collection complete: $totalDFW DFW rules, $totalGFW GFW rules ===" "SUCCESS"

if ($totalDFW -eq 0 -and $totalGFW -eq 0) {
    Write-Log "No rules found. Exiting." "WARN"
    exit 0
}

# ── 4. OUTPUT ────────────────────────────────────────────────────────────────
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$safeMgr    = $NSXManager -replace "[^a-zA-Z0-9_\-]", "_"
$baseName   = "NSX_FW_Export_${safeMgr}_${timestamp}"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

# ── Excel output ─────────────────────────────────────────────────────────────
if ($OutputFormat -in @("Excel", "Both")) {
    $xlsxPath = Join-Path $OutputPath "${baseName}.xlsx"
    Write-Log "Writing Excel file: $xlsxPath"

    # Summary sheet data
    $summaryRows = @(
        [PSCustomObject]@{ Item = "NSX Manager";           Value = $NSXManager }
        [PSCustomObject]@{ Item = "Export Date";           Value = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
        [PSCustomObject]@{ Item = "DFW Rules Exported";    Value = $totalDFW }
        [PSCustomObject]@{ Item = "GFW Rules Exported";    Value = $totalGFW }
        [PSCustomObject]@{ Item = "Total Rules Exported";  Value = ($totalDFW + $totalGFW) }
    )

    # Common Excel styling parameters
    $xlStyle = @{
        AutoSize       = $true
        BoldTopRow     = $true
        FreezeTopRow   = $true
        AutoFilter     = $true
    }

    # Write Summary
    $summaryRows | Export-Excel -Path $xlsxPath -WorksheetName "Summary" `
        -AutoSize -BoldTopRow -FreezeTopRow -TableName "Summary" -TableStyle Medium9

    # Write DFW rules
    if ($allDFWRows.Count -gt 0) {
        $allDFWRows | Export-Excel -Path $xlsxPath -WorksheetName "Distributed Firewall" `
            @xlStyle -TableName "DFWRules" -TableStyle Medium2 -Append:$false
    }

    # Write GFW rules
    if ($allGFWRows.Count -gt 0) {
        $allGFWRows | Export-Excel -Path $xlsxPath -WorksheetName "Gateway Firewall" `
            @xlStyle -TableName "GFWRules" -TableStyle Medium4 -Append:$false
    }

    # Combined sheet (all rules)
    $allRows = [System.Collections.Generic.List[object]]::new()
    $allRows.AddRange($allDFWRows.ToArray())
    $allRows.AddRange($allGFWRows.ToArray())

    $allRows | Export-Excel -Path $xlsxPath -WorksheetName "All Rules" `
        @xlStyle -TableName "AllRules" -TableStyle Medium6 -Append:$false

    Write-Log "Excel export complete: $xlsxPath" "SUCCESS"
}

# ── CSV output ───────────────────────────────────────────────────────────────
if ($OutputFormat -in @("CSV", "Both")) {
    if ($allDFWRows.Count -gt 0) {
        $dfwCsv = Join-Path $OutputPath "${baseName}_DFW.csv"
        $allDFWRows | Export-Csv -Path $dfwCsv -NoTypeInformation -Encoding UTF8
        Write-Log "DFW CSV: $dfwCsv" "SUCCESS"
    }

    if ($allGFWRows.Count -gt 0) {
        $gfwCsv = Join-Path $OutputPath "${baseName}_GFW.csv"
        $allGFWRows | Export-Csv -Path $gfwCsv -NoTypeInformation -Encoding UTF8
        Write-Log "GFW CSV: $gfwCsv" "SUCCESS"
    }

    # Combined
    $allRows2 = @($allDFWRows) + @($allGFWRows)
    $allCsv = Join-Path $OutputPath "${baseName}_ALL.csv"
    $allRows2 | Export-Csv -Path $allCsv -NoTypeInformation -Encoding UTF8
    Write-Log "Combined CSV: $allCsv" "SUCCESS"
}

Write-Log "=== Export finished successfully ===" "SUCCESS"
