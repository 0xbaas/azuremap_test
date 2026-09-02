#==============================================================================
# AzureMap v2 - Core/Console.ps1
# Human-facing console renderer: per-check status lines grouped by domain,
# assessment plan, and the final run summary.
#
# Output discipline:
#   * Never prints raw hashtables, arrays, API objects, tenant-wide data,
#     tokens, tenant IDs, subscription IDs, UPNs, object IDs, or resource IDs.
#   * Only prints aggregate counts and finding TITLES (the human-readable
#     message), plus severity/service/affected-count.
#   * Internal statuses (Pass/Fail/Partial/NotEvaluated/...) stay in JSON/CSV/
#     HTML and tests; the CLI shows human display labels (Clean, Needs review,
#     Partially checked, Could not check, Not in scope, Skipped, Tool error,
#     Inventory) via Get-StatusDisplayInfo.
#   * -Quiet suppresses all output. -VerboseOutput adds INFO log lines,
#     -DebugOutput adds raw log lines and legacy banners. Colors are
#     suppressed when Config.NoColor / NO_COLOR is set (via Write-UiHost).
#   * Opt-in detail switches: -ShowFindings prints raw per-finding blocks,
#     -ShowRemediation adds remediation text to those blocks, and
#     -DetailedSummary shows Not in scope / Skipped rows during the run plus
#     the full Check results section in the final summary. Remediation and
#     per-finding detail are always preserved in HTML/JSON/CSV and the log.
#==============================================================================

#region ---- Display metadata (human names, domains, status labels) ----

# Curated short display names per check. The CLI leads with these; the raw
# CheckId is secondary metadata (muted, end of line). Fallback for unmapped
# checks: the registered Name (Test-* function names are de-camelcased).
$script:CheckDisplayNames = @{
    # Azure - Identity
    'IDENTITY-001'       = 'Long-lived credentials'
    'IDENTITY-002'       = 'Dormant service principals'
    'IDENTITY-003'       = 'Privileged RBAC assignments'
    'IDENTITY-004'       = 'Expired credentials'
    'IDENTITY-005'       = 'Custom RBAC roles'
    'IDENTITY-006'       = 'Identity-resource mapping'
    'IDENTITY-007'       = 'RBAC decomposition'
    # Entra
    'ENTRA-01'           = 'Privileged role assignments'
    'ENTRA-02'           = 'PIM eligible assignments'
    'ENTRA-03'           = 'Dangerous app permissions'
    'ENTRA-04'           = 'Ownership risks'
    'ENTRA-05'           = 'Role-assignable groups'
    'ENTRA-06'           = 'OAuth consent risks'
    'ENTRA-07'           = 'App credential hygiene'
    'ENTRA-08'           = 'External collaboration risks'
    'ENTRA-09'           = 'Conditional Access coverage'
    'ENTRA-10'           = 'Authentication methods'
    'ENTRA-11'           = 'Break-glass account hygiene'
    'ENTRA-12'           = 'Workload identity federation'
    # Key Vault
    'KEYVAULT-001'       = 'Key Vault RBAC authorization'
    'KEYVAULT-002'       = 'Key Vault network exposure'
    'KEYVAULT-003'       = 'Secret expiration hygiene'
    # Storage
    'STORAGE-001'        = 'Shared key authentication'
    'STORAGE-002'        = 'Public network access'
    'STORAGE-003'        = 'Advanced security'
    'STORAGE-004'        = 'Anonymous blob access'
    'STORAGE-005'        = 'Data exfiltration vectors'
    'STORAGE-006'        = 'Storage key & SAS exposure'
    'STORAGE-007'        = 'Storage double encryption'
    # Networking
    'NETWORK-001'        = 'Sensitive inbound exposure'
    'NETWORK-002'        = 'Private endpoint DNS linkage'
    'NETWORK-003'        = 'Public IP inventory'
    'NETWORK-004'        = 'VNet subnet security'
    'NETWORK-005'        = 'VNet peering security'
    'NETWORK-006'        = 'Firewall threat intelligence'
    'NETWORK-007'        = 'Application Gateway WAF'
    'NETWORK-008'        = 'Outbound exfiltration paths'
    'NETWORK-009'        = 'App Gateway listener hygiene'
    'NETWORK-010'        = 'PaaS private connectivity'
    # Data platforms
    'SQL-001'            = 'SQL database security'
    'SQL-002'            = 'SQL advanced security'
    'DATAPLATFORM-001'   = 'Cosmos DB security'
    'DATAPLATFORM-002'   = 'Synapse public access'
    # Compute & apps
    'COMPUTE-001'        = 'AKS advanced security'
    'COMPUTE-002'        = 'AKS privilege escalation'
    'COMPUTE-003'        = 'Container registry security'
    'COMPUTE-004'        = 'VM monitoring agents'
    'COMPUTE-005'        = 'App Service security'
    'COMPUTE-006'        = 'App Service FTP state'
    'COMPUTE-007'        = 'VM backup coverage'
    # Messaging & integration
    'MESSAGING-001'      = 'Event Hub public access'
    'MESSAGING-002'      = 'Service Bus security'
    'MESSAGING-003'      = 'API Management exposure'
    'LOGICAPPS-001'      = 'Logic App managed identities'
    # Monitoring & governance
    'MONITORING-001'     = 'Diagnostic settings coverage'
    'MONITORING-002'     = 'Resource locks'
    'MONITORING-003'     = 'Automation Run As accounts'
    'MONITORING-004'     = 'Extended diagnostics coverage'
    'AZURE-GOV-001'      = 'Defender for Cloud coverage'
    # Exposure
    'AZURE-EXPOSURE-001' = 'Public exposure inventory'
}

# Domain grouping for the per-check output. Checks are displayed (and executed)
# in this order within each phase so the operator reads themed sections.
$script:CheckDomainOrder = @(
    'Identity',
    'Key Vault',
    'Storage',
    'Networking',
    'Data platforms',
    'Compute & apps',
    'Messaging & integration',
    'Monitoring & governance',
    'Exposure',
    'Other'
)

# EntraMap product grouping (registered Service -> human CLI group). Applied
# ONLY when the loaded product is EntraMap (State.Metadata.ProductName); in
# every other composition Entra checks keep the legacy single 'Identity'
# bucket, so AzureMap/combined output is unchanged. Covers all 15 Entra-side
# checks: ENTRA-01..12 plus the relocated IDENTITY-001/002/004 (Service
# 'Identity', Category 'Entra').
$script:EntraCheckGroupByService = @{
    'EntraRoles'             = 'Identity & roles'
    'EntraPIM'               = 'Identity & roles'
    'EntraGroups'            = 'Identity & roles'
    'EntraBreakGlass'        = 'Identity & roles'
    'EntraApps'              = 'Applications'
    'EntraOwnership'         = 'Applications'
    'EntraOAuth'             = 'Applications'
    'EntraOverview'          = 'Applications'
    'Identity'               = 'Applications'
    'EntraConditionalAccess' = 'Conditional Access'
    'EntraAuthMethods'       = 'Authentication'
    'EntraExternalCollab'    = 'Collaboration'
    'EntraWorkloadIdentity'  = 'Workload identity'
}

# EntraMap group render/execution order (unknown groups sort last via 'Other').
$script:EntraCheckDomainOrder = @(
    'Identity & roles',
    'Applications',
    'Conditional Access',
    'Authentication',
    'Collaboration',
    'Workload identity',
    'Other'
)

function Test-EntraMapProductLoaded {
    <#
    .SYNOPSIS
        Returns $true when the current session state belongs to the EntraMap
        product (drives product-specific grouping/plan rendering). $false for
        AzureMap, combined loads, and uninitialized state.
    #>
    [CmdletBinding()]
    param()
    return ($script:State -and
            $script:State.Metadata -and
            "$($script:State.Metadata.ProductName)" -eq 'EntraMap')
}

function Get-CheckDomainOrderList {
    <#
    .SYNOPSIS
        Returns the active domain-order list for the loaded product: the
        EntraMap group order for EntraMap, the Azure domain order otherwise.
    #>
    [CmdletBinding()]
    param()
    if (Test-EntraMapProductLoaded) { return $script:EntraCheckDomainOrder }
    return $script:CheckDomainOrder
}

function Get-CheckDomain {
    <#
    .SYNOPSIS
        Maps a registered check to its human CLI/HTML domain section.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Check)

    if ("$($Check.Category)" -eq 'Entra') {
        # EntraMap renders its own human group names; every other composition
        # keeps the legacy single 'Identity' bucket (AzureMap output unchanged).
        if (Test-EntraMapProductLoaded) {
            $group = $script:EntraCheckGroupByService["$($Check.Service)"]
            if ($group) { return $group }
            return 'Other'
        }
        return 'Identity'
    }
    switch ("$($Check.Service)") {
        'Identity'   { return 'Identity' }
        'KeyVault'   { return 'Key Vault' }
        'Storage'    { return 'Storage' }
        'Network'    { return 'Networking' }
        { $_ -in @('SQL', 'CosmosDB', 'Synapse') }                 { return 'Data platforms' }
        { $_ -in @('AKS', 'Compute', 'ContainerRegistry', 'AppService') } { return 'Compute & apps' }
        { $_ -in @('EventHub', 'ServiceBus', 'APIM', 'LogicApp') } { return 'Messaging & integration' }
        { $_ -in @('Diagnostics', 'ResourceLocks', 'Automation', 'Governance', 'Monitoring') } { return 'Monitoring & governance' }
        'Exposure'   { return 'Exposure' }
        default      { return 'Other' }
    }
}

function Get-CheckDomainSortIndex {
    <#
    .SYNOPSIS
        Returns the sort ordinal of a check's domain (unknown domains last).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Check)
    $order = Get-CheckDomainOrderList
    $idx = [Array]::IndexOf($order, (Get-CheckDomain -Check $Check))
    if ($idx -lt 0) { return $order.Count }
    return $idx
}

function Get-CheckDisplayName {
    <#
    .SYNOPSIS
        Returns the curated human display name for a check. Never truncated:
        display names are short by design, so no "..." ellipses appear.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Check)

    $id = "$($Check.CheckId)"
    if ($script:CheckDisplayNames.ContainsKey($id)) { return $script:CheckDisplayNames[$id] }

    $name = "$($Check.Name)"
    if ($name -match '^Test-') {
        # Entra definitions register their function name; make it readable.
        # -creplace: case-SENSITIVE split on lower/digit -> Upper boundaries
        # (plain -replace is case-insensitive and would split every bigram).
        $name = $name -replace '^Test-', ''
        $name = ($name -creplace '([a-z0-9])([A-Z])', '$1 $2')
    }
    return $name
}

function Get-StatusDisplayInfo {
    <#
    .SYNOPSIS
        Maps an internal status (+ optional severity) to the human CLI display
        label and its BAAS palette color.
    .DESCRIPTION
        Internal statuses are preserved verbatim in JSON/CSV/HTML; only the
        console shows display labels:
          PASS -> Clean, FAIL -> Needs review (severity-derived color),
          PARTIAL -> Partially checked, NOTEVALUATED -> Could not check,
          NOTAPPLICABLE -> Not in scope, SKIPPED -> Skipped,
          ERROR -> Tool error, INVENTORY -> Inventory.
        Severity colors follow CVSS-like expectations: CRITICAL #F05252
        (CritRed), HIGH #E68A3A (DarkYellow), MEDIUM #D6A84B (Yellow),
        LOW #9BE7A1 (LightGreen), INFO #38A8DC (Cyan).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Status,
        [string]$Severity = ''
    )

    $label = 'Unknown'
    $color = 'Gray'
    switch ("$Status".ToUpperInvariant()) {
        'PASS'          { $label = 'Clean';             $color = 'Green' }
        'FAIL'          {
            $label = 'Needs review'
            $color = switch ("$Severity".ToUpperInvariant()) {
                'CRITICAL' { 'CritRed' }
                'HIGH'     { 'DarkYellow' }
                'MEDIUM'   { 'Yellow' }
                'LOW'      { 'LightGreen' }
                'INFO'     { 'Cyan' }
                default    { 'DarkYellow' }
            }
        }
        'WARNING'       { $label = 'Needs review';      $color = 'Yellow' }
        'PARTIAL'       { $label = 'Partially checked'; $color = 'Yellow' }
        'NOTEVALUATED'  { $label = 'Could not check';   $color = 'Gray' }
        'NOTAPPLICABLE' { $label = 'Not in scope';      $color = 'DarkGray' }
        'SKIPPED'       { $label = 'Skipped';           $color = 'DarkGray' }
        'INVENTORY'     { $label = 'Inventory';         $color = 'Cyan' }
        'ERROR'         { $label = 'Tool error';        $color = 'Magenta' }
        default         { $label = "$Status";           $color = 'Gray' }
    }
    return [PSCustomObject]@{ Label = $label; Color = $color }
}

#endregion

#region ---- Count semantics + finding caveats (display layer only) ----
# Pure presentation helpers: they map already-produced finding metadata
# (CountType, CheckId) to human labels/caveats. No severity/status logic here.

function Get-CountTypeLabel {
    <#
    .SYNOPSIS
        Maps a finding's CountType to the short noun used wherever an affected
        count is displayed ("5 resources" instead of a generic "5 affected").
    .DESCRIPTION
        CountType semantics (finding schema, New-AzureMapFinding):
        UniqueResources = distinct resources; Containers / RoleAssignments =
        sub-resource collections; RiskSignals = individual risk observations
        (one resource may contribute several); Observations = informational
        notes; NotEvaluatedItems = items that could NOT be evaluated (never
        affected). Unknown/empty falls back to the generic 'affected'.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$CountType = '')

    switch ($CountType) {
        'UniqueResources'   { 'resources' }
        'Containers'        { 'containers' }
        'RoleAssignments'   { 'assignments' }
        'RiskSignals'       { 'risk signals' }
        'Observations'      { 'observations' }
        'NotEvaluatedItems' { 'not-evaluated items' }
        default             { 'affected' }
    }
}

# Static display-layer caveat map: CheckId -> caveat rule(s). A rule with a
# 'Pattern' applies only to finding messages matching that regex (one check
# can emit several finding categories); a rule without a Pattern applies to
# every finding group of the check. Presentation only - no evaluation logic.
$script:FindingCaveatMap = @{
    'STORAGE-002' = @(
        @{ Text = 'Public network access does not mean anonymous data access.' },
        @{ Text = 'Account-level public blob access does not prove public containers.' }
    )
    'STORAGE-004' = @(
        @{ Pattern = 'account level'; Text = 'Account-level public blob access does not prove public containers.' }
    )
    'KEYVAULT-002' = @(
        @{ Pattern = 'public (network )?access'; Text = 'Public network access does not mean anonymous data access.' },
        @{ Pattern = 'private endpoint';         Text = 'Private IP/private endpoint does not prove full private-only access.' }
    )
    'NETWORK-001' = @(
        @{ Text = 'NSG rule does not prove reachability unless attached to a public path.' }
    )
    'NETWORK-002' = @(
        @{ Text = 'Private IP/private endpoint does not prove full private-only access.' }
    )
    'NETWORK-008' = @(
        @{ Pattern = 'NSG'; Text = 'NSG rule does not prove reachability unless attached to a public path.' }
    )
    'NETWORK-010' = @(
        @{ Pattern = 'public network access'; Text = 'Public network access does not mean anonymous data access.' },
        @{ Text = 'Private IP/private endpoint does not prove full private-only access.' }
    )
    'IDENTITY-003' = @(
        @{ Text = 'RBAC assignment counts are not unique users.' }
    )
    'IDENTITY-007' = @(
        @{ Text = 'RBAC assignment counts are not unique users.' }
    )
}

# Rendered in the Not Evaluated / Partial / Errors section of both HTML
# layouts: a not-evaluated result is not a pass.
$script:NotEvaluatedCaveat = 'NotEvaluated is not Pass.'

function Get-FindingCaveats {
    <#
    .SYNOPSIS
        Returns the display caveats for a finding group (CheckId + finding
        message), or an empty array when the check has none.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$CheckId = '',
        [AllowEmptyString()][string]$Finding = ''
    )

    $entries = $null
    if ($CheckId -and $script:FindingCaveatMap.ContainsKey($CheckId)) {
        $entries = $script:FindingCaveatMap[$CheckId]
    }
    if (-not $entries) { return @() }

    $result = New-Object System.Collections.Generic.List[string]
    foreach ($e in $entries) {
        if ($e.ContainsKey('Pattern') -and $e.Pattern) {
            if ($Finding -notmatch $e.Pattern) { continue }
        }
        if (-not $result.Contains($e.Text)) { $result.Add($e.Text) }
    }
    return $result.ToArray()
}

#endregion

function Write-ConsoleLine {
    [CmdletBinding()]
    param([string]$Text = '', [string]$Color = 'Gray')
    Write-UiHost -Text $Text -Color $Color
}

function Get-CheckLineSummary {
    <#
    .SYNOPSIS
        Builds the short human summary for a per-check status line.
    .DESCRIPTION
        Fallback chain: execution-record SummaryText -> Detail -> the most
        frequent aggregated error for the check (normalized, truncated). The
        "; coverage complete/partial" tail is stripped - the coverage state is
        already conveyed by the status label (Clean vs Partially checked).
        Never contains raw identifiers: CheckErrors keys are normalized at
        collection time (GUIDs/subscription names stripped).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Check,
        [Parameter(Mandatory)][object]$Record
    )

    $summary = ''
    if (($Record.PSObject.Properties.Name -contains 'SummaryText') -and $Record.SummaryText) {
        $summary = "$($Record.SummaryText)"
    }
    elseif (($Record.PSObject.Properties.Name -contains 'Detail') -and $Record.Detail) {
        $summary = "$($Record.Detail)"
    }
    else {
        # State is a hashtable in production/tests; check membership accordingly.
        $cid = "$($Check.CheckId)"
        $bucket = $null
        if ($script:State -is [hashtable]) {
            if ($script:State.ContainsKey('CheckErrors') -and $script:State.CheckErrors -and $script:State.CheckErrors.ContainsKey($cid)) {
                $bucket = $script:State.CheckErrors[$cid]
            }
        }
        elseif ($script:State -and ($script:State.PSObject.Properties.Name -contains 'CheckErrors') -and
                $script:State.CheckErrors -and $script:State.CheckErrors.ContainsKey($cid)) {
            $bucket = $script:State.CheckErrors[$cid]
        }
        if ($bucket) {
            $top = @($bucket.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1)
            if ($top.Count -gt 0) {
                $summary = "$($top[0].Key)"
                if ([int]$top[0].Value -gt 1) { $summary = "{0} (x{1})" -f $summary, [int]$top[0].Value }
            }
        }
    }

    $summary = ($summary -replace '\s*\r?\n\s*', ' ').Trim()
    $summary = ($summary -replace ';\s*coverage (complete|partial)\.?\s*$', '')
    # Cap below the summary column width so a truncated summary never abuts
    # the trailing CheckId.
    if ($summary.Length -gt 44) { $summary = $summary.Substring(0, 41) + '...' }
    return $summary
}

function Format-UiColumn {
    <#
    .SYNOPSIS
        Pads text to a fixed column width, guaranteeing at least one trailing
        space so an over-long value can never collide with the next column.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text = '',
        [Parameter(Mandatory)][int]$Width
    )
    if ($Text.Length -ge $Width) { return ($Text + ' ') }
    return $Text.PadRight($Width)
}

function Write-CheckStatusLine {
    <#
    .SYNOPSIS
        Prints one human per-check status line during the run, grouped under
        domain section headers:
            Storage
              Shared key authentication    Needs review     20 of 60 risky    STORAGE-001
    .DESCRIPTION
        This is the primary live CLI signal. The display name leads, the human
        status label (Get-StatusDisplayInfo) carries the only strong color,
        the CheckId is secondary metadata (muted, end of line). A domain
        section header is emitted whenever the domain changes (checks are
        executed in domain order). Suppressed under -Quiet; alignment is
        computed on plain text so it survives ANSI escapes and -NoColor.
        Non-relevant rows (Not in scope / Skipped) are hidden from the normal
        run - the assessment plan and the final summary already carry their
        counts - and render only under -DetailedSummary / -VerboseOutput /
        -DebugOutput. Full detail stays in HTML/JSON/CSV and the log.
    #>
    [CmdletBinding()]
    param(
        [int]$Index,
        [int]$Total,
        [Parameter(Mandatory)]
        [object]$Check,
        [Parameter(Mandatory)]
        [object]$Record
    )

    if ($script:State.Config.Quiet) { return }

    # Only relevant/executed checks print during "Running assessment".
    # Exception: data-plane Skipped rows stay visible in normal mode - they mark
    # relevant, in-scope resources whose check was gated off, which is coverage
    # information the operator must see (not noise like mode/module skips).
    $status = "$($Record.Status)"
    $showAll = [bool]$script:State.Config.DetailedSummary -or
               [bool]$script:State.Config.VerboseOutput -or
               [bool]$script:State.Config.DebugOutput
    $isDataPlaneSkip = ($status -eq 'Skipped') -and
                       ($Record.PSObject.Properties.Name -contains 'Detail') -and
                       ("$($Record.Detail)" -eq 'Data-plane checks disabled')
    if (-not $showAll -and $status -in @('NotApplicable', 'Skipped') -and -not $isDataPlaneSkip) { return }

    # Domain section header on transition.
    $domain = Get-CheckDomain -Check $Check
    $last = $null
    if ($script:State -is [hashtable]) {
        if ($script:State.ContainsKey('LastCheckDomain')) { $last = $script:State.LastCheckDomain }
    }
    elseif ($script:State -and ($script:State.PSObject.Properties.Name -contains 'LastCheckDomain')) {
        $last = $script:State.LastCheckDomain
    }
    if ($domain -ne $last) {
        Write-UiHost -Text ''
        Write-UiHost -Text $domain -Color Cyan
        if ($script:State -is [hashtable]) { $script:State['LastCheckDomain'] = $domain }
        elseif ($script:State) { $script:State | Add-Member -NotePropertyName LastCheckDomain -NotePropertyValue $domain -Force }
    }

    $severity = ''
    if ($Check.PSObject.Properties.Name -contains 'DefaultSeverity') { $severity = "$($Check.DefaultSeverity)" }
    $info = Get-StatusDisplayInfo -Status "$($Record.Status)" -Severity $severity

    $name    = Get-CheckDisplayName -Check $Check
    $summary = Get-CheckLineSummary -Check $Check -Record $Record

    # Fixed columns computed on plain text; only the label is strongly colored.
    # Format-UiColumn guarantees a gap so a long name never touches the status.
    $nameCol  = Format-UiColumn -Text ('  ' + $name) -Width 40
    $labelCol = Format-UiColumn -Text $info.Label -Width 20
    Write-UiHost -Text $nameCol  -Color White -NoNewline
    Write-UiHost -Text $labelCol -Color $info.Color -NoNewline
    if ($summary) {
        Write-UiHost -Text (Format-UiColumn -Text $summary -Width 47) -Color Gray -NoNewline
    }
    Write-UiHost -Text " $($Check.CheckId)" -Color DarkGray
}

function Show-AssessmentPlan {
    <#
    .SYNOPSIS
        Prints the pre-run assessment plan: how many registered checks are
        relevant to this environment vs skipped by mode, excluded by service
        filter, blocked by missing modules, not in scope (footprint-proven),
        or limited by missing Graph permissions (EntraMap only).
    .DESCRIPTION
        EntraMap product: when the Graph token's granted scopes decode
        successfully (Get-GraphTokenScopeInfo), checks whose RequiredPerms are
        not granted are counted separately as permission-limited instead of
        relevant. When the scopes cannot be determined the limited count is
        NOT shown (never faked). The AzureMap data-plane line is Azure-only
        and hidden for the EntraMap product.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipEntra,
        [switch]$EntraOnly,
        [string[]]$Services
    )

    if ($script:State.Config.Quiet) { return }
    if (-not (Get-Command Get-AuditChecks -ErrorAction SilentlyContinue)) { return }

    $isEntraProduct = $EntraOnly.IsPresent -or (Test-EntraMapProductLoaded)

    # EntraMap: decode the token's granted scopes once (cached). Unknown scope
    # state (no token / undecodable JWT) fails open - no limited count at all.
    $scopeInfo = $null
    if ($isEntraProduct -and (Get-Command Get-GraphTokenScopeInfo -ErrorAction SilentlyContinue)) {
        $scopeInfo = Get-GraphTokenScopeInfo
    }

    $planned = 0; $relevant = 0; $modeSkipped = 0; $filtered = 0; $modMissing = 0; $notApp = 0; $dpGated = 0; $permLimited = 0
    $includeDataPlane = [bool]$script:State.Config.IncludeDataPlane
    foreach ($c in @(Get-AuditChecks)) {
        $planned++
        if (($SkipEntra -and $c.Category -eq 'Entra') -or ($EntraOnly -and $c.Category -ne 'Entra')) { $modeSkipped++; continue }
        if ($Services -and $Services -notcontains 'All' -and $c.Service -notin $Services) { $filtered++; continue }
        $missing = @($c.RequiredModules | Where-Object {
            $_ -and -not (Get-Module -Name $_ -ListAvailable -ErrorAction SilentlyContinue)
        })
        if ($missing.Count -gt 0) { $modMissing++; continue }
        $applic = Resolve-CheckApplicability -Check $c
        if (-not $applic.Applicable) { $notApp++; continue }
        # Data-plane checks are relevant but gated off unless -IncludeDataPlane
        # was passed (Phase B3: read-only by default).
        if ($c.RequiresDataPlane -and -not $includeDataPlane) { $dpGated++; continue }
        # EntraMap permission pre-check: a check whose RequiredPerms are provably
        # absent from the token cannot evaluate - report it as limited, not relevant.
        if ($scopeInfo -and $scopeInfo.DecodeSucceeded -and $c.Category -eq 'Entra' -and @($c.RequiredPerms).Count -gt 0) {
            $grantedScopes = @($scopeInfo.GrantedScopes)
            $missingPerms = @($c.RequiredPerms | Where-Object { $_ -and ($_ -notin $grantedScopes) })
            if ($missingPerms.Count -gt 0) { $permLimited++; continue }
        }
        $relevant++
    }

    Write-UiHost -Text 'Assessment plan' -Color Cyan
    Write-UiHost -Text ("  {0} checks planned" -f $planned) -Color Gray
    Write-UiHost -Text ("  {0} relevant to this environment" -f $relevant) -Color White
    if ($modeSkipped -gt 0) {
        $why = if ($SkipEntra) { 'Azure-only mode' } else { 'Entra-only mode' }
        Write-UiHost -Text ("  {0} skipped by mode ({1})" -f $modeSkipped, $why) -Color DarkGray
    }
    if ($filtered -gt 0)   { Write-UiHost -Text ("  {0} excluded by service filter" -f $filtered) -Color DarkGray }
    if ($modMissing -gt 0) { Write-UiHost -Text ("  {0} skipped (required module missing)" -f $modMissing) -Color DarkGray }
    if ($notApp -gt 0)     { Write-UiHost -Text ("  {0} not in scope (no relevant resources)" -f $notApp) -Color DarkGray }
    if ($permLimited -gt 0) { Write-UiHost -Text ("  {0} limited (missing Graph permissions)" -f $permLimited) -Color DarkGray }
    if (-not $isEntraProduct) {
        if ($includeDataPlane) {
            Write-UiHost -Text '  Data-plane checks: enabled' -Color White
        } else {
            $dpText = '  Data-plane checks: disabled'
            if ($dpGated -gt 0) { $dpText = "  Data-plane checks: disabled ($dpGated relevant check(s) gated; use -IncludeDataPlane to enable)" }
            Write-UiHost -Text $dpText -Color DarkGray
        }
    }
    Write-UiHost -Text ''
}

function Show-AuditConsole {
    <#
    .SYNOPSIS
        Renders the default clean summary (or nothing under -Quiet) using human
        display labels and domain-grouped per-check results.
    .PARAMETER ExportedFiles
        Paths of files written during the export phase.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ExportedFiles = @()
    )

    if ($script:State.Config.Quiet) { return }

    $verbose = [bool]$script:State.Config.VerboseOutput
    $diag    = Get-RunDiagnostics

    Write-ConsoleLine ''
    Write-ConsoleLine 'Summary' 'Cyan'
    if ($script:State.StartTime) {
        $dur = (Get-Date) - $script:State.StartTime
        $durText = if ($dur.TotalHours -ge 1) { '{0}h {1}m {2}s' -f [int]$dur.TotalHours, $dur.Minutes, $dur.Seconds }
                   elseif ($dur.TotalMinutes -ge 1) { '{0}m {1}s' -f [int]$dur.TotalMinutes, $dur.Seconds }
                   else { '{0}s' -f [int]$dur.TotalSeconds }
        Write-ConsoleLine ("  Duration            {0}" -f $durText)
    }
    $fp = $script:State.Footprint
    if ($fp -and $fp.Source -ne 'Unavailable') {
        Write-ConsoleLine ("  Subscriptions       {0}" -f (Format-UiNumber $fp.Subscriptions))
        Write-ConsoleLine ("  Resources           {0} ({1} types, {2} regions)" -f (Format-UiNumber $fp.Resources), (Format-UiNumber $fp.ResourceTypeCount), (Format-UiNumber $fp.RegionCount))
    }
    Write-ConsoleLine ("  Findings            {0} groups / {1} affected" -f (Format-UiNumber $diag.FindingGroups), (Format-UiNumber $diag.AffectedResources))
    $covChecks = @($script:State.ExecutedChecks | Where-Object { $_.Coverage })
    if ($covChecks.Count -gt 0) {
        $covComplete = @($covChecks | Where-Object { $_.Coverage.CompleteEvaluation }).Count
        $covPartial  = @($covChecks | Where-Object { $_.Coverage.PartialEvaluation }).Count
        $legacy      = $script:State.ExecutedChecks.Count - $covChecks.Count
        Write-ConsoleLine ("  Coverage            {0} coverage-aware checks ({1} complete, {2} partial); {3} legacy checks" -f $covChecks.Count, $covComplete, $covPartial, $legacy)
    }

    # ---- Status totals (human labels) ----
    Write-ConsoleLine ''
    Write-ConsoleLine 'Status' 'Cyan'
    $needsReview = $diag.Failed + $diag.Warnings
    Write-ConsoleLine ("  Needs review        {0}" -f $needsReview)        'DarkYellow'
    Write-ConsoleLine ("  Clean               {0}" -f $diag.Passed)          'Green'
    if ($diag.Inventory -gt 0)    { Write-ConsoleLine ("  Inventory           {0}" -f $diag.Inventory)    'Cyan' }
    if ($diag.Partial -gt 0)      { Write-ConsoleLine ("  Partially checked   {0}" -f $diag.Partial)      'Yellow' }
    if ($diag.NotEvaluated -gt 0) { Write-ConsoleLine ("  Could not check     {0}" -f $diag.NotEvaluated) 'Gray' }
    if ($diag.NotApplicable -gt 0){ Write-ConsoleLine ("  Not in scope        {0}" -f $diag.NotApplicable) 'DarkGray' }
    if ($diag.Skipped -gt 0)      { Write-ConsoleLine ("  Skipped             {0}" -f $diag.Skipped)      'DarkGray' }
    Write-ConsoleLine ("  Tool errors         {0}" -f $diag.Errors)          $(if ($diag.Errors -gt 0) { 'Magenta' } else { 'Gray' })

    # ---- Per-check results grouped by domain (human names + labels) ----
    # The normal run already showed every relevant check live; repeating the
    # full list here is noise. Opt in with -DetailedSummary (HTML/JSON/CSV
    # always carry the complete per-check detail).
    if ($script:State.Config.DetailedSummary) {
        Write-ConsoleLine ''
        Write-ConsoleLine 'Check results' 'Cyan'
        $exec = @($script:State.ExecutedChecks)
        if ($exec.Count -eq 0) {
            Write-ConsoleLine "  (none)"
        } else {
            $ordered = @($exec | Sort-Object {
                $order = Get-CheckDomainOrderList
                $idx = [Array]::IndexOf($order, (Get-CheckDomain -Check $_))
                if ($idx -lt 0) { $order.Count } else { $idx }
            }, CheckId)
            $lastDomain = $null
            foreach ($c in $ordered) {
                $domain = Get-CheckDomain -Check $c
                if ($domain -ne $lastDomain) {
                    Write-ConsoleLine "  $domain" 'White'
                    $lastDomain = $domain
                }
                $info = Get-StatusDisplayInfo -Status "$($c.Status)"
                $sum  = ''
                if (($c.PSObject.Properties.Name -contains 'SummaryText') -and $c.SummaryText) {
                    $sum = ($c.SummaryText -replace ';\s*coverage (complete|partial)\.?\s*$', '')
                }
                elseif ($c.Detail) { $sum = "$($c.Detail)" }
                elseif ($c.ErrorClass -and ("$($c.Status)" -eq 'Error' -or "$($c.Status)" -eq 'NotEvaluated')) {
                    $sum = "$($c.ErrorClass)"
                }
                $nameCol  = Format-UiColumn -Text ('    ' + (Get-CheckDisplayName -Check $c)) -Width 42
                $labelCol = Format-UiColumn -Text $info.Label -Width 20
                Write-UiHost -Text $nameCol  -Color Gray -NoNewline
                Write-UiHost -Text $labelCol -Color $info.Color -NoNewline
                if ($sum) {
                    if ($sum.Length -gt 44) { $sum = $sum.Substring(0, 41) + '...' }
                    Write-UiHost -Text (Format-UiColumn -Text $sum -Width 47) -Color Gray -NoNewline
                }
                Write-UiHost -Text " $($c.CheckId)" -Color DarkGray
            }
        }
    }

    # ---- Findings totals ----
    Write-ConsoleLine ''
    Write-ConsoleLine 'Findings' 'Cyan'
    Write-ConsoleLine ("  Finding groups      {0}" -f (Format-UiNumber $diag.FindingGroups))
    Write-ConsoleLine ("  Affected resources  {0}" -f (Format-UiNumber $diag.AffectedResources))
    $sev = $diag.BySeverity
    Write-UiHost -Text '  By severity         ' -NoNewline
    Write-UiHost -Text ("CRITICAL {0}  " -f $sev['CRITICAL']) -Color CritRed    -NoNewline
    Write-UiHost -Text ("HIGH {0}  " -f $sev['HIGH'])         -Color DarkYellow -NoNewline
    Write-UiHost -Text ("MEDIUM {0}  " -f $sev['MEDIUM'])     -Color Yellow     -NoNewline
    Write-UiHost -Text ("LOW {0}  " -f $sev['LOW'])           -Color LightGreen -NoNewline
    Write-UiHost -Text ("INFO {0}" -f $sev['INFO'])           -Color Cyan

    # ---- Top Findings (titles only, no identifiers) ----
    $realFindings = @($script:State.Results | Where-Object {
        ($_.PSObject.Properties.Name -contains 'Count') -and ($null -ne $_.Count) -and ([int]$_.Count -gt 0) -and
        ("$($_.Status)" -ne 'NotEvaluated') -and ("$($_.Status)" -ne 'Skipped')
    })

    Write-ConsoleLine ''
    Write-ConsoleLine 'Top findings' 'Cyan'
    if ($realFindings.Count -eq 0) {
        Write-ConsoleLine "  (none)"
    } else {
        $sevRank = { param($s) switch ("$s".ToUpper()) { 'CRITICAL' {1} 'HIGH' {2} 'MEDIUM' {3} 'LOW' {4} 'INFO' {5} default {6} } }

        # Deduplicate repeated identical findings (same Severity + Service + message)
        # into one line, summing affected resources across subscriptions. Multi-
        # subscription checks emit one finding per subscription, which otherwise fills
        # Top Findings with duplicate titles.
        $grouped = $realFindings |
            Group-Object -Property { "$($_.Severity)|$($_.Service)|$($_.Finding)" } |
            ForEach-Object {
                $first = $_.Group[0]
                $sum   = 0
                $countType = ''
                foreach ($g in $_.Group) {
                    $sum += [int]$g.Count
                    if (-not $countType -and "$($g.CountType)") { $countType = "$($g.CountType)" }
                }
                [PSCustomObject]@{
                    Severity  = $first.Severity
                    Service   = $first.Service
                    Finding   = $first.Finding
                    Affected  = $sum
                    CountType = $countType
                    Groups    = $_.Count
                }
            }
        $grouped = @($grouped)

        $top = $grouped |
            Sort-Object @{ Expression = { & $sevRank $_.Severity } }, @{ Expression = { [int]$_.Affected }; Descending = $true } |
            Select-Object -First ([int]$(if ($verbose) { 25 } else { 10 }))
        foreach ($f in $top) {
            $color  = switch ("$($f.Severity)".ToUpper()) { 'CRITICAL' {'CritRed'} 'HIGH' {'DarkYellow'} 'MEDIUM' {'Yellow'} 'LOW' {'LightGreen'} default {'Cyan'} }
            $suffix = if ([int]$f.Groups -gt 1) { " across $([int]$f.Groups) subscriptions" } else { "" }
            Write-UiHost -Text ("  {0,-9} " -f "$($f.Severity)".ToUpper()) -Color $color -NoNewline
            Write-ConsoleLine ("{0} - {1} ({2} {3}{4})" -f $f.Service, $f.Finding, (Format-UiNumber $f.Affected), (Get-CountTypeLabel -CountType $f.CountType), $suffix)
        }
        if ($grouped.Count -gt $top.Count) {
            Write-ConsoleLine ("  ... and {0} more finding group(s). See exported report." -f ($grouped.Count - $top.Count)) 'DarkGray'
        }
    }

    # ---- Capability insights (Phase B2): top 5 only; full graph lives in
    #      the HTML/JSON exports. No per-edge detail in the normal CLI. ----
    $capModel = $script:State.CapabilityModel
    if ($capModel) {
        Write-ConsoleLine ''
        Write-ConsoleLine 'Capability insights' 'Cyan'
        $capInsights = @($capModel.Insights)
        if ($capInsights.Count -eq 0) {
            Write-ConsoleLine '  (none)' 'DarkGray'
        } else {
            $capRank = 0
            foreach ($ci in @($capInsights | Select-Object -First 5)) {
                $capRank++
                $capColor = switch ("$($ci.Severity)".ToUpper()) { 'CRITICAL' {'CritRed'} 'HIGH' {'DarkYellow'} 'MEDIUM' {'Yellow'} 'LOW' {'LightGreen'} default {'Cyan'} }
                Write-UiHost -Text (Format-UiColumn -Text ("  {0}. {1}" -f $capRank, $ci.Title) -Width 52) -Color Gray -NoNewline
                Write-UiHost -Text (Format-UiColumn -Text ("$($ci.Severity)".ToUpper()) -Width 10) -Color $capColor -NoNewline
                Write-ConsoleLine ("{0} {1}" -f (Format-UiNumber $ci.ImpactedResourceCount), $ci.ResourceUnit)
            }
            if ($capInsights.Count -gt 5) {
                Write-ConsoleLine ("  ... and {0} more. See HTML/JSON exports." -f ($capInsights.Count - 5)) 'DarkGray'
            }
        }
    }

    # ---- Checks needing attention (no raw error text / identifiers) ----
    $attention = @($script:State.ExecutedChecks | Where-Object {
        "$($_.Status)" -eq 'NotEvaluated' -or "$($_.Status)" -eq 'Error' -or "$($_.Status)" -eq 'Partial'
    })
    Write-ConsoleLine ''
    Write-ConsoleLine 'Needs attention' 'Cyan'
    if ($attention.Count -eq 0) {
        Write-ConsoleLine "  (none)"
    } else {
        foreach ($c in $attention) {
            $info = Get-StatusDisplayInfo -Status "$($c.Status)"
            $reason = ''
            if ($c.Detail) { $reason = "$($c.Detail)" }
            elseif (($c.PSObject.Properties.Name -contains 'SummaryText') -and $c.SummaryText) { $reason = "$($c.SummaryText)" }
            elseif ($c.ErrorClass) { $reason = "$($c.ErrorClass)" }
            if (-not $reason) {
                # Same fallback as the live status line: the most frequent
                # aggregated collection error for this check.
                $reason = Get-CheckLineSummary -Check $c -Record $c
            }
            if ($reason.Length -gt 60) { $reason = $reason.Substring(0, 59) + '...' }
            $nameCol  = Format-UiColumn -Text ('    ' + (Get-CheckDisplayName -Check $c)) -Width 42
            $labelCol = Format-UiColumn -Text $info.Label -Width 20
            Write-UiHost -Text $nameCol  -Color Gray -NoNewline
            Write-UiHost -Text $labelCol -Color $info.Color -NoNewline
            if ($reason) { Write-UiHost -Text (Format-UiColumn -Text $reason -Width 59) -Color Gray -NoNewline }
            Write-UiHost -Text " $($c.CheckId)" -Color DarkGray
        }
        if ($script:State.LogFile) {
            Write-ConsoleLine ("  Details saved to {0}" -f (Split-Path -Path $script:State.LogFile -Leaf)) 'DarkGray'
        }
    }

    # ---- Performance (clean totals; per-check detail is in JSON/log) ----
    $perf = Get-PerformanceSummary -Top 10
    Write-ConsoleLine ''
    Write-ConsoleLine 'Performance' 'Cyan'
    if ($perf.Phases.Count -gt 0) {
        $phaseParts = @()
        foreach ($pk in $perf.Phases.Keys) { $phaseParts += ("{0} {1}" -f $pk.ToLower(), (Format-UiDuration $perf.Phases[$pk])) }
        Write-ConsoleLine ("  Phases              {0}" -f ($phaseParts -join '  ')) 'DarkGray'
    }
    if ($perf.SlowestChecks.Count -gt 0) {
        Write-ConsoleLine '  Slowest checks' 'DarkGray'
        foreach ($sc in $perf.SlowestChecks) {
            $dispName = Get-CheckDisplayName -Check $sc
            Write-ConsoleLine ("    {0,-9} {1,-38} {2}" -f $sc.CheckId, $dispName, (Format-UiDuration $sc.DurationSeconds)) 'DarkGray'
        }
    }
    if ($perf.SlowestSubscriptions.Count -gt 0) {
        Write-ConsoleLine '  Slowest subscriptions (collection)' 'DarkGray'
        foreach ($ss in $perf.SlowestSubscriptions) {
            Write-ConsoleLine ("    {0,-48} {1}" -f $ss.Subscription, (Format-UiDuration $ss.FetchSeconds)) 'DarkGray'
        }
    }
    Write-ConsoleLine ("  Total runtime       {0}" -f (Format-UiDuration $perf.TotalSeconds)) 'DarkGray'

    # ---- Report locations (full paths) ----
    Write-ConsoleLine ''
    $htmlFile   = $null
    $otherFiles = @()
    foreach ($file in @($ExportedFiles)) {
        if ("$file" -match '\.html$') { $htmlFile = "$file" } else { $otherFiles += "$file" }
    }
    if ($htmlFile) {
        Write-ConsoleLine ("Report written to: {0}" -f $htmlFile) 'Cyan'
        Write-ConsoleLine 'You can view the findings report here:' 'Cyan'
        Write-ConsoleLine ("  {0}" -f $htmlFile)
    }
    Write-ConsoleLine 'Exports written to:' 'Cyan'
    if ($otherFiles.Count -gt 0) {
        foreach ($f in $otherFiles) {
            Write-ConsoleLine ("  {0}" -f $f)
        }
    } else {
        Write-ConsoleLine "  (none)"
    }
    if ($script:State.LogFile) {
        Write-UiHost -Text ("  {0,-15}" -f 'Log') -Color Cyan -NoNewline
        Write-ConsoleLine (Split-Path -Path $script:State.LogFile -Leaf) 'DarkGray'
    }

    Write-ConsoleLine ''
    Write-ConsoleLine 'Done.' 'Cyan'
}
