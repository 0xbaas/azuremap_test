#==============================================================================
# AzureMap v2 - Core/Footprint.ps1
# Environment footprint pre-scan: discovers the shape of the environment
# (subscriptions, resource groups, resources, resource types, regions, top
# services) BEFORE checks run. Read-only: Azure Resource Graph when available,
# Get-AzResource per subscription as fallback. Drives check applicability
# (NotApplicable when a check's RequiredResourceTypes are absent from scope).
#==============================================================================

function Get-EnvironmentFootprint {
    <#
    .SYNOPSIS
        Builds the environment footprint object. Read-only.
    .DESCRIPTION
        Prefers Azure Resource Graph (Search-AzGraph, cross-subscription). Falls
        back to Get-AzResource per subscription (Set-AzContext local switch only).
        Never throws: on total failure returns an object with Source='Unavailable'
        so applicability decisions degrade to "run everything" (no false
        NotApplicable when the footprint itself could not be proven).
    .OUTPUTS
        [pscustomobject] with Subscriptions, ResourceGroups, Resources,
        ResourceTypeCount, RegionCount, Regions, TopTypes, TypeCounts (lowercased
        type -> count), Source, SubscriptionsExpected, SubscriptionsCovered,
        CoverageStatus (Complete/Partial/Unavailable), Confidence (High/Low),
        Note.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Subscriptions
    )

    $expectedIds = @($Subscriptions | ForEach-Object { "$($_.Id)".ToLowerInvariant() } | Where-Object { $_ })

    $fp = [PSCustomObject]@{
        Subscriptions         = @($Subscriptions).Count
        ResourceGroups        = 0
        Resources             = 0
        ResourceTypeCount     = 0
        RegionCount           = 0
        Regions               = @()
        TopTypes              = @()
        TypeCounts            = @{}
        Source                = 'Unavailable'
        SubscriptionsExpected = $expectedIds.Count
        SubscriptionsCovered  = 0
        CoverageStatus        = 'Unavailable'
        Confidence            = 'Low'
        Note                  = ''
    }

    # Merges one resource object into the aggregate counters. Uses dynamic
    # scoping: invoked with & from inside this function, so it sees $fp/$rgNames.
    $rgNames = @{}
    $addResource = {
        param([string]$Type, [string]$Location, [string]$ResourceGroup)
        $t = "$Type".ToLowerInvariant()
        if (-not $t) { return }
        if ($fp.TypeCounts.ContainsKey($t)) { $fp.TypeCounts[$t]++ } else { $fp.TypeCounts[$t] = 1 }
        $fp.Resources++
        if ($Location -and $fp.Regions -notcontains $Location) { $fp.Regions += $Location }
        if ($ResourceGroup) { $rgNames[$ResourceGroup.ToLowerInvariant()] = $true }
    }

    # Per-subscription Get-AzResource fallback for a given set of subscriptions.
    # Returns the IDs that were successfully enumerated.
    $collectViaArm = {
        param([array]$Subs)
        $ok = New-Object System.Collections.Generic.List[string]
        foreach ($sub in $Subs) {
            try {
                $null = Set-AzContext -SubscriptionId "$($sub.Id)" -ErrorAction Stop
                $res = @(Get-AzResource -ErrorAction Stop)
                foreach ($r in $res) {
                    & $addResource -Type $r.ResourceType -Location "$($r.Location)" -ResourceGroup "$($r.ResourceGroupName)"
                }
                $ok.Add("$($sub.Id)".ToLowerInvariant())
            }
            catch {
                Write-AuditLog -Message "Footprint fallback failed for subscription $($sub.Name): $($_.Exception.Message)" -Level WARN
            }
        }
        return ,[string[]]$ok.ToArray()
    }

    $coveredIds = New-Object System.Collections.Generic.List[string]

    # ---- Preferred: Azure Resource Graph ----
    $argAvailable = [bool](Get-Command Search-AzGraph -ErrorAction SilentlyContinue)
    if ($argAvailable) {
        try {
            $subIds = @($Subscriptions | ForEach-Object { "$($_.Id)" } | Where-Object { $_ })
            $typeRows = @(Search-AzGraph -Query "Resources | summarize Count=count() by type=tostring(type)" -Subscription $subIds -ErrorAction Stop)
            $locRows  = @(Search-AzGraph -Query "Resources | summarize Count=count() by location=tostring(location)" -Subscription $subIds -ErrorAction Stop)
            $rgRows   = @(Search-AzGraph -Query "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' | summarize Count=count()" -Subscription $subIds -ErrorAction Stop)
            # Coverage verification: which of the in-scope subscriptions did ARG
            # actually see? Without this, an ARG call that silently covered only
            # the current/default subscription (or the wrong tenant) would
            # produce a narrow footprint that drives false NotApplicable.
            $subRows  = @(Search-AzGraph -Query "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId=tostring(subscriptionId)" -Subscription $subIds -ErrorAction Stop)

            foreach ($row in $typeRows) {
                $t = "$($row.type)".ToLowerInvariant()
                if ($t) { $fp.TypeCounts[$t] = [int]$row.Count; $fp.Resources += [int]$row.Count }
            }
            $fp.Regions = @($locRows | ForEach-Object { "$($_.location)" } | Where-Object { $_ } | Sort-Object -Unique)
            if ($rgRows.Count -gt 0) { $fp.ResourceGroups = [int]$rgRows[0].Count }

            $argSeen = @($subRows | ForEach-Object { "$($_.subscriptionId)".ToLowerInvariant() } | Where-Object { $_ })
            foreach ($id in $expectedIds) {
                if ($argSeen -contains $id) { $coveredIds.Add($id) }
            }
            $fp.Source = 'ResourceGraph'
        }
        catch {
            Write-AuditLog -Message "Resource Graph footprint query failed; falling back to Get-AzResource: $($_.Exception.Message)" -Level WARN
            $fp.Source = 'Unavailable'
        }
    }

    # ---- Fallback: Get-AzResource for subscriptions ARG did not cover ----
    $missing = @($Subscriptions | Where-Object { $coveredIds -notcontains "$($_.Id)".ToLowerInvariant() })
    if ($fp.Source -eq 'Unavailable') {
        # ARG unusable: fall back for every in-scope subscription.
        $missing = @($Subscriptions)
        $armOk = & $collectViaArm -Subs $missing
        foreach ($id in $armOk) { if ($coveredIds -notcontains $id) { $coveredIds.Add($id) } }
        if ($coveredIds.Count -gt 0) { $fp.Source = 'Get-AzResource' }
    }
    elseif ($missing.Count -gt 0) {
        Write-AuditLog -Message "Resource Graph covered $($coveredIds.Count) of $($expectedIds.Count) in-scope subscriptions; enumerating the remaining $($missing.Count) via Get-AzResource." -Level WARN
        $armOk = & $collectViaArm -Subs $missing
        foreach ($id in $armOk) { if ($coveredIds -notcontains $id) { $coveredIds.Add($id) } }
        $fp.Source = 'ResourceGraph+Get-AzResource'
        # RG count from ARG is complete only for ARG-covered subs; once we merge
        # ARM data, report the union instead of the ARG-only number.
        $fp.ResourceGroups = $rgNames.Count
    }

    # ---- Finalize coverage/confidence ----
    $fp.SubscriptionsCovered = $coveredIds.Count
    $fp.ResourceTypeCount    = $fp.TypeCounts.Count
    $fp.Regions              = @($fp.Regions | Sort-Object)
    $fp.RegionCount          = $fp.Regions.Count
    if ($fp.ResourceGroups -eq 0 -and $rgNames.Count -gt 0) { $fp.ResourceGroups = $rgNames.Count }

    if ($fp.Source -ne 'Unavailable') {
        if ($fp.SubscriptionsCovered -ge $fp.SubscriptionsExpected -and $fp.SubscriptionsExpected -gt 0) {
            $fp.CoverageStatus = 'Complete'
            $fp.Confidence     = 'High'
        }
        else {
            $fp.CoverageStatus = 'Partial'
            $fp.Confidence     = 'Low'
            $fp.Note = "Footprint covers $($fp.SubscriptionsCovered) of $($fp.SubscriptionsExpected) in-scope subscriptions; check applicability gating is disabled (checks will run)."
        }
        # Sanity heuristic: a multi-subscription tenant essentially never has a
        # single resource type. Treat a suspiciously narrow footprint as low
        # confidence even when every subscription answered.
        if ($fp.CoverageStatus -eq 'Complete' -and $fp.SubscriptionsExpected -ge 3 -and $fp.ResourceTypeCount -le 1 -and $fp.Resources -gt 0) {
            $fp.Confidence = 'Low'
            $fp.Note = "Footprint is suspiciously narrow ($($fp.ResourceTypeCount) resource type across $($fp.SubscriptionsExpected) subscriptions); check applicability gating is disabled (checks will run)."
        }
    }

    # Top services by resource count, normalized into human service names:
    # child resource types are folded into their parent service (e.g. template
    # spec versions under "Template specs") so the list never shows raw child
    # type names like "versions" or duplicate-looking rows.
    $fp.TopTypes = @(Get-FriendlyTopServices -TypeCounts $fp.TypeCounts -Top 10)

    return $fp
}

# Curated human service names for common resource types. Keyed by the full
# lowercased ARM type; child types (3+ segments) are mapped explicitly so they
# get their own meaningful label instead of a bare child segment.
$script:FriendlyServiceNames = @{
    'microsoft.storage/storageaccounts'                    = 'Storage accounts'
    'microsoft.keyvault/vaults'                            = 'Key Vaults'
    'microsoft.network/networkinterfaces'                  = 'Network interfaces'
    'microsoft.network/networksecuritygroups'              = 'Network security groups'
    'microsoft.network/privateendpoints'                   = 'Private endpoints'
    'microsoft.network/publicipaddresses'                  = 'Public IP addresses'
    'microsoft.network/virtualnetworks'                    = 'Virtual networks'
    'microsoft.network/virtualnetworks/virtualnetworklinks' = 'Virtual network links'
    'microsoft.network/privatednszones'                    = 'Private DNS zones'
    'microsoft.network/privatednszones/virtualnetworklinks' = 'Private DNS links'
    'microsoft.web/sites'                                  = 'App services'
    'microsoft.web/serverfarms'                            = 'App Service plans'
    'microsoft.resources/templatespecs'                    = 'Template specs'
    'microsoft.compute/virtualmachines'                    = 'Virtual machines'
    'microsoft.compute/disks'                              = 'Managed disks'
    'microsoft.containerregistry/registries'               = 'Container registries'
    'microsoft.containerservice/managedclusters'           = 'AKS clusters'
    'microsoft.sql/servers'                                = 'SQL servers'
    'microsoft.documentdb/databaseaccounts'                = 'Cosmos DB accounts'
    'microsoft.eventhub/namespaces'                        = 'Event Hub namespaces'
    'microsoft.servicebus/namespaces'                      = 'Service Bus namespaces'
    'microsoft.apimanagement/service'                      = 'API Management services'
    'microsoft.automation/automationaccounts'              = 'Automation accounts'
    'microsoft.insights/components'                        = 'Application Insights'
    'microsoft.operationalinsights/workspaces'             = 'Log Analytics workspaces'
    'microsoft.managedidentity/userassignedidentities'     = 'Managed identities'
    'microsoft.authorization/roleassignments'              = 'Role assignments'
    'microsoft.insights/activitylogalerts'                 = 'Activity log alerts'
    'microsoft.insights/actiongroups'                      = 'Action groups'
    'microsoft.insights/privatelinkscopes'                 = 'Private link scopes'
    'microsoft.network/routetables'                        = 'Route tables'
    'microsoft.network/dnsforwardingrulesets'              = 'DNS forwarding rulesets'
}

# Human labels for common LEAF type segments, used when the full type is not
# curated. Keeps a bare technical segment ("virtualnetworklinks") readable even
# when its parent type is unknown.
$script:FriendlyTypeSegments = @{
    'virtualnetworklinks' = 'Virtual network links'
    'activitylogalerts'   = 'Activity log alerts'
    'actiongroups'        = 'Action groups'
    'privatelinkscopes'   = 'Private link scopes'
    'templatespecs'       = 'Template specs'
}

function Get-ServiceLabelFromType {
    <#
    .SYNOPSIS
        Maps a full ARM resource type to a human service label.
    .DESCRIPTION
        Exact curated hits win. Unmapped child types (3+ segments) are labeled
        "<parent service> <child>" so a bare segment like "versions" never
        appears without parent context. Unmapped leaf types fall back to a
        curated segment label, then the last segment capitalized. Note: the
        camel-case split MUST be case-sensitive (-creplace) - a plain -replace
        is case-insensitive and would split every bigram of an all-lowercase
        segment ("virtualnetworklinks" -> "V ir tu al ...").
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type)

    $t = $Type.ToLowerInvariant()
    if ($script:FriendlyServiceNames.ContainsKey($t)) { return $script:FriendlyServiceNames[$t] }

    $segments = $t -split '/'
    $leafKey  = $segments[-1]

    if ($segments.Count -ge 3) {
        $parent = ($segments[0..1] -join '/')
        if ($script:FriendlyServiceNames.ContainsKey($parent)) {
            $child = ($segments[2..($segments.Count - 1)] -join '/')
            $childLabel = if ($script:FriendlyTypeSegments.ContainsKey($child)) { $script:FriendlyTypeSegments[$child] }
                          else { ($child -creplace '([a-z0-9])([A-Z])', '$1 $2') }
            return "{0} ({1})" -f $script:FriendlyServiceNames[$parent], $childLabel
        }
    }

    if ($script:FriendlyTypeSegments.ContainsKey($leafKey)) { return $script:FriendlyTypeSegments[$leafKey] }

    $leaf = $leafKey -creplace '([a-z0-9])([A-Z])', '$1 $2'
    return ([string]$leaf).Substring(0, 1).ToUpperInvariant() + ([string]$leaf).Substring(1)
}

function Get-FriendlyTopServices {
    <#
    .SYNOPSIS
        Aggregates raw resource-type counts into human service rows.
    .DESCRIPTION
        Rows are grouped by friendly label (merging duplicate-looking entries)
        and sorted by count. Template spec versions are folded into the
        "Template specs" row and rendered as "N specs / M versions" instead of
        a separate bare "versions" row.
    .OUTPUTS
        Array of rows: @{ Type; Label; Count; CountText }. CountText is an
        optional display override for the count column.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$TypeCounts,
        [int]$Top = 10
    )

    $specsKey   = 'microsoft.resources/templatespecs'
    $versionsKey = 'microsoft.resources/templatespecs/versions'

    $specCount    = if ($TypeCounts.ContainsKey($specsKey))    { [int]$TypeCounts[$specsKey] }    else { 0 }
    $versionCount = if ($TypeCounts.ContainsKey($versionsKey)) { [int]$TypeCounts[$versionsKey] } else { 0 }

    $byLabel = @{}
    $labelType = @{}
    foreach ($kvp in $TypeCounts.GetEnumerator()) {
        $t = "$($kvp.Key)".ToLowerInvariant()
        if ($t -eq $specsKey -or $t -eq $versionsKey) { continue }   # folded below
        $label = Get-ServiceLabelFromType -Type $t
        if ($byLabel.ContainsKey($label)) { $byLabel[$label] += [int]$kvp.Value } else { $byLabel[$label] = [int]$kvp.Value; $labelType[$label] = $t }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($label in $byLabel.Keys) {
        $rows.Add([PSCustomObject]@{
            Type      = $labelType[$label]
            Label     = $label
            Count     = $byLabel[$label]
            CountText = $null
        })
    }

    if ($specCount -gt 0 -or $versionCount -gt 0) {
        $specText = "{0} specs" -f (Format-UiNumber $specCount)
        if ($versionCount -gt 0) { $specText = "{0} / {1} versions" -f $specText, (Format-UiNumber $versionCount) }
        $rows.Add([PSCustomObject]@{
            Type      = $specsKey
            Label     = 'Template specs'
            Count     = $specCount
            CountText = $specText
        })
    }

    return @($rows | Sort-Object -Property Count -Descending | Select-Object -First $Top)
}

function Show-EnvironmentFootprint {
    <#
    .SYNOPSIS
        Prints the compact environment discovery block (respects -Quiet/NoColor).
    .DESCRIPTION
        Complete/high-confidence discovery renders as "Environment discovery"
        with aggregate counts only. Incomplete or low-confidence discovery
        renders as "Environment discovery incomplete" with the reason and the
        fail-safe consequence (applicability gating disabled, checks run). The
        ARG->Get-AzResource fallback is an internal detail: when it completes
        successfully it is logged, not shown as a warning.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Footprint)

    if ($script:State.Config.Quiet) { return }

    # Discovery source (ResourceGraph/Get-AzResource) is an internal detail:
    # log file / debug output only, never the normal CLI.
    Write-AuditLog -Message "Environment footprint source: $($Footprint.Source) (coverage: $($Footprint.CoverageStatus), confidence: $($Footprint.Confidence))" -Level INFO

    $complete = ($Footprint.PSObject.Properties.Name -contains 'CoverageStatus') -and
                $Footprint.CoverageStatus -eq 'Complete' -and
                "$($Footprint.Confidence)" -eq 'High'

    Write-UiHost -Text ""
    if ($complete) {
        Write-UiHost -Text "Environment discovery" -Color Cyan
        Write-UiHost -Text ("  {0} subscriptions, {1} resource groups, {2} resources" -f
            (Format-UiNumber $Footprint.Subscriptions), (Format-UiNumber $Footprint.ResourceGroups), (Format-UiNumber $Footprint.Resources)) -Color Gray
        Write-UiHost -Text ("  {0} resource types, {1} regions" -f
            (Format-UiNumber $Footprint.ResourceTypeCount), (Format-UiNumber $Footprint.RegionCount)) -Color Gray
    }
    else {
        Write-UiHost -Text "Environment discovery incomplete" -Color Yellow
        Write-UiHost -Text ("  {0} of {1} subscriptions could not be fully enumerated." -f
            (Format-UiNumber ($Footprint.SubscriptionsExpected - $Footprint.SubscriptionsCovered)),
            (Format-UiNumber $Footprint.SubscriptionsExpected)) -Color Yellow
        Write-UiHost -Text "  Applicability decisions disabled to avoid false Not in scope results." -Color Yellow
        if ($Footprint.Note) { Write-UiHost -Text ("  {0}" -f $Footprint.Note) -Color DarkGray }
        Write-UiHost -Text ("  Partial picture: {0} resources, {1} resource types" -f
            (Format-UiNumber $Footprint.Resources), (Format-UiNumber $Footprint.ResourceTypeCount)) -Color Gray
    }

    if ($Footprint.TopTypes.Count -gt 0) {
        Write-UiHost -Text "  Most common services" -Color Cyan
        foreach ($t in $Footprint.TopTypes) {
            $countText = if (($t.PSObject.Properties.Name -contains 'CountText') -and $t.CountText) { "$($t.CountText)" } else { Format-UiNumber $t.Count }
            Write-UiHost -Text ("    {0,-30} {1}" -f $t.Label, $countText) -Color Gray
        }
    }
    Write-UiHost -Text ""
}

function Get-CheckApplicability {
    <#
    .SYNOPSIS
        Decides whether a registered check is applicable to the current scope.
    .DESCRIPTION
        * AlwaysRun checks and checks without RequiredResourceTypes are Applicable.
        * When the footprint is unavailable (not proven), every check stays
          Applicable - applicability never penalizes on unknown data.
        * When the footprint proves none of the check's RequiredResourceTypes
          exist in scope, the check is NotApplicable with a human reason.
    .OUTPUTS
        [pscustomobject] @{ Applicable = [bool]; Reason = [string] }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Check)

    $types = @()
    if ($Check.PSObject.Properties.Name -contains 'RequiredResourceTypes') { $types = @($Check.RequiredResourceTypes) }
    $alwaysRun = ($Check.PSObject.Properties.Name -contains 'AlwaysRun') -and $Check.AlwaysRun

    if ($alwaysRun -or $types.Count -eq 0) {
        return [PSCustomObject]@{ Applicable = $true; Reason = '' }
    }

    $fp = $script:State.Footprint
    if (-not $fp -or -not $fp.TypeCounts -or $fp.Source -eq 'Unavailable') {
        return [PSCustomObject]@{ Applicable = $true; Reason = '' }
    }

    # Fail-safe: NotApplicable requires HIGH-confidence proof that the resource
    # type is absent. A partial or low-confidence footprint (ARG covered only
    # some subscriptions, narrow/suspicious result) must never gate checks off.
    $coverageStatus = ''
    if ($fp.PSObject.Properties.Name -contains 'CoverageStatus') { $coverageStatus = "$($fp.CoverageStatus)" }
    if ($coverageStatus -ne 'Complete' -or "$($fp.Confidence)" -ne 'High') {
        return [PSCustomObject]@{ Applicable = $true; Reason = '' }
    }

    foreach ($t in $types) {
        if ($t -and $fp.TypeCounts.ContainsKey("$t".ToLowerInvariant())) {
            return [PSCustomObject]@{ Applicable = $true; Reason = '' }
        }
    }

    $short = ($types | ForEach-Object { ("$_" -split '/')[-1] }) -join '/'
    return [PSCustomObject]@{
        Applicable = $false
        Reason     = "No $short resources in scope"
    }
}
