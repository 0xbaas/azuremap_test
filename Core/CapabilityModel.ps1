#==============================================================================
# AzureMap v2 - Core/CapabilityModel.ps1
# Phase B2: capability / attack-path modeling (READ-ONLY MODELING ONLY).
#
# Builds a capability graph (nodes/edges) plus grouped capability insights from
# data that is ALREADY collected during the run: finding evidence rows
# ($script:State.Results), the in-memory inventory cache
# ($script:State.Cache.ResourceLists, Core/InventoryCache.ps1), the RBAC
# assignment cache ($script:State.Cache.RBACAssignments) and the environment
# footprint ($script:State.Footprint).
#
# HARD SAFETY CONTRACT:
#   - This module performs NO Azure/Graph API calls of any kind. It reads only
#     in-memory state produced earlier in the run. It must never call
#     Get-Az*/Invoke-Az*/Set-Az*/New-Az*/Remove-Az* or Graph helpers.
#   - It never retrieves keys, secrets, SAS tokens, connection strings, tokens
#     or blob/file content, and never executes remediation or write actions.
#   - Modeled capabilities are hypotheses about what a principal COULD do,
#     expressed only where the collected metadata already proves the building
#     blocks (role + scope + configuration). Unit tests grep this file to
#     enforce the contract.
#
# Severity discipline (per B2 spec): CRITICAL only when multiple confirmed
# conditions combine into a realistic high-impact path; HIGH for strong
# capability paths; MEDIUM for context-dependent capability; LOW/INFO for
# weak signals. Confidence: High = directly confirmed by collected metadata,
# Medium = inferred from role/action/scope combination, Low = manual
# validation required.
#==============================================================================

$script:CapabilityModelVersion = '1.0'

# Output caps (graph explosion guard). JSON: top 100 insights; HTML renders
# top 25; CLI renders top 5 (rendering caps live in the export/console code).
$script:CapabilityLimits = @{
    MaxInsights                    = 100
    MaxNodes                       = 500
    MaxEdges                       = 1000
    MaxImpactedResourcesPerInsight = 50
}

# Roles whose Action set includes Microsoft.Storage/storageAccounts/listKeys/action
# (or equivalent key-management capability). Membership in this list is used to
# MODEL key-retrieval capability only - listKeys is never called.
$script:CapabilityKeyCapableRoles = @(
    'Owner',
    'Contributor',
    'Storage Account Contributor',
    'Storage Account Key Operator Service Role'
)

# Broad control-plane roles used for managed-identity blast-radius modeling.
$script:CapabilityBroadRoles = @(
    'Owner',
    'Contributor',
    'User Access Administrator'
)

# The ARM control-plane action that retrieves storage account keys. This is a
# STATIC COMPARISON STRING ONLY: it is matched against role-definition Actions
# that IDENTITY-005 already collected (Get-AzRoleDefinition -Custom, cached in
# State.Cache.RoleDefinitions) so the model can recognize key-retrieval
# capability in custom roles. It is never invoked - invoking it would be a
# POST call AzureMap never performs.
$script:CapabilityStorageKeyListAction = 'microsoft.storage/storageaccounts/listkeys/action'

$script:CapabilitySeverityRank = @{ CRITICAL = 1; HIGH = 2; MEDIUM = 3; LOW = 4; INFO = 5 }

function Test-CapabilityKeyListCapableActions {
    <#
    .SYNOPSIS
        Returns $true when a role definition's action set grants the storage
        account key-retrieval permission, directly or via wildcard.
    .DESCRIPTION
        Pure string matching over already-collected role-definition metadata:
        an exact match on the key-list action, or a wildcard action that
        covers it ('*', 'Microsoft.Storage/*', 'Microsoft.Storage/storageAccounts/*').
        No API calls; no key retrieval.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Actions,
        [string[]]$DataActions
    )

    $target = $script:CapabilityStorageKeyListAction
    foreach ($a in (@($Actions) + @($DataActions))) {
        $action = "$a".ToLower()
        if (-not $action) { continue }
        if ($action -eq $target) { return $true }
        if ($action.Contains('*') -and ($target -like $action)) { return $true }
    }
    return $false
}

#------------------------------------------------------------------------------
# Input readers (in-memory only; never fetch)
#------------------------------------------------------------------------------

function Get-CapabilityEvidenceRows {
    <#
    .SYNOPSIS
        Returns cloned evidence rows from findings of the given check(s).
    .DESCRIPTION
        Read-only view over $script:State.Results: findings with Count>0 whose
        Status is not NotEvaluated/Skipped/Error. Rows are CLONED (shallow copy)
        before annotation so the original finding evidence - which flows into
        the CSV/JSON/HTML exports - is never mutated. Each row gains:
        _CheckId, _FindingMessage, _FindingSeverity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$CheckIds,

        [string]$MessageLike
    )

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not $script:State -or -not $script:State.Results) { return @() }

    foreach ($f in @($script:State.Results)) {
        if ($CheckIds -notcontains "$($f.CheckId)") { continue }
        if ($MessageLike -and "$($f.Finding)" -notlike $MessageLike) { continue }
        if ($null -eq $f.Count -or [int]$f.Count -le 0) { continue }
        if ("$($f.Status)" -in @('NotEvaluated', 'Skipped', 'Error')) { continue }
        foreach ($ev in @($f.Evidence)) {
            if ($null -eq $ev) { continue }
            if ($ev -is [PSCustomObject]) {
                $clone = $ev | Select-Object -Property *
            } else {
                $clone = [PSCustomObject]@{ Value = "$ev" }
            }
            $clone | Add-Member -NotePropertyName '_CheckId'         -NotePropertyValue "$($f.CheckId)"  -Force
            $clone | Add-Member -NotePropertyName '_FindingMessage'  -NotePropertyValue "$($f.Finding)"  -Force
            $clone | Add-Member -NotePropertyName '_FindingSeverity' -NotePropertyValue "$($f.Severity)" -Force
            $rows.Add($clone)
        }
    }
    return $rows.ToArray()
}

function Get-CapabilityCachedInventoryItems {
    <#
    .SYNOPSIS
        Reads cached inventory items of one kind from the per-run inventory
        cache. NEVER triggers a fetch: entries that are missing or marked
        Unavailable are simply skipped.
    .OUTPUTS
        Array of @{ SubscriptionId; Item } (item shape = raw Az cmdlet output).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Kind
    )

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not $script:State -or -not $script:State.Cache -or -not $script:State.Cache.ResourceLists) { return @() }

    $suffix = "|$Kind"
    foreach ($key in @($script:State.Cache.ResourceLists.Keys)) {
        if (-not "$key".EndsWith($suffix)) { continue }
        $entry = $script:State.Cache.ResourceLists[$key]
        if ($null -eq $entry -or $entry.Unavailable) { continue }
        $subId = "$key".Substring(0, "$key".Length - $suffix.Length)
        foreach ($item in @($entry.Items)) {
            $rows.Add([PSCustomObject]@{ SubscriptionId = $subId; Item = $item })
        }
    }
    return $rows.ToArray()
}

function Get-CapabilityRBACAssignments {
    <#
    .SYNOPSIS
        Reads cached role assignments (collected earlier by the identity
        checks). NEVER triggers an RBAC read. Subscriptions whose RBAC read
        failed (RBACUnavailable) are skipped - no capability is inferred from
        an unproven source.
    .OUTPUTS
        Array of @{ SubscriptionId; Assignment }.
    #>
    [CmdletBinding()]
    param()

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not $script:State -or -not $script:State.Cache -or -not $script:State.Cache.RBACAssignments) { return @() }

    $rbac    = $script:State.Cache.RBACAssignments
    $unavail = $script:State.Cache.RBACUnavailable
    foreach ($key in @($rbac.Keys)) {
        if ($unavail -and $unavail.ContainsKey($key) -and $unavail[$key]) { continue }
        foreach ($a in @($rbac[$key])) {
            $rows.Add([PSCustomObject]@{ SubscriptionId = "$key"; Assignment = $a })
        }
    }
    return $rows.ToArray()
}

function Get-CapabilityScopeInfo {
    <#
    .SYNOPSIS
        Classifies an ARM scope string.
    .OUTPUTS
        Hashtable: Kind (Root|ManagementGroup|Subscription|ResourceGroup|Resource|Other),
        SubscriptionId (lower), ResourceGroup (lower).
    #>
    [CmdletBinding()]
    param([string]$Scope)

    $s = "$Scope".TrimEnd('/').ToLower()
    if ($s -notlike '/subscriptions/*') {
        if ($s -like '/providers/microsoft.management/managementgroups/*') { return @{ Kind = 'ManagementGroup'; SubscriptionId = ''; ResourceGroup = '' } }
        if ([string]::IsNullOrWhiteSpace($s) -or $s -eq '/') { return @{ Kind = 'Root'; SubscriptionId = ''; ResourceGroup = '' } }
        return @{ Kind = 'Other'; SubscriptionId = ''; ResourceGroup = '' }
    }
    $parts = @($s -split '/' | Where-Object { $_ })
    $info = @{ Kind = 'Subscription'; SubscriptionId = $(if ($parts.Count -ge 2) { $parts[1] } else { '' }); ResourceGroup = '' }
    if ($parts.Count -ge 4 -and $parts[2] -eq 'resourcegroups') {
        $info.Kind = 'ResourceGroup'
        $info.ResourceGroup = $parts[3]
        if ($parts.Count -gt 4) { $info.Kind = 'Resource' }
    }
    return $info
}

#------------------------------------------------------------------------------
# Graph primitives (dedupe + caps)
#------------------------------------------------------------------------------

function New-CapabilityContext {
    [CmdletBinding()]
    param()
    return @{
        Nodes        = @{}
        Edges        = @{}
        Insights     = [System.Collections.Generic.List[object]]::new()
        SourceChecks = [System.Collections.Generic.List[string]]::new()
        Limits       = [ordered]@{
            MaxInsights                    = $script:CapabilityLimits.MaxInsights
            MaxNodes                       = $script:CapabilityLimits.MaxNodes
            MaxEdges                       = $script:CapabilityLimits.MaxEdges
            MaxImpactedResourcesPerInsight = $script:CapabilityLimits.MaxImpactedResourcesPerInsight
            NodesTruncated                 = 0
            EdgesTruncated                 = 0
            InsightsTruncated              = 0
            Notes                          = [System.Collections.Generic.List[string]]::new()
        }
    }
}

function Add-CapabilityNode {
    <#
    .SYNOPSIS
        Adds (or merges) a graph node. Returns $true when the node is present
        after the call, $false when the node cap blocked it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Type,
        [string]$Name,
        [string]$Scope,
        [string]$ResourceType,
        [string]$Sensitivity,
        [string]$Exposure
    )

    if ($Context.Nodes.ContainsKey($Id)) {
        $existing = $Context.Nodes[$Id]
        # Merge: only fill fields that were empty on the first sighting.
        if (-not $existing.Exposure -and $Exposure)         { $existing.Exposure = $Exposure }
        if (-not $existing.Sensitivity -and $Sensitivity)   { $existing.Sensitivity = $Sensitivity }
        return $true
    }
    if ($Context.Nodes.Count -ge $script:CapabilityLimits.MaxNodes) {
        $Context.Limits.NodesTruncated++
        return $false
    }
    $Context.Nodes[$Id] = [PSCustomObject][ordered]@{
        Id           = $Id
        Type         = $Type
        Name         = $(if ($Name) { $Name } else { $Id })
        Scope        = $Scope
        ResourceType = $ResourceType
        Sensitivity  = $Sensitivity
        Exposure     = $Exposure
    }
    return $true
}

function Add-CapabilityEdge {
    <#
    .SYNOPSIS
        Adds (or merges) a graph edge, deduped on From|To|Capability. Repeat
        sightings union the SourceCheckIds and keep the higher severity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string]$To,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Capability,
        [string[]]$SourceCheckIds = @(),
        [string]$Confidence = 'Medium',
        [string]$Severity   = 'MEDIUM',
        [string]$Reason
    )

    $key = "$From|$To|$Capability"
    if ($Context.Edges.ContainsKey($key)) {
        $existing = $Context.Edges[$key]
        foreach ($cid in $SourceCheckIds) {
            if ($cid -and -not $existing.SourceCheckIds.Contains($cid)) { $existing.SourceCheckIds.Add($cid) }
        }
        $newRank = $script:CapabilitySeverityRank["$Severity".ToUpper()]
        $oldRank = $script:CapabilitySeverityRank["$($existing.Severity)".ToUpper()]
        if ($newRank -and (-not $oldRank -or $newRank -lt $oldRank)) { $existing.Severity = "$Severity".ToUpper() }
        if ($existing.Confidence -ne 'High' -and $Confidence -eq 'High') { $existing.Confidence = 'High' }
        return $true
    }
    if ($Context.Edges.Count -ge $script:CapabilityLimits.MaxEdges) {
        $Context.Limits.EdgesTruncated++
        return $false
    }
    $cids = [System.Collections.Generic.List[string]]::new()
    foreach ($cid in $SourceCheckIds) { if ($cid -and -not $cids.Contains($cid)) { $cids.Add($cid) } }
    $Context.Edges[$key] = [PSCustomObject][ordered]@{
        From           = $From
        To             = $To
        Type           = $Type
        Capability     = $Capability
        SourceCheckIds = $cids
        Confidence     = $Confidence
        Severity       = "$Severity".ToUpper()
        Reason         = $Reason
    }
    return $true
}

function Add-CapabilityInsight {
    <#
    .SYNOPSIS
        Registers a grouped capability insight. ImpactedResources is capped at
        MaxImpactedResourcesPerInsight; ImpactedResourceCount always carries
        the full (uncapped) count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Confidence,
        [Parameter(Mandatory)][string[]]$SourceCheckIds,
        [string[]]$ImpactedResources = @(),
        [int]$ImpactedResourceCount = -1,
        [string]$ResourceUnit = 'resources',
        [string]$EvidenceSummary,
        [string]$RecommendedReview
    )

    $fullCount = if ($ImpactedResourceCount -ge 0) { $ImpactedResourceCount } else { @($ImpactedResources).Count }
    $cap = $script:CapabilityLimits.MaxImpactedResourcesPerInsight
    $capped = @($ImpactedResources | Select-Object -First $cap)
    if (@($ImpactedResources).Count -gt $cap) {
        $Context.Limits.Notes.Add("Insight '$Title': impacted-resource list capped at $cap of $(@($ImpactedResources).Count).")
    }

    foreach ($cid in $SourceCheckIds) {
        if ($cid -and -not $Context.SourceChecks.Contains($cid)) { $Context.SourceChecks.Add($cid) }
    }

    $Context.Insights.Add([PSCustomObject][ordered]@{
        Id                    = $null   # assigned after final sort in Build-CapabilityModel
        Title                 = $Title
        Description           = $Description
        Severity              = "$Severity".ToUpper()
        Confidence            = $Confidence
        ImpactedResourceCount = $fullCount
        ResourceUnit          = $ResourceUnit
        ImpactedResources     = $capped
        SourceCheckIds        = @($SourceCheckIds)
        EvidenceSummary       = $EvidenceSummary
        RecommendedReview     = $RecommendedReview
    })
}

function Add-CapabilityInternetNode {
    <# Shared pseudo-node for the public internet side of exposure edges. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    [void](Add-CapabilityNode -Context $Context -Id 'internet|public' -Type 'PublicExposure' `
        -Name 'Public Internet' -Sensitivity 'None' -Exposure 'Public')
}

#------------------------------------------------------------------------------
# Insight builders (one per modeled capability)
#------------------------------------------------------------------------------

function Invoke-CapabilityStorageKeyModeling {
    <#
    .SYNOPSIS
        Capability 1: storage data access via account keys.
        Shared Key enabled (STORAGE-001) + a principal whose role grants the
        storage account key-retrieval permission at account (STORAGE-006,
        direct) or subscription/RG scope (cached RBAC, inferred). Modeling
        only - no key retrieval is performed and no keys/SAS/content are read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $sharedKeyRows = @(Get-CapabilityEvidenceRows -CheckIds @('STORAGE-001'))
    if ($sharedKeyRows.Count -eq 0) { return }

    # Index shared-key-enabled accounts: key = sub|account (lower).
    $accounts = @{}
    foreach ($r in $sharedKeyRows) {
        $sub = "$($r.SubscriptionId)".ToLower()
        $acc = "$($r.StorageAccountName)".ToLower()
        if (-not $sub -or -not $acc) { continue }
        $key = "$sub|$acc"
        if (-not $accounts.ContainsKey($key)) {
            $accounts[$key] = [PSCustomObject]@{
                SubscriptionId = "$($r.SubscriptionId)"
                SubLower       = $sub
                Account        = "$($r.StorageAccountName)"
                ResourceGroup  = "$($r.ResourceGroupName)".ToLower()
                Principals     = @{}
            }
        }
    }
    if ($accounts.Count -eq 0) { return }

    # Direct evidence: per-account role assignments flagged by STORAGE-006.
    $anyDirect = $false
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('STORAGE-006'))) {
        if ("$($r.Risk)" -notlike '*retrieve/manage storage account keys*') { continue }
        $key = "$($r.SubscriptionId)".ToLower() + '|' + "$($r.StorageAccount)".ToLower()
        if (-not $accounts.ContainsKey($key)) { continue }
        $principal = $(if ($r.Principal) { "$($r.Principal)" } else { '(unknown principal)' })
        $pkey = "$principal|$($r.Role)"
        if (-not $accounts[$key].Principals.ContainsKey($pkey)) {
            $accounts[$key].Principals[$pkey] = [PSCustomObject]@{
                Name = $principal; Role = "$($r.Role)"; Confidence = 'High'
                ScopeText = 'storage account scope'
            }
            $anyDirect = $true
        }
    }

    # Inferred: cached subscription/RG-scope assignments with key-capable roles.
    # Key-capable = well-known built-in role name OR a custom role whose
    # already-collected definition (cached by IDENTITY-005) grants the storage
    # key-retrieval action, directly or via wildcard. Static metadata only.
    $customRolesByGuid = @{}
    if ($script:State.Cache -and $script:State.Cache.RoleDefinitions) {
        foreach ($subKey in @($script:State.Cache.RoleDefinitions.Keys)) {
            foreach ($rd in @($script:State.Cache.RoleDefinitions[$subKey])) {
                $g = "$($rd.RoleGuid)".ToLower()
                if ($g -and -not $customRolesByGuid.ContainsKey($g)) { $customRolesByGuid[$g] = $rd }
            }
        }
    }
    foreach ($row in @(Get-CapabilityRBACAssignments)) {
        $a = $row.Assignment
        $roleName = "$($a.RoleDefinitionName)"
        $keyCapable = $script:CapabilityKeyCapableRoles -contains $roleName
        if (-not $keyCapable) {
            $roleGuid = ("$($a.RoleDefinitionId)" -split '/')[-1].ToLower()
            if ($roleGuid -and $customRolesByGuid.ContainsKey($roleGuid)) {
                $rd = $customRolesByGuid[$roleGuid]
                if (Test-CapabilityKeyListCapableActions -Actions $rd.Actions -DataActions $rd.DataActions) {
                    $keyCapable = $true
                    if (-not $roleName) { $roleName = "$($rd.RoleName)" }
                }
            }
        }
        if (-not $keyCapable) { continue }
        $scope = Get-CapabilityScopeInfo -Scope "$($a.Scope)"
        if ($scope.Kind -ne 'Subscription' -and $scope.Kind -ne 'ResourceGroup') { continue }
        $principal = $(if ($a.DisplayName) { "$($a.DisplayName)" } else { "principal $($a.ObjectId)" })
        foreach ($key in @($accounts.Keys)) {
            $acct = $accounts[$key]
            if ($acct.SubLower -ne $scope.SubscriptionId) { continue }
            if ($scope.Kind -eq 'ResourceGroup' -and $acct.ResourceGroup -ne $scope.ResourceGroup) { continue }
            $scopeText = $(if ($scope.Kind -eq 'Subscription') { 'subscription scope' } else { "resource group '$($scope.ResourceGroup)' scope" })
            $pkey = "$principal|$roleName|$scopeText"
            if (-not $acct.Principals.ContainsKey($pkey)) {
                $acct.Principals[$pkey] = [PSCustomObject]@{
                    Name = $principal; Role = $roleName; Confidence = 'Medium'
                    ScopeText = $scopeText
                }
            }
        }
    }

    $impacted  = New-Object System.Collections.Generic.List[string]
    $principalTotal = 0
    foreach ($key in @($accounts.Keys | Sort-Object)) {
        $acct = $accounts[$key]
        if ($acct.Principals.Count -eq 0) { continue }
        $principalTotal += $acct.Principals.Count

        $nodeOk = Add-CapabilityNode -Context $Context -Id "storage|$key" -Type 'Resource' `
            -Name $acct.Account -Scope $acct.SubscriptionId -ResourceType 'Microsoft.Storage/storageAccounts' `
            -Sensitivity 'Data' -Exposure 'SharedKeyAuth'
        foreach ($p in @($acct.Principals.Values | Sort-Object Name)) {
            $pNodeId = "principal|$($acct.SubLower)|$($p.Name)".ToLower()
            [void](Add-CapabilityNode -Context $Context -Id $pNodeId -Type 'Principal' -Name $p.Name -Scope $acct.SubscriptionId)
            if ($nodeOk) {
                [void](Add-CapabilityEdge -Context $Context -From $pNodeId -To "storage|$key" `
                    -Type 'CanObtainKeys' -Capability 'Obtain storage account keys (modeled only - keys never retrieved)' `
                    -SourceCheckIds @('STORAGE-001', 'STORAGE-006') -Confidence $p.Confidence -Severity 'HIGH' `
                    -Reason "Role '$($p.Role)' at $($p.ScopeText) grants the storage account key-retrieval permission and Shared Key authentication is enabled; the account key would grant full data-plane access.")
            }
        }
        $pText = (@($acct.Principals.Values | Sort-Object Name | ForEach-Object { "$($_.Name) ($($_.Role))" }) | Select-Object -First 3) -join '; '
        if ($acct.Principals.Count -gt 3) { $pText += " +$($acct.Principals.Count - 3) more" }
        $impacted.Add("$($acct.Account) [$($acct.SubscriptionId)] - $pText")
    }

    if ($impacted.Count -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Storage key capability with Shared Key enabled' `
        -Description 'Principals may be able to obtain storage account keys because Shared Key authentication is enabled and their RBAC role grants key-list capability. An account key bypasses data-plane RBAC and grants full data access to the storage account. Modeled from RBAC and account configuration only; no keys were retrieved.' `
        -Severity 'HIGH' -Confidence $(if ($anyDirect) { 'High' } else { 'Medium' }) `
        -SourceCheckIds @('STORAGE-001', 'STORAGE-006') `
        -ImpactedResources $impacted -ResourceUnit 'accounts' `
        -EvidenceSummary "$($impacted.Count) storage account(s) with Shared Key enabled have $principalTotal key-capable principal assignment(s) (account scope = high confidence; subscription/RG scope = inferred)." `
        -RecommendedReview 'Review whether each listed principal legitimately needs a key-capable role on these accounts. Prefer disabling Shared Key access and using Microsoft Entra authorization so key retrieval loses its impact.'
}

function Invoke-CapabilityPublicStorageModeling {
    <#
    .SYNOPSIS
        Capability 2: public storage exposure combinations. Escalates only
        when multiple conditions combine on the same account: confirmed public
        network exposure (STORAGE-002), blob public access, firewall default
        allow, Shared Key enabled (STORAGE-001) and data-plane-confirmed
        anonymous containers (STORAGE-004, only when -IncludeDataPlane ran).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $exposureRows = @(Get-CapabilityEvidenceRows -CheckIds @('STORAGE-002'))
    if ($exposureRows.Count -eq 0) { return }

    $sharedKey = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('STORAGE-001'))) {
        $sharedKey["$($r.SubscriptionId)".ToLower() + '|' + "$($r.StorageAccountName)".ToLower()] = $true
    }
    $publicContainers = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('STORAGE-004'))) {
        $publicContainers["$($r.SubscriptionId)".ToLower() + '|' + "$($r.StorageAccount)".ToLower()] = $true
    }

    $accounts = @{}
    foreach ($r in $exposureRows) {
        $key = "$($r.SubscriptionId)".ToLower() + '|' + "$($r.StorageAccount)".ToLower()
        if (-not $accounts.ContainsKey($key)) {
            $accounts[$key] = [PSCustomObject]@{
                SubscriptionId = "$($r.SubscriptionId)"
                Account        = "$($r.StorageAccount)"
                PublicNetwork  = ($r.Confirmed -eq $true)
                BlobPublic     = ("$($r.BlobPublicAccess)" -eq 'True')
                DefaultAllow   = ("$($r.DefaultAction)" -eq 'Allow')
                SharedKey      = $false
                PublicContainers = $false
            }
        } else {
            $a = $accounts[$key]
            if ($r.Confirmed -eq $true)                { $a.PublicNetwork = $true }
            if ("$($r.BlobPublicAccess)" -eq 'True')   { $a.BlobPublic = $true }
            if ("$($r.DefaultAction)" -eq 'Allow')     { $a.DefaultAllow = $true }
        }
    }
    foreach ($key in @($accounts.Keys)) {
        if ($sharedKey.ContainsKey($key))          { $accounts[$key].SharedKey = $true }
        if ($publicContainers.ContainsKey($key))   { $accounts[$key].PublicContainers = $true }
    }

    $impactedCrit = New-Object System.Collections.Generic.List[string]
    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($accounts.Keys | Sort-Object)) {
        $a = $accounts[$key]
        $conditions = @()
        if ($a.PublicNetwork)     { $conditions += 'public network access' }
        if ($a.BlobPublic)        { $conditions += 'blob public access' }
        if ($a.DefaultAllow)      { $conditions += 'firewall default allow' }
        if ($a.SharedKey)         { $conditions += 'shared key enabled' }
        if ($a.PublicContainers)  { $conditions += 'anonymous containers (data-plane confirmed)' }
        $hasExposure = $a.PublicNetwork -or $a.BlobPublic -or $a.PublicContainers
        if (-not $hasExposure -or $conditions.Count -lt 2) { continue }

        $sev = 'MEDIUM'
        if ($a.PublicContainers -and ($a.PublicNetwork -or $a.DefaultAllow)) { $sev = 'CRITICAL' }
        elseif ($a.PublicNetwork -and $conditions.Count -ge 2)               { $sev = 'HIGH' }

        [void](Add-CapabilityNode -Context $Context -Id "storage|$key" -Type 'Resource' `
            -Name $a.Account -Scope $a.SubscriptionId -ResourceType 'Microsoft.Storage/storageAccounts' `
            -Sensitivity 'Data' -Exposure 'Public')
        Add-CapabilityInternetNode -Context $Context
        [void](Add-CapabilityEdge -Context $Context -From 'internet|public' -To "storage|$key" `
            -Type 'Exposes' -Capability 'Public storage data access path (modeled)' `
            -SourceCheckIds @('STORAGE-001', 'STORAGE-002', 'STORAGE-004') `
            -Confidence $(if ($a.PublicNetwork -or $a.PublicContainers) { 'High' } else { 'Medium' }) -Severity $sev `
            -Reason ("Storage account combines: " + ($conditions -join '; ') + '.'))

        $text = "$($a.Account) [$($a.SubscriptionId)] - $($conditions -join '; ')"
        switch ($sev) {
            'CRITICAL' { $impactedCrit.Add($text) }
            'HIGH'     { $impactedHigh.Add($text) }
            default    { $impactedMed.Add($text) }
        }
    }

    $total = $impactedCrit.Count + $impactedHigh.Count + $impactedMed.Count
    if ($total -eq 0) { return }

    $overallSev = 'MEDIUM'
    if ($impactedCrit.Count -gt 0) { $overallSev = 'CRITICAL' }
    elseif ($impactedHigh.Count -gt 0) { $overallSev = 'HIGH' }

    $all = @($impactedCrit.ToArray()) + @($impactedHigh.ToArray()) + @($impactedMed.ToArray())
    Add-CapabilityInsight -Context $Context `
        -Title 'Public storage exposure with weak authentication' `
        -Description 'Storage accounts combine public network exposure with additional weak conditions (Shared Key authentication, firewall default allow, blob public access, or data-plane-confirmed anonymous containers). Each condition alone is a finding; combined they form a realistic public data exposure path.' `
        -Severity $overallSev -Confidence $(if ($impactedCrit.Count -gt 0 -or $impactedHigh.Count -gt 0) { 'High' } else { 'Medium' }) `
        -SourceCheckIds @('STORAGE-001', 'STORAGE-002', 'STORAGE-004') `
        -ImpactedResources $all -ImpactedResourceCount $total -ResourceUnit 'accounts' `
        -EvidenceSummary "$total storage account(s) with combined exposure conditions: $($impactedCrit.Count) critical combination(s), $($impactedHigh.Count) high, $($impactedMed.Count) medium." `
        -RecommendedReview 'Prioritize accounts in the critical/high groups: disable public network access or enforce firewall default-deny, disable Shared Key and blob public access, and verify no container allows anonymous access.'
}

function Invoke-CapabilityPublicWorkloadModeling {
    <#
    .SYNOPSIS
        Capability 3: public workload + privileged identity. Workloads flagged
        by IDENTITY-006 (system-assigned managed identity with privileged RBAC)
        joined with public exposure evidence (AZURE-EXPOSURE-001 AppService
        rows = confirmed; a public default hostname in the cached web/function
        app inventory = inferred, lower confidence). No tokens requested, no
        workload interaction.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $idRows = @(Get-CapabilityEvidenceRows -CheckIds @('IDENTITY-006'))
    if ($idRows.Count -eq 0) { return }

    # Confirmed exposure (per sub|name, lower).
    $exposed = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('AZURE-EXPOSURE-001'))) {
        if ("$($r.ResourceType)" -ne 'AppService') { continue }
        $exposed["$($r.SubscriptionId)".ToLower() + '|' + "$($r.ResourceName)".ToLower()] = $true
    }

    # Inferred exposure: public default hostname present in cached inventory.
    $hostnames = @{}
    foreach ($kind in @('WebApps', 'FunctionApps')) {
        foreach ($row in @(Get-CapabilityCachedInventoryItems -Kind $kind)) {
            $item = $row.Item
            if (-not "$($item.DefaultHostName)") { continue }
            $hostnames["$($row.SubscriptionId)".ToLower() + '|' + "$($item.Name)".ToLower()] = "$($item.DefaultHostName)"
        }
    }

    $confirmed = @{}
    $inferred  = @{}
    $seen      = @{}
    foreach ($r in $idRows) {
        $sub  = "$($r.SubscriptionId)".ToLower()
        $name = "$($r.ResourceName)"
        if (-not $name) { continue }
        $wkey = "$sub|$($r.ResourceGroup)|$name".ToLower()
        $dedupeKey = "$wkey|$($r.Role)|$($r.Scope)"
        if ($seen.ContainsKey($dedupeKey)) { continue }
        $seen[$dedupeKey] = $true

        $isWebLike = "$($r.ResourceType)" -match 'web|function|app'
        $entry = [PSCustomObject]@{
            SubscriptionId = "$($r.SubscriptionId)"
            Name           = $name
            ResourceType   = "$($r.ResourceType)"
            ResourceGroup  = "$($r.ResourceGroup)"
            Role           = "$($r.Role)"
            Scope          = "$($r.Scope)"
            WKey           = $wkey
            Hostname       = $null
        }

        if ($isWebLike -and $exposed.ContainsKey("$sub|$($name.ToLower())")) {
            if (-not $confirmed.ContainsKey($wkey)) { $confirmed[$wkey] = $entry }
            continue
        }
        if ($isWebLike -and $hostnames.ContainsKey("$sub|$($name.ToLower())")) {
            $entry.Hostname = $hostnames["$sub|$($name.ToLower())"]
            if (-not $confirmed.ContainsKey($wkey) -and -not $inferred.ContainsKey($wkey)) { $inferred[$wkey] = $entry }
        }
    }

    $emitWorkload = {
        param($Context, $entry, $severity, $confidence, $reason)
        $wNodeId = "workload|$($entry.WKey)"
        $iNodeId = "identity|$($entry.WKey)"
        $sNodeId = "scope|$("$($entry.Scope)".ToLower())"
        [void](Add-CapabilityNode -Context $Context -Id $wNodeId -Type 'Workload' `
            -Name $entry.Name -Scope $entry.SubscriptionId -ResourceType $entry.ResourceType `
            -Sensitivity 'Workload' -Exposure $(if ($severity -eq 'HIGH') { 'Public' } else { 'PotentiallyPublic' }))
        [void](Add-CapabilityNode -Context $Context -Id $iNodeId -Type 'ManagedIdentity' `
            -Name "$($entry.Name) (system-assigned)" -Scope $entry.SubscriptionId -Sensitivity 'Privileged')
        [void](Add-CapabilityNode -Context $Context -Id $sNodeId -Type 'Scope' -Name $entry.Scope)
        Add-CapabilityInternetNode -Context $Context
        [void](Add-CapabilityEdge -Context $Context -From $wNodeId -To $iNodeId -Type 'RunsAs' `
            -Capability 'Workload runs as managed identity' -SourceCheckIds @('IDENTITY-006') `
            -Confidence 'High' -Severity $severity -Reason 'System-assigned managed identity attached to workload.')
        [void](Add-CapabilityEdge -Context $Context -From $iNodeId -To $sNodeId -Type 'HasRole' `
            -Capability "Modify resources via role '$($entry.Role)' (modeled)" -SourceCheckIds @('IDENTITY-006') `
            -Confidence 'High' -Severity $severity -Reason "Managed identity holds '$($entry.Role)' at $($entry.Scope).")
        [void](Add-CapabilityEdge -Context $Context -From 'internet|public' -To $wNodeId -Type 'Exposes' `
            -Capability 'Internet-reachable workload (modeled)' -SourceCheckIds @('IDENTITY-006', 'AZURE-EXPOSURE-001') `
            -Confidence $confidence -Severity $severity -Reason $reason)
    }

    if ($confirmed.Count -gt 0) {
        $impacted = New-Object System.Collections.Generic.List[string]
        foreach ($key in @($confirmed.Keys | Sort-Object)) {
            $e = $confirmed[$key]
            & $emitWorkload $Context $e 'HIGH' 'High' 'Public exposure confirmed by the public exposure inventory; the workload runs under an identity with broad Azure permissions.'
            $impacted.Add("$($e.Name) ($($e.ResourceType)) [$($e.SubscriptionId)] - identity role '$($e.Role)' at $($e.Scope)")
        }
        Add-CapabilityInsight -Context $Context `
            -Title 'Public workload with privileged identity' `
            -Description 'Internet-facing workloads run under managed identities with broad Azure permissions. A compromise of the workload (or its code/config pipeline) would inherit those permissions. Modeled from exposure and RBAC metadata only; no workload was contacted and no tokens were requested.' `
            -Severity 'HIGH' -Confidence 'High' `
            -SourceCheckIds @('IDENTITY-006', 'AZURE-EXPOSURE-001') `
            -ImpactedResources $impacted -ResourceUnit 'workloads' `
            -EvidenceSummary "$($confirmed.Count) publicly exposed workload(s) carry a managed identity with Owner/Contributor-class RBAC." `
            -RecommendedReview 'Reduce the attached identity to least privilege (resource-scoped roles), and validate the public exposure of each listed workload (access restrictions, private endpoints, Front Door/WAF).'
    }

    if ($inferred.Count -gt 0) {
        $impacted = New-Object System.Collections.Generic.List[string]
        foreach ($key in @($inferred.Keys | Sort-Object)) {
            $e = $inferred[$key]
            & $emitWorkload $Context $e 'MEDIUM' 'Medium' 'Public default hostname present in inventory; access restrictions were not evaluated, so public reachability is inferred, not confirmed.'
            $impacted.Add("$($e.Name) ($($e.ResourceType)) [$($e.SubscriptionId)] - identity role '$($e.Role)' at $($e.Scope); hostname $($e.Hostname)")
        }
        Add-CapabilityInsight -Context $Context `
            -Title 'Potentially public workload with privileged identity' `
            -Description 'Workloads with a public default hostname run under managed identities with broad Azure permissions. Public reachability is inferred from the default hostname (access restrictions and Private Link were not evaluated), so manual validation is required.' `
            -Severity 'MEDIUM' -Confidence 'Medium' `
            -SourceCheckIds @('IDENTITY-006', 'AZURE-EXPOSURE-001') `
            -ImpactedResources $impacted -ResourceUnit 'workloads' `
            -EvidenceSummary "$($inferred.Count) workload(s) with a public default hostname carry a managed identity with privileged RBAC; reachability not confirmed." `
            -RecommendedReview 'Confirm whether each workload is actually internet-reachable (access restrictions, private endpoints). If it is, treat it like the confirmed insight above and scope the identity down.'
    }
}

function Invoke-CapabilityManagedIdentityBlastRadius {
    <#
    .SYNOPSIS
        Capability 4: managed identity blast radius. System-assigned managed
        identities (from the cached workload inventory) whose principal id
        holds Owner/Contributor/User Access Administrator at subscription or
        resource group scope (cached RBAC). Supplemented by IDENTITY-006
        evidence rows (which lack principal ids) at lower confidence.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    # Index managed identities from cached workload inventory by principal id.
    $miByPrincipal = @{}
    foreach ($kind in @('WebApps', 'FunctionApps', 'VirtualMachines')) {
        foreach ($row in @(Get-CapabilityCachedInventoryItems -Kind $kind)) {
            $item = $row.Item
            $principalId = "$($item.Identity.PrincipalId)"
            if (-not $principalId) { continue }
            $miByPrincipal[$principalId.ToLower()] = [PSCustomObject]@{
                PrincipalId    = $principalId
                Name           = "$($item.Name)"
                ResourceType   = $kind
                ResourceGroup  = "$($item.ResourceGroupName)"
                SubscriptionId = "$($row.SubscriptionId)"
            }
        }
    }

    $entries = @{}   # dedupe key: sub|name|role|scope
    $anyDirect = $false

    foreach ($row in @(Get-CapabilityRBACAssignments)) {
        $a = $row.Assignment
        if ($script:CapabilityBroadRoles -notcontains "$($a.RoleDefinitionName)") { continue }
        $principalId = "$($a.ObjectId)".ToLower()
        if (-not $principalId -or -not $miByPrincipal.ContainsKey($principalId)) { continue }
        $scope = Get-CapabilityScopeInfo -Scope "$($a.Scope)"
        if ($scope.Kind -ne 'Subscription' -and $scope.Kind -ne 'ResourceGroup') { continue }
        $mi = $miByPrincipal[$principalId]
        $key = "$($mi.SubscriptionId)|$($mi.Name)|$($a.RoleDefinitionName)|$($a.Scope)".ToLower()
        if ($entries.ContainsKey($key)) { continue }
        $entries[$key] = [PSCustomObject]@{
            MI = $mi; Role = "$($a.RoleDefinitionName)"; Scope = "$($a.Scope)"
            ScopeInfo = $scope; Confidence = 'High'
        }
        $anyDirect = $true
    }

    # Supplement from IDENTITY-006 evidence (no principal id available there).
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('IDENTITY-006'))) {
        $key = "$($r.SubscriptionId)|$($r.ResourceName)|$($r.Role)|$($r.Scope)".ToLower()
        if ($entries.ContainsKey($key)) { continue }
        $scope = Get-CapabilityScopeInfo -Scope "$($r.Scope)"
        if ($scope.Kind -ne 'Subscription' -and $scope.Kind -ne 'ResourceGroup') { continue }
        $entries[$key] = [PSCustomObject]@{
            MI = [PSCustomObject]@{
                PrincipalId = $null; Name = "$($r.ResourceName)"; ResourceType = "$($r.ResourceType)"
                ResourceGroup = "$($r.ResourceGroup)"; SubscriptionId = "$($r.SubscriptionId)"
            }
            Role = "$($r.Role)"; Scope = "$($r.Scope)"; ScopeInfo = $scope; Confidence = 'Medium'
        }
    }

    if ($entries.Count -eq 0) { return }

    $fp = $script:State.Footprint
    $impacted = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($entries.Keys | Sort-Object)) {
        $e = $entries[$key]
        $wkey = "$($e.MI.SubscriptionId)|$($e.MI.ResourceGroup)|$($e.MI.Name)".ToLower()
        $iNodeId = "identity|$wkey"
        $sNodeId = "scope|$("$($e.Scope)".ToLower())"
        [void](Add-CapabilityNode -Context $Context -Id $iNodeId -Type 'ManagedIdentity' `
            -Name "$($e.MI.Name) (system-assigned)" -Scope $e.MI.SubscriptionId -Sensitivity 'Privileged')
        [void](Add-CapabilityNode -Context $Context -Id $sNodeId -Type 'Scope' -Name $e.Scope)
        [void](Add-CapabilityEdge -Context $Context -From $iNodeId -To $sNodeId -Type 'HasRole' `
            -Capability "Modify resources via role '$($e.Role)' (modeled)" -SourceCheckIds @('IDENTITY-006') `
            -Confidence $e.Confidence -Severity 'MEDIUM' `
            -Reason "Managed identity on $($e.MI.ResourceType) '$($e.MI.Name)' holds '$($e.Role)' at $($e.Scope).")

        $blast = ''
        if ($e.ScopeInfo.Kind -eq 'Subscription' -and $fp -and $fp.TypeCountsBySub) {
            $subKey = $e.ScopeInfo.SubscriptionId
            $matchKey = @($fp.TypeCountsBySub.Keys | Where-Object { "$_".ToLower() -eq $subKey }) | Select-Object -First 1
            if ($matchKey) {
                $count = 0
                foreach ($t in @($fp.TypeCountsBySub[$matchKey].Values)) { $count += [int]$t }
                if ($count -gt 0) { $blast = "; ~$count resources in scope" }
            }
        }
        $impacted.Add("$($e.MI.Name) ($($e.MI.ResourceType)) [$($e.MI.SubscriptionId)] - '$($e.Role)' at $($e.Scope)$blast")
    }

    Add-CapabilityInsight -Context $Context `
        -Title 'Managed identity blast radius' `
        -Description 'Managed identities attached to workloads can modify resources across subscription or resource group scope. If the hosting workload (or its deployment pipeline) is compromised, the attacker inherits this scope. Modeled from cached RBAC and inventory metadata only.' `
        -Severity 'MEDIUM' -Confidence $(if ($anyDirect) { 'High' } else { 'Medium' }) `
        -SourceCheckIds @('IDENTITY-006') `
        -ImpactedResources $impacted -ResourceUnit 'identities' `
        -EvidenceSummary "$($entries.Count) managed identity assignment(s) with Owner/Contributor/User Access Administrator at subscription or resource group scope." `
        -RecommendedReview 'Replace broad roles with resource-scoped, least-privilege assignments for each listed identity. Where broad scope is genuinely required, harden the hosting workload and its pipeline accordingly.'
}

function Invoke-CapabilityKeyVaultExposureModeling {
    <#
    .SYNOPSIS
        Capability 5: Key Vault exposure combination. Per-vault combination of
        public access without firewall (KEYVAULT-002 CRITICAL), legacy access
        policies (KEYVAULT-001), missing purge protection (KEYVAULT-002 HIGH)
        and missing private endpoint (KEYVAULT-002 MEDIUM). Never reads secret
        values; data-plane metadata is only referenced as a finding source.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $vaults = @{}
    $ensure = {
        param($sub, $name)
        $key = "$sub".ToLower() + '|' + "$name".ToLower()
        if (-not $vaults.ContainsKey($key)) {
            $vaults[$key] = [PSCustomObject]@{
                SubscriptionId = "$sub"; Vault = "$name"
                Public = $false; NoPurge = $false; NoPE = $false; Legacy = $false
            }
        }
        return $key
    }

    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('KEYVAULT-002') -MessageLike '*public access and no firewall*')) {
        $vaults[(& $ensure $r.SubscriptionId $r.VaultName)].Public = $true
    }
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('KEYVAULT-002') -MessageLike '*without purge protection*')) {
        $vaults[(& $ensure $r.SubscriptionId $r.VaultName)].NoPurge = $true
    }
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('KEYVAULT-002') -MessageLike '*without private endpoints*')) {
        $vaults[(& $ensure $r.SubscriptionId $r.VaultName)].NoPE = $true
    }
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('KEYVAULT-001'))) {
        $vaults[(& $ensure $r.SubscriptionId $r.VaultName)].Legacy = $true
    }

    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($vaults.Keys | Sort-Object)) {
        $v = $vaults[$key]
        $conditions = @()
        if ($v.Public) { $conditions += 'public access, no firewall' }
        if ($v.Legacy) { $conditions += 'legacy access policies' }
        if ($v.NoPurge) { $conditions += 'no purge protection' }
        if ($v.NoPE)    { $conditions += 'no private endpoint' }
        if ($conditions.Count -lt 2) { continue }

        $sev = 'MEDIUM'
        if (($v.Public -and $v.Legacy) -or $conditions.Count -ge 3) { $sev = 'HIGH' }

        [void](Add-CapabilityNode -Context $Context -Id "keyvault|$key" -Type 'Resource' `
            -Name $v.Vault -Scope $v.SubscriptionId -ResourceType 'Microsoft.KeyVault/vaults' `
            -Sensitivity 'Secrets' -Exposure $(if ($v.Public) { 'Public' } else { 'Internal' }))
        if ($v.Public) {
            Add-CapabilityInternetNode -Context $Context
            [void](Add-CapabilityEdge -Context $Context -From 'internet|public' -To "keyvault|$key" `
                -Type 'Exposes' -Capability 'Public Key Vault access path (modeled)' `
                -SourceCheckIds @('KEYVAULT-001', 'KEYVAULT-002') -Confidence 'High' -Severity $sev `
                -Reason ("Key Vault combines: " + ($conditions -join '; ') + '.'))
        }

        $text = "$($v.Vault) [$($v.SubscriptionId)] - $($conditions -join '; ')"
        if ($sev -eq 'HIGH') { $impactedHigh.Add($text) } else { $impactedMed.Add($text) }
    }

    $total = $impactedHigh.Count + $impactedMed.Count
    if ($total -eq 0) { return }

    $anyPublic = $false
    foreach ($key in @($vaults.Keys)) { if ($vaults[$key].Public) { $anyPublic = $true; break } }

    Add-CapabilityInsight -Context $Context `
        -Title $(if ($anyPublic) { 'Public Key Vault exposure combination' } else { 'Key Vault exposure combination' }) `
        -Description 'Key Vaults combine multiple exposure conditions (public network access without firewall, legacy access policies, missing purge protection, missing private endpoint). Combined, these increase both the reachability and the impact of vault compromise. Modeled from vault configuration metadata only; no secrets were read.' `
        -Severity $(if ($impactedHigh.Count -gt 0) { 'HIGH' } else { 'MEDIUM' }) -Confidence 'High' `
        -SourceCheckIds @('KEYVAULT-001', 'KEYVAULT-002') `
        -ImpactedResources (@($impactedHigh.ToArray()) + @($impactedMed.ToArray())) -ImpactedResourceCount $total -ResourceUnit 'vaults' `
        -EvidenceSummary "$total vault(s) with combined exposure conditions: $($impactedHigh.Count) high-severity combination(s), $($impactedMed.Count) medium." `
        -RecommendedReview 'For public vaults: enable firewall default-deny and private endpoints. Migrate legacy access policies to RBAC authorization and enable purge protection on vaults that hold production secrets.'
}

function Invoke-CapabilityNetworkEgressModeling {
    <#
    .SYNOPSIS
        Capability 6: network exfiltration paths. NSG outbound rules allowing
        broad internet access (NETWORK-008) combined with the presence of
        sensitive resources (Key Vaults, storage accounts, SQL servers) in the
        same subscription. NSG-to-subnet attachment is not verified, so
        confidence stays Medium and severity realistic.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $nsgRows = @(Get-CapabilityEvidenceRows -CheckIds @('NETWORK-008') -MessageLike '*outbound rules allowing internet*')
    if ($nsgRows.Count -eq 0) { return }

    $routeCount = @(@(Get-CapabilityEvidenceRows -CheckIds @('NETWORK-008') -MessageLike '*default route*Internet*')).Count

    # Sensitive resource presence per subscription (cached inventory only).
    $sensitiveBySub = @{}
    foreach ($kind in @('KeyVaults', 'StorageAccounts', 'SqlServers')) {
        foreach ($row in @(Get-CapabilityCachedInventoryItems -Kind $kind)) {
            $sub = "$($row.SubscriptionId)".ToLower()
            if (-not $sensitiveBySub.ContainsKey($sub)) { $sensitiveBySub[$sub] = 0 }
            $sensitiveBySub[$sub]++
        }
    }

    # Group rules per NSG so the graph carries one edge per NSG, not per rule.
    $nsgs = @{}
    $anySensitive = $false
    foreach ($r in $nsgRows) {
        $sub = "$($r.SubscriptionId)".ToLower()
        $key = "$sub|$($r.ResourceGroup)|$($r.NSGName)".ToLower()
        if (-not $nsgs.ContainsKey($key)) {
            $nsgs[$key] = [PSCustomObject]@{
                SubscriptionId = "$($r.SubscriptionId)"
                NSG            = "$($r.NSGName)"
                Rules          = [System.Collections.Generic.List[string]]::new()
                Sensitive      = ($sensitiveBySub.ContainsKey($sub) -and $sensitiveBySub[$sub] -gt 0)
            }
        }
        if ($nsgs[$key].Rules.Count -lt 5) { $nsgs[$key].Rules.Add("$($r.RuleName) -> $($r.Destination):$($r.Port)") }
        if ($nsgs[$key].Sensitive) { $anySensitive = $true }
    }

    $impacted = New-Object System.Collections.Generic.List[string]
    foreach ($key in @($nsgs.Keys | Sort-Object)) {
        $n = $nsgs[$key]
        [void](Add-CapabilityNode -Context $Context -Id "nsg|$key" -Type 'Resource' `
            -Name $n.NSG -Scope $n.SubscriptionId -ResourceType 'Microsoft.Network/networkSecurityGroups' `
            -Sensitivity 'Network' -Exposure 'Egress')
        Add-CapabilityInternetNode -Context $Context
        [void](Add-CapabilityEdge -Context $Context -From "nsg|$key" -To 'internet|public' -Type 'AllowsEgress' `
            -Capability 'Broad outbound internet access (exfiltration path, modeled)' `
            -SourceCheckIds @('NETWORK-008') -Confidence 'Medium' -Severity $(if ($n.Sensitive) { 'MEDIUM' } else { 'LOW' }) `
            -Reason ("NSG permits broad outbound internet access: " + (@($n.Rules) -join '; ') + '.'))
        $sensNote = $(if ($n.Sensitive) { '; sensitive resources present in subscription' } else { '' })
        $impacted.Add("$($n.NSG) [$($n.SubscriptionId)] - $($n.Rules.Count) outbound internet rule(s)$sensNote")
    }

    Add-CapabilityInsight -Context $Context `
        -Title 'Broad outbound exfiltration paths' `
        -Description 'NSG outbound rules permit broad internet access from network segments that also contain sensitive Azure resources (Key Vaults, storage accounts, SQL servers). Broad egress lowers the bar for data exfiltration if a workload in scope is compromised. NSG-to-subnet attachment was not verified; treat as review candidates.' `
        -Severity $(if ($anySensitive) { 'MEDIUM' } else { 'LOW' }) -Confidence 'Medium' `
        -SourceCheckIds @('NETWORK-008') `
        -ImpactedResources $impacted -ResourceUnit 'NSGs' `
        -EvidenceSummary "$($nsgs.Count) NSG(s) with broad outbound internet rules across $($nsgRows.Count) rule row(s); $routeCount default route(s) to Internet also recorded. Subscriptions with sensitive resources in scope: $(@($sensitiveBySub.Keys).Count)." `
        -RecommendedReview 'Restrict outbound rules to required destinations (FQDNs/service tags), prefer Azure Firewall or NAT-controlled egress, and verify which subnets each listed NSG is attached to.'
}

function Invoke-CapabilityMonitoringGapModeling {
    <#
    .SYNOPSIS
        Capability 7: monitoring blind spots on exposed critical resources.
        MONITORING-001 (Key Vaults / SQL servers without diagnostic settings)
        joined with public exposure evidence (KEYVAULT-002 public-no-firewall,
        AZURE-EXPOSURE-001 KeyVault/SqlServer rows). Only exposed resources
        are modeled here; non-exposed gaps remain plain findings.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $monRows = @(Get-CapabilityEvidenceRows -CheckIds @('MONITORING-001'))
    if ($monRows.Count -eq 0) { return }

    $publicKvCritical = @{}   # KEYVAULT-002 public + no firewall (critical exposure)
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('KEYVAULT-002') -MessageLike '*public access and no firewall*')) {
        $publicKvCritical["$($r.SubscriptionId)".ToLower() + '|' + "$($r.VaultName)".ToLower()] = $true
    }
    $exposedKv = @{}
    $exposedSql = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('AZURE-EXPOSURE-001'))) {
        $key = "$($r.SubscriptionId)".ToLower() + '|' + "$($r.ResourceName)".ToLower()
        if ("$($r.ResourceType)" -eq 'KeyVault')  { $exposedKv[$key] = $true }
        if ("$($r.ResourceType)" -eq 'SqlServer') { $exposedSql[$key] = $true }
    }

    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    foreach ($r in $monRows) {
        $sub  = "$($r.SubscriptionId)".ToLower()
        $name = "$($r.ResourceName)"
        if (-not $name) { continue }
        $key = "$sub|$($name.ToLower())"
        $isKv  = "$($r.ResourceType)" -eq 'KeyVault'
        $isSql = "$($r.ResourceType)" -eq 'SQLServer'
        $exposed = ($isKv -and ($exposedKv.ContainsKey($key) -or $publicKvCritical.ContainsKey($key))) -or
                   ($isSql -and $exposedSql.ContainsKey($key))
        if (-not $exposed) { continue }

        $criticalExposure = $isKv -and $publicKvCritical.ContainsKey($key)
        $sev = $(if ($criticalExposure) { 'HIGH' } else { 'MEDIUM' })

        $rNodeId = "resource|$key|$("$($r.ResourceType)".ToLower())"
        [void](Add-CapabilityNode -Context $Context -Id $rNodeId -Type 'Resource' `
            -Name $name -Scope $r.SubscriptionId -ResourceType $r.ResourceType `
            -Sensitivity 'High' -Exposure 'Public')
        [void](Add-CapabilityNode -Context $Context -Id 'monitoring|diagnostics' -Type 'Monitoring' -Name 'Diagnostic logging / monitoring')
        [void](Add-CapabilityEdge -Context $Context -From $rNodeId -To 'monitoring|diagnostics' -Type 'DetectionGap' `
            -Capability 'Exposed resource without diagnostic logging (detection gap, modeled)' `
            -SourceCheckIds @('MONITORING-001', 'AZURE-EXPOSURE-001') -Confidence 'High' -Severity $sev `
            -Reason 'Resource is publicly exposed but has no diagnostic settings, reducing detection coverage for access and misuse.')

        $text = "$name ($($r.ResourceType)) [$($r.SubscriptionId)] - publicly exposed, no diagnostic settings"
        if ($sev -eq 'HIGH') { $impactedHigh.Add($text) } else { $impactedMed.Add($text) }
    }

    $total = $impactedHigh.Count + $impactedMed.Count
    if ($total -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Monitoring gaps on exposed critical resources' `
        -Description 'Publicly exposed Key Vaults and SQL servers lack diagnostic settings, so access and misuse would have reduced visibility in logs. Detection gaps matter most where exposure is already confirmed; severity is only raised where that combination exists.' `
        -Severity $(if ($impactedHigh.Count -gt 0) { 'HIGH' } else { 'MEDIUM' }) -Confidence 'High' `
        -SourceCheckIds @('MONITORING-001', 'AZURE-EXPOSURE-001', 'KEYVAULT-002') `
        -ImpactedResources (@($impactedHigh.ToArray()) + @($impactedMed.ToArray())) -ImpactedResourceCount $total -ResourceUnit 'resources' `
        -EvidenceSummary "$total exposed critical resource(s) without diagnostic settings ($($impactedHigh.Count) with critical public exposure)." `
        -RecommendedReview 'Enable diagnostic settings (audit / request logs) to a Log Analytics workspace or storage account for each listed resource, and alert on anomalous access patterns.'
}

#------------------------------------------------------------------------------
# Top-level builder
#------------------------------------------------------------------------------

function Build-CapabilityModel {
    <#
    .SYNOPSIS
        Builds the B2 capability model from already-collected run data.
    .DESCRIPTION
        Runs every insight builder over in-memory state (findings, caches,
        footprint), sorts insights by severity then impacted count, assigns
        stable ids (CAP-001...), applies output caps and returns the model.
        Never throws: a failing builder is logged and skipped so the report
        phase always completes. NO Azure/Graph API calls are made here.
    .OUTPUTS
        [PSCustomObject] CapabilityModel with ModelVersion, GeneratedAt,
        Summary, Nodes, Edges, Insights, SourceChecks, Limits.
    #>
    [CmdletBinding()]
    param()

    $ctx = New-CapabilityContext

    $builders = @(
        'Invoke-CapabilityStorageKeyModeling',
        'Invoke-CapabilityPublicStorageModeling',
        'Invoke-CapabilityPublicWorkloadModeling',
        'Invoke-CapabilityManagedIdentityBlastRadius',
        'Invoke-CapabilityKeyVaultExposureModeling',
        'Invoke-CapabilityNetworkEgressModeling',
        'Invoke-CapabilityMonitoringGapModeling'
    )
    foreach ($builder in $builders) {
        try {
            & $builder -Context $ctx
        }
        catch {
            Write-AuditLog -Message "Capability model builder '$builder' failed (skipped, model continues without it): $($_.Exception.Message)" -Level WARN
            $ctx.Limits.Notes.Add("Builder '$builder' failed and was skipped: $($_.Exception.Message)")
        }
    }

    # Sort insights: severity rank first, then impacted count (desc), then title.
    $sorted = @($ctx.Insights | Sort-Object `
        @{ Expression = { $r = $script:CapabilitySeverityRank["$($_.Severity)".ToUpper()]; if ($r) { $r } else { 9 } } }, `
        @{ Expression = { -[int]$_.ImpactedResourceCount } }, `
        Title)

    $truncated = 0
    if ($sorted.Count -gt $script:CapabilityLimits.MaxInsights) {
        $truncated = $sorted.Count - $script:CapabilityLimits.MaxInsights
        $sorted = @($sorted | Select-Object -First $script:CapabilityLimits.MaxInsights)
    }
    $ctx.Limits.InsightsTruncated = $truncated

    $n = 0
    foreach ($insight in $sorted) {
        $n++
        $insight.Id = 'CAP-{0:d3}' -f $n
    }

    $nodes = @($ctx.Nodes.Values | Sort-Object Type, Id)
    $edges = @($ctx.Edges.Values | Sort-Object From, To)

    $highest = $null
    foreach ($insight in $sorted) {
        $rank = $script:CapabilitySeverityRank["$($insight.Severity)".ToUpper()]
        if ($rank -and (-not $highest -or $rank -lt $script:CapabilitySeverityRank[$highest])) {
            $highest = "$($insight.Severity)".ToUpper()
        }
    }

    $limitsOut = [ordered]@{
        MaxInsights                    = $ctx.Limits.MaxInsights
        MaxNodes                       = $ctx.Limits.MaxNodes
        MaxEdges                       = $ctx.Limits.MaxEdges
        MaxImpactedResourcesPerInsight = $ctx.Limits.MaxImpactedResourcesPerInsight
        NodesTruncated                 = $ctx.Limits.NodesTruncated
        EdgesTruncated                 = $ctx.Limits.EdgesTruncated
        InsightsTruncated              = $ctx.Limits.InsightsTruncated
        Notes                          = @($ctx.Limits.Notes.ToArray())
    }

    $model = [PSCustomObject][ordered]@{
        ModelVersion = $script:CapabilityModelVersion
        GeneratedAt  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Summary      = [PSCustomObject][ordered]@{
            InsightCount       = $sorted.Count
            HighestSeverity    = $highest
            NodeCount          = $nodes.Count
            EdgeCount          = $edges.Count
            DataPlaneIncluded  = [bool]$script:State.Config.IncludeDataPlane
        }
        Nodes        = $nodes
        Edges        = $edges
        Insights     = $sorted
        SourceChecks = @($ctx.SourceChecks | Sort-Object)
        Limits       = $limitsOut
    }

    Write-AuditLog -Message ("Capability model built: {0} insight(s), {1} node(s), {2} edge(s), highest severity {3}." -f `
        $sorted.Count, $nodes.Count, $edges.Count, $(if ($highest) { $highest } else { 'n/a' })) -Level INFO

    return $model
}
