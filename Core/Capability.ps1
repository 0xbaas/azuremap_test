#==============================================================================
# AzureMap v2 - Core/Capability.ps1
# Phase B2: shared capability / attack-path modeling primitives (READ-ONLY
# MODELING ONLY): model version + output caps, context creation,
# node/edge/insight constructors with dedupe + truncation bookkeeping, and
# the generic readers Get-CapabilityEvidenceRows / Get-CapabilityScopeInfo.
# Azure-specific readers, insight builders and Build-CapabilityModel live
# in Core/Azure/CapabilityModel.Azure.ps1 (extracted from
# Core/CapabilityModel.ps1).
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

$script:CapabilitySeverityRank = @{ CRITICAL = 1; HIGH = 2; MEDIUM = 3; LOW = 4; INFO = 5 }

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
