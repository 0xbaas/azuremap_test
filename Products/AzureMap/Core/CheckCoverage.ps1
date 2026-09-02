#==============================================================================
# AzureMap v2 - Core/Azure/CheckCoverage.ps1
# Generic Phase B1 coverage/status helpers for checks outside the Storage
# family (Storage.ps1 carries its own storage-noun copies). Same status
# contract as Core/RunStatus.ps1:
#   * nothing evaluated + collection/context failures -> NOTEVALUATED
#     (never a clean PASS)
#   * evaluated subset + failures                     -> PARTIAL
#     (FAIL instead when risky resources were found; PartialEvaluation
#     stays $true so the incomplete coverage remains visible)
#   * full coverage, 0 resources discovered           -> PASS
#   * full coverage, 0 risky                          -> PASS
#   * risky > 0                                       -> FAIL
# Read-only helpers; no Azure calls.
#==============================================================================

function New-AzureCheckCoverage {
    <#
    .SYNOPSIS
        Builds the Phase B1 coverage/status view for a check from
        per-subscription collection tracking (noun-parametrized version of
        New-StorageCoverage in Checks/Storage.ps1).
    #>
    [CmdletBinding()]
    param(
        [int]$Discovered,
        [int]$Evaluated,
        [int]$SkippedResources,
        [object]$CollectionFailures,      # List[object]: per-sub/per-resource failure detail
        [object]$SkippedSubscriptions,    # List[string]: sub names where Set-AzContext failed
        [object]$EvaluatedSubscriptions,  # List[string]
        [int]$Risky,
        [string]$ResourceNoun = 'resources'
    )

    # NOTE: never wrap $CollectionFailures / $SkippedSubscriptions in @(...) - under
    # Windows PowerShell 5.1, coercing a raw generic List throws "Argument types do
    # not match". Read .Count directly instead (works for List and arrays).
    $failedCount = 0
    if ($null -ne $CollectionFailures)   { $failedCount += $CollectionFailures.Count }
    if ($null -ne $SkippedSubscriptions) { $failedCount += $SkippedSubscriptions.Count }

    $status           = 'PASS'
    $collectionStatus = 'Complete'
    $complete         = $true
    $partial          = $false
    $summary          = ''

    if ($Evaluated -eq 0 -and $failedCount -gt 0) {
        $status           = 'NOTEVALUATED'
        $collectionStatus = 'Failed'
        $complete         = $false
        if ($Discovered -gt 0) {
            $summary = "Could not evaluate $Discovered $ResourceNoun; reads failed or permission/API unavailable."
        } else {
            $summary = "Could not evaluate $ResourceNoun; collection failed or permission/API unavailable."
        }
    }
    else {
        if ($failedCount -gt 0) {
            $collectionStatus = 'Partial'
            $complete         = $false
            $partial          = $true
        }
        if ($Risky -gt 0) {
            $status  = 'FAIL'
            $covText = if ($complete) { 'coverage complete.' } else { "coverage partial ($failedCount skipped/failed); findings may be incomplete." }
            $summary = "$Risky of $Evaluated $ResourceNoun risky; $covText"
        }
        elseif ($partial) {
            $status  = 'PARTIAL'
            $summary = "$Evaluated of $Discovered $ResourceNoun evaluated; 0 risky; $failedCount skipped/failed - findings may be incomplete."
        }
        elseif ($Discovered -eq 0) {
            $summary = "No $ResourceNoun discovered in evaluated scope."
        }
        else {
            $summary = "$Evaluated $ResourceNoun evaluated; 0 risky; coverage complete."
        }
    }

    return [PSCustomObject]@{
        Status                   = $status
        CollectionStatus         = $collectionStatus
        CompleteEvaluation       = $complete
        PartialEvaluation        = $partial
        FailedCollectionCount    = $failedCount
        CoverageSummary          = $summary
        Confidence               = if ($status -eq 'NOTEVALUATED') { 'Low' } elseif ($partial) { 'Medium' } else { 'High' }
        ManualValidationRequired = ($status -in @('PARTIAL', 'NOTEVALUATED'))
        # Zero-risky records are informational - there is nothing to remediate.
        # NOTEVALUATED keeps the check's default severity (evaluation failed).
        # $null = caller keeps the check's default severity.
        Severity                 = if ($Risky -eq 0 -and $status -in @('PASS','PARTIAL')) { 'INFO' } else { $null }
    }
}

function New-AzureCheckCoverageParams {
    <#
    .SYNOPSIS
        Builds the splat hashtable of Phase B1 coverage/reporting parameters for
        Write-Finding, so each check passes identical metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Coverage,
        [int]$Discovered,
        [int]$Evaluated,
        [int]$SkippedResources,
        [object]$SkippedSubscriptions,
        [object]$EvaluatedSubscriptions,
        [string[]]$ApiSources,
        [string]$FindingType,
        [bool]$DataPlaneRequired = $false
    )

    # Enumerate explicitly (no @(...) around possible generic Lists - PS 5.1 throws
    # "Argument types do not match" on that coercion).
    $evalList = @()
    if ($null -ne $EvaluatedSubscriptions) { foreach ($s in $EvaluatedSubscriptions) { $evalList += $s } }
    $skipList = @()
    if ($null -ne $SkippedSubscriptions)   { foreach ($s in $SkippedSubscriptions)   { $skipList += $s } }

    return @{
        DiscoveredResourceCount  = $Discovered
        EvaluatedResourceCount   = $Evaluated
        SkippedResourceCount     = $SkippedResources
        FailedCollectionCount    = $Coverage.FailedCollectionCount
        SubscriptionsEvaluated   = $evalList
        SubscriptionsSkipped     = $skipList
        CollectionStatus         = $Coverage.CollectionStatus
        CompleteEvaluation       = $Coverage.CompleteEvaluation
        PartialEvaluation        = $Coverage.PartialEvaluation
        CoverageSummary          = $Coverage.CoverageSummary
        SummaryText              = $Coverage.CoverageSummary
        Confidence               = $Coverage.Confidence
        ManualValidationRequired = $Coverage.ManualValidationRequired
        ApiSources               = $ApiSources
        FindingType              = $FindingType
        DataPlaneRequired        = $DataPlaneRequired
    }
}
