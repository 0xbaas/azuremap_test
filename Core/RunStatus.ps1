#==============================================================================
# AzureMap v2 - Core/RunStatus.ps1
# Per-check execution tracking and run-level diagnostics.
#
# Statuses: Pass | Fail | Warning | Partial | NotEvaluated | NotApplicable | Error | Skipped
#
# Phase B1 status x coverage contract:
#   Pass         = collection succeeded AND (resources were evaluated OR it was
#                  proven none exist in scope) AND no issues found. A check proves
#                  this only by emitting an explicit PASS record - silence is
#                  never a Pass.
#   Fail         = evaluation ran and produced at least one real finding (Count>0).
#   Partial      = part of the scope could not be collected/evaluated
#                  (FailedCollectionCount > 0) but the rest was evaluated.
#   NotEvaluated = relevant resources may exist but the check could not prove
#                  evaluation: collection failed, permission/API unavailable, or
#                  the check produced no records at all (legacy checks that only
#                  Write-Finding on issues land here until migrated).
#   NotApplicable = no relevant resources exist in the evaluated scope (proven via
#                  the environment footprint / explicit check record). This is a
#                  truthful "nothing to check", distinct from NotEvaluated.
#   Error        = the check threw an unexpected exception.
#   Skipped      = prerequisites missing or intentionally excluded by mode/flag
#                  (e.g. required module not installed, -SkipEntra, data-plane off).
#
# Summary math (corrected):
#   ChecksAttempted   = number of checks executed/attempted (NOT finding count)
#   FindingGroups     = number of grouped findings (finding rows with Count > 0)
#   AffectedResources = SUM of Count across finding groups (e.g. 227 assignments)
# A Count of 227 means 227 affected resources within ONE finding group - it must
# never be reported as "227 findings".
#==============================================================================

# Canonical status labels.
$script:AzureMapCheckStatuses = @('Pass','Fail','Warning','Partial','NotEvaluated','NotApplicable','Error','Skipped')

function New-CheckExecutionRecord {
    <#
    .SYNOPSIS
        Builds a per-check execution record with the full status schema.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Check,

        [string]$Phase
    )

    [PSCustomObject]@{
        CheckId     = $Check.CheckId
        Name        = $Check.Name
        Category    = $Check.Category
        Service     = $Check.Service
        Phase       = if ($Phase) { $Phase } else { $Check.Phase }
        Status      = 'Pending'
        StartedAt   = Get-Date
        CompletedAt = $null
        ErrorClass  = $null
        Detail      = $null
        StackTrace  = $null
        # Phase B1: aggregated coverage metadata (Get-CheckCoverage) and the
        # one-line human summary shown in CLI/HTML. $null when the check did
        # not emit coverage data (legacy/unmigrated checks).
        Coverage    = $null
        SummaryText = $null
        # Phase B3: mirrors the registration flag so exports can show which
        # checks need data-plane access even when the check never ran
        # (Skipped: data-plane checks disabled).
        DataPlaneRequired = [bool]$Check.RequiresDataPlane
    }
}

function Resolve-CheckStatus {
    <#
    .SYNOPSIS
        Derives a check's Status from whether it threw and the findings it produced.
    .DESCRIPTION
        Phase B1 semantics - Pass must be PROVEN, never inferred from silence:
        * Threw                                             -> Error
        * No findings produced at all                       -> NotEvaluated
          (the check left no proof that anything was evaluated)
        * Any real finding (Count>0, not NotEvaluated/Skipped) -> Fail
        * Any Partial finding (Status PARTIAL or PartialEvaluation) -> Partial
        * Any Warning finding                               -> Warning
        * Any NotEvaluated finding                          -> NotEvaluated
        * Any inventory record that captured items          -> Inventory
          (even when mixed with empty PASS records; zero-item
          inventory-only records are a proven-empty scope -> Pass)
        * Otherwise (explicit/inferred PASS records exist)  -> Pass
    #>
    [CmdletBinding()]
    param(
        [switch]$Threw,
        [object[]]$ProducedFindings
    )

    if ($Threw) { return 'Error' }

    $f = @($ProducedFindings)
    if ($f.Count -eq 0) { return 'NotEvaluated' }

    # Inventory/context records (IsInventoryOnly) never fail a check by
    # themselves - they describe the environment, not a risky condition.
    $hasFail = @($f | Where-Object {
        ($_.PSObject.Properties.Name -contains 'Count') -and
        ($null -ne $_.Count) -and ([int]$_.Count -gt 0) -and
        ("$($_.Status)" -ne 'NotEvaluated') -and ("$($_.Status)" -ne 'Skipped') -and
        -not (($_.PSObject.Properties.Name -contains 'IsInventoryOnly') -and $_.IsInventoryOnly)
    }).Count -gt 0
    if ($hasFail) { return 'Fail' }

    # Partial means "part evaluated, part failed". A finding whose own status is
    # NotEvaluated (nothing was evaluated at all) must NOT flip the check to
    # Partial just because its coverage metadata carries PartialEvaluation=true
    # (e.g. KEYVAULT-003 sets PartialEvaluation on its nothing-evaluated record).
    $hasPartial = @($f | Where-Object {
        ("$($_.Status)".ToUpper() -eq 'PARTIAL') -or
        (("$($_.Status)" -ne 'NotEvaluated') -and
         ($_.PSObject.Properties.Name -contains 'PartialEvaluation') -and ($_.PartialEvaluation -eq $true))
    }).Count -gt 0
    if ($hasPartial) { return 'Partial' }

    $hasWarning = @($f | Where-Object { "$($_.Status)".ToUpper() -eq 'WARNING' }).Count -gt 0
    if ($hasWarning) { return 'Warning' }

    $hasNotEval = @($f | Where-Object { "$($_.Status)" -eq 'NotEvaluated' }).Count -gt 0
    if ($hasNotEval) { return 'NotEvaluated' }

    $hasNotApplicable = @($f | Where-Object { "$($_.Status)".ToUpper() -eq 'NOTAPPLICABLE' }).Count -gt 0
    if ($hasNotApplicable) { return 'NotApplicable' }

    # Inventory/context checks never resolve to plain Pass: their records describe
    # the environment (e.g. a public exposure inventory with N affected), not a
    # clean bill of health. An inventory record that actually captured items means
    # "context produced" -> INVENTORY, even when the same check also emitted
    # empty PASS records for subscriptions with nothing exposed (the mixed case
    # that previously mislabeled the row as Clean). Inventory-only records with
    # zero items are a proven-empty scope -> Pass ("Clean" only ever means
    # nothing relevant was produced).
    $inventoryWithItems = @($f | Where-Object {
        (($_.PSObject.Properties.Name -contains 'IsInventoryOnly') -and $_.IsInventoryOnly) -and
        ($_.PSObject.Properties.Name -contains 'Count') -and ($null -ne $_.Count) -and ([int]$_.Count -gt 0) -and
        ("$($_.Status)" -ne 'NotEvaluated') -and ("$($_.Status)" -ne 'Skipped')
    }).Count
    if ($inventoryWithItems -gt 0) { return 'Inventory' }

    return 'Pass'
}

function Get-CheckCoverage {
    <#
    .SYNOPSIS
        Aggregates Phase B1 coverage metadata from the findings a check produced.
    .DESCRIPTION
        Findings emitted by a single check describe the SAME evaluated population,
        so resource counts are combined with Max (not Sum) to avoid double-counting
        when a check emits several severity-split findings carrying identical
        coverage. Subscription lists are unioned. Returns $null when no produced
        finding carried any coverage signal (legacy/unmigrated checks).
    .OUTPUTS
        [pscustomobject] coverage object, or $null.
    #>
    [CmdletBinding()]
    param([object[]]$Findings)

    $f = @($Findings)
    if ($f.Count -eq 0) { return $null }

    $withCoverage = @($f | Where-Object {
        ($_.PSObject.Properties.Name -contains 'CompleteEvaluation') -and (
            $_.CompleteEvaluation -eq $true -or
            $_.PartialEvaluation  -eq $true -or
            $null -ne $_.DiscoveredResourceCount -or
            $null -ne $_.EvaluatedResourceCount  -or
            $null -ne $_.SkippedResourceCount    -or
            $null -ne $_.FailedCollectionCount
        )
    })
    if ($withCoverage.Count -eq 0) { return $null }

    $discovered = 0; $evaluated = 0; $skipped = 0; $failed = 0
    $subsEval = New-Object System.Collections.Generic.List[string]
    $subsSkip = New-Object System.Collections.Generic.List[string]
    $summary = $null
    $anyPartial = $false
    $allComplete = $true

    foreach ($x in $withCoverage) {
        if ($null -ne $x.DiscoveredResourceCount) { $discovered = [Math]::Max($discovered, [int]$x.DiscoveredResourceCount) }
        if ($null -ne $x.EvaluatedResourceCount)  { $evaluated  = [Math]::Max($evaluated,  [int]$x.EvaluatedResourceCount) }
        if ($null -ne $x.SkippedResourceCount)    { $skipped    = [Math]::Max($skipped,    [int]$x.SkippedResourceCount) }
        if ($null -ne $x.FailedCollectionCount)   { $failed     = [Math]::Max($failed,     [int]$x.FailedCollectionCount) }
        foreach ($s in @($x.SubscriptionsEvaluated)) { if ($s -and -not $subsEval.Contains($s)) { $subsEval.Add($s) } }
        foreach ($s in @($x.SubscriptionsSkipped))   { if ($s -and -not $subsSkip.Contains($s)) { $subsSkip.Add($s) } }
        if ($x.PartialEvaluation -eq $true) { $anyPartial = $true }
        if ($x.CompleteEvaluation -ne $true) { $allComplete = $false }
        if (-not $summary -and ($x.PSObject.Properties.Name -contains 'CoverageSummary') -and $x.CoverageSummary) {
            $summary = [string]$x.CoverageSummary
        }
    }

    return [PSCustomObject]@{
        DiscoveredResourceCount = $discovered
        EvaluatedResourceCount  = $evaluated
        SkippedResourceCount    = $skipped
        FailedCollectionCount   = $failed
        SubscriptionsEvaluated  = @($subsEval)
        SubscriptionsSkipped    = @($subsSkip)
        CompleteEvaluation      = ($allComplete -and -not $anyPartial)
        PartialEvaluation       = $anyPartial
        Summary                 = $summary
    }
}

function Get-RunDiagnostics {
    <#
    .SYNOPSIS
        Computes run-level diagnostics with corrected summary math.
    .DESCRIPTION
        Robust against: no findings, one finding, many findings, missing Count,
        Count = 0, Count = 227, and all-error runs. Never assumes Measure-Object
        exposes a populated .Sum.
    .OUTPUTS
        [pscustomobject] with ChecksAttempted, Passed, Failed, Warnings, Partial,
        NotEvaluated, Errors, Skipped, FindingGroups, AffectedResources, BySeverity.
    #>
    [CmdletBinding()]
    param()

    $exec = @()
    if ($script:State -and $script:State.ExecutedChecks) {
        $exec = @($script:State.ExecutedChecks)
    }

    $statusCount = {
        param([string]$Status)
        @($exec | Where-Object { "$($_.Status)".ToLower() -eq $Status.ToLower() }).Count
    }

    $attempted    = $exec.Count
    $passed       = & $statusCount 'Pass'
    $failed       = & $statusCount 'Fail'
    $warnings     = & $statusCount 'Warning'
    $partial      = & $statusCount 'Partial'
    $notEvaluated = & $statusCount 'NotEvaluated'
    $notApplicable = & $statusCount 'NotApplicable'
    $inventory    = & $statusCount 'Inventory'
    $errors       = & $statusCount 'Error'
    $skipped      = & $statusCount 'Skipped'

    # Finding groups = finding rows that represent real affected resources.
    $results = @()
    if ($script:State -and $script:State.Results) {
        $results = @($script:State.Results)
    }

    $findings = @($results | Where-Object {
        ($_.PSObject.Properties.Name -contains 'Count') -and
        ($null -ne $_.Count) -and
        ([int]$_.Count -gt 0) -and
        ("$($_.Status)" -ne 'NotEvaluated') -and
        ("$($_.Status)" -ne 'Skipped')
    })

    $findingGroups = $findings.Count

    # Affected resources = SUM of Count. Do not assume .Sum is present/populated.
    $affected = 0
    if ($findingGroups -gt 0) {
        $measured = $findings | Measure-Object -Property Count -Sum
        if ($measured -and ($measured.PSObject.Properties.Name -contains 'Sum') -and ($null -ne $measured.Sum)) {
            $affected = [int]$measured.Sum
        } else {
            foreach ($fnd in $findings) { $affected += [int]$fnd.Count }
        }
    }

    $bySeverity = [ordered]@{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }
    foreach ($fnd in $findings) {
        $sev = "$($fnd.Severity)".ToUpper()
        if ($bySeverity.Contains($sev)) { $bySeverity[$sev]++ }
    }

    [PSCustomObject]@{
        ChecksAttempted   = $attempted
        Passed            = $passed
        Failed            = $failed
        Warnings          = $warnings
        Partial           = $partial
        NotEvaluated      = $notEvaluated
        NotApplicable     = $notApplicable
        Inventory         = $inventory
        Errors            = $errors
        Skipped           = $skipped
        FindingGroups     = $findingGroups
        AffectedResources = $affected
        BySeverity        = $bySeverity
    }
}
