#==============================================================================
# AzureMap v2 - Core/CheckRegistry.ps1
# Check registration, filtering, finding creation, orchestration engine,
# subscription helpers, and tenant-wide data fetching.
# All functions reference $script:State. Strictly read-only operations.
#==============================================================================

#region --- Check Registry Management ---

function Register-AuditCheck {
    <#
    .SYNOPSIS
        Registers an audit check in $script:State.CheckRegistry.
    .PARAMETER CheckId
        Unique identifier (e.g. "AZ-STOR-001").
    .PARAMETER Category
        "Azure" or "Entra".
    .PARAMETER Service
        Service name (Storage, SQL, Identity, etc.).
    .PARAMETER Name
        Human-readable check name.
    .PARAMETER Function
        Scriptblock or function name to invoke when the check runs.
    .PARAMETER DefaultSeverity
        Default severity if the check produces findings.
    .PARAMETER RequiredModules
        Array of Az module names required for this check.
    .PARAMETER RequiredPerms
        Array of Graph or ARM permission scopes needed.
    .PARAMETER Phase
        "PerSubscription" or "TenantWide".
    .PARAMETER Provider
        Logical provider or area (same as Category by default).
    .PARAMETER Safe
        Indicates this check is read-only and safe by default.
    .PARAMETER OutputType
        Type of output produced by this check (default "Finding").
    .PARAMETER Description
        Short description of what the check validates.
    .PARAMETER Enabled
        Whether the check is active (default $true).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CheckId,

        [Parameter(Mandatory)]
        [ValidateSet("Azure","Entra")]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Service,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object]$Function,

        [ValidateSet("CRITICAL","HIGH","MEDIUM","LOW","INFO")]
        [string]$DefaultSeverity = "MEDIUM",

        [string[]]$RequiredModules = @(),
        [string[]]$RequiredPerms  = @(),

        [ValidateSet("PerSubscription","TenantWide")]
        [string]$Phase = "PerSubscription",

        [string]$Provider = "",
        [bool]$Safe = $true,
        [string]$OutputType = "Finding",

        [string]$Description = "",
        [bool]$Enabled = $true,

        # ---- Applicability metadata (UX phase) ----
        # ARM resource types the check evaluates (e.g. Microsoft.Storage/storageAccounts).
        # When the environment footprint proves none of these exist in scope, the
        # check is recorded NotApplicable instead of running. Empty = unknown.
        [string[]]$RequiredResourceTypes = @(),
        # Global/inventory checks that must run regardless of footprint contents.
        [bool]$AlwaysRun = $false,
        # Data-plane access required for full evaluation (STORAGE-004, KEYVAULT-003).
        # Gated off by default (Phase B3): the check runs only when the operator
        # passes -IncludeDataPlane. Even then, safe metadata only - never values,
        # keys, SAS tokens, connection strings, or blob/file content.
        [bool]$RequiresDataPlane = $false
    )

    if ($Function -is [string]) {
        $command = Get-Command -Name $Function -ErrorAction SilentlyContinue
        if ($command) {
            $Function = $command.ScriptBlock
        }
        else {
            throw "Register-AuditCheck failed: function '$Function' not found."
        }
    }

    $existing = $script:State.CheckRegistry | Where-Object { $_.CheckId -eq $CheckId }
    if ($existing) {
        Write-AuditLog -Message "Check $CheckId already registered - skipping duplicate" -Level WARN
        return
    }

    if (-not $Provider) {
        $Provider = $Category
    }

    $script:State.CheckRegistry.Add([PSCustomObject]@{
        CheckId         = $CheckId
        Category        = $Category
        Service         = $Service
        Provider        = $Provider
        Name            = $Name
        Function        = $Function
        DefaultSeverity = $DefaultSeverity
        RequiredModules = $RequiredModules
        RequiredPerms   = $RequiredPerms
        Phase           = $Phase
        Description     = $Description
        Safe            = $Safe
        OutputType      = $OutputType
        Enabled         = $Enabled
        RequiredResourceTypes = $RequiredResourceTypes
        AlwaysRun       = $AlwaysRun
        RequiresDataPlane = $RequiresDataPlane
    })

    Write-AuditLog -Message "Registered check: $CheckId ($Name)" -Level DEBUG
}

function Register-CheckDefinition {
    <#
    .SYNOPSIS
        Registers a check from a hashtable definition (used by Register-Entra*Checks).
    .DESCRIPTION
        The Entra check modules return hashtable definitions rather than calling
        Register-AuditCheck directly. This helper resolves the definition's
        Function name to a ScriptBlock and registers it via Register-AuditCheck.
        It FAILS LOUDLY (throws) if the check id or function cannot be resolved,
        so a broken definition is never silently dropped.
    .PARAMETER Definition
        Hashtable with keys: CheckId, Category, Service, Name, Function, and
        optionally DefaultSeverity, RequiredModules, RequiredPerms, Phase, Description.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Definition
    )

    $checkId = [string]$Definition['CheckId']
    if ([string]::IsNullOrWhiteSpace($checkId)) {
        throw "Register-CheckDefinition: definition is missing a required 'CheckId'."
    }

    $fnName = [string]$Definition['Function']
    if ([string]::IsNullOrWhiteSpace($fnName)) {
        throw "Register-CheckDefinition: check '$checkId' has no 'Function' specified."
    }

    $cmd = Get-Command -Name $fnName -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Register-CheckDefinition: check '$checkId' references function '$fnName', which could not be resolved."
    }

    $params = @{
        CheckId  = $checkId
        Category = [string]$Definition['Category']
        Service  = [string]$Definition['Service']
        Name     = [string]$Definition['Name']
        Function = $cmd.ScriptBlock   # store a ScriptBlock, never the string
    }
    if ($Definition.ContainsKey('DefaultSeverity') -and $Definition['DefaultSeverity']) { $params['DefaultSeverity'] = [string]$Definition['DefaultSeverity'] }
    if ($Definition.ContainsKey('RequiredModules') -and $null -ne $Definition['RequiredModules']) { $params['RequiredModules'] = [string[]]$Definition['RequiredModules'] }
    if ($Definition.ContainsKey('RequiredPerms')   -and $null -ne $Definition['RequiredPerms'])   { $params['RequiredPerms']   = [string[]]$Definition['RequiredPerms'] }
    if ($Definition.ContainsKey('Phase')       -and $Definition['Phase'])       { $params['Phase']       = [string]$Definition['Phase'] }
    if ($Definition.ContainsKey('Description') -and $Definition['Description']) { $params['Description'] = [string]$Definition['Description'] }

    Register-AuditCheck @params
}

function Get-AuditChecks {
    <#
    .SYNOPSIS
        Returns registered checks filtered by Category, Service, and/or Phase.
    .OUTPUTS
        Array of check registration objects.
    #>
    [CmdletBinding()]
    param(
        [string]$Category,
        [string]$Service,
        [string]$Phase
    )

    $checks = $script:State.CheckRegistry | Where-Object { $_.Enabled }

    if ($Category) {
        $checks = $checks | Where-Object { $_.Category -eq $Category }
    }
    if ($Service) {
        $checks = $checks | Where-Object { $_.Service -eq $Service }
    }
    if ($Phase) {
        $checks = $checks | Where-Object { $_.Phase -eq $Phase }
    }

    return @($checks)
}

function New-AzureMapFinding {
    <#
    .SYNOPSIS
        Builds a normalized finding object for audit checks.
    .DESCRIPTION
        Normalizes evidence, adds metadata, and ensures the finding schema
        is consistent across all checks.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("CRITICAL","HIGH","MEDIUM","LOW","INFO")]
        [Parameter(Mandatory)]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$Count = 0,
        [object]$Data,
        [string]$Service,
        [string]$Remediation,
        [hashtable]$Exclusions,
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceId,
        [string]$ResourceName,
        [hashtable]$Tags,
        [string]$Category,
        [string]$Provider,
        [string]$CheckId,
        [string]$CheckName,
        [string]$OutputType = "Finding",
        [string[]]$References = @(),
        [string]$ResourceType,
        [ValidateSet("", "PASS", "FAIL", "WARNING", "PARTIAL", "NOTEVALUATED", "NOTAPPLICABLE", "ERROR", "SKIPPED")]
        [string]$Status = "",
        [guid]$FindingId = (New-Guid),

        # ---- Phase B1 coverage / reporting metadata (all optional) ----
        # Counts use [object] so $null ("unknown / not tracked") stays distinct
        # from 0 ("proven zero").
        [object]$DiscoveredResourceCount,
        [object]$EvaluatedResourceCount,
        [object]$SkippedResourceCount,
        [object]$FailedCollectionCount,
        [string[]]$SubscriptionsEvaluated = @(),
        [string[]]$SubscriptionsSkipped   = @(),
        # Complete | Partial | Failed (collection outcome, not check verdict)
        [ValidateSet("", "Complete", "Partial", "Failed")]
        [string]$CollectionStatus = "",
        [bool]$CompleteEvaluation = $false,
        [bool]$PartialEvaluation  = $false,
        [string]$CoverageSummary,
        [string]$SummaryText,
        [string]$TechnicalSummary,
        [ValidateSet("", "High", "Medium", "Low")]
        [string]$Confidence = "",
        [string]$FindingType,
        [string[]]$ApiSources = @(),
        [bool]$DataPlaneRequired        = $false,
        [bool]$ManualValidationRequired = $false,
        # Severity calibration: why this severity was chosen, and whether the
        # record is inventory/context only (never fails a check by itself).
        [string]$SeverityReason,
        [bool]$IsInventoryOnly = $false
    )

    if (-not $CheckId -and $script:State.CurrentCheck) {
        $CheckId = $script:State.CurrentCheck.CheckId
    }
    if (-not $CheckName -and $script:State.CurrentCheck) {
        $CheckName = $script:State.CurrentCheck.Name
    }
    if (-not $Category -and $script:State.CurrentCheck) {
        $Category = $script:State.CurrentCheck.Category
    }
    if (-not $Provider -and $script:State.CurrentCheck) {
        $Provider = $script:State.CurrentCheck.Provider
    }
    if (-not $Provider) {
        $Provider = $Category
    }

    $evidenceCount = 0
    $evidenceData  = @()

    # Normalize $Data to a plain object[] WITHOUT ever evaluating it in a boolean
    # context or via @($Data). Many checks accumulate findings in a
    # System.Collections.Generic.List[object] and pass it raw as -Data; under Windows
    # PowerShell 5.1, coercing a raw generic List in "$Count -gt 0 -and $Data" or
    # "@($Data)" throws "Argument types do not match" (only when the list is non-empty,
    # which is why empty/PASS checks never hit it). Enumerate explicitly so the finding
    # schema is identical whether a check passes a List, an array, a scalar, or $null.
    $normalizedList = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Data) {
        if ($Data -is [string]) {
            [void]$normalizedList.Add($Data)
        }
        elseif ($Data -is [System.Collections.IEnumerable]) {
            foreach ($item in $Data) { [void]$normalizedList.Add($item) }
        }
        else {
            [void]$normalizedList.Add($Data)
        }
    }
    $normalizedData = $normalizedList.ToArray()
    $evidenceCount  = $normalizedData.Count

    if ($Count -gt 0 -and $evidenceCount -gt 0) {
        $maxEvidence = 1000

        if ($evidenceCount -gt $maxEvidence) {
            Write-AuditLog -Message "Capping evidence for finding '$Message': $evidenceCount -> $maxEvidence" -Level WARN
            $prioritizedData = $normalizedData | Sort-Object @{ Expression = {
                $priority = 999
                if ($_.PSObject.Properties.Name -contains 'Severity') {
                    $priority = switch ($_.Severity) {
                        'CRITICAL' { 1 }
                        'HIGH'     { 2 }
                        'MEDIUM'   { 3 }
                        'LOW'      { 4 }
                        default    { 999 }
                    }
                }
                elseif ($_.PSObject.Properties.Name -contains 'RoleDefinitionName') {
                    $priority = switch ($_.RoleDefinitionName) {
                        { $_ -in @('Owner','User Access Administrator','Privileged Role Administrator') } { 1 }
                        { $_ -in @('Contributor','Key Vault Contributor') } { 2 }
                        default { 999 }
                    }
                }
                $priority
            }} | Select-Object -First $maxEvidence

            $evidenceData = $prioritizedData | ForEach-Object {
                if ($_ -is [PSCustomObject] -or $_ -is [System.Management.Automation.PSObject]) {
                    try {
                        $_ | Add-Member -NotePropertyName '_Truncated' -NotePropertyValue "True (showing $maxEvidence of $evidenceCount)" -Force -ErrorAction SilentlyContinue
                        $_
                    }
                    catch {
                        $_ | Select-Object *, @{ Name = '_Truncated'; Expression = { "True (showing $maxEvidence of $evidenceCount)" } }
                    }
                }
                else {
                    [PSCustomObject]@{
                        Value      = $_
                        _Truncated = "True (showing $maxEvidence of $evidenceCount)"
                    }
                }
            }
        }
        else {
            $evidenceData = $normalizedData
        }
    }

    return [PSCustomObject]@{
        FindingId       = $FindingId
        Timestamp       = Get-Date
        CheckId         = $CheckId
        CheckName       = $CheckName
        Category        = $Category
        Provider        = $Provider
        Service         = $Service
        OutputType      = $OutputType
        Severity        = $Severity
        Finding         = $Message
        Count           = $Count
        EvidenceCount   = $evidenceCount
        References      = @($References)
        Status          = if ($Status) { $Status } else { if ($Count -gt 0) { 'FAIL' } else { 'PASS' } }
        SubscriptionId  = $SubscriptionId
        SubscriptionName = $SubscriptionName
        ResourceType    = $ResourceType
        ResourceId      = $ResourceId
        ResourceName    = $ResourceName
        Tags            = $Tags
        Remediation     = $Remediation
        Evidence        = $evidenceData
        # Phase B1 coverage / reporting metadata
        DiscoveredResourceCount = $DiscoveredResourceCount
        EvaluatedResourceCount  = $EvaluatedResourceCount
        SkippedResourceCount    = $SkippedResourceCount
        FailedCollectionCount   = $FailedCollectionCount
        SubscriptionsEvaluated  = @($SubscriptionsEvaluated)
        SubscriptionsSkipped    = @($SubscriptionsSkipped)
        CollectionStatus        = $CollectionStatus
        CompleteEvaluation      = $CompleteEvaluation
        PartialEvaluation       = $PartialEvaluation
        CoverageSummary         = $CoverageSummary
        SummaryText             = $SummaryText
        TechnicalSummary        = $TechnicalSummary
        Confidence              = $Confidence
        FindingType             = $FindingType
        SeverityReason          = $SeverityReason
        IsInventoryOnly         = $IsInventoryOnly
        ApiSources              = @($ApiSources)
        DataPlaneRequired       = $DataPlaneRequired
        ManualValidationRequired = $ManualValidationRequired
    }
}

function Test-AzureMapExclusion {
    <#
    .SYNOPSIS
        Alias to Test-Exclusion for AzureMap exclusion evaluation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Finding,

        [Parameter(Mandatory)]
        [hashtable]$Exclusions
    )

    return Test-Exclusion -Finding $Finding -Exclusions $Exclusions
}

#endregion

#region --- Write-Finding (migrated from original lines 872-1014) ---

function Write-Finding {
    <#
    .SYNOPSIS
        Creates a structured finding object and adds it to $script:State.Results.
    .DESCRIPTION
        Applies severity filter, normalizes evidence data, caps evidence at 1000
        items with priority-based sorting, checks exclusions, and writes
        color-coded console output.
    .PARAMETER Severity
        CRITICAL, HIGH, MEDIUM, LOW, or INFO.
    .PARAMETER Message
        Finding description.
    .PARAMETER Count
        Number of affected resources (0 = PASS).
    .PARAMETER Data
        Evidence data (array or single object).
    .PARAMETER Service
        Service category for the finding.
    .PARAMETER Remediation
        Recommended remediation text.
    .PARAMETER Exclusions
        Exclusion hashtable (or uses $script:State.Exclusions if omitted).
    .PARAMETER SubscriptionId
    .PARAMETER SubscriptionName
    .PARAMETER ResourceId
    .PARAMETER ResourceName
    .PARAMETER Tags
    .PARAMETER Category
    .PARAMETER Provider
    .PARAMETER CheckId
    .PARAMETER CheckName
    .PARAMETER ResourceType
    .PARAMETER References
    .PARAMETER FindingId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("CRITICAL","HIGH","MEDIUM","LOW","INFO")]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Message,

        [int]$Count = 0,
        [object]$Data,
        [string]$Service,
        [string]$Remediation,
        [hashtable]$Exclusions,
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceId,
        [string]$ResourceName,
        [hashtable]$Tags,
        [string]$Category,
        [string]$Provider,
        [string]$CheckId,
        [string]$CheckName,
        [string]$ResourceType,
        [string[]]$References = @(),
        [ValidateSet("", "PASS", "FAIL", "WARNING", "PARTIAL", "NOTEVALUATED", "NOTAPPLICABLE", "ERROR", "SKIPPED")]
        [string]$Status = "",
        [guid]$FindingId = (New-Guid),

        # ---- Phase B1 coverage / reporting metadata (passed through to
        # New-AzureMapFinding; see there for semantics) ----
        [object]$DiscoveredResourceCount,
        [object]$EvaluatedResourceCount,
        [object]$SkippedResourceCount,
        [object]$FailedCollectionCount,
        [string[]]$SubscriptionsEvaluated = @(),
        [string[]]$SubscriptionsSkipped   = @(),
        [ValidateSet("", "Complete", "Partial", "Failed")]
        [string]$CollectionStatus = "",
        [bool]$CompleteEvaluation = $false,
        [bool]$PartialEvaluation  = $false,
        [string]$CoverageSummary,
        [string]$SummaryText,
        [string]$TechnicalSummary,
        [ValidateSet("", "High", "Medium", "Low")]
        [string]$Confidence = "",
        [string]$FindingType,
        [string[]]$ApiSources = @(),
        [bool]$DataPlaneRequired        = $false,
        [bool]$ManualValidationRequired = $false,
        # Severity calibration: why this severity was chosen, and whether the
        # record is inventory/context only (never fails a check by itself).
        [string]$SeverityReason,
        [bool]$IsInventoryOnly = $false
    )

    if (-not $Exclusions) {
        $Exclusions = $script:State.Exclusions
    }

    $sevLevel = $script:State.Config.SeverityLevel
    if ($sevLevel -eq "CriticalOnly" -and $Severity -ne "CRITICAL") {
        return
    }
    if ($sevLevel -eq "HighAndAbove" -and @("MEDIUM","LOW","INFO") -contains $Severity) {
        return
    }

    $finding = New-AzureMapFinding -Severity $Severity -Message $Message -Count $Count -Data $Data -Service $Service `
        -Remediation $Remediation -Exclusions $Exclusions -SubscriptionId $SubscriptionId `
        -SubscriptionName $SubscriptionName -ResourceId $ResourceId -ResourceName $ResourceName `
        -Tags $Tags -Category $Category -Provider $Provider -CheckId $CheckId `
        -CheckName $CheckName -ResourceType $ResourceType -References $References -Status $Status -FindingId $FindingId `
        -DiscoveredResourceCount $DiscoveredResourceCount -EvaluatedResourceCount $EvaluatedResourceCount `
        -SkippedResourceCount $SkippedResourceCount -FailedCollectionCount $FailedCollectionCount `
        -SubscriptionsEvaluated $SubscriptionsEvaluated -SubscriptionsSkipped $SubscriptionsSkipped `
        -CollectionStatus $CollectionStatus -CompleteEvaluation $CompleteEvaluation -PartialEvaluation $PartialEvaluation `
        -CoverageSummary $CoverageSummary -SummaryText $SummaryText -TechnicalSummary $TechnicalSummary `
        -Confidence $Confidence -FindingType $FindingType -ApiSources $ApiSources `
        -DataPlaneRequired $DataPlaneRequired -ManualValidationRequired $ManualValidationRequired `
        -SeverityReason $SeverityReason -IsInventoryOnly $IsInventoryOnly

    if (Test-AzureMapExclusion -Finding $finding -Exclusions $Exclusions) {
        Write-Verbose "Finding excluded: $Message (ID: $FindingId)"
        return
    }

    $script:State.Results.Add($finding)

    if ($script:State.Config.Quiet) { return }

    # Clean default console: per-finding blocks are strictly opt-in via
    # -ShowFindings / -ShowRemediation. -VerboseOutput adds timestamped log
    # lines and all per-check rows, but NEVER raw finding blocks - the grouped
    # per-check status lines and the sectioned summary (Show-AuditConsole) are
    # the run output; every record is preserved in the CSV/JSON/HTML exports
    # and the log regardless. Never dump raw evidence objects to the console.
    if (-not ($script:State.Config.ShowFindings -or $script:State.Config.ShowRemediation)) { return }

    # Count=0 records are quiet by default - even under -VerboseOutput - except
    # NOTEVALUATED/ERROR, which are signal (evaluation was not proven). PASS and
    # PARTIAL Count=0 records are coverage records: they are still recorded in
    # $script:State.Results (exports unchanged) and surface in the per-check
    # "Check Results" summary, not as per-finding blocks. A green checkmark next
    # to a CRITICAL Count=0 record reads as a finding - it must not print.
    $statusUpper = "$Status".ToUpper()
    $isQuietPass = ($Count -le 0) -and ($statusUpper -notin @('NOTEVALUATED','ERROR'))
    if ($isQuietPass -and -not $script:State.Config.DebugOutput) { return }

    # Verbose finding-block dedupe: the same CheckId+Severity+Message often repeats
    # per subscription/resource. Print the block once, note the first repeat, and
    # keep further repeats in the exports only. Every record is still added to
    # $script:State.Results above - this only affects console rendering.
    $seenKey = "$CheckId|$Severity|$Message"
    if ($script:State.FindingConsoleSeen.ContainsKey($seenKey)) {
        $script:State.FindingConsoleSeen[$seenKey] = [int]$script:State.FindingConsoleSeen[$seenKey] + 1
        if ([int]$script:State.FindingConsoleSeen[$seenKey] -eq 2) {
            Write-Host "   [i] Identical finding repeated (further repeats suppressed on console - all instances are in the CSV/JSON/HTML exports)" -ForegroundColor DarkGray
        }
        return
    }
    $script:State.FindingConsoleSeen[$seenKey] = 1

    switch ($Severity.ToUpper()) {
        "CRITICAL" { $Color = "Red" }
        "HIGH"     { $Color = "Red" }
        "MEDIUM"   { $Color = "Yellow" }
        "LOW"      { $Color = "Green" }
        "INFO"     { $Color = "Gray" }
        default    { $Color = "White" }
    }

    $icon = if ($Count -gt 0) { $script:State.CrossMark }
            elseif ($statusUpper -in @('NOTEVALUATED','ERROR')) { '!' }
            else { $script:State.CheckMark }

    Write-Host "`n[$icon] Severity: $Severity" -ForegroundColor $Color
    Write-Host "   Finding: $Message" -ForegroundColor $Color
    Write-Host "   Count: $Count" -ForegroundColor $Color

    # Remediation text (often raw cmdlet snippets) is never printed in normal
    # or verbose output; it lives in the HTML/JSON/CSV exports and the log,
    # and reaches the console only behind the explicit -ShowRemediation flag.
    if (-not [string]::IsNullOrEmpty($Remediation) -and $script:State.Config.ShowRemediation) {
        Write-Host "   Remediation: $Remediation" -ForegroundColor $Color
    }
}

function Get-SubscriptionRBACAssignments {
    <#
    .SYNOPSIS
        Fetches (and caches) RBAC assignments scoped to a subscription.
    .OUTPUTS
        Array of role assignment objects.
    #>
    [CmdletBinding()]
    param(
        # Accept [object] and coerce, so a raw subscription object/array can never
        # cause a parameter-transformation or "Key cannot be null" failure.
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$SubscriptionId,

        [object]$SubscriptionName,
        [switch]$ForceRefresh
    )

    $SubscriptionId   = ConvertTo-ScalarString $SubscriptionId
    $SubscriptionName = ConvertTo-ScalarString $SubscriptionName

    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        Write-AuditLog -Message "Get-SubscriptionRBACAssignments called without a resolvable subscription id; returning no assignments." -Level WARN
        return @()
    }

    if (-not $ForceRefresh -and $script:State.Cache.RBACAssignments.ContainsKey($SubscriptionId)) {
        return $script:State.Cache.RBACAssignments[$SubscriptionId]
    }

    Write-AuditLog -Message "Fetching RBAC assignments for subscription $SubscriptionName (scoped to subscription)" -Level DEBUG

    if (-not $script:State.Cache.ContainsKey('RBACUnavailable')) {
        $script:State.Cache.RBACUnavailable = @{}
    }

    try {
        # RBAC ASSIGNMENTS come from ARM (Microsoft.Authorization/roleAssignments).
        # Get-AzRoleAssignment additionally enriches each assignment with the principal's
        # DisplayName/SignInName via Microsoft Graph. Under Azure-only (-SkipEntra) that
        # enrichment fails with "MicrosoftGraphEndpointResourceId" auth errors. Using
        # -ErrorAction SilentlyContinue (NOT Stop) keeps that enrichment failure
        # NON-terminating, so the ARM assignment data is still returned and the error is
        # not promoted/re-logged per subscription. -Critical is removed so there is no
        # auth retry loop. This is the fix for the repeated Graph auth spam.
        $assignments = Invoke-AzureCommand -Command {
            Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } -CommandName "Get-RoleAssignments-Scoped" -SkipContextCheck

        $assignments = @($assignments)
        $script:State.Cache.RBACAssignments[$SubscriptionId] = $assignments
        $script:State.Cache.RBACUnavailable[$SubscriptionId] = $false

        Write-AuditLog -Message "Cached $($assignments.Count) RBAC assignments for subscription $SubscriptionName" -Level DEBUG
        return $assignments
    }
    catch {
        # A THROWN (terminating) error means the ARM RBAC read itself failed - typically a
        # Graph/Authentication error surfaced under Azure-only. Mark the subscription's RBAC
        # as unavailable so callers emit ONE clean NotEvaluated (never a misleading PASS),
        # and never call Connect-AzAccount. A single WARN line per subscription, no spam.
        Write-AuditLog -Message "RBAC could not be evaluated for subscription ${SubscriptionName} (Azure RBAC read unavailable under current auth); marked NotEvaluated." -Level WARN
        $script:State.Cache.RBACAssignments[$SubscriptionId] = @()
        $script:State.Cache.RBACUnavailable[$SubscriptionId] = $true
        return @()
    }
}

#endregion

#region --- Subscription normalization ---

function ConvertTo-ScalarString {
    <#
    .SYNOPSIS
        Coerces any value to a single scalar string (or $null).
    .DESCRIPTION
        Defensive helper so a subscription id/name is never bound as a collection or
        object into a string context. Handles: plain string (returned as-is), a
        single-/multi-element collection (unwrapped to one element), or an object that
        carries an Id/SubscriptionId property (that value is used). This prevents the
        "Cannot process argument transformation on parameter 'SubscriptionId'. Cannot
        convert value to type System.String" failure when a raw subscription object or
        array reaches a string parameter.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    # Unwrap collections (but not strings, which are IEnumerable[char]).
    if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
        $arr = @($Value | Where-Object { $null -ne $_ })
        if ($arr.Count -eq 0) { return $null }
        $Value = $arr[0]
        if ($null -eq $Value) { return $null }
    }

    # If an object slipped through, prefer its Id / SubscriptionId.
    if (($Value -isnot [string]) -and $Value.PSObject) {
        $pn = @($Value.PSObject.Properties.Name)
        if (($pn -contains 'Id') -and $Value.Id)                          { return [string]$Value.Id }
        elseif (($pn -contains 'SubscriptionId') -and $Value.SubscriptionId) { return [string]$Value.SubscriptionId }
    }

    return [string]$Value
}

function ConvertTo-AzureMapSubscription {
    <#
    .SYNOPSIS
        Normalizes subscription input into a consistent shape for all checks.
    .DESCRIPTION
        Every PerSubscription check reads $sub.Id and $sub.Name. Depending on how
        subscriptions were discovered, the raw objects differ:
          - Get-AzSubscription -> PSAzureSubscription with .Id, .Name, .TenantId
          - Get-AzContext      -> PSAzureContext with .Subscription.Id/.Name and .Tenant.Id
        This helper maps both shapes to a uniform object:
          { Id; Name; TenantId; SubscriptionId }
        (SubscriptionId is an alias of Id, kept so existing exclusion logic that
        references .SubscriptionId does not fault under Set-StrictMode.)
        If an object matches neither shape it throws a clear error so preflight
        fails before any checks run - never silently producing objects without Id.
    .PARAMETER InputObject
        One or more raw subscription/context objects.
    .OUTPUTS
        Array of [PSCustomObject] with Id, Name, TenantId, SubscriptionId.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$InputObject
    )

    $normalized = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $InputObject) {
        if ($null -eq $item) { continue }

        $props    = @($item.PSObject.Properties.Name)
        $id       = $null
        $name     = $null
        $tenantId = $null

        if (($props -contains 'Id') -and $item.Id) {
            # Get-AzSubscription shape (scalarize defensively - .Id must be a string)
            $id   = ConvertTo-ScalarString $item.Id
            $name = if ($props -contains 'Name') { ConvertTo-ScalarString $item.Name } else { $null }
            if ($props -contains 'TenantId') { $tenantId = ConvertTo-ScalarString $item.TenantId }
        }
        elseif (($props -contains 'Subscription') -and $item.Subscription) {
            # Get-AzContext shape
            $sub  = $item.Subscription
            $id   = ConvertTo-ScalarString $sub.Id
            $name = ConvertTo-ScalarString $sub.Name
            if (($props -contains 'Tenant') -and $item.Tenant) { $tenantId = ConvertTo-ScalarString $item.Tenant.Id }
        }

        if ([string]::IsNullOrWhiteSpace($id) -or [string]::IsNullOrWhiteSpace($name)) {
            throw "ConvertTo-AzureMapSubscription: subscription input does not match a supported shape. Expected Get-AzSubscription (.Id/.Name) or Get-AzContext (.Subscription.Id/.Subscription.Name)."
        }

        $normalized.Add([PSCustomObject]@{
            Id             = $id
            Name           = $name
            TenantId       = $tenantId
            SubscriptionId = $id
        })
    }

    # Return the array WITHOUT a unary comma: in Windows PowerShell 5.1 a
    # "return ,$array" consumed by the caller's @() nests into a single-element
    # array ([ [subs] ]), which makes every check iterate the whole array as one
    # $sub. Emitting the elements lets the caller's @() build a flat array.
    return $normalized.ToArray()
}

function Set-SubscriptionContext {
    <#
    .SYNOPSIS
        Switches the local PowerShell Az session to the given subscription.
    .DESCRIPTION
        Read-only, local-session operation. Uses Set-AzContext only to change which
        subscription subsequent Get-* calls target. It never signs in
        (no Connect-AzAccount) and never modifies any Azure resource. Returns $true
        on success and $false on failure (it does not throw, so a single failed
        subscription simply causes the caller to skip that subscription).
    .PARAMETER SubscriptionId
        Subscription id to switch to (from a normalized subscription's .Id).
    .PARAMETER SubscriptionName
        Friendly name, used only for the failure warning.
    .PARAMETER TenantId
        Optional tenant id (from a normalized subscription's .TenantId).
    .OUTPUTS
        [bool] $true if the context was switched, otherwise $false.
    #>
    [CmdletBinding()]
    param(
        # Accept [object] (not [string]) so a raw subscription object or a
        # single-element collection can never trigger a parameter-transformation
        # failure; the value is coerced to a scalar string below.
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$SubscriptionId,

        [object]$SubscriptionName,

        [object]$TenantId
    )

    $SubscriptionId   = ConvertTo-ScalarString $SubscriptionId
    $SubscriptionName = ConvertTo-ScalarString $SubscriptionName
    $TenantId         = ConvertTo-ScalarString $TenantId

    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        Write-AuditLog -Message "Set-SubscriptionContext called without a resolvable subscription id; skipping this subscription." -Level WARN
        return $false
    }

    try {
        $ctxParams = @{
            SubscriptionId = $SubscriptionId
            ErrorAction    = 'Stop'
        }
        if ($TenantId) { $ctxParams['TenantId'] = $TenantId }

        # Local session context switch only (no sign-in, no resource change).
        $null = Set-AzContext @ctxParams
        return $true
    }
    catch {
        # Clean warning by name only - never emit the subscription id or tenant id.
        $label = if ($SubscriptionName) { "subscription '$SubscriptionName'" } else { "the target subscription" }
        Write-AuditLog -Message "Unable to switch Azure session context to $label; skipping its checks." -Level WARN
        return $false
    }
}

#endregion

#region --- Tenant-wide data (migrated from original lines 758-822) ---

function Get-TenantWideData {
    <#
    .SYNOPSIS
        Fetches tenant-wide identity data (applications, service principals) once.
    .DESCRIPTION
        Uses Az.Resources cmdlets (best effort). Warns when counts >= 1000
        indicating potential pagination limits.
    .OUTPUTS
        [hashtable] The TenantWideData structure.
    #>
    [CmdletBinding()]
    param(
        [switch]$ForceRefresh
    )

    # Azure-only mode: never perform Graph/AAD-backed tenant identity collection.
    # Returns the (empty) initialized structure so callers see no data and mark
    # tenant-dependent checks as NotEvaluated rather than triggering collection.
    if ($script:State.Config.SkipEntra) {
        Write-AuditLog -Message "SkipEntra set: not collecting tenant-wide identity data (Get-AzADApplication/Get-AzADServicePrincipal suppressed)." -Level INFO
        return $script:State.TenantWideData
    }

    if (-not $ForceRefresh -and $null -ne $script:State.TenantWideData.Applications) {
        return $script:State.TenantWideData
    }

    Write-AuditLog -Message "Fetching tenant-wide identity data (BEST EFFORT - Az.Resources may not return all objects)" -Level INFO

    try {
        $context = Get-AzContext
        if (-not $context) {
            throw "No Azure context available"
        }

        Write-AuditLog -Message "Fetching tenant applications (BEST EFFORT - may be incomplete in large tenants)" -Level INFO
        $allApps = @(Invoke-AzureCommand -Command {
            Get-AzADApplication -ErrorAction Stop
        } -CommandName "Get-TenantApplications" -SkipContextCheck -Critical)

        if ($allApps.Count -ge 1000) {
            Write-AuditLog -Message "WARNING: Fetched $($allApps.Count) applications. Results may be incomplete. For complete enumeration, use Microsoft Graph API." -Level WARN -ForceConsole
        }
        elseif ($allApps.Count -eq 0) {
            Write-AuditLog -Message "WARNING: No applications found. This may indicate pagination limits or insufficient permissions." -Level WARN
        }

        Write-AuditLog -Message "Fetching tenant service principals (BEST EFFORT - may be incomplete in large tenants)" -Level INFO
        $allSps = @(Invoke-AzureCommand -Command {
            Get-AzADServicePrincipal -ErrorAction Stop
        } -CommandName "Get-TenantServicePrincipals" -SkipContextCheck -Critical)

        if ($allSps.Count -ge 1000) {
            Write-AuditLog -Message "WARNING: Fetched $($allSps.Count) service principals. Results may be incomplete. For complete enumeration, use Microsoft Graph API." -Level WARN -ForceConsole
        }
        elseif ($allSps.Count -eq 0) {
            Write-AuditLog -Message "WARNING: No service principals found. This may indicate pagination limits or insufficient permissions." -Level WARN
        }

        $script:State.TenantWideData = @{
            Applications      = $allApps
            ServicePrincipals = $allSps
            TenantId          = $context.Tenant.Id
            FetchedAt         = Get-Date
        }

        Write-AuditLog -Message "Fetched $($allApps.Count) applications and $($allSps.Count) service principals" -Level INFO
    }
    catch {
        Write-AuditLog -Message "Failed to fetch tenant-wide identity data: $_" -Level ERROR
        $script:State.TenantWideData = @{
            Applications      = @()
            ServicePrincipals = @()
            TenantId          = $null
            FetchedAt         = Get-Date
        }
    }

    return $script:State.TenantWideData
}

#endregion

#region --- Orchestration Engine ---

function Get-CheckFunctionParameterName {
    <#
    .SYNOPSIS
        Returns the declared parameter names of a check function.
    .DESCRIPTION
        Works whether the function is stored as a [scriptblock] (the normal case,
        produced by Register-AuditCheck) or a CommandInfo. ScriptBlocks do not
        expose a .Parameters collection, so the parameter names are read from the
        AST param block.
    .OUTPUTS
        [string[]] parameter names (empty array if none / not introspectable).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Function
    )

    $names = [System.Collections.Generic.List[string]]::new()
    try {
        if ($Function -is [System.Management.Automation.CommandInfo]) {
            foreach ($k in $Function.Parameters.Keys) { $names.Add([string]$k) }
        }
        elseif ($Function -is [scriptblock]) {
            $ast = $Function.Ast
            $paramBlock = $null
            if ($ast) {
                if (($ast.PSObject.Properties.Name -contains 'ParamBlock') -and $ast.ParamBlock) {
                    $paramBlock = $ast.ParamBlock
                }
                elseif (($ast.PSObject.Properties.Name -contains 'Body') -and $ast.Body -and $ast.Body.ParamBlock) {
                    $paramBlock = $ast.Body.ParamBlock
                }
            }
            if ($paramBlock) {
                foreach ($p in $paramBlock.Parameters) {
                    $names.Add([string]$p.Name.VariablePath.UserPath)
                }
            }
        }
    }
    catch {
        # Non-introspectable function: return whatever we have (possibly empty).
    }

    return ,$names.ToArray()
}

function Invoke-AzureMapCheck {
    <#
    .SYNOPSIS
        Executes a single registered audit check and captures execution metadata.
    .PARAMETER Check
        The registered check object from the registry.
    .PARAMETER Subscriptions
        Array of subscriptions for PerSubscription checks.
    .PARAMETER Exclusions
        Exclusion rules to pass through to the check.
    .PARAMETER Services
        Service filter list.
    .PARAMETER SkipEntra
        Skip Entra checks when present.
    .PARAMETER EntraOnly
        Run only Entra checks when present.
    .PARAMETER ProgressId
        Progress bar id.
    .OUTPUTS
        [bool] $true when the check executed or was skipped safely.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Check,

        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [string[]]$Services,
        [switch]$SkipEntra,
        [switch]$EntraOnly,
        [int]$ProgressId = 1
    )

    if ($SkipEntra -and $Check.Category -eq 'Entra') {
        return $true
    }
    if ($EntraOnly -and $Check.Category -ne 'Entra') {
        return $true
    }

    if ($Services -and $Services -notcontains 'All' -and $Check.Service -notin $Services) {
        return $true
    }

    foreach ($mod in $Check.RequiredModules) {
        if (-not (Get-Module -Name $mod -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-AuditLog -Message "Skipping check $($Check.CheckId): required module '$mod' not installed" -Level WARN
            return $true
        }
    }

    if ($Check.Category -eq 'Entra' -and $Check.RequiredPerms.Count -gt 0) {
        try {
            $scopeResult = Test-GraphTokenScopes -RequiredScopes $Check.RequiredPerms
            if (-not $scopeResult.IsValid) {
                Write-AuditLog -Message "Graph token missing required scopes for $($Check.CheckId): $($scopeResult.MissingScopes -join ', ')" -Level WARN
            }
        }
        catch {
            Write-AuditLog -Message "Unable to validate Graph scopes for $($Check.CheckId): $_" -Level WARN
        }
    }

    # Determine the check function's declared parameters robustly. Checks are stored
    # as ScriptBlocks (Register-AuditCheck resolves the function name to .ScriptBlock),
    # and a [scriptblock] does NOT expose a .Parameters member - so the previous
    # ".Function.Parameters.Name" test always returned nothing and no arguments were
    # forwarded. Introspect via the AST instead (works for ScriptBlock and CommandInfo).
    $paramNames  = Get-CheckFunctionParameterName -Function $Check.Function

    # Forwarding contract:
    #   * A check declaring [array]$Subscriptions (the common case) receives the whole
    #     normalized array once and loops internally (unchanged behavior).
    #   * A check declaring a singular -Subscription / -SubscriptionId / -SubscriptionName
    #     is dispatched once PER normalized subscription, receiving TYPED values:
    #       -SubscriptionId   -> scalar string ($sub.Id)   (never a PSCustomObject/array)
    #       -SubscriptionName -> scalar string ($sub.Name)
    #       -Subscription     -> the normalized subscription object
    $wantsPlural = $paramNames -contains 'Subscriptions'
    $wantsPerSub = (-not $wantsPlural) -and (
        ($paramNames -contains 'Subscription') -or
        ($paramNames -contains 'SubscriptionId') -or
        ($paramNames -contains 'SubscriptionName')
    )

    $previousCheck = $null
    if ($script:State.ContainsKey('CurrentCheck')) {
        $previousCheck = $script:State.CurrentCheck
    }
    $script:State.CurrentCheck = $Check

    try {
        if ($wantsPerSub) {
            foreach ($sub in @($Subscriptions)) {
                $p = [ordered]@{}
                if ($paramNames -contains 'Subscription')     { $p['Subscription']     = $sub }
                if ($paramNames -contains 'SubscriptionId')   { $p['SubscriptionId']   = ConvertTo-ScalarString $sub.Id }
                if ($paramNames -contains 'SubscriptionName') { $p['SubscriptionName'] = ConvertTo-ScalarString $sub.Name }
                if ($paramNames -contains 'Exclusions')       { $p['Exclusions']       = $Exclusions }
                if ($paramNames -contains 'ProgressId')       { $p['ProgressId']       = $ProgressId }
                if ($paramNames -contains 'UseGraphBeta')     { $p['UseGraphBeta']     = $script:State.Config.UseGraphBeta }
                & $Check.Function @p
            }
        }
        else {
            $checkParams = [ordered]@{}
            if ($paramNames -contains 'Subscriptions') { $checkParams['Subscriptions'] = $Subscriptions }
            if ($paramNames -contains 'Exclusions')    { $checkParams['Exclusions']    = $Exclusions }
            if ($paramNames -contains 'ProgressId')    { $checkParams['ProgressId']    = $ProgressId }
            if ($paramNames -contains 'UseGraphBeta')  { $checkParams['UseGraphBeta']  = $script:State.Config.UseGraphBeta }
            & $Check.Function @checkParams
        }
        return $true
    }
    finally {
        $script:State.CurrentCheck = $previousCheck
    }
}

function Invoke-AuditChecks {
    <#
    .SYNOPSIS
        Orchestration engine that iterates the check registry and executes checks.
    .DESCRIPTION
        Filters by phase, service, and tenant mode; validates module availability
        and logs execution metadata to $script:State.ExecutedChecks.
    .PARAMETER Phase
        Run only checks matching this phase.
    .PARAMETER Subscriptions
        Array of subscription objects for PerSubscription checks.
    .PARAMETER Exclusions
        Exclusion hashtable passed to each check.
    .PARAMETER Services
        Service filter list.
    .PARAMETER SkipEntra
        Skip Entra checks.
    .PARAMETER EntraOnly
        Run only Entra checks.
    .PARAMETER ProgressId
        Progress bar id.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("PerSubscription","TenantWide")]
        [string]$Phase,

        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [string[]]$Services,
        [switch]$SkipEntra,
        [switch]$EntraOnly,
        [int]$ProgressId = 1
    )

    if (-not $Phase) {
        # Global numbering across both phases for the per-check CLI status line.
        # Entra/Azure checks excluded by mode stay in the list: they are recorded
        # as Skipped (intentional operator choice) instead of vanishing silently.
        $all = @(Get-AuditChecks)
        if ($Services -and $Services -notcontains 'All') { $all = @($all | Where-Object { $_.Service -in $Services }) }
        $script:State.CheckRunIndex = 0
        $script:State.CheckRunTotal = $all.Count
        $script:State['LastCheckDomain'] = $null

        Invoke-AuditChecks -Phase TenantWide -Subscriptions $Subscriptions -Exclusions $Exclusions -Services $Services -SkipEntra:$SkipEntra -EntraOnly:$EntraOnly -ProgressId $ProgressId
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions $Subscriptions -Exclusions $Exclusions -Services $Services -SkipEntra:$SkipEntra -EntraOnly:$EntraOnly -ProgressId $ProgressId
        return
    }

    $checks = Get-AuditChecks -Phase $Phase

    if ($Services -and $Services -notcontains 'All') {
        $checks = $checks | Where-Object { $_.Service -in $Services }
    }

    # Execute in domain order so the grouped CLI output (Identity, Key Vault,
    # Storage, ...) prints each section contiguously. Checks are independent,
    # so execution order within a phase carries no functional meaning.
    $checks = @($checks | Sort-Object @{ Expression = { Get-CheckDomainSortIndex -Check $_ } }, @{ Expression = { "$($_.CheckId)" } })

    $total = ($checks | Measure-Object).Count
    $index = 0

    if ($Phase -eq 'PerSubscription' -and (-not $Subscriptions -or $Subscriptions.Count -eq 0)) {
        Write-AuditLog -Message "No subscriptions provided for PerSubscription checks; skipping phase." -Level WARN
        return
    }

    foreach ($check in $checks) {
        $index++
        $pctComplete = [int](($index / [Math]::Max($total, 1)) * 100)

        if ($ProgressId -gt 0) {
            Write-Progress -Activity "AzureMap Security Audit" `
                -Status "[$index/$total] $($check.Name)" `
                -PercentComplete $pctComplete `
                -Id $ProgressId
        }

        $rec = New-CheckExecutionRecord -Check $check -Phase $Phase

        # Mode skip: Entra checks under -SkipEntra (and Azure checks under
        # -EntraOnly) are an intentional operator choice, not a failure. Record
        # them as Skipped with a clear reason so CLI/exports show the decision.
        if (($SkipEntra -and $check.Category -eq 'Entra') -or ($EntraOnly -and $check.Category -ne 'Entra')) {
            $rec.Status      = 'Skipped'
            $rec.Detail      = if ($check.Category -eq 'Entra') { 'Entra checks disabled by -SkipEntra' } else { 'Azure checks disabled by -EntraOnly' }
            $rec.CompletedAt = Get-Date
            $script:State.ExecutedChecks.Add($rec)
            $script:State.CheckRunIndex++
            $lineIdx = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunIndex } else { $index }
            $lineTot = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunTotal } else { $total }
            Write-CheckStatusLine -Index $lineIdx -Total $lineTot -Check $check -Record $rec
            continue
        }

        # Skip cleanly when a required module is unavailable (records Skipped, not Pass).
        $missingModules = @($check.RequiredModules | Where-Object {
            $_ -and -not (Get-Module -Name $_ -ListAvailable -ErrorAction SilentlyContinue)
        })
        if ($missingModules.Count -gt 0) {
            $rec.Status      = 'Skipped'
            $rec.Detail      = "Required module(s) not installed: $($missingModules -join ', ')"
            $rec.CompletedAt = Get-Date
            $script:State.ExecutedChecks.Add($rec)
            Write-AuditLog -Message "Skipping check $($check.CheckId): $($rec.Detail)" -Level WARN
            $script:State.CheckRunIndex++
            $lineIdx = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunIndex } else { $index }
            $lineTot = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunTotal } else { $total }
            Write-CheckStatusLine -Index $lineIdx -Total $lineTot -Check $check -Record $rec
            continue
        }

        # Applicability gate: when the environment footprint proves none of the
        # check's resource types exist in scope, record NotApplicable (truthful
        # "nothing to check") instead of running the check into a misleading
        # NotEvaluated/empty result. Unknown footprint -> check runs as before.
        $applic = Get-CheckApplicability -Check $check
        if (-not $applic.Applicable) {
            $rec.Status      = 'NotApplicable'
            $rec.Detail      = $applic.Reason
            $rec.CompletedAt = Get-Date
            $script:State.ExecutedChecks.Add($rec)
            $script:State.CheckRunIndex++
            $lineIdx = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunIndex } else { $index }
            $lineTot = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunTotal } else { $total }
            Write-CheckStatusLine -Index $lineIdx -Total $lineTot -Check $check -Record $rec
            continue
        }

        # Phase B3 data-plane gate: checks flagged RequiresDataPlane (STORAGE-004,
        # KEYVAULT-003) never run unless the operator explicitly passed
        # -IncludeDataPlane. AzureMap is safely read-only (ARM control plane) by
        # default. Recorded as Skipped with a human reason; the row is shown in
        # normal output (unlike mode/module skips) because it changes coverage
        # semantics for relevant, in-scope resources.
        if ($check.RequiresDataPlane -and -not $script:State.Config.IncludeDataPlane) {
            $rec.Status      = 'Skipped'
            $rec.Detail      = 'Data-plane checks disabled'
            $rec.CompletedAt = Get-Date
            $script:State.ExecutedChecks.Add($rec)
            Write-AuditLog -Message "Skipping check $($check.CheckId): requires data-plane access; -IncludeDataPlane not set." -Level INFO
            $script:State.CheckRunIndex++
            $lineIdx = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunIndex } else { $index }
            $lineTot = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunTotal } else { $total }
            Write-CheckStatusLine -Index $lineIdx -Total $lineTot -Check $check -Record $rec
            continue
        }

        $findingsBefore = $script:State.Results.Count
        $produced = @()
        $script:State.CurrentCheckId = "$($check.CheckId)"
        try {
            Write-AuditLog -Message "Running check $($check.CheckId): $($check.Name)" -Level DEBUG

            $null = Invoke-AzureMapCheck -Check $check -Subscriptions $Subscriptions -Exclusions $Exclusions -Services $Services -SkipEntra:$SkipEntra -EntraOnly:$EntraOnly -ProgressId $ProgressId

            if ($script:State.Results.Count -gt $findingsBefore) {
                $produced = @($script:State.Results[$findingsBefore..($script:State.Results.Count - 1)])
            }
            $rec.Status = Resolve-CheckStatus -ProducedFindings $produced

            # Phase B1: aggregate coverage metadata and a one-line summary onto the
            # execution record so CLI/HTML/JSON can report proven coverage per check.
            $rec.Coverage = Get-CheckCoverage -Findings $produced
            $rec.SummaryText = $null
            foreach ($pf in $produced) {
                if (($pf.PSObject.Properties.Name -contains 'SummaryText') -and $pf.SummaryText) {
                    $rec.SummaryText = [string]$pf.SummaryText
                    break
                }
            }
            if (-not $rec.SummaryText -and $rec.Coverage -and $rec.Coverage.Summary) {
                $rec.SummaryText = [string]$rec.Coverage.Summary
            }
            # "Could not check" rows must carry a human reason: when the check
            # produced NotEvaluated records, surface the first one's message
            # (e.g. "Az.EventHub cmdlet unavailable") as the CLI summary.
            if (-not $rec.SummaryText -and -not $rec.Detail -and $rec.Status -eq 'NotEvaluated') {
                $ne = @($produced | Where-Object { "$($_.Status)" -eq 'NotEvaluated' -and $_.Finding })
                if ($ne.Count -gt 0) {
                    $rec.SummaryText = ("$($ne[0].Finding)" -replace '\s*\r?\n\s*', ' ').Trim()
                }
            }
        }
        catch {
            $rec.Status = 'Error'
            $rec.Detail = $_.Exception.Message
            # Capture the script stack trace so the exact throwing line is recorded
            # in the exported record (JSON) and log - this is diagnostic surfacing,
            # NOT error suppression. The error still marks the check as Error.
            if ($_.PSObject.Properties.Name -contains 'ScriptStackTrace') {
                $rec.StackTrace = [string]$_.ScriptStackTrace
            }
            try { $rec.ErrorClass = (Get-ErrorClass -ErrorRecord $_).Class } catch { $rec.ErrorClass = 'Unknown' }
            Write-AuditLog -Message "Check $($check.CheckId) failed [$($rec.ErrorClass)]: $($_.Exception.Message)" -Level ERROR
            if ($rec.StackTrace) {
                Write-AuditLog -Message "Check $($check.CheckId) stack: $($rec.StackTrace -replace '\s*\r?\n\s*',' | ')" -Level ERROR
            }
        }
        finally {
            $rec.CompletedAt = Get-Date
            # Phase B1: an unresolved record is NOT a Pass. If execution ended without
            # a resolved status, the check proved nothing -> NotEvaluated.
            if ($rec.Status -eq 'Pending') {
                $rec.Status = 'NotEvaluated'
                if (-not $rec.Detail) { $rec.Detail = 'Check execution ended without producing a resolvable status.' }
            }
            # Legacy FAIL checks without an explicit summary still get a compact
            # affected-count line for CLI/exports.
            if (-not $rec.SummaryText -and $rec.Status -eq 'Fail') {
                $affected = 0
                foreach ($pf in $produced) { if ([int]$pf.Count -gt 0) { $affected += [int]$pf.Count } }
                if ($affected -gt 0) { $rec.SummaryText = "$affected affected" }
            }
            # Inventory checks: summarize how many items were captured so the row
            # reads "Inventory   70 public-facing items", never a bare Clean.
            if (-not $rec.SummaryText -and $rec.Status -eq 'Inventory') {
                $items = 0
                foreach ($pf in $produced) { if ([int]$pf.Count -gt 0) { $items += [int]$pf.Count } }
                if ($items -gt 0) {
                    $noun = if ("$($check.Service)" -eq 'Exposure') { 'public-facing items' } else { 'items inventoried' }
                    $rec.SummaryText = "{0} {1}" -f (Format-UiNumber $items), $noun
                }
            }
            # A check that found issues but could not evaluate part of its scope
            # must say so on the row itself, not just in the log. Two signals:
            # B1 coverage metadata (PartialEvaluation) or, for legacy checks
            # without coverage, aggregated collection errors/warnings bucketed
            # under this check while it ran.
            $cidForErrors = "$($check.CheckId)"
            $hadCollectionErrors = $script:State.CheckErrors -and $script:State.CheckErrors.ContainsKey($cidForErrors)
            if ($rec.Status -eq 'Fail' -and (($rec.Coverage -and $rec.Coverage.PartialEvaluation) -or $hadCollectionErrors)) {
                if (-not $rec.SummaryText) {
                    $rec.SummaryText = 'evaluation incomplete'
                }
                elseif ($rec.SummaryText -notmatch 'incomplete') {
                    $rec.SummaryText = "$($rec.SummaryText) · evaluation incomplete"
                }
            }
            $script:State.ExecutedChecks.Add($rec)

            # One compact per-check status line: the primary live CLI signal.
            $script:State.CheckRunIndex++
            $lineIdx = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunIndex } else { $index }
            $lineTot = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunTotal } else { $total }
            Write-CheckStatusLine -Index $lineIdx -Total $lineTot -Check $check -Record $rec

            # Summarized per-check errors: the status line already shows the most
            # frequent failure reason; add a single pointer to the log file that
            # holds full detail. No raw exception text floods the console.
            $cid = "$($check.CheckId)"
            if (-not $script:State.Config.Quiet -and $script:State.CheckErrors.ContainsKey($cid)) {
                $logLeaf = if ($script:State.LogFile) { Split-Path -Path $script:State.LogFile -Leaf } else { 'the log file' }
                Write-UiHost -Text ("    Details saved to {0}" -f $logLeaf) -Color DarkGray
            }
            $script:State.CurrentCheckId = $null
        }
    }

    if ($ProgressId -gt 0) {
        Write-Progress -Activity "AzureMap Security Audit" -Id $ProgressId -Completed
    }
}

#endregion
