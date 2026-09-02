#==============================================================================
# AzureMap v2 - Core/CheckRegistry.ps1
# Check registration, filtering, finding creation, orchestration engine,
# orchestration engine.
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

function Resolve-CheckApplicability {
    <#
    .SYNOPSIS
        Product-safe applicability wrapper around Get-CheckApplicability.
    .DESCRIPTION
        Get-CheckApplicability lives in Core/Azure/Footprint.ps1, which only the
        AzureMap composition loads. EntraMap has no resource-type footprint, so
        when the function is absent every check stays applicable (fail-open,
        same as an unproven footprint). AzureMap behavior is identical: the
        real Get-CheckApplicability is used whenever it is loaded.
    .OUTPUTS
        [pscustomobject] @{ Applicable = [bool]; Reason = [string] }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Check)

    if (Get-Command -Name 'Get-CheckApplicability' -ErrorAction SilentlyContinue) {
        return Get-CheckApplicability -Check $Check
    }
    return [PSCustomObject]@{ Applicable = $true; Reason = '' }
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
        # What Count actually enumerates (count semantics standardization).
        # UniqueResources = distinct resources; Containers / RoleAssignments =
        # sub-resource collections; RiskSignals = individual risk observations
        # (one resource may contribute several); Observations = informational
        # notes; NotEvaluatedItems = items that could NOT be evaluated (never
        # counted as affected). Adding a property is schema-safe; renaming is not.
        [ValidateSet("", "UniqueResources", "Containers", "RoleAssignments", "RiskSignals", "Observations", "NotEvaluatedItems")]
        [string]$CountType = "UniqueResources",
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
        CountType       = $CountType
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
        [ValidateSet("", "UniqueResources", "Containers", "RoleAssignments", "RiskSignals", "Observations", "NotEvaluatedItems")]
        [string]$CountType = "UniqueResources",
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

    $finding = New-AzureMapFinding -Severity $Severity -Message $Message -Count $Count -CountType $CountType -Data $Data -Service $Service `
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

    # Graph scope check only when the Entra modules are loaded (azuremap.ps1 is
    # ARM-only after the product split; the guard makes this a safe no-op there).
    if ($Check.Category -eq 'Entra' -and $Check.RequiredPerms.Count -gt 0 -and
        (Get-Command -Name 'Test-GraphTokenScopes' -ErrorAction SilentlyContinue)) {
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
            Complete-CheckExecutionRecord -Record $rec
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
            Complete-CheckExecutionRecord -Record $rec
            $script:State.ExecutedChecks.Add($rec)
            Write-AuditLog -Message "Skipping check $($check.CheckId): $($rec.Detail)" -Level WARN
            $script:State.CheckRunIndex++
            $lineIdx = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunIndex } else { $index }
            $lineTot = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunTotal } else { $total }
            Write-CheckStatusLine -Index $lineIdx -Total $lineTot -Check $check -Record $rec
            continue
        }

        # Graph permission gate (EntraMap): when the token's granted scopes
        # decoded successfully and a check requires scopes that are missing,
        # record "Could not check" with the missing permission names instead of
        # running it into raw Graph errors or a misleading empty result.
        # Fail-open when scopes cannot be determined (undecodable/opaque token).
        if ($check.Category -eq 'Entra' -and @($check.RequiredPerms).Count -gt 0 -and
            (Get-Command -Name 'Get-GraphTokenScopeInfo' -ErrorAction SilentlyContinue)) {
            $scopeInfo = Get-GraphTokenScopeInfo
            if ($scopeInfo.DecodeSucceeded) {
                $grantedScopes = @($scopeInfo.GrantedScopes)
                $missingPerms = @($check.RequiredPerms | Where-Object { $_ -and ($_ -notin $grantedScopes) })
                if ($missingPerms.Count -gt 0) {
                    $rec.Status      = 'NotEvaluated'
                    $rec.Detail      = "Missing Graph permission(s): $($missingPerms -join ', ')"
                    Complete-CheckExecutionRecord -Record $rec
                    $script:State.ExecutedChecks.Add($rec)
                    Write-AuditLog -Message "Check $($check.CheckId) not evaluated: $($rec.Detail)" -Level WARN
                    $script:State.CheckRunIndex++
                    $lineIdx = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunIndex } else { $index }
                    $lineTot = if ($script:State.CheckRunTotal -gt 0) { $script:State.CheckRunTotal } else { $total }
                    Write-CheckStatusLine -Index $lineIdx -Total $lineTot -Check $check -Record $rec
                    continue
                }
            }
        }

        # Applicability gate: when the environment footprint proves none of the
        # check's resource types exist in scope, record NotApplicable (truthful
        # "nothing to check") instead of running the check into a misleading
        # NotEvaluated/empty result. Unknown footprint -> check runs as before.
        $applic = Resolve-CheckApplicability -Check $check
        if (-not $applic.Applicable) {
            $rec.Status      = 'NotApplicable'
            $rec.Detail      = $applic.Reason
            Complete-CheckExecutionRecord -Record $rec
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
            Complete-CheckExecutionRecord -Record $rec
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
            Complete-CheckExecutionRecord -Record $rec
            Write-AuditLog -Message ("Check {0} finished in {1:n1}s (status: {2})" -f $check.CheckId, $rec.DurationSeconds, $rec.Status) -Level DEBUG
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
