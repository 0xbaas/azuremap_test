<#
.SYNOPSIS
    Azure Security Audit Tool v2.0 (AzureMap)
.DESCRIPTION
    AzureMap scans Azure subscriptions for security misconfigurations,
    excessive permissions, and compliance gaps on the ARM control plane
    (read-only; no Microsoft Graph required). Results are exported to CSV,
    JSON, and HTML. EntraMap (Entra ID tenant audits) is parked for a future
    phase under Future/EntraMap.
.PARAMETER SeverityLevel
    Filter findings by severity threshold.
.PARAMETER Services
    Limit audit scope to specific service areas. The ValidateSet still
    accepts the Entra service names for CLI compatibility; they simply
    match zero checks here (Entra checks live in EntraMap, parked under
    Future/EntraMap).
.PARAMETER ConfigPath
    Path to an optional JSON configuration override file.
.PARAMETER ExclusionPath
    Path to an optional JSON exclusion/baseline file.
.PARAMETER Quiet
    Suppress console output (logs still written to file).
.PARAMETER ShowFindings
    Print per-finding detail blocks during the run (normal CLI shows only
    the grouped per-check status lines).
.PARAMETER ShowRemediation
    Include remediation guidance in console finding blocks. Remediation is
    always preserved in the HTML/JSON/CSV exports and the log.
.PARAMETER DetailedSummary
    Show every check row (including Not in scope / Skipped) during the run
    and the full Check results section in the final summary.
.PARAMETER IncludeDataPlane
    Enable data-plane checks (STORAGE-004 anonymous blob access,
    KEYVAULT-003 secret expiry). Off by default: AzureMap is safely
    read-only on the ARM control plane unless this switch is given.
    Even when enabled, only safe metadata is read - never secret values,
    keys, SAS tokens, connection strings, or blob/file content.
.PARAMETER SkipModuleCheck
    Skip Azure PowerShell module dependency validation.
.PARAMETER SkipEntra
    DEPRECATED no-op: azuremap.ps1 is always Azure-only now (Entra checks
    live in EntraMap, parked under Future/EntraMap). Accepted for CLI
    compatibility.
.PARAMETER EntraOnly
    DEPRECATED: prints a note that EntraMap is parked for a future phase
    (Future/EntraMap) and stops before any Azure work.
.PARAMETER ReportLayout
    HTML report layout: 'Pentester' (default) dashboard layout or the legacy
    'Classic' layout. JSON/CSV exports are unaffected.
#>
[CmdletBinding()]
param(
    [ValidateSet("CriticalOnly", "HighAndAbove", "All")]
    [string]$SeverityLevel = "All",

    [ValidateSet("Storage", "SQL", "AKS", "KeyVault", "Network", "Compute", "Identity",
                 "ContainerRegistry", "CosmosDB", "EventHub", "ServiceBus", "APIM",
                 "Synapse", "Automation", "Monitoring", "Diagnostics", "PublicIP",
                 "Exfiltration", "AppService", "LogicApp",
                 "EntraRoles", "EntraApps", "EntraGroups", "EntraOwnership",
                 "EntraOAuth", "EntraOverview", "EntraExternalCollab", "EntraPIM",
                 "All")]
    [string[]]$Services = @("All"),

    [string]$ConfigPath,
    [string]$ExclusionPath,
    [switch]$Quiet,
    [switch]$SkipModuleCheck,
    [switch]$SkipEntra,
    [switch]$EntraOnly,
    [switch]$VerboseOutput,
    [switch]$DebugOutput,
    [switch]$ShowFindings,
    [switch]$ShowRemediation,
    [switch]$DetailedSummary,
    [switch]$IncludeDataPlane,
    [switch]$NoColor,
    [switch]$RedactSensitive,
    [switch]$RedactPublicIps,

    [ValidateSet('Classic', 'Pentester')]
    [string]$ReportLayout = 'Pentester'
)

# NOTE: Version 1.0 (not Latest). AzureMap uses PowerShell 7-style soft member
# access throughout (reading optional properties on Az/Graph objects, hashtable
# keys, and finding fields). Under Windows PowerShell 5.1, StrictMode Latest throws
# on any missing member, which crashes checks on 5.1. Version 1.0 still catches
# uninitialized variables but permits soft member access (absent members read as $null).
Set-StrictMode -Version 1.0
$ErrorActionPreference = "Stop"

# --- Windows PowerShell 5.1 hardening ---
# These are set at GLOBAL scope on purpose: Az modules auto-load mid-run and run
# code (module autoload warnings, any internal web call) in module session
# state, which does NOT reliably inherit script-scoped preference variables.
# Global scope makes the hardening airtight for the whole process. The previous
# values are restored in the finally block so an interactive session that
# dot-sources azuremap.ps1 is not left modified.
$script:PrevWarningPreference   = $global:WarningPreference
$script:PrevProgressPreference  = $global:ProgressPreference
$script:PrevIwrParsing  = $null
$script:PrevIrmParsing  = $null
if ($global:PSDefaultParameterValues) {
    if ($global:PSDefaultParameterValues.ContainsKey('Invoke-WebRequest:UseBasicParsing')) { $script:PrevIwrParsing = $global:PSDefaultParameterValues['Invoke-WebRequest:UseBasicParsing'] }
    if ($global:PSDefaultParameterValues.ContainsKey('Invoke-RestMethod:UseBasicParsing')) { $script:PrevIrmParsing = $global:PSDefaultParameterValues['Invoke-RestMethod:UseBasicParsing'] }
}
# Suppress the legacy Invoke-WebRequest "script execution risk" prompt and noisy
# progress bars so an unattended run never blocks on a confirmation prompt.
$global:ProgressPreference = 'SilentlyContinue'
# Az modules auto-load mid-run and emit host warnings (e.g. "unapproved verbs"
# for Az.Network) that pollute the grouped check output. AzureMap does not
# consume the Warning stream; checks that care use -WarningAction explicitly.
$global:WarningPreference = 'SilentlyContinue'
# Any Invoke-WebRequest/Invoke-RestMethod anywhere in this process (including
# inside Az module scope) gets basic parsing: no IE DOM engine, no prompt.
if (-not $global:PSDefaultParameterValues) { $global:PSDefaultParameterValues = @{} }
$global:PSDefaultParameterValues['Invoke-WebRequest:UseBasicParsing'] = $true
$global:PSDefaultParameterValues['Invoke-RestMethod:UseBasicParsing'] = $true
# Az modules auto-load on first cmdlet use and print breaking-change warnings per
# module (Az.Monitor etc.). Suppress them for this session only - no Az config is
# modified and no Azure resource is touched.
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

#region ---- Dot-source all modules ----

# Layout: this script lives in Products\AzureMap; the repo root is two levels
# up. Shared modules come from Shared\, product modules from this directory.
$scriptRoot = $PSScriptRoot
$repoRoot   = Split-Path -Path (Split-Path -Path $scriptRoot -Parent) -Parent

# Shared core modules (order matters: State first, then Logging, Config,
# Exclusions, rest)
. "$repoRoot\Shared\Core\State.ps1"
. "$repoRoot\Shared\Core\Logging.ps1"
. "$repoRoot\Shared\Core\Config.ps1"
. "$repoRoot\Shared\Core\Exclusions.ps1"

# Remaining shared core modules (Retry, Cache, CheckRegistry, ...) plus the
# Azure product subtrees (Core, Capability). No EntraMap product code:
# AzureMap is ARM-only and never acquires a Microsoft Graph token.
$alreadyLoaded = @("State.ps1", "Logging.ps1", "Config.ps1", "Exclusions.ps1")
foreach ($coreDir in @("$repoRoot\Shared\Core", "$scriptRoot\Core", "$scriptRoot\Capability")) {
    foreach ($coreFile in Get-ChildItem -Path "$coreDir\*.ps1" -File -ErrorAction SilentlyContinue) {
        if ($coreFile.Name -notin $alreadyLoaded) {
            . $coreFile.FullName
        }
    }
}

# Azure check modules
foreach ($checkFile in Get-ChildItem -Path "$scriptRoot\Checks\*.ps1" -File -ErrorAction SilentlyContinue) {
    . $checkFile.FullName
}

# Export modules
foreach ($exportFile in Get-ChildItem -Path "$repoRoot\Shared\Export\*.ps1" -File) {
    . $exportFile.FullName
}

#endregion

#region ---- Main execution ----

try {
    # 1. Initialize state (Azure product slots only)
    $script:State = Initialize-AzureAuditState
    $script:State.Config.SeverityLevel = $SeverityLevel
    $script:State.Config.Services      = $Services
    $script:State.Config.Quiet         = $Quiet.IsPresent
    $script:State.Config.VerboseOutput = $VerboseOutput.IsPresent
    $script:State.Config.DebugOutput   = $DebugOutput.IsPresent
    $script:State.Config.ShowFindings    = $ShowFindings.IsPresent
    $script:State.Config.ShowRemediation = $ShowRemediation.IsPresent
    $script:State.Config.DetailedSummary = $DetailedSummary.IsPresent
    $script:State.Config.IncludeDataPlane = $IncludeDataPlane.IsPresent
    $script:State.Config.NoColor       = $NoColor.IsPresent
    $script:State.Config.RedactSensitive = $RedactSensitive.IsPresent
    $script:State.Config.RedactPublicIps = $RedactPublicIps.IsPresent
    $script:State.Config.ReportLayout  = $ReportLayout
    if ($DebugOutput) { $DebugPreference = 'Continue' }

    # 2. Banner
    Show-AzureMapBanner -SeverityLevel $SeverityLevel -Services $Services

    # 2.5 Deprecated switches (migration path; no broken automation).
    #     -EntraOnly stops BEFORE any Azure work with guidance; -SkipEntra is a
    #     no-op because Azure-only is now the only mode of this entrypoint.
    if ($EntraOnly) {
        Write-AuditLog -Message "-EntraOnly is no longer supported by azuremap.ps1. EntraMap (Entra ID tenant audits) is parked for a future phase (Future/EntraMap) and is not part of the active workflow." -Level WARN -ForceConsole
        return
    }
    if ($SkipEntra) {
        Write-AuditLog -Message "-SkipEntra is deprecated and ignored: azuremap.ps1 is always Azure-only (Entra checks live in EntraMap, parked under Future/EntraMap)." -Level INFO -ForceConsole
    }

    # 3. Module dependency check
    if (-not $SkipModuleCheck) {
        $modulesOk = Test-AzureModuleDependency
        if (-not $modulesOk) {
            Write-AuditLog -Message "Required Azure modules are missing. Exiting." -Level ERROR -ForceConsole
            return
        }
    }

    # 4. Load configuration & exclusions
    Load-Configuration -ConfigPath $ConfigPath
    $exclusions = Load-Exclusions -ExclusionPath $ExclusionPath

    # 5. Authentication preflight (read-only; NEVER calls Connect-AzAccount,
    #    never probes Microsoft Graph).
    $preflight = Test-AzureAuthPreflight

    if ($preflight.Guidance -and -not $script:State.Config.Quiet) {
        Write-Host ""
        foreach ($line in ($preflight.Guidance -split "`n")) { Write-Host $line -ForegroundColor Yellow }
        Write-Host ""
    }

    if ($preflight.ShouldStop) {
        Write-AuditLog -Message "Stopping before checks due to authentication preflight (see guidance above)." -Level WARN -ForceConsole
        return
    }

    # Resolved run context (mode/account/tenant) now that preflight has run.
    Show-RunContext

    # 6. Register all Azure checks
    foreach ($regFunc in Get-Command -Name "Register-Azure*Checks" -ErrorAction SilentlyContinue) {
        & $regFunc.Name
    }

    # 7. Discover subscriptions
    #    Always use the tool's own discovery (Get-AzSubscription). Do NOT bind to a
    #    session-global 'Get-Subscriptions' - that is not a modular AzureMap function
    #    and, if a legacy/monolith copy is loaded in the session, it returns a
    #    different object shape that breaks per-subscription dispatch.
    $rawSubscriptions = @(Get-AzSubscription -ErrorAction SilentlyContinue)

    # Fallback: an identity may be denied tenant-wide subscription enumeration
    # (Get-AzSubscription returns nothing) yet still have a subscription selected in
    # the current Az context. Audit at least that one rather than silently skipping
    # every PerSubscription check (a common cause of an empty, misleading report).
    if ($rawSubscriptions.Count -eq 0) {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Subscription) {
            Write-AuditLog -Message "Get-AzSubscription returned no subscriptions; falling back to the current Az context subscription so PerSubscription checks still run." -Level WARN -ForceConsole
            $rawSubscriptions = @($ctx.Subscription)
        }
    }

    # Normalize to a uniform shape { Id; Name; TenantId; SubscriptionId } so every
    # PerSubscription check receives .Id and .Name regardless of source shape.
    # Throws a clear preflight error if the input matches no supported shape.
    $subscriptions = @(ConvertTo-AzureMapSubscription -InputObject $rawSubscriptions)

    # Hard stop: without any usable Azure subscription there is nothing to
    # audit. Stop cleanly instead of running zero-scope checks and emitting an
    # empty, misleading report.
    $scopeGuard = Test-AzureSubscriptionScope -Subscriptions $subscriptions
    if (-not $scopeGuard.Usable) {
        Write-AuditLog -Message $scopeGuard.Message -Level ERROR -ForceConsole
        Write-AuditLog -Message "Stopping before collection/check execution: no Azure scope to audit." -Level WARN -ForceConsole
        return
    }

    # Apply subscription exclusions
    if ($exclusions.Subscriptions.Count -gt 0) {
        $before = $subscriptions.Count
        $subscriptions = $subscriptions | Where-Object {
            $_.SubscriptionId -notin $exclusions.Subscriptions -and
            $_.Id             -notin $exclusions.Subscriptions
        }
        $excluded = $before - $subscriptions.Count
        if ($excluded -gt 0) {
            Write-AuditLog -Message "Excluded $excluded subscription(s) via exclusion rules" -Level INFO
        }
    }

    # 7.5 Environment footprint pre-scan (read-only; ARG preferred, Get-AzResource
    #     fallback). Drives check applicability (NotApplicable vs NotEvaluated).
    $script:State.Subscriptions = @($subscriptions)
    if ($subscriptions.Count -gt 0) {
        # Phase progress: discovery can take minutes on large scopes (especially
        # the Get-AzResource fallback); never let a long phase look frozen.
        if (-not $script:State.Config.Quiet) { Write-UiHost -Text "Discovering environment..." -Color Cyan }
        $phaseStart = Get-Date
        Write-AuditLog -Message "Building environment footprint (read-only)..." -Level INFO
        $script:State.Footprint = Get-EnvironmentFootprint -Subscriptions $subscriptions
        Show-EnvironmentFootprint -Footprint $script:State.Footprint
        if (-not $script:State.Config.Quiet) {
            $phaseElapsed = (Get-Date) - $phaseStart
            $script:State.Timing.Phases['Discovery'] = [Math]::Round($phaseElapsed.TotalSeconds, 1)
            Write-UiHost -Text ("  Discovery completed in {0}m {1}s" -f [int]$phaseElapsed.TotalMinutes, $phaseElapsed.Seconds) -Color DarkGray
        } else {
            $script:State.Timing.Phases['Discovery'] = [Math]::Round(((Get-Date) - $phaseStart).TotalSeconds, 1)
        }
    }

    # 7.6 Assessment plan: how many registered checks are relevant to this
    #     environment vs filtered / not in scope.
    Show-AssessmentPlan -Services $Services

    # 8. Execution phase (Azure collection is lazy, in-check; there is no
    #    separate collection phase in the Azure-only product).
    if (Get-Command -Name "Invoke-AuditChecks" -ErrorAction SilentlyContinue) {
        if (-not $script:State.Config.Quiet) {
            Write-UiHost -Text "Running assessment" -Color Cyan
        }
        $phaseStart = Get-Date
        Invoke-AuditChecks -Subscriptions $subscriptions -Exclusions $exclusions -Services $Services
        $script:State.Timing.Phases['Assessment'] = [Math]::Round(((Get-Date) - $phaseStart).TotalSeconds, 1)
        if (-not $script:State.Config.Quiet) {
            $phaseElapsed = (Get-Date) - $phaseStart
            Write-UiHost -Text ''
            Write-UiHost -Text ("  Assessment completed in {0}m {1}s ({2} checks)" -f [int]$phaseElapsed.TotalMinutes, $phaseElapsed.Seconds, $script:State.ExecutedChecks.Count) -Color DarkGray
        }
    } else {
        Write-AuditLog -Message "Invoke-AuditChecks not found; check execution skipped." -Level WARN
    }

    # 8.5 Capability modeling (Phase B2): read-only relationship modeling over
    #     already-collected findings, evidence and in-memory caches. Performs
    #     NO Azure/Graph API calls and never retrieves keys/secrets/tokens or
    #     content; failures degrade to a skipped builder, never a failed run.
    if (Get-Command -Name "Build-CapabilityModel" -ErrorAction SilentlyContinue) {
        $capStart = Get-Date
        $script:State.CapabilityModel = Build-CapabilityModel
        $script:State.Timing.Phases['CapabilityModel'] = [Math]::Round(((Get-Date) - $capStart).TotalSeconds, 1)
    }

    # 9. Report phase
    Show-AuditSummary
}
catch {
    if ($script:State) {
        Write-AuditLog -Message "Fatal error: $_" -Level ERROR -ForceConsole
        Write-AuditLog -Message "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    } else {
        Write-Error "Fatal error during initialization: $_"
    }
}
finally {
    if ($script:State) {
        Flush-AuditLog
        if (Get-Command -Name "Clear-AuditCache" -ErrorAction SilentlyContinue) {
            Clear-AuditCache
        }
    }
    # Restore the caller's global preferences (only matters when dot-sourced
    # into an interactive session; a -File process exits anyway).
    $global:WarningPreference  = $script:PrevWarningPreference
    $global:ProgressPreference = $script:PrevProgressPreference
    if ($global:PSDefaultParameterValues) {
        if ($null -ne $script:PrevIwrParsing) { $global:PSDefaultParameterValues['Invoke-WebRequest:UseBasicParsing'] = $script:PrevIwrParsing }
        else { $global:PSDefaultParameterValues.Remove('Invoke-WebRequest:UseBasicParsing') }
        if ($null -ne $script:PrevIrmParsing) { $global:PSDefaultParameterValues['Invoke-RestMethod:UseBasicParsing'] = $script:PrevIrmParsing }
        else { $global:PSDefaultParameterValues.Remove('Invoke-RestMethod:UseBasicParsing') }
    }
}
