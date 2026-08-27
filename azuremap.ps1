<#
.SYNOPSIS
    Azure Security & Entra ID Audit Tool v2.0
.DESCRIPTION
    AzureMap scans Azure subscriptions and Entra ID tenants for security
    misconfigurations, excessive permissions, and compliance gaps.
    Results are exported to CSV, JSON, and HTML.
.PARAMETER SeverityLevel
    Filter findings by severity threshold.
.PARAMETER Services
    Limit audit scope to specific service areas.
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
    Skip all Entra ID checks.
.PARAMETER EntraOnly
    Run only Entra ID checks (skip Azure subscription checks).
.PARAMETER UseGraphBeta
    Use the Microsoft Graph beta endpoint for Entra checks.
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
    [switch]$UseGraphBeta,
    [switch]$ContinueWithoutEntra,
    [switch]$VerboseOutput,
    [switch]$DebugOutput,
    [switch]$ShowFindings,
    [switch]$ShowRemediation,
    [switch]$DetailedSummary,
    [switch]$IncludeDataPlane,
    [switch]$NoColor,
    [switch]$RedactSensitive,
    [switch]$RedactPublicIps
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

$scriptRoot = $PSScriptRoot

# Core modules (order matters: State first, then Logging, Config, Exclusions, rest)
. "$scriptRoot\Core\State.ps1"
. "$scriptRoot\Core\Logging.ps1"
. "$scriptRoot\Core\Config.ps1"
. "$scriptRoot\Core\Exclusions.ps1"

# Remaining Core modules (Retry, Graph, ResourceGraph, Cache, CheckRegistry)
foreach ($coreFile in Get-ChildItem -Path "$scriptRoot\Core\*.ps1" -File) {
    $alreadyLoaded = @("State.ps1", "Logging.ps1", "Config.ps1", "Exclusions.ps1")
    if ($coreFile.Name -notin $alreadyLoaded) {
        . $coreFile.FullName
    }
}

# Azure check modules
foreach ($checkFile in Get-ChildItem -Path "$scriptRoot\Checks\Azure\*.ps1" -File -ErrorAction SilentlyContinue) {
    . $checkFile.FullName
}

# Entra check modules
foreach ($checkFile in Get-ChildItem -Path "$scriptRoot\Checks\Entra\*.ps1" -File -ErrorAction SilentlyContinue) {
    . $checkFile.FullName
}

# Export modules
foreach ($exportFile in Get-ChildItem -Path "$scriptRoot\Export\*.ps1" -File) {
    . $exportFile.FullName
}

#endregion

#region ---- Main execution ----

try {
    # 1. Initialize state
    $script:State = Initialize-AuditState
    $script:State.Config.SeverityLevel = $SeverityLevel
    $script:State.Config.Services      = $Services
    $script:State.Config.Quiet         = $Quiet.IsPresent
    $script:State.Config.UseGraphBeta  = $UseGraphBeta.IsPresent
    $script:State.Config.SkipEntra     = $SkipEntra.IsPresent
    $script:State.Config.VerboseOutput = $VerboseOutput.IsPresent
    $script:State.Config.DebugOutput   = $DebugOutput.IsPresent
    $script:State.Config.ShowFindings    = $ShowFindings.IsPresent
    $script:State.Config.ShowRemediation = $ShowRemediation.IsPresent
    $script:State.Config.DetailedSummary = $DetailedSummary.IsPresent
    $script:State.Config.IncludeDataPlane = $IncludeDataPlane.IsPresent
    $script:State.Config.NoColor       = $NoColor.IsPresent
    $script:State.Config.RedactSensitive = $RedactSensitive.IsPresent
    $script:State.Config.RedactPublicIps = $RedactPublicIps.IsPresent
    if ($DebugOutput) { $DebugPreference = 'Continue' }

    # 2. Banner
    Show-Banner -SeverityLevel $SeverityLevel -Services $Services

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

    # 5. Authentication preflight (read-only; NEVER calls Connect-AzAccount)
    $preflight = Test-AuthenticationPreflight -SkipEntra:$SkipEntra -EntraOnly:$EntraOnly -ContinueWithoutEntra:$ContinueWithoutEntra

    if ($preflight.Guidance -and -not $script:State.Config.Quiet) {
        Write-Host ""
        foreach ($line in ($preflight.Guidance -split "`n")) { Write-Host $line -ForegroundColor Yellow }
        Write-Host ""
    }

    if ($preflight.ShouldStop) {
        Write-AuditLog -Message "Stopping before checks due to authentication preflight (see guidance above)." -Level WARN -ForceConsole
        return
    }

    # Resolve effective scope: Azure-only when Entra was skipped OR Graph auth was
    # unavailable and -ContinueWithoutEntra was used. This single flag drives the
    # collection gating and marks Entra/tenant-dependent checks NotEvaluated.
    $script:State.Config.SkipEntra = -not $preflight.EntraInScope
    $azureOnly = [bool]$script:State.Config.SkipEntra

    # Resolved run context (mode/account/tenant) now that preflight has run.
    Show-RunContext

    # 6. Register all checks
    foreach ($regFunc in Get-Command -Name "Register-Azure*Checks" -ErrorAction SilentlyContinue) {
        & $regFunc.Name
    }
    # Entra register functions RETURN hashtable definitions (they do not call
    # Register-AuditCheck themselves). Capture and register each definition.
    foreach ($regFunc in Get-Command -Name "Register-Entra*Checks" -ErrorAction SilentlyContinue) {
        $entraDefs = & $regFunc.Name
        foreach ($def in @($entraDefs)) {
            if ($def -is [hashtable]) {
                try {
                    Register-CheckDefinition -Definition $def
                }
                catch {
                    Write-AuditLog -Message "Entra check registration failed: $($_.Exception.Message)" -Level ERROR -ForceConsole
                }
            }
        }
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

    # Hard stop: without any usable Azure subscription (and not Entra-only) there
    # is nothing to audit. Stop cleanly instead of running zero-scope checks and
    # emitting an empty, misleading report.
    $scopeGuard = Test-AzureSubscriptionScope -Subscriptions $subscriptions -EntraOnly:$EntraOnly
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
    if ($subscriptions.Count -gt 0 -and -not $EntraOnly) {
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
    #     environment vs skipped by mode / filtered / not in scope.
    Show-AssessmentPlan -SkipEntra:$azureOnly -EntraOnly:$EntraOnly -Services $Services

    # 8. Collection phase
    #    Graph token, Entra collection, and tenant-wide identity collection are all
    #    gated on the resolved Azure-only scope inside Invoke-AzureMapCollection.
    if (-not $script:State.Config.Quiet) { Write-UiHost -Text "Collecting data..." -Color Cyan }
    $phaseStart = Get-Date
    Invoke-AzureMapCollection -SkipEntra:$azureOnly -EntraOnly:$EntraOnly -UseGraphBeta:$UseGraphBeta
    $script:State.Timing.Phases['Collection'] = [Math]::Round(((Get-Date) - $phaseStart).TotalSeconds, 1)
    if (-not $script:State.Config.Quiet) {
        $phaseElapsed = (Get-Date) - $phaseStart
        Write-UiHost -Text ("  Collection completed in {0}m {1}s" -f [int]$phaseElapsed.TotalMinutes, $phaseElapsed.Seconds) -Color DarkGray
    }

    # 9. Execution phase
    if (Get-Command -Name "Invoke-AuditChecks" -ErrorAction SilentlyContinue) {
        if (-not $script:State.Config.Quiet) {
            Write-UiHost -Text "Running assessment" -Color Cyan
        }
        $phaseStart = Get-Date
        $auditParams = @{
            Subscriptions = $subscriptions
            Exclusions    = $exclusions
            Services      = $Services
        }
        if ($azureOnly)  { $auditParams["SkipEntra"]  = $true }
        if ($EntraOnly)  { $auditParams["EntraOnly"]  = $true }
        Invoke-AuditChecks @auditParams
        $script:State.Timing.Phases['Assessment'] = [Math]::Round(((Get-Date) - $phaseStart).TotalSeconds, 1)
        if (-not $script:State.Config.Quiet) {
            $phaseElapsed = (Get-Date) - $phaseStart
            Write-UiHost -Text ''
            Write-UiHost -Text ("  Assessment completed in {0}m {1}s ({2} checks)" -f [int]$phaseElapsed.TotalMinutes, $phaseElapsed.Seconds, $script:State.ExecutedChecks.Count) -Color DarkGray
        }
    } else {
        Write-AuditLog -Message "Invoke-AuditChecks not found; check execution skipped." -Level WARN
    }

    # 10. Report phase
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

#endregion
