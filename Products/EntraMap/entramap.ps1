<#
.SYNOPSIS
    Entra ID Security Audit Tool v2.0 (EntraMap)
.DESCRIPTION
    EntraMap scans an Entra ID tenant for security misconfigurations,
    excessive permissions, and credential hygiene gaps via Microsoft Graph
    (read-only). Results are exported to CSV, JSON, and HTML.

    Auth note: EntraMap needs an Az context as the token vehicle
    (Get-GraphToken rides on Get-AzAccessToken) but performs NO subscription
    discovery and NO ARM resource scanning.
.PARAMETER SeverityLevel
    Filter findings by severity threshold.
.PARAMETER Services
    Limit audit scope to specific Entra service areas.
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
.PARAMETER SkipModuleCheck
    Skip Azure PowerShell module dependency validation.
.PARAMETER UseGraphBeta
    Use the Microsoft Graph beta endpoint for Entra checks.
.PARAMETER ReportLayout
    HTML report layout: 'Classic' (default) or the opt-in 'Pentester'
    dashboard layout. JSON/CSV exports are unaffected.
#>
[CmdletBinding()]
param(
    [ValidateSet("CriticalOnly", "HighAndAbove", "All")]
    [string]$SeverityLevel = "All",

    [ValidateSet("EntraRoles", "EntraApps", "EntraGroups", "EntraOwnership",
                 "EntraOAuth", "EntraOverview", "EntraExternalCollab", "EntraPIM",
                 "EntraConditionalAccess", "EntraAuthMethods", "EntraBreakGlass",
                 "EntraWorkloadIdentity", "Identity",
                 "All")]
    [string[]]$Services = @("All"),

    [string]$ConfigPath,
    [string]$ExclusionPath,
    [switch]$Quiet,
    [switch]$SkipModuleCheck,
    [switch]$UseGraphBeta,
    [switch]$VerboseOutput,
    [switch]$DebugOutput,
    [switch]$ShowFindings,
    [switch]$ShowRemediation,
    [switch]$DetailedSummary,
    [switch]$NoColor,
    [switch]$RedactSensitive,
    [switch]$RedactPublicIps,

    [ValidateSet('Classic', 'Pentester')]
    [string]$ReportLayout = 'Classic'
)

# NOTE: Version 1.0 (not Latest). EntraMap uses PowerShell 7-style soft member
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
# dot-sources entramap.ps1 is not left modified.
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
# Az modules auto-load mid-run and emit host warnings that pollute the grouped
# check output. EntraMap does not consume the Warning stream; checks that care
# use -WarningAction explicitly.
$global:WarningPreference = 'SilentlyContinue'
# Any Invoke-WebRequest/Invoke-RestMethod anywhere in this process (including
# inside Az module scope) gets basic parsing: no IE DOM engine, no prompt.
if (-not $global:PSDefaultParameterValues) { $global:PSDefaultParameterValues = @{} }
$global:PSDefaultParameterValues['Invoke-WebRequest:UseBasicParsing'] = $true
$global:PSDefaultParameterValues['Invoke-RestMethod:UseBasicParsing'] = $true
# Az modules auto-load on first cmdlet use and print breaking-change warnings per
# module. Suppress them for this session only - no Az config is modified and no
# Azure resource is touched.
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

#region ---- Dot-source all modules ----

# Layout: this script lives in Products\EntraMap; the repo root is two levels
# up. Shared modules come from Shared\, product modules from this directory.
$scriptRoot = $PSScriptRoot
$repoRoot   = Split-Path -Path (Split-Path -Path $scriptRoot -Parent) -Parent

# Shared core modules (order matters: State first, then Logging, Config,
# Exclusions, rest)
. "$repoRoot\Shared\Core\State.ps1"
. "$repoRoot\Shared\Core\Logging.ps1"
. "$repoRoot\Shared\Core\Config.ps1"
. "$repoRoot\Shared\Core\Exclusions.ps1"

# Remaining shared core modules (Retry, Cache, CheckRegistry, Console, ...) plus
# the Entra product subtrees (Core, Capability). No AzureMap product code:
# EntraMap performs no subscription discovery or ARM scanning.
$alreadyLoaded = @("State.ps1", "Logging.ps1", "Config.ps1", "Exclusions.ps1")
foreach ($coreDir in @("$repoRoot\Shared\Core", "$scriptRoot\Core", "$scriptRoot\Capability")) {
    foreach ($coreFile in Get-ChildItem -Path "$coreDir\*.ps1" -File -ErrorAction SilentlyContinue) {
        if ($coreFile.Name -notin $alreadyLoaded) {
            . $coreFile.FullName
        }
    }
}

# Entra check modules (includes the relocated tenant-identity checks)
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
    # 1. Initialize state (Entra product slots only)
    $script:State = Initialize-EntraAuditState
    $script:State.Config.SeverityLevel = $SeverityLevel
    $script:State.Config.Services      = $Services
    $script:State.Config.Quiet         = $Quiet.IsPresent
    $script:State.Config.UseGraphBeta  = $UseGraphBeta.IsPresent
    $script:State.Config.VerboseOutput = $VerboseOutput.IsPresent
    $script:State.Config.DebugOutput   = $DebugOutput.IsPresent
    $script:State.Config.ShowFindings    = $ShowFindings.IsPresent
    $script:State.Config.ShowRemediation = $ShowRemediation.IsPresent
    $script:State.Config.DetailedSummary = $DetailedSummary.IsPresent
    $script:State.Config.NoColor       = $NoColor.IsPresent
    $script:State.Config.RedactSensitive = $RedactSensitive.IsPresent
    $script:State.Config.RedactPublicIps = $RedactPublicIps.IsPresent
    $script:State.Config.ReportLayout  = $ReportLayout
    if ($DebugOutput) { $DebugPreference = 'Continue' }

    # 2. Banner
    Show-Banner -SeverityLevel $SeverityLevel -Services $Services

    # 3. Module dependency check (Az.Accounts only - the token vehicle)
    if (-not $SkipModuleCheck) {
        $modulesOk = Test-AzureModuleDependency
        if (-not $modulesOk) {
            Write-AuditLog -Message "Required modules are missing. Exiting." -Level ERROR -ForceConsole
            return
        }
    }

    # 4. Load configuration & exclusions
    Load-Configuration -ConfigPath $ConfigPath
    $exclusions = Load-Exclusions -ExclusionPath $ExclusionPath

    # 5. Authentication preflight (read-only; NEVER calls Connect-AzAccount).
    #    Graph token required; ARM context optional (token vehicle only).
    $preflight = Test-EntraAuthPreflight

    if ($preflight.Guidance -and -not $script:State.Config.Quiet) {
        Write-Host ""
        foreach ($line in ($preflight.Guidance -split "`n")) { Write-Host $line -ForegroundColor Yellow }
        Write-Host ""
    }

    if ($preflight.ShouldStop) {
        Write-AuditLog -Message "Stopping before checks due to authentication preflight (see guidance above)." -Level WARN -ForceConsole
        return
    }

    # Resolved assessment scope (mode/tenant/account/Graph access) now that
    # preflight has run. EntraMap product variant of Show-RunContext.
    Show-EntraAssessmentScope

    # 6. Register all Entra checks (ENTRA-01..12 + relocated IDENTITY-001/002/004).
    #    Entra register functions RETURN hashtable definitions (they do not call
    #    Register-AuditCheck themselves). Capture and register each definition.
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

    # 6.5 Tenant discovery (read-only Graph metadata, per-dimension degradation).
    #     Runs BEFORE the assessment so the operator sees the tenant shape and
    #     any permission-limited dimensions up front. Cached in
    #     $script:State.EntraFootprint; never written to disk.
    if (-not $script:State.Config.Quiet) { Write-UiHost -Text "Discovering tenant..." -Color Cyan }
    $phaseStart = Get-Date
    $script:State.EntraFootprint = Build-EntraFootprint
    Show-EntraFootprint -Footprint $script:State.EntraFootprint
    $script:State.Timing.Phases['Discovery'] = [Math]::Round(((Get-Date) - $phaseStart).TotalSeconds, 1)
    if (-not $script:State.Config.Quiet) {
        $phaseElapsed = (Get-Date) - $phaseStart
        Write-UiHost -Text ("  Discovery completed in {0}m {1}s" -f [int]$phaseElapsed.TotalMinutes, $phaseElapsed.Seconds) -Color DarkGray
        Write-UiHost -Text ''
    }

    # 6.6 Assessment plan: how many registered checks are relevant vs filtered
    #     or limited by missing Graph permissions.
    Show-AssessmentPlan -Services $Services

    # 7. Collection phase (Graph token, Entra collection, tenant-wide identity).
    if (-not $script:State.Config.Quiet) { Write-UiHost -Text "Collecting data..." -Color Cyan }
    $phaseStart = Get-Date
    Invoke-AzureMapCollection -UseGraphBeta:$UseGraphBeta
    $script:State.Timing.Phases['Collection'] = [Math]::Round(((Get-Date) - $phaseStart).TotalSeconds, 1)
    if (-not $script:State.Config.Quiet) {
        $phaseElapsed = (Get-Date) - $phaseStart
        Write-UiHost -Text ("  Collection completed in {0}m {1}s" -f [int]$phaseElapsed.TotalMinutes, $phaseElapsed.Seconds) -Color DarkGray
    }

    # 8. Execution phase (tenant-wide checks only - no subscription scope).
    if (Get-Command -Name "Invoke-AuditChecks" -ErrorAction SilentlyContinue) {
        if (-not $script:State.Config.Quiet) {
            Write-UiHost -Text "Running assessment" -Color Cyan
        }
        $phaseStart = Get-Date
        Invoke-AuditChecks -Phase TenantWide -Subscriptions @() -Exclusions $exclusions -Services $Services
        $script:State.Timing.Phases['Assessment'] = [Math]::Round(((Get-Date) - $phaseStart).TotalSeconds, 1)
        if (-not $script:State.Config.Quiet) {
            $phaseElapsed = (Get-Date) - $phaseStart
            Write-UiHost -Text ''
            Write-UiHost -Text ("  Assessment completed in {0}m {1}s ({2} checks)" -f [int]$phaseElapsed.TotalMinutes, $phaseElapsed.Seconds, $script:State.ExecutedChecks.Count) -Color DarkGray
        }
    } else {
        Write-AuditLog -Message "Invoke-AuditChecks not found; check execution skipped." -Level WARN
    }

    # 8.5 Capability modeling: build the Entra capability model from the
    #     already-collected findings/state (read-only modeling, no Graph calls).
    if (Get-Command -Name "Build-EntraCapabilityModel" -ErrorAction SilentlyContinue) {
        $capStart = Get-Date
        $script:State.CapabilityModel = Build-EntraCapabilityModel
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
