<#
.SYNOPSIS
    Entra ID Security Audit Tool v2.0 (EntraMap) - repo-root entrypoint wrapper.
.DESCRIPTION
    Thin wrapper: forwards every parameter verbatim to the real product
    entrypoint at Products\EntraMap\entramap.ps1 (invoked as a script, so
    $PSScriptRoot inside it resolves to its real location and an early
    'return' there does not affect this wrapper's host). Kept at the repo
    root so existing invocations (.\entramap.ps1 ...) keep working after the
    Products/Shared layout refactor. Log and export files still land in the
    caller's current directory, exactly as before.
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
    [switch]$RedactPublicIps
)

& (Join-Path $PSScriptRoot 'Products\EntraMap\entramap.ps1') @PSBoundParameters
