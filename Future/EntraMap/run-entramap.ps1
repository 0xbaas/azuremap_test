<#
.SYNOPSIS
    Entra ID Security Audit Tool v2.0 (EntraMap) - entrypoint wrapper.
.DESCRIPTION
    EntraMap is parked for a future phase - not part of the active AzureMap
    workflow.

    Thin wrapper: forwards every parameter verbatim to the real product
    entrypoint entramap.ps1 in this same directory (invoked as a script, so
    $PSScriptRoot inside it resolves to its real location and an early
    'return' there does not affect this wrapper's host). Log and export files
    land in the caller's current directory.
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
    [string]$ReportLayout = 'Pentester'
)

& (Join-Path $PSScriptRoot 'entramap.ps1') @PSBoundParameters
