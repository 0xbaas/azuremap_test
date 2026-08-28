<#
.SYNOPSIS
    Azure Security Audit Tool v2.0 (AzureMap) - repo-root entrypoint wrapper.
.DESCRIPTION
    Thin wrapper: forwards every parameter verbatim to the real product
    entrypoint at Products\AzureMap\azuremap.ps1 (invoked as a script, so
    $PSScriptRoot inside it resolves to its real location and an early
    'return' there does not affect this wrapper's host). Kept at the repo
    root so existing invocations (.\azuremap.ps1 ...) keep working after the
    Products/Shared layout refactor. Log and export files still land in the
    caller's current directory, exactly as before.
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
    [string]$ReportLayout = 'Classic'
)

& (Join-Path $PSScriptRoot 'Products\AzureMap\azuremap.ps1') @PSBoundParameters
