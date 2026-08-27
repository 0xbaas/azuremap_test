#==============================================================================
# AzureMap v2 - Core/Preflight.ps1
# Combined-mode authentication preflight for Azure Resource Manager (ARM) and
# Microsoft Graph. The product entrypoints use the dedicated variants instead:
# Core/Azure/Preflight.Azure.ps1 (Test-AzureAuthPreflight; ARM-required, never
# probes Graph, also hosts Test-AzureSubscriptionScope) and
# Core/Entra/Preflight.Entra.ps1 (Test-EntraAuthPreflight; Graph-required,
# ARM context optional).
#
# Guarantees:
#   * Never calls Connect-AzAccount automatically.
#   * Never prints or logs a token value.
#   * Only attempts a Graph token when Entra is in scope (not -SkipEntra).
#   * On Graph auth failure: clean, actionable guidance (no raw stack trace).
#   * -ContinueWithoutEntra downgrades to Azure-only instead of stopping.
#==============================================================================

function Test-AuthenticationPreflight {
    <#
    .SYNOPSIS
        Validates ARM context and (when in scope) Microsoft Graph auth.
    .DESCRIPTION
        Returns a result object and stores it in $script:State.Auth:
          ArmAvailable       [bool]   - an Az context exists
          EntraRequested     [bool]   - Entra was requested (not -SkipEntra)
          EntraInScope       [bool]   - Entra checks will run (Graph token acquired)
          GraphTokenAcquired [bool]   - a Graph token was obtained
          ShouldStop         [bool]   - caller should stop before running checks
          Guidance           [string] - user-facing, no secrets/identifiers
          Detail             [string] - short diagnostic for DEBUG logs only (no token)
    .PARAMETER SkipEntra
        Azure-only; do not acquire a Graph token at all.
    .PARAMETER EntraOnly
        Entra-only run (informational here; scope handling unchanged).
    .PARAMETER ContinueWithoutEntra
        If Graph auth is unavailable, continue Azure-only instead of stopping.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipEntra,
        [switch]$EntraOnly,
        [switch]$ContinueWithoutEntra
    )

    $graphAuthCommand = 'Connect-AzAccount -AuthScope "https://graph.microsoft.com"'

    $result = [PSCustomObject]@{
        ArmAvailable       = $false
        EntraRequested     = (-not $SkipEntra)
        EntraInScope       = $false
        GraphTokenAcquired = $false
        ShouldStop         = $false
        Guidance           = ''
        Detail             = ''
    }

    # ---- 1. ARM context (read-only; never auto Connect-AzAccount) ----
    $armCtx = $null
    try {
        $armCtx = Get-AzContext -ErrorAction SilentlyContinue
    } catch {
        $result.Detail = $_.Exception.Message
    }
    $result.ArmAvailable = [bool]$armCtx

    if (-not $result.ArmAvailable) {
        $result.ShouldStop = $true
        $result.Guidance   = "No Azure Resource Manager sign-in was found. Sign in first, then re-run AzureMap:`n    Connect-AzAccount"
        Write-AuditLog -Message "Preflight: no Azure Resource Manager context available." -Level WARN -ForceConsole
        $script:State.Auth = $result
        return $result
    }
    Write-AuditLog -Message "Preflight: Azure Resource Manager context available." -Level INFO

    # ---- 2. Entra scope ----
    if ($SkipEntra) {
        Write-AuditLog -Message "Preflight: -SkipEntra set; skipping Microsoft Graph token acquisition (Azure-only mode)." -Level INFO
        $result.EntraInScope = $false
        $script:State.Auth = $result
        return $result
    }

    # ---- 3. Microsoft Graph token (only when Entra is in scope) ----
    if (-not (Get-Command -Name 'Get-GraphToken' -ErrorAction SilentlyContinue)) {
        $result.Detail   = 'Get-GraphToken command not available.'
        $result.Guidance = "Entra ID checks require Microsoft Graph authentication. Run:`n    $graphAuthCommand"
        if ($ContinueWithoutEntra) {
            $result.EntraInScope = $false
            $result.ShouldStop   = $false
            Write-AuditLog -Message "Preflight: Microsoft Graph unavailable; continuing Azure-only (-ContinueWithoutEntra). Entra checks will be NotEvaluated." -Level WARN -ForceConsole
        } else {
            $result.EntraInScope = $false
            $result.ShouldStop   = $true
            Write-AuditLog -Message "Preflight: Microsoft Graph unavailable and -ContinueWithoutEntra not set." -Level WARN -ForceConsole
        }
        $script:State.Auth = $result
        return $result
    }

    $graphOk = $false
    try {
        # Get-GraphToken returns the token STRING. We record only a boolean and
        # immediately drop the reference - the value is never logged or stored.
        $token   = Get-GraphToken
        $graphOk = -not [string]::IsNullOrWhiteSpace([string]$token)
        $token   = $null
    } catch {
        $graphOk = $false
        # Keep a short diagnostic (message only, no token, no stack trace) for DEBUG.
        $result.Detail = $_.Exception.Message
    }

    $result.GraphTokenAcquired = $graphOk

    if ($graphOk) {
        $result.EntraInScope = $true
        Write-AuditLog -Message "Preflight: Microsoft Graph token acquired; Entra checks enabled." -Level INFO
    } else {
        $result.EntraInScope = $false
        $result.Guidance = "Entra ID checks require Microsoft Graph authentication. Run:`n    $graphAuthCommand`nThen re-run AzureMap. To proceed without Entra now, use -ContinueWithoutEntra; for Azure-only, use -SkipEntra."

        if ($result.Detail) {
            # DEBUG only - not shown in normal output, and contains no token.
            Write-AuditLog -Message "Preflight: Graph auth diagnostic: $($result.Detail)" -Level DEBUG
        }

        if ($ContinueWithoutEntra) {
            $result.ShouldStop = $false
            Write-AuditLog -Message "Preflight: Microsoft Graph authentication unavailable; continuing Azure-only (-ContinueWithoutEntra). Entra checks will be NotEvaluated." -Level WARN -ForceConsole
        } else {
            $result.ShouldStop = $true
            Write-AuditLog -Message "Preflight: Microsoft Graph authentication unavailable. See guidance." -Level WARN -ForceConsole
        }
    }

    $script:State.Auth = $result
    return $result
}
