#==============================================================================
# AzureMap v2 - Products/EntraMap/Core/Preflight.Entra.ps1
# Authentication preflight for the EntraMap product (Microsoft Graph).
#
# Guarantees:
#   * Never calls Connect-AzAccount automatically.
#   * Never prints or logs a token value.
#   * Requires a Microsoft Graph token; an ARM context is OPTIONAL (it is only
#     the token vehicle via Get-AzAccessToken - no subscription discovery or
#     ARM scanning is performed).
#   * On Graph auth failure: clean, actionable guidance (no raw stack trace).
#==============================================================================

function Test-EntraAuthPreflight {
    <#
    .SYNOPSIS
        Validates Microsoft Graph auth for an EntraMap run.
    .DESCRIPTION
        Returns a result object and stores it in $script:State.Auth:
          ArmAvailable       [bool] - an Az context exists (optional; token vehicle)
          GraphTokenAcquired [bool] - a Graph token was obtained
          EntraInScope       [bool] - Entra checks will run (token acquired)
          ShouldStop         [bool] - caller should stop before running checks
          Guidance           [string] - user-facing, no secrets/identifiers
          Detail             [string] - short diagnostic for DEBUG logs only (no token)
        A missing/unusable Graph token stops the run with guidance:
            Connect-AzAccount -AuthScope https://graph.microsoft.com
    #>
    [CmdletBinding()]
    param()

    $graphAuthCommand = 'Connect-AzAccount -AuthScope https://graph.microsoft.com'

    $result = [PSCustomObject]@{
        ArmAvailable       = $false
        GraphTokenAcquired = $false
        EntraInScope       = $false
        ShouldStop         = $false
        Guidance           = ''
        Detail             = ''
    }

    # ---- ARM context (OPTIONAL - token vehicle only; no subscription use) ----
    $armCtx = $null
    try {
        $armCtx = Get-AzContext -ErrorAction SilentlyContinue
    } catch {
        $result.Detail = $_.Exception.Message
    }
    $result.ArmAvailable = [bool]$armCtx
    if ($result.ArmAvailable) {
        Write-AuditLog -Message "Preflight: Azure context available (token vehicle only; no subscription scanning)." -Level INFO
    } else {
        Write-AuditLog -Message "Preflight: no Azure context; Graph token acquisition requires one." -Level DEBUG
    }

    # ---- Microsoft Graph token (required) ----
    if (-not (Get-Command -Name 'Get-GraphToken' -ErrorAction SilentlyContinue)) {
        $result.Detail     = 'Get-GraphToken command not available.'
        $result.Guidance   = "EntraMap requires Microsoft Graph authentication. Run:`n    $graphAuthCommand"
        $result.ShouldStop = $true
        Write-AuditLog -Message "Preflight: Microsoft Graph unavailable (Get-GraphToken not loaded)." -Level WARN -ForceConsole
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
        $result.ShouldStop   = $true
        $result.Guidance     = "EntraMap requires Microsoft Graph authentication. Run:`n    $graphAuthCommand`nThen re-run EntraMap."
        if ($result.Detail) {
            # DEBUG only - not shown in normal output, and contains no token.
            Write-AuditLog -Message "Preflight: Graph auth diagnostic: $($result.Detail)" -Level DEBUG
        }
        Write-AuditLog -Message "Preflight: Microsoft Graph authentication unavailable. See guidance." -Level WARN -ForceConsole
    }

    $script:State.Auth = $result
    return $result
}
