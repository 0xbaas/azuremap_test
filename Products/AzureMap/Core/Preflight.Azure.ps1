#==============================================================================
# AzureMap v2 - Core/Azure/Preflight.Azure.ps1
# Authentication preflight for the AzureMap product (Azure Resource Manager).
#
# Guarantees:
#   * Never calls Connect-AzAccount automatically.
#   * Never prints or logs a token value.
#   * NEVER probes Microsoft Graph - AzureMap is ARM-only.
#   * On missing ARM context: clean, actionable guidance (no raw stack trace).
#==============================================================================

function Test-AzureAuthPreflight {
    <#
    .SYNOPSIS
        Validates that an Azure Resource Manager (ARM) context exists.
    .DESCRIPTION
        Returns a result object and stores it in $script:State.Auth:
          ArmAvailable [bool]   - an Az context exists
          ShouldStop   [bool]   - caller should stop before running checks
          Guidance     [string] - user-facing, no secrets/identifiers
          Detail       [string] - short diagnostic for DEBUG logs only
        Microsoft Graph is never probed: AzureMap checks run on the ARM
        control plane only.
    #>
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{
        ArmAvailable = $false
        ShouldStop   = $false
        Guidance     = ''
        Detail       = ''
    }

    # ---- ARM context (read-only; never auto Connect-AzAccount) ----
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

    $script:State.Auth = $result
    return $result
}

function Test-AzureSubscriptionScope {
    <#
    .SYNOPSIS
        Decides whether the run has any usable Azure subscription scope.
    .DESCRIPTION
        When neither Get-AzSubscription nor the current Az context produced a
        usable subscription (and the run is not Entra-only), there is nothing
        to audit: continuing would emit an empty, misleading report. Returns
        Usable=$false with an actionable Message so the caller stops before
        collection and check execution instead of producing partial output.
    .OUTPUTS
        [pscustomobject] @{ Usable = [bool]; Message = [string] }
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Subscriptions,

        [switch]$EntraOnly
    )

    if (@($Subscriptions).Count -gt 0 -or $EntraOnly) {
        return [PSCustomObject]@{ Usable = $true; Message = '' }
    }

    return [PSCustomObject]@{
        Usable  = $false
        Message = 'No usable Azure subscriptions found. Run Connect-AzAccount and select a valid tenant/subscription (or grant the identity subscription read), then re-run.'
    }
}
