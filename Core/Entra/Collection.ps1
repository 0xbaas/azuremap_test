#==============================================================================
# AzureMap v2 - Core/Entra/Collection.ps1
# Central collection-phase orchestration. Decides, in one testable place,
# whether Graph/Entra/tenant-wide identity collection runs.
#
# Azure-only guarantee: when -SkipEntra is set, NONE of the following happen:
#   - Microsoft Graph token acquisition (Get-GraphToken)
#   - Entra data collection (Invoke-EntraCollection)
#   - Tenant-wide identity collection (Get-TenantWideData -> Get-AzAD*)
#==============================================================================

function Invoke-AzureMapCollection {
    <#
    .SYNOPSIS
        Runs the collection phase, gating all Graph/AAD-backed work on -SkipEntra.
    .PARAMETER SkipEntra
        Azure-only mode. Suppresses Graph token, Entra collection, and tenant-wide
        identity collection entirely.
    .PARAMETER EntraOnly
        Entra-only mode (reserved; does not change Azure resource collection here).
    .PARAMETER UseGraphBeta
        Forwarded to Invoke-EntraCollection when Entra is in scope.
    #>
    [CmdletBinding()]
    param(
        [switch]$SkipEntra,
        [switch]$EntraOnly,
        [switch]$UseGraphBeta
    )

    if ($SkipEntra) {
        Write-AuditLog -Message "Azure-only mode (-SkipEntra): skipping Graph token acquisition, Entra collection, and tenant-wide identity collection." -Level INFO
        return
    }

    # Acquire the Graph token first so Entra collection can use it.
    if (Get-Command -Name "Get-GraphToken" -ErrorAction SilentlyContinue) {
        [void](Get-GraphToken)
    } else {
        Write-AuditLog -Message "Get-GraphToken not available; Entra checks may fail without a Graph token." -Level WARN
    }

    if (Get-Command -Name "Invoke-EntraCollection" -ErrorAction SilentlyContinue) {
        $entraParams = @{}
        if ($UseGraphBeta) { $entraParams["UseGraphBeta"] = $true }
        Invoke-EntraCollection @entraParams
    }

    # Tenant-wide identity data (used by Azure Identity checks) is Graph/AAD-backed,
    # so it belongs to Entra scope and is only collected when Entra is in scope.
    if (Get-Command -Name "Get-TenantWideData" -ErrorAction SilentlyContinue) {
        [void](Get-TenantWideData)
    }
}
