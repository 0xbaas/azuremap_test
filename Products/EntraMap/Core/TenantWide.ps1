#==============================================================================
# AzureMap v2 - Products/EntraMap/Core/TenantWide.ps1
# Tenant-wide identity data (applications, service principals) fetched once
# per run, best effort via Az.Resources (extracted from
# Core/CheckRegistry.ps1). All functions reference $script:State.
# Strictly read-only operations.
#==============================================================================

#region --- Tenant-wide data (migrated from original lines 758-822) ---

function Get-TenantWideData {
    <#
    .SYNOPSIS
        Fetches tenant-wide identity data (applications, service principals) once.
    .DESCRIPTION
        Uses Az.Resources cmdlets (best effort). Warns when counts >= 1000
        indicating potential pagination limits.
    .OUTPUTS
        [hashtable] The TenantWideData structure.
    #>
    [CmdletBinding()]
    param(
        [switch]$ForceRefresh
    )

    # Azure-only mode: never perform Graph/AAD-backed tenant identity collection.
    # Returns the (empty) initialized structure so callers see no data and mark
    # tenant-dependent checks as NotEvaluated rather than triggering collection.
    if ($script:State.Config.SkipEntra) {
        Write-AuditLog -Message "SkipEntra set: not collecting tenant-wide identity data (Get-AzADApplication/Get-AzADServicePrincipal suppressed)." -Level INFO
        return $script:State.TenantWideData
    }

    if (-not $ForceRefresh -and $null -ne $script:State.TenantWideData.Applications) {
        return $script:State.TenantWideData
    }

    Write-AuditLog -Message "Fetching tenant-wide identity data (BEST EFFORT - Az.Resources may not return all objects)" -Level INFO

    try {
        $context = Get-AzContext
        if (-not $context) {
            throw "No Azure context available"
        }

        Write-AuditLog -Message "Fetching tenant applications (BEST EFFORT - may be incomplete in large tenants)" -Level INFO
        $allApps = @(Invoke-AzureCommand -Command {
            Get-AzADApplication -ErrorAction Stop
        } -CommandName "Get-TenantApplications" -SkipContextCheck -Critical)

        if ($allApps.Count -ge 1000) {
            Write-AuditLog -Message "WARNING: Fetched $($allApps.Count) applications. Results may be incomplete. For complete enumeration, use Microsoft Graph API." -Level WARN -ForceConsole
        }
        elseif ($allApps.Count -eq 0) {
            Write-AuditLog -Message "WARNING: No applications found. This may indicate pagination limits or insufficient permissions." -Level WARN
        }

        Write-AuditLog -Message "Fetching tenant service principals (BEST EFFORT - may be incomplete in large tenants)" -Level INFO
        $allSps = @(Invoke-AzureCommand -Command {
            Get-AzADServicePrincipal -ErrorAction Stop
        } -CommandName "Get-TenantServicePrincipals" -SkipContextCheck -Critical)

        if ($allSps.Count -ge 1000) {
            Write-AuditLog -Message "WARNING: Fetched $($allSps.Count) service principals. Results may be incomplete. For complete enumeration, use Microsoft Graph API." -Level WARN -ForceConsole
        }
        elseif ($allSps.Count -eq 0) {
            Write-AuditLog -Message "WARNING: No service principals found. This may indicate pagination limits or insufficient permissions." -Level WARN
        }

        $script:State.TenantWideData = @{
            Applications      = $allApps
            ServicePrincipals = $allSps
            TenantId          = $context.Tenant.Id
            FetchedAt         = Get-Date
        }

        Write-AuditLog -Message "Fetched $($allApps.Count) applications and $($allSps.Count) service principals" -Level INFO
    }
    catch {
        Write-AuditLog -Message "Failed to fetch tenant-wide identity data: $_" -Level ERROR
        $script:State.TenantWideData = @{
            Applications      = @()
            ServicePrincipals = @()
            TenantId          = $null
            FetchedAt         = Get-Date
        }
    }

    return $script:State.TenantWideData
}

#endregion
