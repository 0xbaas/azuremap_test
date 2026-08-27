#==============================================================================
# AzureMap v2 - Core/Azure/Rbac.ps1
# Subscription-scoped RBAC assignment fetch/cache plus subscription
# normalization and local-session context-switch helpers (extracted from
# Core/CheckRegistry.ps1). All functions reference $script:State.
# Strictly read-only operations.
#==============================================================================

#region --- Subscription RBAC assignments ---

function Get-SubscriptionRBACAssignments {
    <#
    .SYNOPSIS
        Fetches (and caches) RBAC assignments scoped to a subscription.
    .OUTPUTS
        Array of role assignment objects.
    #>
    [CmdletBinding()]
    param(
        # Accept [object] and coerce, so a raw subscription object/array can never
        # cause a parameter-transformation or "Key cannot be null" failure.
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$SubscriptionId,

        [object]$SubscriptionName,
        [switch]$ForceRefresh
    )

    $SubscriptionId   = ConvertTo-ScalarString $SubscriptionId
    $SubscriptionName = ConvertTo-ScalarString $SubscriptionName

    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        Write-AuditLog -Message "Get-SubscriptionRBACAssignments called without a resolvable subscription id; returning no assignments." -Level WARN
        return @()
    }

    if (-not $ForceRefresh -and $script:State.Cache.RBACAssignments.ContainsKey($SubscriptionId)) {
        return $script:State.Cache.RBACAssignments[$SubscriptionId]
    }

    Write-AuditLog -Message "Fetching RBAC assignments for subscription $SubscriptionName (scoped to subscription)" -Level DEBUG

    if (-not $script:State.Cache.ContainsKey('RBACUnavailable')) {
        $script:State.Cache.RBACUnavailable = @{}
    }

    try {
        # RBAC ASSIGNMENTS come from ARM (Microsoft.Authorization/roleAssignments).
        # Get-AzRoleAssignment additionally enriches each assignment with the principal's
        # DisplayName/SignInName via Microsoft Graph. Under Azure-only (-SkipEntra) that
        # enrichment fails with "MicrosoftGraphEndpointResourceId" auth errors. Using
        # -ErrorAction SilentlyContinue (NOT Stop) keeps that enrichment failure
        # NON-terminating, so the ARM assignment data is still returned and the error is
        # not promoted/re-logged per subscription. -Critical is removed so there is no
        # auth retry loop. This is the fix for the repeated Graph auth spam.
        $assignments = Invoke-AzureCommand -Command {
            Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } -CommandName "Get-RoleAssignments-Scoped" -SkipContextCheck

        $assignments = @($assignments)
        $script:State.Cache.RBACAssignments[$SubscriptionId] = $assignments
        $script:State.Cache.RBACUnavailable[$SubscriptionId] = $false

        Write-AuditLog -Message "Cached $($assignments.Count) RBAC assignments for subscription $SubscriptionName" -Level DEBUG
        return $assignments
    }
    catch {
        # A THROWN (terminating) error means the ARM RBAC read itself failed - typically a
        # Graph/Authentication error surfaced under Azure-only. Mark the subscription's RBAC
        # as unavailable so callers emit ONE clean NotEvaluated (never a misleading PASS),
        # and never call Connect-AzAccount. A single WARN line per subscription, no spam.
        Write-AuditLog -Message "RBAC could not be evaluated for subscription ${SubscriptionName} (Azure RBAC read unavailable under current auth); marked NotEvaluated." -Level WARN
        $script:State.Cache.RBACAssignments[$SubscriptionId] = @()
        $script:State.Cache.RBACUnavailable[$SubscriptionId] = $true
        return @()
    }
}

#endregion

#region --- Subscription normalization ---

function ConvertTo-ScalarString {
    <#
    .SYNOPSIS
        Coerces any value to a single scalar string (or $null).
    .DESCRIPTION
        Defensive helper so a subscription id/name is never bound as a collection or
        object into a string context. Handles: plain string (returned as-is), a
        single-/multi-element collection (unwrapped to one element), or an object that
        carries an Id/SubscriptionId property (that value is used). This prevents the
        "Cannot process argument transformation on parameter 'SubscriptionId'. Cannot
        convert value to type System.String" failure when a raw subscription object or
        array reaches a string parameter.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }

    # Unwrap collections (but not strings, which are IEnumerable[char]).
    if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
        $arr = @($Value | Where-Object { $null -ne $_ })
        if ($arr.Count -eq 0) { return $null }
        $Value = $arr[0]
        if ($null -eq $Value) { return $null }
    }

    # If an object slipped through, prefer its Id / SubscriptionId.
    if (($Value -isnot [string]) -and $Value.PSObject) {
        $pn = @($Value.PSObject.Properties.Name)
        if (($pn -contains 'Id') -and $Value.Id)                          { return [string]$Value.Id }
        elseif (($pn -contains 'SubscriptionId') -and $Value.SubscriptionId) { return [string]$Value.SubscriptionId }
    }

    return [string]$Value
}

function ConvertTo-AzureMapSubscription {
    <#
    .SYNOPSIS
        Normalizes subscription input into a consistent shape for all checks.
    .DESCRIPTION
        Every PerSubscription check reads $sub.Id and $sub.Name. Depending on how
        subscriptions were discovered, the raw objects differ:
          - Get-AzSubscription -> PSAzureSubscription with .Id, .Name, .TenantId
          - Get-AzContext      -> PSAzureContext with .Subscription.Id/.Name and .Tenant.Id
        This helper maps both shapes to a uniform object:
          { Id; Name; TenantId; SubscriptionId }
        (SubscriptionId is an alias of Id, kept so existing exclusion logic that
        references .SubscriptionId does not fault under Set-StrictMode.)
        If an object matches neither shape it throws a clear error so preflight
        fails before any checks run - never silently producing objects without Id.
    .PARAMETER InputObject
        One or more raw subscription/context objects.
    .OUTPUTS
        Array of [PSCustomObject] with Id, Name, TenantId, SubscriptionId.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$InputObject
    )

    $normalized = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $InputObject) {
        if ($null -eq $item) { continue }

        $props    = @($item.PSObject.Properties.Name)
        $id       = $null
        $name     = $null
        $tenantId = $null

        if (($props -contains 'Id') -and $item.Id) {
            # Get-AzSubscription shape (scalarize defensively - .Id must be a string)
            $id   = ConvertTo-ScalarString $item.Id
            $name = if ($props -contains 'Name') { ConvertTo-ScalarString $item.Name } else { $null }
            if ($props -contains 'TenantId') { $tenantId = ConvertTo-ScalarString $item.TenantId }
        }
        elseif (($props -contains 'Subscription') -and $item.Subscription) {
            # Get-AzContext shape
            $sub  = $item.Subscription
            $id   = ConvertTo-ScalarString $sub.Id
            $name = ConvertTo-ScalarString $sub.Name
            if (($props -contains 'Tenant') -and $item.Tenant) { $tenantId = ConvertTo-ScalarString $item.Tenant.Id }
        }

        if ([string]::IsNullOrWhiteSpace($id) -or [string]::IsNullOrWhiteSpace($name)) {
            throw "ConvertTo-AzureMapSubscription: subscription input does not match a supported shape. Expected Get-AzSubscription (.Id/.Name) or Get-AzContext (.Subscription.Id/.Subscription.Name)."
        }

        $normalized.Add([PSCustomObject]@{
            Id             = $id
            Name           = $name
            TenantId       = $tenantId
            SubscriptionId = $id
        })
    }

    # Return the array WITHOUT a unary comma: in Windows PowerShell 5.1 a
    # "return ,$array" consumed by the caller's @() nests into a single-element
    # array ([ [subs] ]), which makes every check iterate the whole array as one
    # $sub. Emitting the elements lets the caller's @() build a flat array.
    return $normalized.ToArray()
}

function Set-SubscriptionContext {
    <#
    .SYNOPSIS
        Switches the local PowerShell Az session to the given subscription.
    .DESCRIPTION
        Read-only, local-session operation. Uses Set-AzContext only to change which
        subscription subsequent Get-* calls target. It never signs in
        (no Connect-AzAccount) and never modifies any Azure resource. Returns $true
        on success and $false on failure (it does not throw, so a single failed
        subscription simply causes the caller to skip that subscription).
    .PARAMETER SubscriptionId
        Subscription id to switch to (from a normalized subscription's .Id).
    .PARAMETER SubscriptionName
        Friendly name, used only for the failure warning.
    .PARAMETER TenantId
        Optional tenant id (from a normalized subscription's .TenantId).
    .OUTPUTS
        [bool] $true if the context was switched, otherwise $false.
    #>
    [CmdletBinding()]
    param(
        # Accept [object] (not [string]) so a raw subscription object or a
        # single-element collection can never trigger a parameter-transformation
        # failure; the value is coerced to a scalar string below.
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$SubscriptionId,

        [object]$SubscriptionName,

        [object]$TenantId
    )

    $SubscriptionId   = ConvertTo-ScalarString $SubscriptionId
    $SubscriptionName = ConvertTo-ScalarString $SubscriptionName
    $TenantId         = ConvertTo-ScalarString $TenantId

    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        Write-AuditLog -Message "Set-SubscriptionContext called without a resolvable subscription id; skipping this subscription." -Level WARN
        return $false
    }

    # Perf phase: skip the switch when the session is already on the target
    # subscription. Get-AzContext is a local read (no ARM call); Set-AzContext
    # costs ~0.5s each and was being called once per check per subscription
    # (~1,900 times per run).
    $currentCtx = Get-AzContext -ErrorAction SilentlyContinue
    if ($currentCtx -and $currentCtx.Subscription -and
        "$($currentCtx.Subscription.Id)" -eq $SubscriptionId) {
        return $true
    }

    try {
        $ctxParams = @{
            SubscriptionId = $SubscriptionId
            ErrorAction    = 'Stop'
        }
        if ($TenantId) { $ctxParams['TenantId'] = $TenantId }

        # Local session context switch only (no sign-in, no resource change).
        $null = Set-AzContext @ctxParams
        return $true
    }
    catch {
        # Clean warning by name only - never emit the subscription id or tenant id.
        $label = if ($SubscriptionName) { "subscription '$SubscriptionName'" } else { "the target subscription" }
        Write-AuditLog -Message "Unable to switch Azure session context to $label; skipping its checks." -Level WARN
        return $false
    }
}

#endregion
