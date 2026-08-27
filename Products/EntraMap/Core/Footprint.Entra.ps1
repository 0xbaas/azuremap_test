#==============================================================================
# AzureMap v2 - Products/EntraMap/Core/Footprint.Entra.ps1
# EntraMap tenant footprint: safe, read-only Microsoft Graph metadata collected
# BEFORE the assessment (tenant id, account, object counts). Mirrors the
# AzureMap "Environment discovery" pattern (Core/Azure/Footprint.ps1) for the
# Entra product.
#
# Guarantees:
#   * Strictly read-only (GET only). Never reads or stores secret VALUES -
#     app credentials are counted from metadata (passwordCredentials /
#     keyCredentials arrays) only.
#   * Per-dimension degradation: a missing permission or failed query marks
#     THAT dimension unavailable; every other dimension still reports. No raw
#     Graph exception text reaches the CLI (reasons are generic; the raw error
#     goes to the log file only).
#   * Permission-class dedupe: a 403/401-class denial is classified once per
#     permission class (DirectoryRead / ApplicationRead / RoleManagementRead /
#     PolicyRead); later dimensions in a denied class are marked unavailable
#     WITHOUT re-calling Graph (no retry spam, no prompts).
#   * Reuses already-collected data ($script:State.Entra from
#     Invoke-EntraCollection, $script:State.TenantWideData) instead of
#     double-fetching. Result cached in $script:State.EntraFootprint;
#     in-memory only, never written to disk.
#==============================================================================

#region ---- Low-level Graph GET helpers (footprint-only) ----

function Invoke-EntraFootprintGraphGet {
    <#
    .SYNOPSIS
        Single read-only Graph GET for tenant discovery. Returns the raw
        response body so callers can read @odata.count / scalar /$count values
        (Invoke-GraphCommand intentionally discards those envelopes).
    .DESCRIPTION
        Routed through Invoke-AzureCommand so Forbidden (403) is classified and
        never retried, and throttling backoff behaves like every other Graph
        call. The token value is never logged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$CommandName = 'EntraFootprint'
    )

    $token   = Get-GraphToken
    $fullUrl = if ($Uri -match '^https?://') { $Uri } else { "https://graph.microsoft.com/v1.0/$Uri" }
    $headers = @{
        "Authorization"    = "Bearer $token"
        "ConsistencyLevel" = "eventual"
        "User-Agent"       = "AzureMap/2.0"
        "Accept"           = "application/json"
    }

    Invoke-AzureCommand -Command {
        Invoke-RestMethod -Uri $fullUrl -Method GET -Headers $headers -UseBasicParsing -ErrorAction Stop
    } -CommandName $CommandName -SkipContextCheck
}

function Get-EntraGraphScalarCount {
    <#
    .SYNOPSIS
        Reads a Graph /<entity>/$count endpoint (returns a bare integer).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CountUri,

        [string]$CommandName = 'EntraFootprintCount'
    )

    $r = Invoke-EntraFootprintGraphGet -Uri $CountUri -CommandName $CommandName
    return [int]"$r"
}

function Get-EntraGraphCollectionCount {
    <#
    .SYNOPSIS
        Counts a Graph collection: prefers a `$top=1&`$count=true probe reading
        @odata.count; falls back to full enumeration when the endpoint does not
        return a count. Read-only either way.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EntityUri,

        [string]$CommandName = 'EntraFootprintCount'
    )

    $sep = if ($EntityUri -match '\?') { '&' } else { '?' }
    $probe = Invoke-EntraFootprintGraphGet -Uri "$EntityUri$sep`$top=1&`$count=true" -CommandName $CommandName
    if ($probe -and ($probe.PSObject.Properties.Name -contains '@odata.count') -and $null -ne $probe.'@odata.count') {
        return [int]$probe.'@odata.count'
    }

    # Enumeration fallback (endpoint does not support $count).
    $total = 0
    $next  = $EntityUri
    while ($next) {
        $page = Invoke-EntraFootprintGraphGet -Uri $next -CommandName $CommandName
        if ($page -and ($page.PSObject.Properties.Name -contains 'value') -and $page.value) {
            $total += @($page.value).Count
        }
        $next = $null
        if ($page -and ($page.PSObject.Properties.Name -contains '@odata.nextLink') -and $page.'@odata.nextLink') {
            $next = [string]$page.'@odata.nextLink'
        }
    }
    return $total
}

#endregion

function Build-EntraFootprint {
    <#
    .SYNOPSIS
        Builds the EntraMap tenant footprint (safe read-only Graph metadata).
    .DESCRIPTION
        Collects tenant id / account (local Az context, no Graph call) and
        per-dimension counts: users, groups, service principals, app
        registrations, directory role definitions, role assignments,
        Conditional Access policies, authentication-method policy availability,
        guest users, and app credential metadata count. Dimensions whose data
        was already collected (Invoke-EntraCollection / TenantWideData) are
        reused instead of re-fetched.

        Never throws for Graph failures: each dimension degrades independently
        to Status='Unavailable' with a generic reason. A 403/401-class denial
        is classified once per permission class; remaining dimensions in that
        class are marked unavailable without another Graph call.
    .PARAMETER ForceRefresh
        Rebuild even when $script:State.EntraFootprint is already populated.
    .OUTPUTS
        [pscustomobject] with TenantId, Account, GraphAccess, Dimensions
        (ordered: key -> @{ Label; Value; Status; Reason; Source }), Source,
        Note, FetchedAt. Also cached in $script:State.EntraFootprint.
    #>
    [CmdletBinding()]
    param(
        [switch]$ForceRefresh
    )

    if (-not $ForceRefresh -and $script:State.EntraFootprint) {
        return $script:State.EntraFootprint
    }

    # ---- Tenant / account from the LOCAL Az context (no Graph call) ----
    $ctx = $null
    try { $ctx = Get-AzContext -ErrorAction SilentlyContinue } catch { $ctx = $null }
    $tenantId = $null
    $account  = $null
    if ($ctx) {
        if ($ctx.Tenant)  { $tenantId = [string]$ctx.Tenant.Id }
        if ($ctx.Account) { $account  = [string]$ctx.Account.Id }
    }
    if (-not $tenantId -and $script:State.TenantWideData -and $script:State.TenantWideData.TenantId) {
        $tenantId = [string]$script:State.TenantWideData.TenantId
    }

    $fp = [PSCustomObject]@{
        TenantId    = $tenantId
        Account     = $account
        GraphAccess = 'Unavailable'
        Dimensions  = [ordered]@{}
        Source      = 'MicrosoftGraph'
        Note        = ''
        FetchedAt   = Get-Date
    }

    # Permission classes already proven denied this run (class -> $true). Once
    # a class is denied, later dimensions in it are not queried again.
    $deniedClasses = @{}

    # Dimension collector (dynamic-scope closure over $fp / $deniedClasses).
    # -Reuse returns a pre-collected value or $null; -Fetch performs ONE Graph
    # query sequence. Failures never propagate.
    $addDimension = {
        param(
            [string]$Key,
            [string]$Label,
            [string]$PermissionClass,
            [string]$RequiredPerm,
            [scriptblock]$Fetch,
            [scriptblock]$Reuse
        )

        if ($Reuse) {
            $reused = & $Reuse
            if ($null -ne $reused) {
                $fp.Dimensions[$Key] = [PSCustomObject]@{ Label = $Label; Value = $reused; Status = 'Available'; Reason = ''; Source = 'Collected' }
                return
            }
        }

        if ($deniedClasses.ContainsKey($PermissionClass)) {
            Write-AuditLog -Message "Tenant discovery: $Key not queried (permission class '$PermissionClass' already denied)." -Level INFO
            $fp.Dimensions[$Key] = [PSCustomObject]@{ Label = $Label; Value = $null; Status = 'Unavailable'; Reason = "missing Graph permission ($RequiredPerm)"; Source = 'None' }
            return
        }

        try {
            $v = & $Fetch
            $fp.Dimensions[$Key] = [PSCustomObject]@{ Label = $Label; Value = $v; Status = 'Available'; Reason = ''; Source = 'MicrosoftGraph' }
        }
        catch {
            $class = 'Unknown'
            try { $class = (Get-ErrorClass -ErrorRecord $_).Class } catch { $class = 'Unknown' }
            if ($class -eq 'Forbidden' -or $class -eq 'Authentication') {
                # Classify the denial ONCE per permission class; do not retry it.
                $deniedClasses[$PermissionClass] = $true
                Write-AuditLog -Message "Tenant discovery: $Key unavailable - missing Graph permission ($RequiredPerm); permission class '$PermissionClass' will not be retried." -Level INFO
                $fp.Dimensions[$Key] = [PSCustomObject]@{ Label = $Label; Value = $null; Status = 'Unavailable'; Reason = "missing Graph permission ($RequiredPerm)"; Source = 'None' }
            }
            else {
                # Raw error text goes to the log file only; the CLI reason stays generic.
                Write-AuditLog -Message "Tenant discovery: $Key query failed [$class]: $($_.Exception.Message)" -Level WARN
                $fp.Dimensions[$Key] = [PSCustomObject]@{ Label = $Label; Value = $null; Status = 'Unavailable'; Reason = 'query failed'; Source = 'None' }
            }
        }
    }

    # ---- Graph access gate ----
    $token = $null
    try { $token = Get-GraphToken } catch { $token = $null }
    if ([string]::IsNullOrWhiteSpace([string]$token)) {
        $fp.Note = 'Microsoft Graph token unavailable; tenant discovery skipped.'
        Write-AuditLog -Message "Tenant discovery: no Graph token; all dimensions unavailable." -Level WARN
        foreach ($spec in @(
            @{ Key = 'Users';                      Label = 'Users';                        Perm = 'User.Read.All' }
            @{ Key = 'Groups';                     Label = 'Groups';                       Perm = 'Group.Read.All' }
            @{ Key = 'ServicePrincipals';          Label = 'Service principals';           Perm = 'Application.Read.All' }
            @{ Key = 'AppRegistrations';           Label = 'App registrations';            Perm = 'Application.Read.All' }
            @{ Key = 'DirectoryRoles';             Label = 'Directory roles';              Perm = 'RoleManagement.Read.Directory' }
            @{ Key = 'RoleAssignments';            Label = 'Role assignments';             Perm = 'RoleManagement.Read.Directory' }
            @{ Key = 'ConditionalAccessPolicies';  Label = 'Conditional Access policies';  Perm = 'Policy.Read.All' }
            @{ Key = 'AuthenticationMethodsPolicy'; Label = 'Authentication methods policy'; Perm = 'Policy.Read.All' }
            @{ Key = 'GuestUsers';                 Label = 'Guest users';                  Perm = 'User.Read.All' }
            @{ Key = 'AppCredentials';             Label = 'App credentials';              Perm = 'Application.Read.All' }
        )) {
            $fp.Dimensions[$spec.Key] = [PSCustomObject]@{ Label = $spec.Label; Value = $null; Status = 'Unavailable'; Reason = 'no Graph access'; Source = 'None' }
        }
        $script:State.EntraFootprint = $fp
        return $fp
    }
    $fp.GraphAccess = 'Available'

    # Already-collected data (populated only if collection ran before discovery).
    $entra = $script:State.Entra
    $twd   = $script:State.TenantWideData

    Write-AuditLog -Message "Building Entra tenant footprint (read-only Graph metadata)..." -Level INFO

    # ---- Dimension: Users ----
    & $addDimension -Key 'Users' -Label 'Users' -PermissionClass 'DirectoryRead' -RequiredPerm 'User.Read.All' `
        -Fetch { Get-EntraGraphScalarCount -CountUri 'users/$count' -CommandName 'FootprintUsers' }

    # ---- Dimension: Groups ----
    & $addDimension -Key 'Groups' -Label 'Groups' -PermissionClass 'DirectoryRead' -RequiredPerm 'Group.Read.All' `
        -Fetch { Get-EntraGraphScalarCount -CountUri 'groups/$count' -CommandName 'FootprintGroups' } `
        -Reuse { if ($entra) { [int](@($entra.Groups).Count) } else { $null } }

    # ---- Dimension: Service principals ----
    & $addDimension -Key 'ServicePrincipals' -Label 'Service principals' -PermissionClass 'ApplicationRead' -RequiredPerm 'Application.Read.All' `
        -Fetch { Get-EntraGraphScalarCount -CountUri 'servicePrincipals/$count' -CommandName 'FootprintServicePrincipals' } `
        -Reuse {
            if ($entra) { [int](@($entra.ServicePrincipals).Count) }
            elseif ($twd -and $null -ne $twd.ServicePrincipals) { [int](@($twd.ServicePrincipals).Count) }
            else { $null }
        }

    # ---- Dimension: App registrations ----
    & $addDimension -Key 'AppRegistrations' -Label 'App registrations' -PermissionClass 'ApplicationRead' -RequiredPerm 'Application.Read.All' `
        -Fetch { Get-EntraGraphScalarCount -CountUri 'applications/$count' -CommandName 'FootprintApplications' } `
        -Reuse {
            if ($entra) { [int](@($entra.Applications).Count) }
            elseif ($twd -and $null -ne $twd.Applications) { [int](@($twd.Applications).Count) }
            else { $null }
        }

    # ---- Dimension: Directory role definitions ----
    & $addDimension -Key 'DirectoryRoles' -Label 'Directory roles' -PermissionClass 'RoleManagementRead' -RequiredPerm 'RoleManagement.Read.Directory' `
        -Fetch { Get-EntraGraphCollectionCount -EntityUri 'roleManagement/directory/roleDefinitions' -CommandName 'FootprintRoleDefinitions' } `
        -Reuse { if ($entra) { [int](@($entra.RoleDefinitions).Count) } else { $null } }

    # ---- Dimension: Role assignments ----
    & $addDimension -Key 'RoleAssignments' -Label 'Role assignments' -PermissionClass 'RoleManagementRead' -RequiredPerm 'RoleManagement.Read.Directory' `
        -Fetch { Get-EntraGraphCollectionCount -EntityUri 'roleManagement/directory/roleAssignments' -CommandName 'FootprintRoleAssignments' } `
        -Reuse { if ($entra) { [int](@($entra.RoleAssignments).Count) } else { $null } }

    # ---- Dimension: Conditional Access policies ----
    & $addDimension -Key 'ConditionalAccessPolicies' -Label 'Conditional Access policies' -PermissionClass 'PolicyRead' -RequiredPerm 'Policy.Read.All' `
        -Fetch { Get-EntraGraphCollectionCount -EntityUri 'identity/conditionalAccess/policies' -CommandName 'FootprintConditionalAccess' }

    # ---- Dimension: Authentication methods policy (availability, not a count) ----
    & $addDimension -Key 'AuthenticationMethodsPolicy' -Label 'Authentication methods policy' -PermissionClass 'PolicyRead' -RequiredPerm 'Policy.Read.All' `
        -Fetch {
            $null = Invoke-EntraFootprintGraphGet -Uri 'policies/authenticationMethodsPolicy?$select=id' -CommandName 'FootprintAuthMethodsPolicy'
            'available'
        }

    # ---- Dimension: Guest (external) users ----
    & $addDimension -Key 'GuestUsers' -Label 'Guest users' -PermissionClass 'DirectoryRead' -RequiredPerm 'User.Read.All' `
        -Fetch { Get-EntraGraphCollectionCount -EntityUri "users?`$filter=userType eq 'Guest'" -CommandName 'FootprintGuestUsers' }

    # ---- Dimension: App credential metadata count (NEVER secret values) ----
    & $addDimension -Key 'AppCredentials' -Label 'App credentials' -PermissionClass 'ApplicationRead' -RequiredPerm 'Application.Read.All' `
        -Fetch {
            $credTotal = 0
            $next = 'applications?$select=id,passwordCredentials,keyCredentials&$top=999'
            while ($next) {
                $page = Invoke-EntraFootprintGraphGet -Uri $next -CommandName 'FootprintAppCredentials'
                foreach ($a in @($page.value)) {
                    $credTotal += @($a.passwordCredentials).Count + @($a.keyCredentials).Count
                }
                $next = $null
                if ($page -and ($page.PSObject.Properties.Name -contains '@odata.nextLink') -and $page.'@odata.nextLink') {
                    $next = [string]$page.'@odata.nextLink'
                }
            }
            $credTotal
        } `
        -Reuse {
            if ($entra -and $entra.Applications) {
                $credTotal = 0
                foreach ($a in @($entra.Applications)) {
                    $credTotal += @($a.passwordCredentials).Count + @($a.keyCredentials).Count
                }
                [int]$credTotal
            } else { $null }
        }

    $availableCount = 0
    foreach ($k in $fp.Dimensions.Keys) { if ($fp.Dimensions[$k].Status -eq 'Available') { $availableCount++ } }
    if ($availableCount -lt $fp.Dimensions.Count) {
        $fp.Note = "$($fp.Dimensions.Count - $availableCount) of $($fp.Dimensions.Count) discovery dimensions unavailable (permission-limited); checks needing those permissions are marked 'Could not check'."
        Write-AuditLog -Message "Tenant discovery partial: $availableCount of $($fp.Dimensions.Count) dimensions available." -Level INFO
    } else {
        Write-AuditLog -Message "Tenant discovery complete: all $($fp.Dimensions.Count) dimensions available." -Level INFO
    }

    $script:State.EntraFootprint = $fp
    return $fp
}

function Show-EntraFootprint {
    <#
    .SYNOPSIS
        Prints the EntraMap "Discovery" block (respects -Quiet/NoColor).
    .DESCRIPTION
        Clean two-column layout (label + count), mirroring AzureMap's
        Environment discovery rendering. Unavailable dimensions render as a
        muted "unavailable (reason)" - never raw Graph error text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Footprint
    )

    if ($script:State.Config.Quiet) { return }

    Write-UiHost -Text ''
    Write-UiHost -Text 'Discovery' -Color Cyan

    if ($Footprint.GraphAccess -ne 'Available') {
        Write-UiHost -Text '  Tenant discovery unavailable (no Microsoft Graph access).' -Color Yellow
        Write-UiHost -Text ''
        return
    }

    foreach ($key in $Footprint.Dimensions.Keys) {
        $d = $Footprint.Dimensions[$key]
        $labelCol = Format-UiColumn -Text ('  ' + $d.Label) -Width 34
        if ($d.Status -eq 'Available') {
            $val = "$($d.Value)"
            if ($val -match '^\d+$') { $val = Format-UiNumber $d.Value }
            Write-UiHost -Text $labelCol -Color Gray -NoNewline
            Write-UiHost -Text $val -Color White
        }
        else {
            Write-UiHost -Text $labelCol -Color Gray -NoNewline
            $reasonText = 'unavailable'
            if ($d.Reason) { $reasonText = "unavailable ($($d.Reason))" }
            Write-UiHost -Text $reasonText -Color DarkGray
        }
    }
    if ($Footprint.Note) {
        Write-UiHost -Text ("  " + $Footprint.Note) -Color DarkGray
    }
    Write-UiHost -Text ''
}

function Show-EntraAssessmentScope {
    <#
    .SYNOPSIS
        Prints the EntraMap "Assessment scope" block after preflight.
    .DESCRIPTION
        EntraMap product variant of the run-context block (Show-RunContext
        stays the AzureMap variant): Entra-only mode, tenant, account, Graph
        access state, and the explicit note that no Azure subscriptions are
        scanned. Account/tenant honor -RedactSensitive via Protect-SensitiveText.
    #>
    [CmdletBinding()]
    param()

    if ($script:State.Config.Quiet) { return }

    $ctx  = Get-AzContext -ErrorAction SilentlyContinue
    $acct = if ($ctx -and $ctx.Account) { [string]$ctx.Account.Id } else { 'Unknown' }
    $ten  = if ($ctx -and $ctx.Tenant)  { [string]$ctx.Tenant.Id }  else { 'Unknown' }
    $acct = Protect-SensitiveText -Text $acct
    $ten  = Protect-SensitiveText -Text $ten

    $graphAccess = 'unavailable'
    if ($script:State.Auth -and
        ($script:State.Auth.PSObject.Properties.Name -contains 'GraphTokenAcquired') -and
        $script:State.Auth.GraphTokenAcquired) {
        $graphAccess = 'available'
    }

    Write-UiHost -Text 'Assessment scope' -Color Cyan
    Write-UiHost -Text ((Format-UiColumn -Text '  Mode:' -Width 26) + 'Entra-only') -Color Gray
    Write-UiHost -Text ((Format-UiColumn -Text '  Tenant:' -Width 26) + $ten) -Color Gray
    Write-UiHost -Text ((Format-UiColumn -Text '  Account:' -Width 26) + $acct) -Color Gray
    $graphColor = if ($graphAccess -eq 'available') { 'Gray' } else { 'Yellow' }
    Write-UiHost -Text ((Format-UiColumn -Text '  Graph access:' -Width 26) + $graphAccess) -Color $graphColor
    Write-UiHost -Text ((Format-UiColumn -Text '  Azure subscriptions:' -Width 26) + 'not scanned') -Color Gray
    Write-UiHost -Text ''
}
