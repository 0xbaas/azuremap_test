#==============================================================================
# AzureMap v2 - Checks/Entra/Collect.ps1
# Centralized Entra ID data collector. Runs once per audit (tenant-scoped).
# Populates $script:State.Entra with all Graph data needed by Entra checks.
# All Graph calls use Invoke-GraphCommand / Invoke-GraphBatch (Core/Entra/Graph.ps1).
#==============================================================================

function Invoke-EntraCollection {
    <#
    .SYNOPSIS
        Collects all Entra ID data required by the Entra security checks.
    .DESCRIPTION
        Runs once per audit. Calls Microsoft Graph to retrieve role definitions,
        role assignments, service principals, applications, groups, PIM schedules,
        OAuth2 grants, cross-tenant policy, and related ownership/membership data.
        Stores everything in $script:State.Entra for consumption by check functions.
    #>
    [CmdletBinding()]
    param()

    Write-AuditLog -Message "Starting Entra ID data collection" -Level INFO
    Write-Section -Title "Entra ID Data Collection" -Color Cyan

    # ---- Load reference data ----
    $scriptRoot = $PSScriptRoot
    $repoRoot   = (Resolve-Path (Join-Path $scriptRoot "..\.." )).Path

    $privRolesPath = Join-Path $repoRoot "ReferenceData\privileged-roles.json"
    $permMapPath   = Join-Path $repoRoot "ReferenceData\permission-escalation-map.json"

    $privilegedRolesData = @()
    if (Test-Path $privRolesPath) {
        $privilegedRolesData = (Get-Content $privRolesPath -Raw | ConvertFrom-Json).privilegedRoles
        Write-AuditLog -Message "Loaded $($privilegedRolesData.Count) privileged role definitions from reference data" -Level INFO
    } else {
        Write-AuditLog -Message "privileged-roles.json not found at $privRolesPath -- privileged role classification will be limited" -Level WARN
    }

    $permEscalationData = @()
    if (Test-Path $permMapPath) {
        $permEscalationData = (Get-Content $permMapPath -Raw | ConvertFrom-Json).dangerousPermissions
        Write-AuditLog -Message "Loaded $($permEscalationData.Count) dangerous permission definitions from reference data" -Level INFO
    } else {
        Write-AuditLog -Message "permission-escalation-map.json not found at $permMapPath -- permission risk classification will be limited" -Level WARN
    }

    # Build fast lookups
    $privRoleLookup = @{}
    foreach ($role in $privilegedRolesData) {
        $privRoleLookup[$role.roleId] = $role
    }

    $permEscalationLookup = @{}
    foreach ($entry in $permEscalationData) {
        $permEscalationLookup[$entry.permission] = $entry
    }

    # ---- Initialize state container ----
    $script:State.Entra = @{
        RoleDefinitions       = @()
        RoleAssignments       = @()
        PrincipalCache        = @{}
        Groups                = @()
        GroupMembers          = @{}
        ServicePrincipals     = @()
        SPPermissions         = @{}
        SPOwners              = @{}
        Applications          = @()
        AppOwners             = @{}
        OAuth2Grants          = @()
        CrossTenantPolicy     = $null
        PIMEligible           = @()
        PIMActive             = @()
        PrivilegedRoles       = $privilegedRolesData
        PrivilegedRoleLookup  = $privRoleLookup
        PermissionEscalationMap    = $permEscalationData
        PermissionEscalationLookup = $permEscalationLookup
        CollectedAt           = $null
    }

    # ---- (a) Role definitions ----
    Write-AuditLog -Message "Collecting Entra role definitions..." -Level INFO
    try {
        $roleDefs = Invoke-GraphCommand `
            -Uri "roleManagement/directory/roleDefinitions?`$select=id,displayName,description,isBuiltIn,isEnabled,templateId" `
            -AllPages -CommandName "EntraRoleDefinitions"
        $script:State.Entra.RoleDefinitions = @($roleDefs)
        Write-AuditLog -Message "Collected $($script:State.Entra.RoleDefinitions.Count) role definitions" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect role definitions: $_" -Level ERROR
    }

    # ---- (b) Role assignments ----
    Write-AuditLog -Message "Collecting Entra role assignments..." -Level INFO
    try {
        $roleAssignments = Invoke-GraphCommand `
            -Uri "roleManagement/directory/roleAssignments" `
            -AllPages -CommandName "EntraRoleAssignments"
        $script:State.Entra.RoleAssignments = @($roleAssignments)
        Write-AuditLog -Message "Collected $($script:State.Entra.RoleAssignments.Count) role assignments" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect role assignments: $_" -Level ERROR
    }

    # ---- (c) Resolve unique principals from role assignments ----
    Write-AuditLog -Message "Resolving principals from role assignments..." -Level INFO
    try {
        $uniquePrincipalIds = @($script:State.Entra.RoleAssignments | ForEach-Object { $_.principalId } | Sort-Object -Unique)

        if ($uniquePrincipalIds.Count -gt 0) {
            $batchRequests = @()
            for ($i = 0; $i -lt $uniquePrincipalIds.Count; $i++) {
                $batchRequests += @{
                    id     = "$i"
                    method = "GET"
                    url    = "/directoryObjects/$($uniquePrincipalIds[$i])?`$select=id,displayName,userPrincipalName,accountEnabled,servicePrincipalType,@odata.type"
                }
            }

            $batchResults = Invoke-GraphBatch -Requests $batchRequests -CommandName "ResolvePrincipals"

            foreach ($key in $batchResults.Keys) {
                $result = $batchResults[$key]
                if ($result.Success -and $result.Data) {
                    $obj = $result.Data
                    $principalType = if ($obj.'@odata.type') {
                        ($obj.'@odata.type' -replace '#microsoft\.graph\.', '')
                    } else { 'unknown' }

                    $script:State.Entra.PrincipalCache[$obj.id] = @{
                        displayName    = $obj.displayName
                        type           = $principalType
                        upn            = $obj.userPrincipalName
                        accountEnabled = $obj.accountEnabled
                    }
                }
            }
            Write-AuditLog -Message "Resolved $($script:State.Entra.PrincipalCache.Count) unique principals" -Level INFO
        }
    } catch {
        Write-AuditLog -Message "Failed to resolve principals: $_" -Level ERROR
    }

    # ---- (d) Groups ----
    Write-AuditLog -Message "Collecting Entra groups..." -Level INFO
    try {
        $groups = Invoke-GraphCommand `
            -Uri "groups?`$filter=securityEnabled eq true&`$select=id,displayName,isAssignableToRole,securityEnabled,groupTypes&`$top=999" `
            -AllPages -CommandName "EntraGroups"
        $script:State.Entra.Groups = @($groups)
        Write-AuditLog -Message "Collected $($script:State.Entra.Groups.Count) security groups" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect groups: $_" -Level ERROR
    }

    # ---- (e) Service Principals ----
    Write-AuditLog -Message "Collecting Entra service principals..." -Level INFO
    try {
        $sps = Invoke-GraphCommand `
            -Uri "servicePrincipals?`$filter=servicePrincipalType eq 'Application'&`$select=id,displayName,appId,servicePrincipalType,accountEnabled&`$top=999" `
            -AllPages -CommandName "EntraServicePrincipals"
        $script:State.Entra.ServicePrincipals = @($sps)
        Write-AuditLog -Message "Collected $($script:State.Entra.ServicePrincipals.Count) service principals" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect service principals: $_" -Level ERROR
    }

    # ---- (f) SP app role assignments (batched, chunks of 20) ----
    Write-AuditLog -Message "Collecting service principal app role assignments..." -Level INFO
    try {
        $spList = $script:State.Entra.ServicePrincipals
        for ($i = 0; $i -lt $spList.Count; $i += 20) {
            $chunk = $spList[$i..([Math]::Min($i + 19, $spList.Count - 1))]
            $batchRequests = @()
            foreach ($sp in $chunk) {
                $batchRequests += @{
                    id     = "approle-$($sp.id)"
                    method = "GET"
                    url    = "/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=999"
                }
            }

            $batchResults = Invoke-GraphBatch -Requests $batchRequests -CommandName "SPAppRoleAssignments"

            foreach ($sp in $chunk) {
                $key = "approle-$($sp.id)"
                if ($batchResults.ContainsKey($key) -and $batchResults[$key].Success) {
                    $assignments = @()
                    if ($batchResults[$key].Data.value) {
                        $assignments = @($batchResults[$key].Data.value)
                    }
                    if ($assignments.Count -gt 0) {
                        $script:State.Entra.SPPermissions[$sp.id] = $assignments
                    }
                }
            }
        }
        $spWithPerms = ($script:State.Entra.SPPermissions.Keys | Measure-Object).Count
        Write-AuditLog -Message "Collected app role assignments for $spWithPerms service principals" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect SP app role assignments: $_" -Level ERROR
    }

    # ---- (g) Applications ----
    Write-AuditLog -Message "Collecting Entra applications..." -Level INFO
    try {
        $apps = Invoke-GraphCommand `
            -Uri "applications?`$select=id,displayName,appId,signInAudience,passwordCredentials,keyCredentials&`$top=999" `
            -AllPages -CommandName "EntraApplications"
        $script:State.Entra.Applications = @($apps)
        Write-AuditLog -Message "Collected $($script:State.Entra.Applications.Count) applications" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect applications: $_" -Level ERROR
    }

    # ---- (h) App owners (batched, chunks of 20) ----
    Write-AuditLog -Message "Collecting application owners..." -Level INFO
    try {
        $appList = $script:State.Entra.Applications
        for ($i = 0; $i -lt $appList.Count; $i += 20) {
            $chunk = $appList[$i..([Math]::Min($i + 19, $appList.Count - 1))]
            $batchRequests = @()
            foreach ($app in $chunk) {
                $batchRequests += @{
                    id     = "appowner-$($app.id)"
                    method = "GET"
                    url    = "/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName,@odata.type"
                }
            }

            $batchResults = Invoke-GraphBatch -Requests $batchRequests -CommandName "AppOwners"

            foreach ($app in $chunk) {
                $key = "appowner-$($app.id)"
                if ($batchResults.ContainsKey($key) -and $batchResults[$key].Success) {
                    $owners = @()
                    if ($batchResults[$key].Data.value) {
                        $owners = @($batchResults[$key].Data.value)
                    }
                    if ($owners.Count -gt 0) {
                        $script:State.Entra.AppOwners[$app.id] = $owners
                    }
                }
            }
        }
        $appsWithOwners = ($script:State.Entra.AppOwners.Keys | Measure-Object).Count
        Write-AuditLog -Message "Collected owners for $appsWithOwners applications" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect app owners: $_" -Level ERROR
    }

    # ---- (i) SP owners for SPs with dangerous permissions ----
    Write-AuditLog -Message "Collecting service principal owners for privileged SPs..." -Level INFO
    try {
        $dangerousSPIds = @()
        foreach ($spId in $script:State.Entra.SPPermissions.Keys) {
            $assignments = $script:State.Entra.SPPermissions[$spId]
            foreach ($assignment in $assignments) {
                $roleValue = $assignment.appRoleId
                if ($permEscalationLookup.Count -gt 0) {
                    $dangerousSPIds += $spId
                    break
                }
            }
        }
        $dangerousSPIds = @($dangerousSPIds | Sort-Object -Unique)

        if ($dangerousSPIds.Count -eq 0) {
            $dangerousSPIds = @($script:State.Entra.SPPermissions.Keys)
        }

        for ($i = 0; $i -lt $dangerousSPIds.Count; $i += 20) {
            $chunk = $dangerousSPIds[$i..([Math]::Min($i + 19, $dangerousSPIds.Count - 1))]
            $batchRequests = @()
            foreach ($spId in $chunk) {
                $batchRequests += @{
                    id     = "spowner-$spId"
                    method = "GET"
                    url    = "/servicePrincipals/$spId/owners?`$select=id,displayName,userPrincipalName,@odata.type"
                }
            }

            $batchResults = Invoke-GraphBatch -Requests $batchRequests -CommandName "SPOwners"

            foreach ($spId in $chunk) {
                $key = "spowner-$spId"
                if ($batchResults.ContainsKey($key) -and $batchResults[$key].Success) {
                    $owners = @()
                    if ($batchResults[$key].Data.value) {
                        $owners = @($batchResults[$key].Data.value)
                    }
                    if ($owners.Count -gt 0) {
                        $script:State.Entra.SPOwners[$spId] = $owners
                    }
                }
            }
        }
        $spsWithOwners = ($script:State.Entra.SPOwners.Keys | Measure-Object).Count
        Write-AuditLog -Message "Collected owners for $spsWithOwners service principals" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect SP owners: $_" -Level ERROR
    }

    # ---- (j) OAuth2 permission grants ----
    Write-AuditLog -Message "Collecting OAuth2 permission grants..." -Level INFO
    try {
        $grants = Invoke-GraphCommand `
            -Uri "oauth2PermissionGrants?`$top=999" `
            -AllPages -CommandName "EntraOAuth2Grants"
        $script:State.Entra.OAuth2Grants = @($grants)
        Write-AuditLog -Message "Collected $($script:State.Entra.OAuth2Grants.Count) OAuth2 permission grants" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect OAuth2 grants: $_" -Level ERROR
    }

    # ---- (k) Group members for role-assignable groups ----
    Write-AuditLog -Message "Collecting members for role-assignable groups..." -Level INFO
    try {
        $roleAssignableGroups = @($script:State.Entra.Groups | Where-Object { $_.isAssignableToRole -eq $true })

        $assignedGroupIds = @($script:State.Entra.RoleAssignments | ForEach-Object { $_.principalId })
        $relevantGroups = @($roleAssignableGroups | Where-Object { $assignedGroupIds -contains $_.id })

        if ($relevantGroups.Count -eq 0) {
            $relevantGroups = $roleAssignableGroups
        }

        for ($i = 0; $i -lt $relevantGroups.Count; $i += 20) {
            $chunk = $relevantGroups[$i..([Math]::Min($i + 19, $relevantGroups.Count - 1))]
            $batchRequests = @()
            foreach ($group in $chunk) {
                $batchRequests += @{
                    id     = "gmember-$($group.id)"
                    method = "GET"
                    url    = "/groups/$($group.id)/members?`$select=id,displayName,userPrincipalName,@odata.type&`$top=999"
                }
            }

            $batchResults = Invoke-GraphBatch -Requests $batchRequests -CommandName "GroupMembers"

            foreach ($group in $chunk) {
                $key = "gmember-$($group.id)"
                if ($batchResults.ContainsKey($key) -and $batchResults[$key].Success) {
                    $members = @()
                    if ($batchResults[$key].Data.value) {
                        $members = @($batchResults[$key].Data.value)
                    }
                    $script:State.Entra.GroupMembers[$group.id] = $members
                }
            }
        }
        Write-AuditLog -Message "Collected members for $($script:State.Entra.GroupMembers.Count) role-assignable groups" -Level INFO
    } catch {
        Write-AuditLog -Message "Failed to collect group members: $_" -Level ERROR
    }

    # ---- (l) Cross-tenant access policy ----
    Write-AuditLog -Message "Collecting cross-tenant access policy..." -Level INFO
    try {
        $ctPolicy = Invoke-GraphCommand `
            -Uri "policies/crossTenantAccessPolicy" `
            -CommandName "EntraCrossTenantPolicy"
        $script:State.Entra.CrossTenantPolicy = $ctPolicy
        Write-AuditLog -Message "Collected cross-tenant access policy" -Level INFO
    } catch {
        Write-AuditLog -Message "Cross-tenant access policy not accessible (may require higher privileges): $_" -Level WARN
    }

    # ---- (m) PIM eligible assignments (beta-gated) ----
    $useBeta = $script:State.Config.UseGraphBeta -eq $true
    if ($useBeta) {
        Write-AuditLog -Message "Collecting PIM eligible role assignments (beta)..." -Level INFO
        try {
            $pimEligible = Invoke-GraphCommand `
                -Uri "roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition" `
                -ApiVersion "beta" -AllPages -CommandName "EntraPIMEligible"
            $script:State.Entra.PIMEligible = @($pimEligible)
            Write-AuditLog -Message "Collected $($script:State.Entra.PIMEligible.Count) PIM eligible assignments" -Level INFO
        } catch {
            Write-AuditLog -Message "Failed to collect PIM eligible assignments: $_" -Level WARN
        }

        # ---- (n) PIM active assignments (beta-gated) ----
        Write-AuditLog -Message "Collecting PIM active role assignments (beta)..." -Level INFO
        try {
            $pimActive = Invoke-GraphCommand `
                -Uri "roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition" `
                -ApiVersion "beta" -AllPages -CommandName "EntraPIMActive"
            $script:State.Entra.PIMActive = @($pimActive)
            Write-AuditLog -Message "Collected $($script:State.Entra.PIMActive.Count) PIM active assignments" -Level INFO
        } catch {
            Write-AuditLog -Message "Failed to collect PIM active assignments: $_" -Level WARN
        }
    } else {
        Write-AuditLog -Message "Skipping PIM collection (beta endpoints). Use -UseGraphBeta to enable." -Level INFO
    }

    $script:State.Entra.CollectedAt = Get-Date

    # Summary
    $summary = @(
        "Role Definitions: $($script:State.Entra.RoleDefinitions.Count)"
        "Role Assignments: $($script:State.Entra.RoleAssignments.Count)"
        "Principals Resolved: $($script:State.Entra.PrincipalCache.Count)"
        "Groups: $($script:State.Entra.Groups.Count)"
        "Service Principals: $($script:State.Entra.ServicePrincipals.Count)"
        "Applications: $($script:State.Entra.Applications.Count)"
        "OAuth2 Grants: $($script:State.Entra.OAuth2Grants.Count)"
        "PIM Eligible: $($script:State.Entra.PIMEligible.Count)"
        "PIM Active: $($script:State.Entra.PIMActive.Count)"
    ) -join " | "

    Write-AuditLog -Message "Entra collection complete. $summary" -Level INFO
}
