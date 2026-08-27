#==============================================================================
# AzureMap v2 - Checks/Entra/Ownership.ps1
# Evaluates ownership risks on applications and service principals.
# Non-admin owners of privileged apps represent escalation paths.
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraOwnershipRisks {
    <#
    .SYNOPSIS
        Identifies ownership-based privilege escalation risks.
    .DESCRIPTION
        For each app/SP with dangerous permissions (from the escalation map),
        checks whether any owner is NOT a privileged admin. Non-admin owners
        of critical apps can inject credentials and escalate. Also flags
        apps with excessive (>5) owners.
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping ownership risk check" -Level WARN
        return
    }

    $permLookup = $entra.PermissionEscalationLookup

    # Build set of admin principal IDs (those with privileged role assignments)
    $privLookup     = $entra.PrivilegedRoleLookup
    $roleDefLookup  = @{}
    foreach ($rd in $entra.RoleDefinitions) { $roleDefLookup[$rd.id] = $rd }

    $adminPrincipalIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ra in $entra.RoleAssignments) {
        $roleDef = $roleDefLookup[$ra.roleDefinitionId]
        if (-not $roleDef) { continue }
        $templateId = if ($roleDef.templateId) { $roleDef.templateId } else { $roleDef.id }
        if ($privLookup.ContainsKey($templateId)) {
            $null = $adminPrincipalIds.Add($ra.principalId)
        }
    }

    # Resolve which SPs have dangerous permissions
    $dangerousSPIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $spDangerousPerms = @{}

    $graphSP = $entra.ServicePrincipals | Where-Object { $_.appId -eq '00000003-0000-0000-c000-000000000000' } | Select-Object -First 1
    $appRoleValueById = @{}
    if ($graphSP -and $graphSP.appRoles) {
        foreach ($role in $graphSP.appRoles) { $appRoleValueById[$role.id] = $role.value }
    }

    foreach ($spId in $entra.SPPermissions.Keys) {
        $assignments = $entra.SPPermissions[$spId]
        $permNames = @()
        foreach ($assignment in $assignments) {
            $appRoleId = $assignment.appRoleId
            if (-not $appRoleId -or $appRoleId -eq '00000000-0000-0000-0000-000000000000') { continue }
            $permValue = $appRoleValueById[$appRoleId]
            if ($permValue -and $permLookup.ContainsKey($permValue)) {
                $permNames += $permValue
            }
        }
        if ($permNames.Count -gt 0) {
            $null = $dangerousSPIds.Add($spId)
            $spDangerousPerms[$spId] = $permNames
        }
    }

    # Map appId (application object ID) -> SP for cross-referencing
    $appIdToSP = @{}
    foreach ($sp in $entra.ServicePrincipals) {
        if ($sp.appId) { $appIdToSP[$sp.appId] = $sp }
    }

    $evidence = [System.Collections.Generic.List[object]]::new()

    # Check SP owners
    foreach ($spId in $entra.SPOwners.Keys) {
        if (-not $dangerousSPIds.Contains($spId)) { continue }
        $owners = $entra.SPOwners[$spId]
        $sp = $entra.ServicePrincipals | Where-Object { $_.id -eq $spId } | Select-Object -First 1
        $spName = if ($sp) { $sp.displayName } else { $spId }

        foreach ($owner in $owners) {
            $ownerId    = $owner.id
            $ownerName  = $owner.displayName
            $ownerIsAdmin = $adminPrincipalIds.Contains($ownerId)

            if (-not $ownerIsAdmin) {
                $evidence.Add([PSCustomObject]@{
                    TargetId             = $spId
                    TargetDisplayName    = $spName
                    TargetType           = "ServicePrincipal"
                    OwnerId              = $ownerId
                    OwnerName            = $ownerName
                    OwnerIsAdmin         = $false
                    DangerousPermissions = $spDangerousPerms[$spId] -join ", "
                    RiskType             = "NonAdminOwnerOfPrivilegedSP"
                    Severity             = "HIGH"
                })
            }
        }
    }

    # Check App owners
    foreach ($appObjId in $entra.AppOwners.Keys) {
        $app = $entra.Applications | Where-Object { $_.id -eq $appObjId } | Select-Object -First 1
        if (-not $app) { continue }

        $matchedSP = $appIdToSP[$app.appId]
        $matchedSPId = if ($matchedSP) { $matchedSP.id } else { $null }

        $appHasDangerousPerms = $matchedSPId -and $dangerousSPIds.Contains($matchedSPId)
        $owners = $entra.AppOwners[$appObjId]
        $appName = $app.displayName

        if ($appHasDangerousPerms) {
            foreach ($owner in $owners) {
                $ownerId    = $owner.id
                $ownerName  = $owner.displayName
                $ownerIsAdmin = $adminPrincipalIds.Contains($ownerId)

                if (-not $ownerIsAdmin) {
                    $evidence.Add([PSCustomObject]@{
                        TargetId             = $appObjId
                        TargetDisplayName    = $appName
                        TargetType           = "Application"
                        OwnerId              = $ownerId
                        OwnerName            = $ownerName
                        OwnerIsAdmin         = $false
                        DangerousPermissions = ($spDangerousPerms[$matchedSPId]) -join ", "
                        RiskType             = "NonAdminOwnerOfPrivilegedApp"
                        Severity             = "HIGH"
                    })
                }
            }
        }

        # Excessive owners (any app with >5 owners)
        if ($owners.Count -gt 5) {
            $evidence.Add([PSCustomObject]@{
                TargetId             = $appObjId
                TargetDisplayName    = $appName
                TargetType           = "Application"
                OwnerId              = "N/A"
                OwnerName            = "($($owners.Count) owners)"
                OwnerIsAdmin         = "N/A"
                DangerousPermissions = "N/A"
                RiskType             = "ExcessiveOwners"
                Severity             = "MEDIUM"
            })
        }
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $highCount = ($evidence | Where-Object { $_.Severity -eq "HIGH" }).Count
        $maxSeverity = if ($highCount -gt 0) { "CRITICAL" } else { "HIGH" }

        Write-Finding `
            -Severity       $maxSeverity `
            -Message        "Application/SP ownership risks detected ($highCount escalation paths, $totalCount total findings)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraOwnership" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Remove non-admin owners from apps/SPs with dangerous permissions. Restrict app ownership to privileged administrators. Enable app instance property locks."
    } else {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No ownership-based escalation risks found" `
            -Count          0 `
            -Service        "EntraOwnership" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
    }
}

function Register-EntraOwnershipChecks {
    <#
    .SYNOPSIS
        Registers the Entra Ownership checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-04"
            Category        = "Entra"
            Service         = "EntraOwnership"
            Name            = "Test-EntraOwnershipRisks"
            Function        = "Test-EntraOwnershipRisks"
            DefaultSeverity = "CRITICAL"
            RequiredModules = @()
            RequiredPerms   = @("Application.Read.All")
            Phase           = "TenantWide"
            Description     = "Ownership chains enabling credential injection on privileged apps"
        }
    )
}
