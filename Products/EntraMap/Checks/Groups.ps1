#==============================================================================
# AzureMap v2 - Products/EntraMap/Checks/Groups.ps1
# Evaluates role-assignable groups and their effective privilege exposure.
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraRoleAssignableGroups {
    <#
    .SYNOPSIS
        Identifies role-assignable groups and evaluates their security posture.
    .DESCRIPTION
        Filters groups where isAssignableToRole is true, cross-references with
        role assignments to determine which roles each group holds, and reports
        member counts to surface blast radius.
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping role-assignable groups check" -Level WARN
        return
    }

    $privLookup = $entra.PrivilegedRoleLookup
    $roleDefLookup = @{}
    foreach ($rd in $entra.RoleDefinitions) {
        $roleDefLookup[$rd.id] = $rd
    }

    $roleAssignableGroups = @($entra.Groups | Where-Object { $_.isAssignableToRole -eq $true })

    if ($roleAssignableGroups.Count -eq 0) {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No role-assignable groups found in tenant" `
            -Count          0 `
            -Service        "EntraGroups" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
        return
    }

    $evidence = [System.Collections.Generic.List[object]]::new()

    foreach ($group in $roleAssignableGroups) {
        $groupId = $group.id

        # Find roles assigned to this group
        $groupRoleAssignments = @($entra.RoleAssignments | Where-Object { $_.principalId -eq $groupId })
        $assignedRoles = [System.Collections.Generic.List[object]]::new()
        $holdsPrivilegedRole = $false

        foreach ($ra in $groupRoleAssignments) {
            $roleDef = $roleDefLookup[$ra.roleDefinitionId]
            if (-not $roleDef) { continue }

            $templateId = if ($roleDef.templateId) { $roleDef.templateId } else { $roleDef.id }
            $isPrivileged = $privLookup.ContainsKey($templateId)
            if ($isPrivileged) { $holdsPrivilegedRole = $true }

            $assignedRoles.Add([PSCustomObject]@{
                RoleName     = $roleDef.displayName
                IsPrivileged = $isPrivileged
                Criticality  = if ($isPrivileged) { $privLookup[$templateId].criticality } else { "N/A" }
            })
        }

        $memberCount = 0
        if ($entra.GroupMembers.ContainsKey($groupId)) {
            $memberCount = $entra.GroupMembers[$groupId].Count
        }

        $severity = if ($holdsPrivilegedRole) { "CRITICAL" } else { "HIGH" }

        $evidence.Add([PSCustomObject]@{
            GroupId       = $groupId
            GroupName     = $group.displayName
            AssignedRoles = $assignedRoles
            RoleCount     = $assignedRoles.Count
            MemberCount   = $memberCount
            HoldsPrivRole = $holdsPrivilegedRole
            Severity      = $severity
        })
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $privGroupCount = ($evidence | Where-Object { $_.HoldsPrivRole }).Count
        $maxSeverity = if ($privGroupCount -gt 0) { "CRITICAL" } else { "HIGH" }

        Write-Finding `
            -Severity       $maxSeverity `
            -Message        "Role-assignable groups detected ($privGroupCount hold privileged roles, $totalCount total)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraGroups" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Restrict membership of role-assignable groups via PIM for Groups. Limit group owners to privileged administrators. Enable access reviews for all role-assignable groups."
    }
}

function Register-EntraGroupsChecks {
    <#
    .SYNOPSIS
        Registers the Entra Groups checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-05"
            Category        = "Entra"
            Service         = "EntraGroups"
            Name            = "Test-EntraRoleAssignableGroups"
            Function        = "Test-EntraRoleAssignableGroups"
            DefaultSeverity = "CRITICAL"
            RequiredModules = @()
            RequiredPerms   = @("Group.Read.All", "RoleManagement.Read.Directory")
            Phase           = "TenantWide"
            Description     = "Role-assignable groups and their privilege exposure"
        }
    )
}
