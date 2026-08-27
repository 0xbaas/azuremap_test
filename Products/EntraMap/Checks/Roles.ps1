#==============================================================================
# AzureMap v2 - Products/EntraMap/Checks/Roles.ps1
# Evaluates standing privileged role assignments in Entra ID.
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraPrivilegedRoleAssignments {
    <#
    .SYNOPSIS
        Identifies standing privileged Entra ID role assignments.
    .DESCRIPTION
        Iterates role assignments, cross-references with the privileged roles
        reference data, resolves principals, and emits findings per assignment.
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping privileged role check" -Level WARN
        return
    }

    $privLookup = $entra.PrivilegedRoleLookup
    $roleDefLookup = @{}
    foreach ($rd in $entra.RoleDefinitions) {
        $roleDefLookup[$rd.id] = $rd
    }

    $evidence = [System.Collections.Generic.List[object]]::new()
    $criticalCount = 0
    $highCount     = 0

    foreach ($assignment in $entra.RoleAssignments) {
        $roleDefId = $assignment.roleDefinitionId
        $roleDef   = $roleDefLookup[$roleDefId]
        if (-not $roleDef) { continue }

        $templateId = $roleDef.templateId
        if (-not $templateId) { $templateId = $roleDef.id }

        $privRole = $privLookup[$templateId]
        if (-not $privRole) { continue }

        $principalId = $assignment.principalId
        $principal   = $entra.PrincipalCache[$principalId]

        $principalDisplayName = if ($principal) { $principal.displayName } else { $principalId }
        $principalType        = if ($principal) { $principal.type }        else { "unknown" }

        $memberCount = $null
        if ($principalType -eq 'group' -and $entra.GroupMembers.ContainsKey($principalId)) {
            $memberCount = $entra.GroupMembers[$principalId].Count
        }

        $severity = switch ($privRole.criticality) {
            "Critical" { "CRITICAL"; $criticalCount++ }
            "High"     { "HIGH";     $highCount++ }
            default    { "MEDIUM" }
        }

        $record = [PSCustomObject]@{
            PrincipalId          = $principalId
            PrincipalType        = $principalType
            PrincipalDisplayName = $principalDisplayName
            RoleName             = $roleDef.displayName
            RoleCriticality      = $privRole.criticality
            IsBuiltIn            = $roleDef.isBuiltIn
            GroupMemberCount     = $memberCount
            Severity             = $severity
        }
        $evidence.Add($record)
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $maxSeverity = if ($criticalCount -gt 0) { "CRITICAL" } elseif ($highCount -gt 0) { "HIGH" } else { "MEDIUM" }

        Write-Finding `
            -Severity       $maxSeverity `
            -Message        "Standing privileged Entra ID role assignments detected ($criticalCount critical, $highCount high)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraRoles" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Convert standing assignments to PIM eligible assignments. Enforce time-limited activation with MFA and approval for Critical roles."
    } else {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No standing privileged role assignments found" `
            -Count          0 `
            -Service        "EntraRoles" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
    }
}

function Register-EntraRolesChecks {
    <#
    .SYNOPSIS
        Registers the Entra Roles checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-01"
            Category        = "Entra"
            Service         = "EntraRoles"
            Name            = "Test-EntraPrivilegedRoleAssignments"
            Function        = "Test-EntraPrivilegedRoleAssignments"
            DefaultSeverity = "CRITICAL"
            RequiredModules = @()
            RequiredPerms   = @("RoleManagement.Read.Directory")
            Phase           = "TenantWide"
            Description     = "Standing privileged Entra ID role assignments"
        }
    )
}
