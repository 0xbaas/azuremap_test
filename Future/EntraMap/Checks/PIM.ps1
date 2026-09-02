#==============================================================================
# AzureMap v2 - Products/EntraMap/Checks/PIM.ps1
# Evaluates PIM (Privileged Identity Management) assignment hygiene.
# Beta-gated: requires -UseGraphBeta for PIM data collection.
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraPIMEligibleAssignments {
    <#
    .SYNOPSIS
        Identifies principals with standing active role assignments where PIM-eligible
        assignments exist for the same role.
    .DESCRIPTION
        Compares standing active role assignments against PIM eligible/active schedules.
        Flags principals who have permanent standing access to privileged roles when
        PIM-eligible assignments exist for the same role, indicating the role should
        be activated through PIM instead.
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping PIM check" -Level WARN
        return
    }

    # Beta-gated: if no PIM data was collected, emit informational finding
    if (($entra.PIMEligible.Count -eq 0) -and ($entra.PIMActive.Count -eq 0)) {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "PIM data not collected -- use -UseGraphBeta to enable PIM analysis" `
            -Count          0 `
            -Service        "EntraPIM" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Run AzureMap with -UseGraphBeta flag to collect PIM eligible and active assignment data from beta Graph endpoints."
        return
    }

    $privLookup = $entra.PrivilegedRoleLookup
    $roleDefLookup = @{}
    foreach ($rd in $entra.RoleDefinitions) { $roleDefLookup[$rd.id] = $rd }

    # Build lookup: roleDefinitionId -> set of principalIds that have PIM eligible assignments
    $pimEligibleByRole = @{}
    foreach ($schedule in $entra.PIMEligible) {
        $roleDefId   = $schedule.roleDefinitionId
        $principalId = $schedule.principalId
        if (-not $roleDefId -or -not $principalId) { continue }

        if (-not $pimEligibleByRole.ContainsKey($roleDefId)) {
            $pimEligibleByRole[$roleDefId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        $null = $pimEligibleByRole[$roleDefId].Add($principalId)
    }

    # Build lookup: set of roles that have ANY PIM eligible assignment (role is PIM-managed)
    $pimManagedRoles = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($pimEligibleByRole.Keys),
        [System.StringComparer]::OrdinalIgnoreCase
    )

    # Build set of principalId+roleDefId from PIM active schedules (these are PIM-activated, not standing)
    $pimActivated = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($schedule in $entra.PIMActive) {
        $key = "$($schedule.principalId)|$($schedule.roleDefinitionId)"
        $null = $pimActivated.Add($key)
    }

    $evidence = [System.Collections.Generic.List[object]]::new()

    foreach ($assignment in $entra.RoleAssignments) {
        $roleDefId   = $assignment.roleDefinitionId
        $principalId = $assignment.principalId

        # Only flag if this role is PIM-managed (has eligible assignments)
        if (-not $pimManagedRoles.Contains($roleDefId)) { continue }

        # Check if this specific principal has a PIM eligible assignment for this role
        $hasPIMEligible = $false
        if ($pimEligibleByRole.ContainsKey($roleDefId)) {
            $hasPIMEligible = $pimEligibleByRole[$roleDefId].Contains($principalId)
        }

        # Skip if this is a PIM-activated assignment (not standing)
        $activatedKey = "$principalId|$roleDefId"
        if ($pimActivated.Contains($activatedKey)) { continue }

        $roleDef = $roleDefLookup[$roleDefId]
        if (-not $roleDef) { continue }

        $roleName   = $roleDef.displayName
        $templateId = if ($roleDef.templateId) { $roleDef.templateId } else { $roleDef.id }
        $isPrivileged = $privLookup.ContainsKey($templateId)

        if (-not $isPrivileged) { continue }

        $principal = $entra.PrincipalCache[$principalId]
        $principalName = if ($principal) { $principal.displayName } else { $principalId }
        $principalType = if ($principal) { $principal.type }        else { "unknown" }

        $evidence.Add([PSCustomObject]@{
            PrincipalId    = $principalId
            PrincipalName  = $principalName
            PrincipalType  = $principalType
            RoleName       = $roleName
            RoleCriticality = $privLookup[$templateId].criticality
            AssignmentType = "Standing-Active"
            HasPIMEligible = $hasPIMEligible
            Severity       = "HIGH"
        })
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $withEligible = ($evidence | Where-Object { $_.HasPIMEligible }).Count

        Write-Finding `
            -Severity       "HIGH" `
            -Message        "Standing active privileged assignments in PIM-managed roles ($withEligible principals also have PIM eligible, $totalCount total)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraPIM" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Convert standing active assignments to PIM-eligible. Require time-limited activation with MFA, justification, and approval for Critical roles. Remove duplicate standing assignments where PIM eligible exists."
    } else {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No standing active assignments found in PIM-managed roles" `
            -Count          0 `
            -Service        "EntraPIM" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
    }
}

function Register-EntraPIMChecks {
    <#
    .SYNOPSIS
        Registers the Entra PIM checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-02"
            Category        = "Entra"
            Service         = "EntraPIM"
            Name            = "Test-EntraPIMEligibleAssignments"
            Function        = "Test-EntraPIMEligibleAssignments"
            DefaultSeverity = "HIGH"
            RequiredModules = @()
            RequiredPerms   = @("RoleEligibilitySchedule.Read.Directory", "RoleAssignmentSchedule.Read.Directory")
            Phase           = "TenantWide"
            Description     = "PIM eligible vs standing active assignments for privileged roles"
        }
    )
}
