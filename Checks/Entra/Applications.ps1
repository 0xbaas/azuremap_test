#==============================================================================
# AzureMap v2 - Checks/Entra/Applications.ps1
# Evaluates service principal application permissions for escalation risk.
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraDangerousServicePrincipalPermissions {
    <#
    .SYNOPSIS
        Identifies service principals with dangerous Microsoft Graph permissions.
    .DESCRIPTION
        For each service principal, resolves its granted app role assignments,
        matches them against the permission escalation map, and flags SPs with
        critical or high-severity permissions.
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping dangerous SP permissions check" -Level WARN
        return
    }

    $permLookup = $entra.PermissionEscalationLookup

    # Build appRoleId -> permission value lookup from the Microsoft Graph SP
    # The Microsoft Graph SP appId is the well-known 00000003-0000-0000-c000-000000000000
    $appRoleValueById = @{}
    $graphSP = $entra.ServicePrincipals | Where-Object { $_.appId -eq '00000003-0000-0000-c000-000000000000' } | Select-Object -First 1
    if ($graphSP -and $graphSP.appRoles) {
        foreach ($role in $graphSP.appRoles) {
            $appRoleValueById[$role.id] = $role.value
        }
    }

    # Hardcoded fallback for the top dangerous permission appRoleIds (from appRoleIds.csv)
    $knownAppRoleIds = @{
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "RoleManagement.ReadWrite.Directory"
        "bdfbf15f-ee85-4955-8571-bf3be0e87060" = "Domain.ReadWrite.All"
        "06b708a9-e830-4db3-a914-8e69da51d44f" = "AppRoleAssignment.ReadWrite.All"
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All"
        "62a82d76-70ea-41e2-9197-370581804d09" = "Group.ReadWrite.All"
        "9241abd9-d0e6-425a-bd4f-47ba86d767a4" = "DeviceManagementConfiguration.ReadWrite.All"
        "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Mail.ReadWrite"
        "741f803b-c850-494e-b5df-cde7c675a1ca" = "User.ReadWrite.All"
        "01c0a623-fc9b-48e9-b794-0756f8e8f067" = "Policy.ReadWrite.ConditionalAccess"
        "6931bccd-447a-43d1-b442-00a195474933" = "MailboxSettings.ReadWrite"
        "9492366f-7969-46a4-8d15-ed1a20078fff" = "Sites.ReadWrite.All"
        "75359482-378d-4052-8f01-80520e7db3cd" = "Files.ReadWrite.All"
        "dc50a0fb-09a3-484d-be87-e023b12c6440" = "Exchange.ManageAsApp"
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "Directory.ReadWrite.All"
        "dbaae8cf-10b5-4b86-a4a1-f871c94c6571" = "GroupMember.ReadWrite.All"
        "89c8469c-83ad-45f7-8ff2-6571f6b0feec" = "ServicePrincipalEndpoint.ReadWrite.All"
        "8e8e4742-1d95-4f68-9d56-6ee75648c72a" = "DelegatedPermissionGrant.ReadWrite.All"
        "292d869f-3427-49a8-9dab-8c70152b74e9" = "Organization.ReadWrite.All"
        "1138cb37-bd11-4084-a2b7-9f71582aeddb" = "Device.ReadWrite.All"
        "ef5f7d5c-338f-44b0-86c3-351f46c8bb5f" = "AccessReview.ReadWrite.All"
        "32531c59-1f32-461f-b8df-6f8a3b89f73b" = "PrivilegedAccess.ReadWrite.AzureADGroup"
        "9acd699f-1e81-4958-b001-93b1d2f6baf2" = "EntitlementManagement.ReadWrite.All"
        "1ff1be21-34eb-448c-9ac9-ce1f506b2a68" = "RoleManagementPolicy.ReadWrite.Directory"
        "50483e42-d915-4231-9639-7fdb7fd190e5" = "UserAuthenticationMethod.ReadWrite.All"
    }

    $evidence = [System.Collections.Generic.List[object]]::new()

    foreach ($sp in $entra.ServicePrincipals) {
        $spId = $sp.id
        if (-not $entra.SPPermissions.ContainsKey($spId)) { continue }

        $assignments = $entra.SPPermissions[$spId]
        $dangerousPerms = [System.Collections.Generic.List[object]]::new()
        $highestSeverityRank = 0

        foreach ($assignment in $assignments) {
            $appRoleId = $assignment.appRoleId
            if (-not $appRoleId -or $appRoleId -eq '00000000-0000-0000-0000-000000000000') { continue }

            $permValue = $null
            if ($appRoleValueById.ContainsKey($appRoleId)) {
                $permValue = $appRoleValueById[$appRoleId]
            } elseif ($knownAppRoleIds.ContainsKey($appRoleId)) {
                $permValue = $knownAppRoleIds[$appRoleId]
            }

            if (-not $permValue) { continue }
            if (-not $permLookup.ContainsKey($permValue)) { continue }

            $permMeta = $permLookup[$permValue]
            $sevRank = switch ($permMeta.severity) {
                "Critical" { 3 }
                "High"     { 2 }
                "Medium"   { 1 }
                default    { 0 }
            }
            if ($sevRank -gt $highestSeverityRank) { $highestSeverityRank = $sevRank }

            $dangerousPerms.Add([PSCustomObject]@{
                Permission     = $permValue
                Severity       = $permMeta.severity
                AttackPath     = $permMeta.attackPath
                Recommendation = $permMeta.recommendation
            })
        }

        if ($dangerousPerms.Count -gt 0) {
            $highestSeverity = switch ($highestSeverityRank) {
                3 { "CRITICAL" }
                2 { "HIGH" }
                1 { "MEDIUM" }
                default { "MEDIUM" }
            }

            $evidence.Add([PSCustomObject]@{
                SPId                = $spId
                DisplayName         = $sp.displayName
                AppId               = $sp.appId
                AccountEnabled      = $sp.accountEnabled
                DangerousPermissions = $dangerousPerms
                PermissionCount     = $dangerousPerms.Count
                HighestSeverity     = $highestSeverity
                Severity            = $highestSeverity
            })
        }
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $maxSeverity = ($evidence | Sort-Object @{
            Expression = { switch ($_.HighestSeverity) { "CRITICAL" { 0 } "HIGH" { 1 } "MEDIUM" { 2 } default { 3 } } }
        } | Select-Object -First 1).HighestSeverity

        Write-Finding `
            -Severity       $maxSeverity `
            -Message        "Service principals with dangerous Microsoft Graph application permissions ($totalCount SPs flagged)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraApps" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Review and reduce application permissions to least privilege. Move to managed identities where possible. Enforce app instance property locks for critical workloads."
    } else {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No service principals with dangerous application permissions found" `
            -Count          0 `
            -Service        "EntraApps" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
    }
}

function Register-EntraApplicationsChecks {
    <#
    .SYNOPSIS
        Registers the Entra Applications checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-03"
            Category        = "Entra"
            Service         = "EntraApps"
            Name            = "Test-EntraDangerousServicePrincipalPermissions"
            Function        = "Test-EntraDangerousServicePrincipalPermissions"
            DefaultSeverity = "CRITICAL"
            RequiredModules = @()
            RequiredPerms   = @("Application.Read.All")
            Phase           = "TenantWide"
            Description     = "Service principals with high-impact Graph application permissions"
        }
    )
}
