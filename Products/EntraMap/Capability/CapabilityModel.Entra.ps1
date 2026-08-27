#==============================================================================
# AzureMap v2 - Products/EntraMap/Capability/CapabilityModel.Entra.ps1
# EntraMap capability / attack-path modeling (READ-ONLY MODELING ONLY):
# ten Entra insight builders and Build-EntraCapabilityModel, mirroring
# Core/Azure/CapabilityModel.Azure.ps1. Shared primitives (New-CapabilityContext,
# Add-CapabilityNode/Edge/Insight, caps, severity rank, Get-CapabilityEvidenceRows)
# live in Core/Capability.ps1 and are reused unchanged.
#
# Builds a capability graph (nodes/edges) plus grouped capability insights from
# data that is ALREADY collected during the run: finding evidence rows
# ($script:State.Results), the Entra collection ($script:State.Entra, mainly
# PrincipalCache for guest/external classification), the tenant-wide data
# ($script:State.TenantWideData) and the tenant footprint
# ($script:State.EntraFootprint). ZERO Graph/Azure API calls are made here.
#
# HARD SAFETY CONTRACT:
#   - This module performs NO Graph/Azure API calls of any kind. It reads only
#     in-memory state produced earlier in the run. It must never call
#     Get-GraphToken / Invoke-GraphCommand / Invoke-GraphBatch / Get-Az* /
#     Invoke-RestMethod or any write API.
#   - It never retrieves secrets, tokens, keys, certificates or content. App
#     credential handling is limited to metadata already collected
#     (displayName/keyId/start/end). Modeled capabilities are hypotheses about
#     what a principal/app COULD do, expressed only where collected metadata
#     already proves the building blocks. Unit tests grep this file to enforce
#     the contract.
#
# Severity discipline (same as Azure): CRITICAL only when multiple confirmed
# conditions combine into a realistic high-impact path; HIGH for a strong
# capability path with one condition to review; MEDIUM for context-dependent
# capability; LOW/INFO for weak signals. Confidence: High = directly confirmed
# by collected metadata, Medium = inferred combination, Low = manual
# validation required.
#==============================================================================

# External/guest marker in Entra UPNs (B2B guests carry '#EXT#' in their UPN).
$script:EntraCapGuestMarker = '#EXT#'

# FIC subject patterns that indicate broad external trust (any branch/PR).
$script:EntraCapBroadFicPattern = '(?i)(wildcard|\*|main branch|:main\b|broad trust|any branch|pull.request)'

function Get-EntraCapIsGuest {
    <#
    .SYNOPSIS
        Classifies a principal as external/guest from ALREADY-COLLECTED
        directory data (State.Entra.PrincipalCache UPN) with a display-name
        fallback. Never fetches.
    .OUTPUTS
        [hashtable] @{ IsGuest = [bool]; Confidence = 'High'|'Medium' }
        High = confirmed via collected UPN; Medium = display-name heuristic.
    #>
    [CmdletBinding()]
    param(
        [string]$PrincipalId,
        [string]$DisplayName
    )

    $entra = $script:State.Entra
    if ($entra -and $entra.PrincipalCache -and $PrincipalId -and $entra.PrincipalCache.ContainsKey($PrincipalId)) {
        $entry = $entra.PrincipalCache[$PrincipalId]
        $upn = "$($entry.upn)"
        if ($upn) {
            return @{ IsGuest = ($upn -match [regex]::Escape($script:EntraCapGuestMarker)); Confidence = 'High' }
        }
    }
    if ($DisplayName -and "$DisplayName" -match [regex]::Escape($script:EntraCapGuestMarker)) {
        return @{ IsGuest = $true; Confidence = 'Medium' }
    }
    return @{ IsGuest = $false; Confidence = 'Medium' }
}

function Get-EntraCapAdminMfaGap {
    <# Returns $true when ENTRA-09 evidence proves no enabled admin-MFA policy. #>
    [CmdletBinding()]
    param()
    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-09'))
    foreach ($r in $rows) {
        if ("$($r.Gap)" -match '(?i)MFA for directory \(admin\) roles') { return $true }
    }
    return $false
}

function Get-EntraCapGuestMfaGap {
    <# Returns $true when ENTRA-09 evidence proves no enabled guest-MFA policy. #>
    [CmdletBinding()]
    param()
    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-09'))
    foreach ($r in $rows) {
        if ("$($r.Gap)" -match '(?i)MFA for guest/external users') { return $true }
    }
    return $false
}

#------------------------------------------------------------------------------
# Insight builders (one per modeled capability)
#------------------------------------------------------------------------------

function Invoke-EntraCapPermanentPrivilegedAssignment {
    <#
    .SYNOPSIS
        Insight 1: permanent (standing) privileged directory role assignments.
    .DESCRIPTION
        ENTRA-01 evidence = standing assignments directly confirmed by
        collected role data. Base HIGH for Critical-privilege roles, MEDIUM
        otherwise. Escalates to CRITICAL only when multiple confirmed
        conditions combine: a Critical-role standing assignment whose
        principal has NO PIM-eligible counterpart (ENTRA-02) AND no enabled
        admin-MFA Conditional Access policy (ENTRA-09) - a permanent,
        immediately usable, MFA-unprotected privileged path.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-01'))
    if ($rows.Count -eq 0) { return }

    # Standing-active-without-eligible principals from ENTRA-02 (PIM analysis).
    $noEligible = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-02'))) {
        if ($r.HasPIMEligible -eq $false) { $noEligible["$($r.PrincipalId)|$($r.RoleName)"] = $true }
    }
    $adminMfaGap = Get-EntraCapAdminMfaGap

    $byPrincipal = @{}
    foreach ($r in $rows) {
        $pkey = "$($r.PrincipalId)"
        if (-not $pkey) { continue }
        if (-not $byPrincipal.ContainsKey($pkey)) {
            $byPrincipal[$pkey] = [PSCustomObject]@{
                PrincipalId   = "$($r.PrincipalId)"
                Name          = $(if ($r.PrincipalDisplayName) { "$($r.PrincipalDisplayName)" } else { "$($r.PrincipalId)" })
                Type          = "$($r.PrincipalType)"
                Roles         = New-Object System.Collections.Generic.List[object]
                WorstEscalated = $false
                HighestCrit   = ''
            }
        }
        $p = $byPrincipal[$pkey]
        $crit = "$($r.RoleCriticality)"
        $roleName = "$($r.RoleName)"
        $p.Roles.Add([PSCustomObject]@{ Role = $roleName; Criticality = $crit })
        $rank = switch ($crit) { 'Critical' { 1 } 'High' { 2 } default { 3 } }
        $curRank = switch ($p.HighestCrit) { 'Critical' { 1 } 'High' { 2 } '' { 9 } default { 3 } }
        if ($rank -lt $curRank) { $p.HighestCrit = $crit }
        if ($crit -eq 'Critical' -and $noEligible.ContainsKey("$($r.PrincipalId)|$roleName") -and $adminMfaGap) {
            $p.WorstEscalated = $true
        }
    }

    $impactedCrit = New-Object System.Collections.Generic.List[string]
    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    foreach ($pkey in @($byPrincipal.Keys | Sort-Object)) {
        $p = $byPrincipal[$pkey]
        $pNodeId = "principal|$($p.PrincipalId)"
        [void](Add-CapabilityNode -Context $Context -Id $pNodeId -Type 'Principal' -Name $p.Name -Scope 'Tenant' -Sensitivity 'High')
        $roleNames = @($p.Roles | ForEach-Object { $_.Role } | Sort-Object -Unique)
        foreach ($rn in $roleNames) {
            $rNodeId = "role|$($rn.ToLower())"
            [void](Add-CapabilityNode -Context $Context -Id $rNodeId -Type 'DirectoryRole' -Name $rn -Scope 'Tenant' -Sensitivity 'High')
            [void](Add-CapabilityEdge -Context $Context -From $pNodeId -To $rNodeId `
                -Type 'HasStandingAssignment' -Capability 'Permanent privileged directory role usage (modeled)' `
                -SourceCheckIds @('ENTRA-01', 'ENTRA-02') -Confidence 'High' `
                -Severity $(if ($p.WorstEscalated) { 'CRITICAL' } elseif ($p.HighestCrit -eq 'Critical') { 'HIGH' } else { 'MEDIUM' }) `
                -Reason "Standing (non-PIM) assignment of '$rn' confirmed by collected role assignment data.")
        }
        $text = "$($p.Name) ($($p.Type)) - standing: $($roleNames -join ', ')"
        if ($p.WorstEscalated)            { $impactedCrit.Add($text + '; no PIM eligible + no admin-MFA CA policy') }
        elseif ($p.HighestCrit -eq 'Critical' -or $p.HighestCrit -eq 'High') { $impactedHigh.Add($text) }
        else                              { $impactedMed.Add($text) }
    }

    $total = $impactedCrit.Count + $impactedHigh.Count + $impactedMed.Count
    if ($total -eq 0) { return }

    $sev = 'MEDIUM'
    if ($impactedCrit.Count -gt 0) { $sev = 'CRITICAL' }
    elseif ($impactedHigh.Count -gt 0) { $sev = 'HIGH' }

    Add-CapabilityInsight -Context $Context `
        -Title 'Permanent privileged role assignments' `
        -Description 'Principals hold standing (always-active) privileged directory role assignments. Standing access is usable at any time without activation, approval or justification. Severity escalates only where collected data confirms the combination: Critical role + no PIM-eligible counterpart + no enabled admin-MFA Conditional Access policy.' `
        -Severity $sev -Confidence 'High' `
        -SourceCheckIds @('ENTRA-01', 'ENTRA-02', 'ENTRA-09') `
        -ImpactedResources (@($impactedCrit.ToArray()) + @($impactedHigh.ToArray()) + @($impactedMed.ToArray())) `
        -ImpactedResourceCount $total -ResourceUnit 'principals' `
        -EvidenceSummary "$total principal(s) with standing privileged assignments: $($impactedCrit.Count) with the confirmed no-PIM + no-admin-MFA combination, $($impactedHigh.Count) with Critical/High-privilege roles." `
        -RecommendedReview 'Convert standing assignments to PIM-eligible with time-limited activation, MFA and approval. Verify every Critical-role holder is covered by an enforced admin-MFA Conditional Access policy.'
}

function Invoke-EntraCapPimWithoutStrongControls {
    <#
    .SYNOPSIS
        Insight 2: PIM-eligible privileged roles without strong activation
        controls (inferred combination).
    .DESCRIPTION
        PIM is in use (ENTRA-02 evidence shows eligible assignments), but
        collected policy data shows weak surrounding controls: no enabled
        admin-MFA CA policy (ENTRA-09) and/or phishable authentication methods
        enabled tenant-wide (ENTRA-10). MEDIUM context-dependent; HIGH when
        both control gaps are present. Confidence Medium (inferred).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $pimRows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-02'))
    $withEligible = @($pimRows | Where-Object { $_.HasPIMEligible -eq $true })
    if ($withEligible.Count -eq 0) { return }

    $adminMfaGap = Get-EntraCapAdminMfaGap
    $weakMethods = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-10'))) {
        if ("$($r.Method)") { $weakMethods["$($r.Method)"] = $true }
    }
    if (-not $adminMfaGap -and $weakMethods.Count -eq 0) { return }

    $conditions = New-Object System.Collections.Generic.List[string]
    if ($adminMfaGap)          { $conditions.Add('no enabled admin-MFA Conditional Access policy') }
    if ($weakMethods.Count -gt 0) { $conditions.Add("weak authentication methods enabled ($((@($weakMethods.Keys) | Sort-Object) -join ', '))") }

    $impacted = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in $withEligible) {
        $key = "$($r.PrincipalId)|$($r.RoleName)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $impacted.Add("$($r.PrincipalName) - eligible+standing: $($r.RoleName)")
    }

    $sev = $(if ($adminMfaGap -and $weakMethods.Count -gt 0) { 'HIGH' } else { 'MEDIUM' })

    Add-CapabilityInsight -Context $Context `
        -Title 'PIM-eligible privileged roles without strong activation controls' `
        -Description 'Principals hold PIM-eligible privileged roles, but collected policy data indicates weak activation-time controls. PIM eligibility only reduces exposure when activation is protected by strong authentication; with the listed gaps an eligible role may be activatable with phishable or MFA-less sign-in. Inferred combination - manual validation of PIM activation policies recommended.' `
        -Severity $sev -Confidence 'Medium' `
        -SourceCheckIds @('ENTRA-02', 'ENTRA-09', 'ENTRA-10') `
        -ImpactedResources $impacted -ResourceUnit 'principals' `
        -EvidenceSummary "$($impacted.Count) principal-role pair(s) with PIM-eligible privileged roles; conditions: $($conditions -join '; ')." `
        -RecommendedReview 'Require MFA (preferably phishing-resistant) for PIM activation, enforce an admin-MFA Conditional Access policy, and disable SMS/Voice authentication methods.'
}

function Invoke-EntraCapPrivilegedAppPermissions {
    <#
    .SYNOPSIS
        Insight 3: apps/service principals with high-privilege Graph
        application permissions (directly confirmed).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-03'))
    if ($rows.Count -eq 0) { return }

    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in $rows) {
        $spId = "$($r.SPId)"
        if (-not $spId -or $seen.ContainsKey($spId)) { continue }
        $seen[$spId] = $true
        $perms = @($r.DangerousPermissions)
        $aNodeId = "app|$spId"
        [void](Add-CapabilityNode -Context $Context -Id $aNodeId -Type 'Application' -Name "$($r.DisplayName)" -Scope 'Tenant' -Sensitivity 'High')
        [void](Add-CapabilityNode -Context $Context -Id 'graph|microsoft' -Type 'ApiSurface' -Name 'Microsoft Graph' -Scope 'Tenant' -Sensitivity 'High')
        [void](Add-CapabilityEdge -Context $Context -From $aNodeId -To 'graph|microsoft' `
            -Type 'HasAppPermission' -Capability 'High-privilege Graph application permission usage (modeled)' `
            -SourceCheckIds @('ENTRA-03') -Confidence 'High' `
            -Severity $(if ("$($r.HighestSeverity)" -eq 'CRITICAL') { 'HIGH' } else { 'MEDIUM' }) `
            -Reason "App role assignments granting $($perms.Count) dangerous permission(s) confirmed by collected Graph data.")
        $permText = (@($perms | Select-Object -First 3) -join ', ')
        if ($perms.Count -gt 3) { $permText += " +$($perms.Count - 3) more" }
        $text = "$($r.DisplayName) - $permText"
        if ("$($r.HighestSeverity)" -eq 'CRITICAL') { $impactedHigh.Add($text) } else { $impactedMed.Add($text) }
    }

    $total = $impactedHigh.Count + $impactedMed.Count
    if ($total -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Applications with high-privilege Graph permissions' `
        -Description 'Service principals hold Microsoft Graph application permissions that allow tenant-wide impact (e.g. directory read/write, role management). Whoever controls one of these app identities - via a credential, an owner, or a federated trust - can use those permissions directly. Confirmed by collected app role assignment data.' `
        -Severity $(if ($impactedHigh.Count -gt 0) { 'HIGH' } else { 'MEDIUM' }) -Confidence 'High' `
        -SourceCheckIds @('ENTRA-03') `
        -ImpactedResources (@($impactedHigh.ToArray()) + @($impactedMed.ToArray())) `
        -ImpactedResourceCount $total -ResourceUnit 'applications' `
        -EvidenceSummary "$total service principal(s) with dangerous Graph application permissions ($($impactedHigh.Count) with critical-tier permissions)." `
        -RecommendedReview 'Reduce each app to least privilege, prefer managed identities, and review who/what can use each app identity (owners, credentials, federated credentials).'
}

function Invoke-EntraCapDangerousPermsWeakOwnership {
    <#
    .SYNOPSIS
        Insight 4: dangerous Graph permissions AND weak ownership (combined
        escalation path).
    .DESCRIPTION
        Joins ENTRA-03 (SP/app has dangerous permissions) with ENTRA-04
        (non-admin owner of that same SP/app). Both conditions are directly
        confirmed by collected metadata; combined they form a realistic
        high-impact path: a non-admin owner can add a credential to the app
        and then use its tenant-wide Graph permissions. CRITICAL by design.
        Apps with only weak signals (e.g. many owners but no dangerous
        permissions) do NOT produce this insight.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $dangerous = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-03'))) {
        if ("$($r.SPId)") { $dangerous["$($r.SPId)"] = "$($r.DisplayName)" }
    }
    if ($dangerous.Count -eq 0) { return }

    $impacted = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-04'))) {
        if ("$($r.RiskType)" -notlike 'NonAdminOwnerOfPrivileged*') { continue }
        $targetId = "$($r.TargetId)"
        if (-not $dangerous.ContainsKey($targetId)) { continue }
        $key = "$targetId|$($r.OwnerId)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $aNodeId = "app|$targetId"
        $oNodeId = "principal|$($r.OwnerId)"
        [void](Add-CapabilityNode -Context $Context -Id $aNodeId -Type 'Application' -Name "$($r.TargetDisplayName)" -Scope 'Tenant' -Sensitivity 'High')
        [void](Add-CapabilityNode -Context $Context -Id $oNodeId -Type 'Principal' -Name "$($r.OwnerName)" -Scope 'Tenant')
        [void](Add-CapabilityEdge -Context $Context -From $oNodeId -To $aNodeId `
            -Type 'CanAddCredentials' -Capability 'Credential injection into privileged app (modeled)' `
            -SourceCheckIds @('ENTRA-03', 'ENTRA-04') -Confidence 'High' -Severity 'CRITICAL' `
            -Reason "Non-admin owner confirmed by collected ownership data; app holds dangerous Graph permissions confirmed by collected app role assignments. Owner could add a credential and use the app's permissions.")
        $impacted.Add("$($r.TargetDisplayName) - non-admin owner $($r.OwnerName); perms: $($r.DangerousPermissions)")
    }

    if ($impacted.Count -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Dangerous app permissions combined with weak ownership' `
        -Description 'Applications/service principals hold dangerous tenant-wide Graph permissions AND have non-administrator owners. An owner of an app can register additional credentials on it; combined with the confirmed dangerous permissions this is a realistic privilege-escalation path from a non-admin account to tenant-wide impact. Both conditions are directly confirmed by collected metadata.' `
        -Severity 'CRITICAL' -Confidence 'High' `
        -SourceCheckIds @('ENTRA-03', 'ENTRA-04') `
        -ImpactedResources $impacted -ResourceUnit 'applications' `
        -EvidenceSummary "$($impacted.Count) owner/app combination(s) where a non-admin owner controls an app with dangerous Graph permissions." `
        -RecommendedReview 'Remove non-admin owners from privileged apps, enable app instance property locks, and reduce the apps'' Graph permissions to least privilege.'
}

function Invoke-EntraCapLongLivedCredentials {
    <#
    .SYNOPSIS
        Insight 5: long-lived app credentials (metadata only - expiry dates,
        never secret values).
    .DESCRIPTION
        ENTRA-07 LongLivedCredential rows. MEDIUM context-dependent; HIGH when
        the same app also holds dangerous Graph permissions (ENTRA-03), because
        a leaked long-lived credential then yields tenant-wide impact.
        Expired-credential and multiple-active-credential rows are weak
        signals and intentionally produce NO insight.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-07'))
    $rows = @($rows | Where-Object { "$($_.FindingType)" -eq 'LongLivedCredential' })
    if ($rows.Count -eq 0) { return }

    $dangerousApps = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-03'))) {
        if ("$($r.AppId)")       { $dangerousApps["$($r.AppId)"] = $true }
        if ("$($r.DisplayName)") { $dangerousApps["name|$($r.DisplayName)"] = $true }
    }

    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in $rows) {
        $appKey = "$($r.AppId)|$($r.KeyId)"
        if ($seen.ContainsKey($appKey)) { continue }
        $seen[$appKey] = $true
        $isDangerous = $dangerousApps.ContainsKey("$($r.AppId)") -or $dangerousApps.ContainsKey("name|$($r.AppName)")
        $sev = $(if ($isDangerous) { 'HIGH' } else { 'MEDIUM' })
        $text = "$($r.AppName) - $($r.CredentialType) credential valid until $($r.ExpiryDate) ($($r.DaysUntilExpiry) days)"
        if ($isDangerous) { $impactedHigh.Add($text + '; app also holds dangerous Graph permissions') }
        else              { $impactedMed.Add($text) }
    }

    $total = $impactedHigh.Count + $impactedMed.Count
    if ($total -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Long-lived application credentials' `
        -Description 'Application credentials (secret/certificate) remain valid far beyond recommended rotation periods. A long-lived credential widens the window in which a leak stays exploitable; where the same app also holds dangerous Graph permissions, a single leaked credential is a tenant-wide compromise path. Modeled from credential metadata only - no secret values were read.' `
        -Severity $(if ($impactedHigh.Count -gt 0) { 'HIGH' } else { 'MEDIUM' }) -Confidence 'High' `
        -SourceCheckIds @('ENTRA-07', 'ENTRA-03') `
        -ImpactedResources (@($impactedHigh.ToArray()) + @($impactedMed.ToArray())) `
        -ImpactedResourceCount $total -ResourceUnit 'credentials' `
        -EvidenceSummary "$total long-lived credential(s) ($($impactedHigh.Count) on apps that also hold dangerous Graph permissions)." `
        -RecommendedReview 'Rotate long-lived credentials, prefer short-lived certificates or managed identities / workload identity federation, and prioritize apps that also hold dangerous permissions.'
}

function Invoke-EntraCapRoleAssignableGroups {
    <#
    .SYNOPSIS
        Insight 6: role-assignable groups with risky membership (indirect
        standing privilege).
    .DESCRIPTION
        ENTRA-05 evidence. HIGH for groups holding privileged roles (every
        member - and every group owner, who can add members - effectively
        holds the role); MEDIUM otherwise. Confidence High where the role
        assignment is collected, Medium otherwise.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-05'))
    if ($rows.Count -eq 0) { return }

    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in $rows) {
        $gid = "$($r.GroupId)"
        if (-not $gid -or $seen.ContainsKey($gid)) { continue }
        $seen[$gid] = $true
        $holdsPriv = ($r.HoldsPrivRole -eq $true)
        $gNodeId = "group|$gid"
        [void](Add-CapabilityNode -Context $Context -Id $gNodeId -Type 'Group' -Name "$($r.GroupName)" -Scope 'Tenant' -Sensitivity $(if ($holdsPriv) { 'High' } else { 'Medium' }))
        foreach ($rn in @($r.AssignedRoles)) {
            $rNodeId = "role|$("$rn".ToLower())"
            [void](Add-CapabilityNode -Context $Context -Id $rNodeId -Type 'DirectoryRole' -Name "$rn" -Scope 'Tenant' -Sensitivity 'High')
            [void](Add-CapabilityEdge -Context $Context -From $gNodeId -To $rNodeId `
                -Type 'GroupConfersRole' -Capability 'Indirect privileged role via group membership (modeled)' `
                -SourceCheckIds @('ENTRA-05') -Confidence $(if ($holdsPriv) { 'High' } else { 'Medium' }) `
                -Severity $(if ($holdsPriv) { 'HIGH' } else { 'MEDIUM' }) `
                -Reason "Role-assignable group confirmed by collected group and role assignment data; members and owners gain or control the role.")
        }
        $text = "$($r.GroupName) - $($r.MemberCount) member(s), roles: $(@($r.AssignedRoles) -join ', ')"
        if ($holdsPriv) { $impactedHigh.Add($text) } else { $impactedMed.Add($text) }
    }

    $total = $impactedHigh.Count + $impactedMed.Count
    if ($total -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Role-assignable groups conferring indirect privilege' `
        -Description 'Role-assignable security groups pass their directory roles to every member, and group owners can add members at will - an indirect, easily overlooked standing-privilege path. Groups confirmed to hold privileged roles are the priority.' `
        -Severity $(if ($impactedHigh.Count -gt 0) { 'HIGH' } else { 'MEDIUM' }) `
        -Confidence $(if ($impactedHigh.Count -gt 0) { 'High' } else { 'Medium' }) `
        -SourceCheckIds @('ENTRA-05') `
        -ImpactedResources (@($impactedHigh.ToArray()) + @($impactedMed.ToArray())) `
        -ImpactedResourceCount $total -ResourceUnit 'groups' `
        -EvidenceSummary "$total role-assignable group(s) ($($impactedHigh.Count) holding privileged roles)." `
        -RecommendedReview 'Protect membership with PIM for Groups, restrict group owners to privileged administrators, and enable access reviews on all role-assignable groups.'
}

function Invoke-EntraCapGuestPrivilegedAccess {
    <#
    .SYNOPSIS
        Insight 7: external/guest users with privileged directory access.
    .DESCRIPTION
        ENTRA-01 standing privileged assignments whose principal is a B2B
        guest ('#EXT#' in the collected UPN = High confidence; display-name
        match = Medium). HIGH for a guest with standing privileged access;
        CRITICAL when additionally no enabled guest-MFA CA policy exists
        (ENTRA-09) - external identity + standing privilege + no MFA
        enforcement is a confirmed multi-condition exposure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-01'))
    if ($rows.Count -eq 0) { return }

    $guestMfaGap = Get-EntraCapGuestMfaGap

    $impacted = New-Object System.Collections.Generic.List[string]
    $confidence = 'High'
    $seen = @{}
    foreach ($r in $rows) {
        $g = Get-EntraCapIsGuest -PrincipalId "$($r.PrincipalId)" -DisplayName "$($r.PrincipalDisplayName)"
        if (-not $g.IsGuest) { continue }
        $key = "$($r.PrincipalId)|$($r.RoleName)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        if ($g.Confidence -ne 'High') { $confidence = 'Medium' }

        $pNodeId = "principal|$($r.PrincipalId)"
        $rNodeId = "role|$("$($r.RoleName)".ToLower())"
        [void](Add-CapabilityNode -Context $Context -Id $pNodeId -Type 'ExternalPrincipal' -Name "$($r.PrincipalDisplayName)" -Scope 'Tenant' -Sensitivity 'High' -Exposure 'External')
        [void](Add-CapabilityNode -Context $Context -Id $rNodeId -Type 'DirectoryRole' -Name "$($r.RoleName)" -Scope 'Tenant' -Sensitivity 'High')
        [void](Add-CapabilityEdge -Context $Context -From $pNodeId -To $rNodeId `
            -Type 'ExternalStandingAssignment' -Capability 'External identity with privileged directory access (modeled)' `
            -SourceCheckIds @('ENTRA-01', 'ENTRA-09') -Confidence $g.Confidence `
            -Severity $(if ($guestMfaGap) { 'CRITICAL' } else { 'HIGH' }) `
            -Reason 'Guest/external account holds a standing privileged role assignment confirmed by collected directory data.')
        $impacted.Add("$($r.PrincipalDisplayName) (external) - standing: $($r.RoleName)")
    }

    if ($impacted.Count -eq 0) { return }

    $sev = $(if ($guestMfaGap) { 'CRITICAL' } else { 'HIGH' })
    $extra = $(if ($guestMfaGap) { ' No enabled Conditional Access policy requires MFA for guest/external users, so this external privileged sign-in may not be MFA-protected.' } else { '' })

    Add-CapabilityInsight -Context $Context `
        -Title 'External/guest users with privileged access' `
        -Description "External (B2B guest) identities hold standing privileged directory roles. Guest accounts are governed by their home tenant's security posture, not yours - privileged access for external identities is a high-impact exposure by itself.$extra" `
        -Severity $sev -Confidence $confidence `
        -SourceCheckIds @('ENTRA-01', 'ENTRA-09') `
        -ImpactedResources $impacted -ResourceUnit 'external principals' `
        -EvidenceSummary "$($impacted.Count) external principal-role assignment(s) confirmed from collected directory and role data." `
        -RecommendedReview 'Remove privileged roles from guest accounts or convert to PIM-eligible with approval, enforce guest-MFA Conditional Access, and review whether the external access is still required.'
}

function Invoke-EntraCapBreakGlassHygiene {
    <#
    .SYNOPSIS
        Insight 8: break-glass / Global Administrator hygiene gaps.
    .DESCRIPTION
        ENTRA-11 evidence. Count-based risks (GA count outside 2-5, disabled
        break-glass account) are directly confirmed -> High confidence.
        Naming-heuristic rows (carry a Limitation) need manual validation ->
        Low confidence. Severity MEDIUM (hygiene / resilience context).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-11'))
    if ($rows.Count -eq 0) { return }

    $impacted = New-Object System.Collections.Generic.List[string]
    $hasConfirmed = $false
    $hasHeuristic = $false
    $seen = @{}
    foreach ($r in $rows) {
        $risk = "$($r.Risk)"
        if (-not $risk -or $seen.ContainsKey($risk)) { continue }
        $seen[$risk] = $true
        if ($r.PSObject.Properties.Name -contains 'Limitation' -and $r.Limitation) { $hasHeuristic = $true }
        else { $hasConfirmed = $true }
        $impacted.Add($risk)
    }
    if ($impacted.Count -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Break-glass and Global Administrator hygiene gaps' `
        -Description 'Emergency-access posture deviates from recommended practice (Global Administrator count outside the 2-5 resilience window, missing or disabled break-glass accounts). A broken break-glass path turns an MFA/Conditional Access outage or account lockout into a tenant lockout; too many standing GAs widens the attack surface.' `
        -Severity 'MEDIUM' -Confidence $(if ($hasConfirmed) { 'High' } elseif ($hasHeuristic) { 'Low' } else { 'Medium' }) `
        -SourceCheckIds @('ENTRA-11') `
        -ImpactedResources $impacted -ResourceUnit 'risks' `
        -EvidenceSummary "$($impacted.Count) break-glass / Global Administrator hygiene risk(s) identified from collected role and principal data." `
        -RecommendedReview 'Maintain 2-5 Global Administrators including at least one enabled, monitored break-glass account excluded from MFA-blocking policies; validate heuristic findings manually.'
}

function Invoke-EntraCapWorkloadIdentityPlusPerms {
    <#
    .SYNOPSIS
        Insight 9: workload identity federation combined with broad/high-
        privilege app permissions.
    .DESCRIPTION
        Joins ENTRA-12 (risky federated identity credentials) with ENTRA-03
        (dangerous Graph permissions) by AppId. A broad-trust FIC
        (wildcard/main-branch subject) on an app that also holds dangerous
        permissions is a confirmed multi-condition path (external repo/CI
        compromise -> token exchange -> tenant-wide Graph impact): CRITICAL.
        A narrower FIC risk on a privileged app: HIGH. FICs on apps WITHOUT
        dangerous permissions produce no insight here (the check already
        reports them).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $ficRows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-12'))
    if ($ficRows.Count -eq 0) { return }

    $dangerousByAppId = @{}
    foreach ($r in @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-03'))) {
        if ("$($r.AppId)") { $dangerousByAppId["$($r.AppId)".ToLower()] = "$($r.DisplayName)" }
    }
    if ($dangerousByAppId.Count -eq 0) { return }

    $impactedCrit = New-Object System.Collections.Generic.List[string]
    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in $ficRows) {
        $appId = "$($r.AppId)".ToLower()
        if (-not $appId -or -not $dangerousByAppId.ContainsKey($appId)) { continue }
        $key = "$appId|$($r.Subject)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $broad = ("$($r.Risk)" -match $script:EntraCapBroadFicPattern) -or ("$($r.Subject)" -match '\*')
        $sev = $(if ($broad) { 'CRITICAL' } else { 'HIGH' })

        $aNodeId = "app|$appId"
        [void](Add-CapabilityNode -Context $Context -Id $aNodeId -Type 'Application' -Name "$($r.AppDisplayName)" -Scope 'Tenant' -Sensitivity 'High' -Exposure 'ExternalTrust')
        [void](Add-CapabilityNode -Context $Context -Id "fic|$appId" -Type 'FederatedTrust' -Name "$($r.Issuer)" -Scope 'External' -Sensitivity 'Medium')
        [void](Add-CapabilityEdge -Context $Context -From "fic|$appId" -To $aNodeId `
            -Type 'ExternalTokenExchange' -Capability 'External identity token exchange into privileged app (modeled)' `
            -SourceCheckIds @('ENTRA-12', 'ENTRA-03') -Confidence 'High' -Severity $sev `
            -Reason "Federated credential '$($r.Subject)' ($($r.Risk)) on an app that also holds dangerous Graph permissions; both confirmed by collected metadata.")
        $text = "$($r.AppDisplayName) - FIC '$($r.Subject)' ($($r.Risk)) + dangerous Graph permissions"
        if ($broad) { $impactedCrit.Add($text) } else { $impactedHigh.Add($text) }
    }

    $total = $impactedCrit.Count + $impactedHigh.Count
    if ($total -eq 0) { return }

    Add-CapabilityInsight -Context $Context `
        -Title 'Workload identity federation into privileged applications' `
        -Description 'Applications with risky federated identity credentials also hold dangerous Graph permissions. An external system (CI/CD repo, Kubernetes cluster) that satisfies the federation trust can exchange its token for this app identity and then use its tenant-wide permissions - no app secret required. Broad-trust subjects (wildcard / main branch) on privileged apps are the critical combinations.' `
        -Severity $(if ($impactedCrit.Count -gt 0) { 'CRITICAL' } else { 'HIGH' }) -Confidence 'High' `
        -SourceCheckIds @('ENTRA-12', 'ENTRA-03') `
        -ImpactedResources (@($impactedCrit.ToArray()) + @($impactedHigh.ToArray())) `
        -ImpactedResourceCount $total -ResourceUnit 'applications' `
        -EvidenceSummary "$total federated-credential/privileged-app combination(s) ($($impactedCrit.Count) with broad-trust subjects)." `
        -RecommendedReview 'Scope federated credential subjects tightly (specific repo + environment/branch), avoid wildcards, and reduce Graph permissions on federated apps to least privilege.'
}

function Invoke-EntraCapConditionalAccessGaps {
    <#
    .SYNOPSIS
        Insight 10: Conditional Access coverage gaps for admins or risky
        clients.
    .DESCRIPTION
        ENTRA-09 evidence. The gaps themselves are directly confirmed
        (Confidence High); the impact rating combines them with collected
        privileged-assignment data: an admin-MFA gap with standing privileged
        assignments present is HIGH; legacy-authentication and guest-MFA gaps
        are MEDIUM context-dependent; report-only policies are a LOW weak
        signal. Guest-privilege escalation from a guest-MFA gap is modeled in
        the external-access insight instead (no double counting).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)

    $rows = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-09'))
    if ($rows.Count -eq 0) { return }

    $hasPrivileged = @(Get-CapabilityEvidenceRows -CheckIds @('ENTRA-01')).Count -gt 0

    $impactedHigh = New-Object System.Collections.Generic.List[string]
    $impactedMed  = New-Object System.Collections.Generic.List[string]
    $impactedLow  = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($r in $rows) {
        $gap = "$($r.Gap)"
        if (-not $gap -or $seen.ContainsKey($gap)) { continue }
        $seen[$gap] = $true
        if ($gap -match '(?i)MFA for directory \(admin\) roles') {
            if ($hasPrivileged) { $impactedHigh.Add("$gap - standing privileged assignments exist in this tenant") }
            else { $impactedMed.Add($gap) }
        }
        elseif ($gap -match '(?i)report-only') { $impactedLow.Add($gap) }
        elseif ($gap -match '(?i)legacy authentication') { $impactedMed.Add($gap) }
        elseif ($gap -match '(?i)MFA for guest/external users') { $impactedMed.Add($gap) }
        elseif ($gap -match '(?i)No Conditional Access policies configured') {
            if ($hasPrivileged) { $impactedHigh.Add("$gap - standing privileged assignments exist in this tenant") }
            else { $impactedMed.Add($gap) }
        }
        else { $impactedLow.Add($gap) }
    }

    $total = $impactedHigh.Count + $impactedMed.Count + $impactedLow.Count
    if ($total -eq 0) { return }

    $sev = 'LOW'
    if ($impactedHigh.Count -gt 0) { $sev = 'HIGH' }
    elseif ($impactedMed.Count -gt 0) { $sev = 'MEDIUM' }

    Add-CapabilityInsight -Context $Context `
        -Title 'Conditional Access coverage gaps for privileged or risky sign-ins' `
        -Description 'Conditional Access does not consistently enforce strong controls: the listed gaps are directly confirmed by collected policy data. Impact is highest where an admin-MFA gap coincides with standing privileged role assignments - privileged sign-ins may occur without MFA. Legacy authentication gaps let clients bypass Conditional Access entirely.' `
        -Severity $sev -Confidence 'High' `
        -SourceCheckIds @('ENTRA-09', 'ENTRA-01') `
        -ImpactedResources (@($impactedHigh.ToArray()) + @($impactedMed.ToArray()) + @($impactedLow.ToArray())) `
        -ImpactedResourceCount $total -ResourceUnit 'gaps' `
        -EvidenceSummary "$total Conditional Access gap(s): $($impactedHigh.Count) high-impact combination(s), $($impactedMed.Count) medium, $($impactedLow.Count) weak signal." `
        -RecommendedReview 'Enforce an admin-MFA policy for all directory roles, block legacy authentication, require MFA for guests, and move report-only policies to enforced after validation.'
}

#------------------------------------------------------------------------------
# Top-level builder
#------------------------------------------------------------------------------

function Build-EntraCapabilityModel {
    <#
    .SYNOPSIS
        Builds the EntraMap capability model from already-collected run data.
    .DESCRIPTION
        Runs every Entra insight builder over in-memory state (findings,
        Entra collection, tenant-wide data, tenant footprint), sorts insights
        by severity then impacted count, assigns stable ids (CAP-001...),
        applies the shared output caps and returns the model. Output shape
        matches Build-CapabilityModel (Azure) so the shared CLI/HTML/JSON
        renderers work unchanged. Never throws: a failing builder is logged
        and skipped. NO Graph/Azure API calls are made here.
    .OUTPUTS
        [PSCustomObject] CapabilityModel with ModelVersion, GeneratedAt,
        Summary, Nodes, Edges, Insights, SourceChecks, Limits.
    #>
    [CmdletBinding()]
    param()

    $ctx = New-CapabilityContext

    $builders = @(
        'Invoke-EntraCapPermanentPrivilegedAssignment',
        'Invoke-EntraCapPimWithoutStrongControls',
        'Invoke-EntraCapPrivilegedAppPermissions',
        'Invoke-EntraCapDangerousPermsWeakOwnership',
        'Invoke-EntraCapLongLivedCredentials',
        'Invoke-EntraCapRoleAssignableGroups',
        'Invoke-EntraCapGuestPrivilegedAccess',
        'Invoke-EntraCapBreakGlassHygiene',
        'Invoke-EntraCapWorkloadIdentityPlusPerms',
        'Invoke-EntraCapConditionalAccessGaps'
    )
    foreach ($builder in $builders) {
        try {
            & $builder -Context $ctx
        }
        catch {
            Write-AuditLog -Message "Entra capability model builder '$builder' failed (skipped, model continues without it): $($_.Exception.Message)" -Level WARN
            $ctx.Limits.Notes.Add("Builder '$builder' failed and was skipped: $($_.Exception.Message)")
        }
    }

    # Sort insights: severity rank first, then impacted count (desc), then title.
    $sorted = @($ctx.Insights | Sort-Object `
        @{ Expression = { $r = $script:CapabilitySeverityRank["$($_.Severity)".ToUpper()]; if ($r) { $r } else { 9 } } }, `
        @{ Expression = { -[int]$_.ImpactedResourceCount } }, `
        Title)

    $truncated = 0
    if ($sorted.Count -gt $script:CapabilityLimits.MaxInsights) {
        $truncated = $sorted.Count - $script:CapabilityLimits.MaxInsights
        $sorted = @($sorted | Select-Object -First $script:CapabilityLimits.MaxInsights)
    }
    $ctx.Limits.InsightsTruncated = $truncated

    $n = 0
    foreach ($insight in $sorted) {
        $n++
        $insight.Id = 'CAP-{0:d3}' -f $n
    }

    $nodes = @($ctx.Nodes.Values | Sort-Object Type, Id)
    $edges = @($ctx.Edges.Values | Sort-Object From, To)

    $highest = $null
    foreach ($insight in $sorted) {
        $rank = $script:CapabilitySeverityRank["$($insight.Severity)".ToUpper()]
        if ($rank -and (-not $highest -or $rank -lt $script:CapabilitySeverityRank[$highest])) {
            $highest = "$($insight.Severity)".ToUpper()
        }
    }

    $limitsOut = [ordered]@{
        MaxInsights                    = $ctx.Limits.MaxInsights
        MaxNodes                       = $ctx.Limits.MaxNodes
        MaxEdges                       = $ctx.Limits.MaxEdges
        MaxImpactedResourcesPerInsight = $ctx.Limits.MaxImpactedResourcesPerInsight
        NodesTruncated                 = $ctx.Limits.NodesTruncated
        EdgesTruncated                 = $ctx.Limits.EdgesTruncated
        InsightsTruncated              = $ctx.Limits.InsightsTruncated
        Notes                          = @($ctx.Limits.Notes.ToArray())
    }

    $model = [PSCustomObject][ordered]@{
        ModelVersion = $script:CapabilityModelVersion
        GeneratedAt  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Summary      = [PSCustomObject][ordered]@{
            InsightCount       = $sorted.Count
            HighestSeverity    = $highest
            NodeCount          = $nodes.Count
            EdgeCount          = $edges.Count
            DataPlaneIncluded  = [bool]$script:State.Config.IncludeDataPlane
        }
        Nodes        = $nodes
        Edges        = $edges
        Insights     = $sorted
        SourceChecks = @($ctx.SourceChecks | Sort-Object)
        Limits       = $limitsOut
    }

    Write-AuditLog -Message ("Entra capability model built: {0} insight(s), {1} node(s), {2} edge(s), highest severity {3}." -f `
        $sorted.Count, $nodes.Count, $edges.Count, $(if ($highest) { $highest } else { 'n/a' })) -Level INFO

    return $model
}
