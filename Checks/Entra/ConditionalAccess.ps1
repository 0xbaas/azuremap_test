#==============================================================================
# AzureMap v2 - Checks/Entra/ConditionalAccess.ps1
# ENTRA-09  Conditional Access / MFA enforcement gaps  (TenantWide, CRITICAL)
#
# READ-ONLY. Microsoft Graph GET only (/identity/conditionalAccess/policies).
# If the Graph query fails or the scope is missing, the check is NotEvaluated -
# it is NEVER reported as PASS on a collection failure.
#==============================================================================

function Get-CaProp {
    # StrictMode-safe property accessor for Graph PSCustomObjects.
    param([object]$Object, [string]$Name)
    if ($null -ne $Object -and ($Object.PSObject.Properties.Name -contains $Name)) {
        return $Object.$Name
    }
    return $null
}

function Get-CaControls {
    param([object]$Policy)
    $gc = Get-CaProp $Policy 'grantControls'
    $bic = Get-CaProp $gc 'builtInControls'
    if ($bic) { return @($bic | ForEach-Object { "$_".ToLower() }) }
    return @()
}

function Get-CaUsers {
    param([object]$Policy)
    Get-CaProp (Get-CaProp $Policy 'conditions') 'users'
}

function Test-CaAdminMfaCoverage {
    # True if any enabled policy requires MFA and targets directory roles.
    param([object[]]$EnabledPolicies)
    foreach ($p in @($EnabledPolicies)) {
        $controls = Get-CaControls $p
        if ($controls -notcontains 'mfa') { continue }
        $users = Get-CaUsers $p
        $roles = @(Get-CaProp $users 'includeRoles')
        if ($roles.Count -gt 0) { return $true }
    }
    return $false
}

function Test-CaGuestMfaCoverage {
    param([object[]]$EnabledPolicies)
    foreach ($p in @($EnabledPolicies)) {
        $controls = Get-CaControls $p
        if ($controls -notcontains 'mfa') { continue }
        $users = Get-CaUsers $p
        $inc = @(Get-CaProp $users 'includeUsers')
        if ($inc -contains 'GuestsOrExternalUsers') { return $true }
        if (Get-CaProp $users 'includeGuestsOrExternalUsers') { return $true }
    }
    return $false
}

function Test-CaLegacyAuthBlock {
    param([object[]]$EnabledPolicies)
    foreach ($p in @($EnabledPolicies)) {
        $controls = Get-CaControls $p
        if ($controls -notcontains 'block') { continue }
        $cats = @(Get-CaProp (Get-CaProp $p 'conditions') 'clientAppTypes' | ForEach-Object { "$_".ToLower() })
        if ($cats -contains 'exchangeactivesync' -or $cats -contains 'other') { return $true }
    }
    return $false
}

function Get-CaBroadExclusions {
    # Flags enabled policies with sweeping exclusions (an escalation blind spot).
    param([object[]]$EnabledPolicies)
    $out = @()
    foreach ($p in @($EnabledPolicies)) {
        $users = Get-CaUsers $p
        $exU = @(Get-CaProp $users 'excludeUsers')
        $exG = @(Get-CaProp $users 'excludeGroups')
        $exR = @(Get-CaProp $users 'excludeRoles')
        $total = $exU.Count + $exG.Count + $exR.Count
        if (($exU -contains 'All') -or ($total -gt 3)) {
            $out += [PSCustomObject]@{
                Gap            = "Broad exclusions on Conditional Access policy"
                PolicyName     = [string](Get-CaProp $p 'displayName')
                ExclusionCount = $total
                Risk           = "Excluded principals bypass the enforced control"
            }
        }
    }
    return $out
}

function Test-EntraConditionalAccess {
    [CmdletBinding()]
    param()

    try {
        $policies = @(Invoke-GraphCommand -Uri "/identity/conditionalAccess/policies" -AllPages -CommandName "EntraConditionalAccessPolicies")
    }
    catch {
        Write-Finding -CheckId "ENTRA-09" -Service "EntraConditionalAccess" -Category "Entra" `
            -Severity "CRITICAL" -Status "NotEvaluated" -Count 0 `
            -Message "Conditional Access policies could not be evaluated (Graph query failed or Policy.Read.All missing)."
        return
    }

    $findings = [System.Collections.Generic.List[object]]::new()

    if ($policies.Count -eq 0) {
        $findings.Add([PSCustomObject]@{ Gap = "No Conditional Access policies configured"; Risk = "Tenant lacks central identity access control" })
    }
    else {
        $enabled    = @($policies | Where-Object { (Get-CaProp $_ 'state') -eq 'enabled' })
        $reportOnly = @($policies | Where-Object { (Get-CaProp $_ 'state') -eq 'enabledForReportingButNotEnforced' })

        if ($reportOnly.Count -gt 0) {
            $findings.Add([PSCustomObject]@{ Gap = "Report-only Conditional Access policies present"; Count = $reportOnly.Count; Risk = "Policies may not actually enforce controls" })
        }
        if (-not (Test-CaAdminMfaCoverage -EnabledPolicies $enabled)) {
            $findings.Add([PSCustomObject]@{ Gap = "No enabled policy requiring MFA for directory (admin) roles"; Risk = "Privileged accounts may sign in without MFA" })
        }
        if (-not (Test-CaLegacyAuthBlock -EnabledPolicies $enabled)) {
            $findings.Add([PSCustomObject]@{ Gap = "No enabled policy blocking legacy authentication"; Risk = "Legacy protocols bypass MFA/Conditional Access" })
        }
        if (-not (Test-CaGuestMfaCoverage -EnabledPolicies $enabled)) {
            $findings.Add([PSCustomObject]@{ Gap = "No enabled policy requiring MFA for guest/external users"; Risk = "External identities may access resources without MFA" })
        }
        foreach ($b in (Get-CaBroadExclusions -EnabledPolicies $enabled)) { $findings.Add($b) }
    }

    $status = if ($findings.Count -gt 0) { "FAIL" } else { "PASS" }
    Write-Finding -CheckId "ENTRA-09" -Service "EntraConditionalAccess" -Category "Entra" `
        -Severity "CRITICAL" -Status $status -Count $findings.Count -Data $findings.ToArray() `
        -Message "Conditional Access / MFA enforcement gaps" `
        -Remediation "Require MFA for all administrators, block legacy authentication, require MFA for guests, and remove broad exclusions. Move report-only policies to enforced after validation."
}

function Register-EntraConditionalAccessChecks {
    [CmdletBinding()]
    param()
    @(
        @{
            CheckId         = "ENTRA-09"
            Category        = "Entra"
            Service         = "EntraConditionalAccess"
            Name            = "Test-EntraConditionalAccess"
            Function        = "Test-EntraConditionalAccess"
            DefaultSeverity = "CRITICAL"
            RequiredModules = @()
            RequiredPerms   = @("Policy.Read.All")
            Phase           = "TenantWide"
            Description     = "Conditional Access / MFA enforcement gaps"
        }
    )
}
