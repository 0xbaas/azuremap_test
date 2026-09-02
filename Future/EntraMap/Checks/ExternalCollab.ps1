#==============================================================================
# AzureMap v2 - Products/EntraMap/Checks/ExternalCollab.ps1
# Evaluates external collaboration and cross-tenant access risks.
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraExternalCollaborationRisks {
    <#
    .SYNOPSIS
        Identifies external collaboration configuration risks.
    .DESCRIPTION
        Examines the cross-tenant access policy for overly permissive inbound
        defaults and broad B2B direct connect settings. Also flags applications
        with multi-org or personal account sign-in audiences.
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping external collaboration check" -Level WARN
        return
    }

    $evidence = [System.Collections.Generic.List[object]]::new()

    # ---- Cross-tenant access policy analysis ----
    $ctPolicy = $entra.CrossTenantPolicy

    if ($ctPolicy) {
        $defaultInbound = $ctPolicy.default
        if ($defaultInbound) {
            # Check B2B collaboration inbound
            $b2bCollab = $defaultInbound.b2bCollaborationInbound
            if ($b2bCollab) {
                $usersAndGroups = $b2bCollab.usersAndGroups
                if ($usersAndGroups -and $usersAndGroups.accessType -eq 'allowed') {
                    $evidence.Add([PSCustomObject]@{
                        PolicyType = "CrossTenantAccessPolicy"
                        Setting    = "Default Inbound B2B Collaboration"
                        Value      = "All external users and groups allowed"
                        Risk       = "Any external tenant can collaborate via B2B without explicit trust configuration"
                        Severity   = "MEDIUM"
                    })
                }
            }

            # Check B2B direct connect inbound
            $b2bDirect = $defaultInbound.b2bDirectConnectInbound
            if ($b2bDirect) {
                $usersAndGroups = $b2bDirect.usersAndGroups
                if ($usersAndGroups -and $usersAndGroups.accessType -eq 'allowed') {
                    $evidence.Add([PSCustomObject]@{
                        PolicyType = "CrossTenantAccessPolicy"
                        Setting    = "Default Inbound B2B Direct Connect"
                        Value      = "All external tenants allowed for direct connect"
                        Risk       = "External users can access shared channels and resources via B2B direct connect without explicit trust"
                        Severity   = "MEDIUM"
                    })
                }
            }

            # Check inbound trust settings (trusting external MFA/device claims)
            $inboundTrust = $defaultInbound.inboundTrust
            if ($inboundTrust) {
                if ($inboundTrust.isMfaAccepted -eq $true) {
                    $evidence.Add([PSCustomObject]@{
                        PolicyType = "CrossTenantAccessPolicy"
                        Setting    = "Default Inbound Trust - MFA"
                        Value      = "Trusting MFA claims from all external tenants"
                        Risk       = "External tenant MFA claims are trusted by default, which may bypass local MFA requirements"
                        Severity   = "MEDIUM"
                    })
                }
                if ($inboundTrust.isCompliantDeviceAccepted -eq $true) {
                    $evidence.Add([PSCustomObject]@{
                        PolicyType = "CrossTenantAccessPolicy"
                        Setting    = "Default Inbound Trust - Compliant Device"
                        Value      = "Trusting compliant device claims from all external tenants"
                        Risk       = "External tenant device compliance claims are trusted by default"
                        Severity   = "MEDIUM"
                    })
                }
            }
        }
    } else {
        $evidence.Add([PSCustomObject]@{
            PolicyType = "CrossTenantAccessPolicy"
            Setting    = "Policy Access"
            Value      = "Not accessible"
            Risk       = "Cross-tenant access policy could not be retrieved -- verify permissions or policy may be at defaults"
            Severity   = "INFO"
        })
    }

    # ---- Multi-org / personal account applications ----
    $riskyAudiences = @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount', 'PersonalMicrosoftAccount')

    foreach ($app in $entra.Applications) {
        $audience = $app.signInAudience
        if (-not $audience) { continue }

        if ($riskyAudiences -contains $audience) {
            $audienceLabel = switch ($audience) {
                'AzureADMultipleOrgs'                  { "Any Azure AD organization (multi-tenant)" }
                'AzureADandPersonalMicrosoftAccount'   { "Any Azure AD org + personal Microsoft accounts" }
                'PersonalMicrosoftAccount'             { "Personal Microsoft accounts only" }
                default { $audience }
            }

            $evidence.Add([PSCustomObject]@{
                PolicyType = "ApplicationSignInAudience"
                Setting    = "signInAudience"
                Value      = $audienceLabel
                Risk       = "Application '$($app.displayName)' (AppId: $($app.appId)) accepts sign-ins from external organizations or personal accounts"
                AppName    = $app.displayName
                AppId      = $app.appId
                Severity   = "LOW"
            })
        }
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $mediumCount = ($evidence | Where-Object { $_.Severity -eq "MEDIUM" }).Count
        $maxSeverity = if ($mediumCount -gt 0) { "HIGH" } else { "MEDIUM" }

        Write-Finding `
            -Severity       $maxSeverity `
            -Message        "External collaboration risks detected ($mediumCount policy issues, $totalCount total findings)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraExternalCollab" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Restrict cross-tenant access default policy to block inbound from untrusted tenants. Limit B2B direct connect to named partners. Scope multi-tenant apps to required audiences only."
    } else {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No external collaboration risks detected" `
            -Count          0 `
            -Service        "EntraExternalCollab" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
    }
}

function Register-EntraExternalCollabChecks {
    <#
    .SYNOPSIS
        Registers the Entra External Collaboration checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-08"
            Category        = "Entra"
            Service         = "EntraExternalCollab"
            Name            = "Test-EntraExternalCollaborationRisks"
            Function        = "Test-EntraExternalCollaborationRisks"
            DefaultSeverity = "HIGH"
            RequiredModules = @()
            RequiredPerms   = @("Policy.Read.All")
            Phase           = "TenantWide"
            Description     = "External collaboration and cross-tenant access configuration risks"
        }
    )
}
