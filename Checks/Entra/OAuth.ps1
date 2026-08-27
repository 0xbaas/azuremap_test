#==============================================================================
# AzureMap v2 - Checks/Entra/OAuth.ps1
# Evaluates OAuth2 consent grants for tenant-wide exposure risks.
# Operates on $script:State.Entra (populated by Invoke-EntraCollection).
#==============================================================================

function Test-EntraOAuthConsentRisks {
    <#
    .SYNOPSIS
        Identifies risky OAuth2 consent grants, particularly tenant-wide admin consents.
    .DESCRIPTION
        Examines oauth2PermissionGrants for grants where consentType is 'AllPrincipals'
        (admin consented for entire tenant). Cross-references scopes with dangerous
        permission names to determine severity.
    #>
    [CmdletBinding()]
    param()

    $entra = $script:State.Entra
    if (-not $entra) {
        Write-AuditLog -Message "Entra data not collected -- skipping OAuth consent risk check" -Level WARN
        return
    }

    $permLookup = $entra.PermissionEscalationLookup

    # Sensitive delegated scopes that are particularly dangerous when admin-consented tenant-wide
    $sensitiveScopes = @(
        'Mail.ReadWrite', 'Mail.Read', 'Mail.Send',
        'MailboxSettings.ReadWrite',
        'Files.ReadWrite.All', 'Files.Read.All',
        'Sites.ReadWrite.All', 'Sites.Read.All',
        'User.ReadWrite.All', 'User.Read.All',
        'Directory.ReadWrite.All', 'Directory.Read.All',
        'Group.ReadWrite.All',
        'Calendars.ReadWrite',
        'Contacts.ReadWrite',
        'People.Read.All',
        'Notes.ReadWrite.All',
        'Chat.ReadWrite',
        'ChannelMessage.Read.All',
        'Policy.ReadWrite.ConditionalAccess'
    )
    $sensitiveScopeSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$sensitiveScopes,
        [System.StringComparer]::OrdinalIgnoreCase
    )

    # Build SP lookup for display name resolution
    $spLookup = @{}
    foreach ($sp in $entra.ServicePrincipals) {
        $spLookup[$sp.id] = $sp.displayName
    }

    $evidence = [System.Collections.Generic.List[object]]::new()

    foreach ($grant in $entra.OAuth2Grants) {
        if ($grant.consentType -ne 'AllPrincipals') { continue }

        $clientId    = $grant.clientId
        $resourceId  = $grant.resourceId
        $scopeString = $grant.scope
        if (-not $scopeString) { continue }

        $scopes      = @($scopeString -split '\s+' | Where-Object { $_ -ne '' })
        $clientName  = if ($spLookup.ContainsKey($clientId)) { $spLookup[$clientId] } else { $clientId }
        $resourceName = if ($spLookup.ContainsKey($resourceId)) { $spLookup[$resourceId] } else { $resourceId }

        $hasSensitiveScope = $false
        foreach ($scope in $scopes) {
            if ($sensitiveScopeSet.Contains($scope)) {
                $hasSensitiveScope = $true
                break
            }
        }

        $severity = if ($hasSensitiveScope) { "HIGH" } else { "MEDIUM" }

        $evidence.Add([PSCustomObject]@{
            ClientId          = $clientId
            ClientDisplayName = $clientName
            ResourceId        = $resourceId
            ResourceName      = $resourceName
            Scope             = $scopeString
            ScopeCount        = $scopes.Count
            ConsentType       = $grant.consentType
            HasSensitiveScope = $hasSensitiveScope
            Severity          = $severity
        })
    }

    $totalCount = $evidence.Count

    if ($totalCount -gt 0) {
        $highCount = ($evidence | Where-Object { $_.Severity -eq "HIGH" }).Count
        $maxSeverity = if ($highCount -gt 0) { "HIGH" } else { "MEDIUM" }

        Write-Finding `
            -Severity       $maxSeverity `
            -Message        "Tenant-wide OAuth2 consent grants detected ($highCount with sensitive scopes, $totalCount total)" `
            -Count          $totalCount `
            -Data           $evidence `
            -Service        "EntraOAuth" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide" `
            -Remediation    "Review all tenant-wide consent grants. Remove unnecessary admin consents. Enable admin consent workflow to prevent future broad grants. Prefer per-user consent with scope restrictions."
    } else {
        Write-Finding `
            -Severity       "INFO" `
            -Message        "No tenant-wide OAuth2 consent grants found" `
            -Count          0 `
            -Service        "EntraOAuth" `
            -SubscriptionId "Tenant-wide" `
            -SubscriptionName "Tenant-wide"
    }
}

function Register-EntraOAuthChecks {
    <#
    .SYNOPSIS
        Registers the Entra OAuth checks into the check registry.
    #>
    [CmdletBinding()]
    param()

    @(
        @{
            CheckId         = "ENTRA-06"
            Category        = "Entra"
            Service         = "EntraOAuth"
            Name            = "Test-EntraOAuthConsentRisks"
            Function        = "Test-EntraOAuthConsentRisks"
            DefaultSeverity = "HIGH"
            RequiredModules = @()
            RequiredPerms   = @("DelegatedPermissionGrant.Read.All")
            Phase           = "TenantWide"
            Description     = "Tenant-wide OAuth2 consent grants with sensitive scopes"
        }
    )
}
