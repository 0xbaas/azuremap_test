# ============================================================================
# EntraMap - Tenant Identity Security Checks (Graph/tenant scope)
# ============================================================================
# Relocated from Checks/Azure/Identity.ps1 for the product split (same
# CheckIds, unchanged check logic): tenant credential hygiene and dormant
# service principals are tenant-scope concerns - the EntraMap product.
# Functions:
#   Test-LongLivedCredentials        (IDENTITY-001)
#   Test-DormantServicePrincipals    (IDENTITY-002; the ARM RBAC correlation
#                                     degrades to NotEvaluated when no Azure
#                                     subscription scope exists)
#   Test-ExpiredCredentials          (IDENTITY-004)
#   Register-EntraTenantIdentityChecks
# ============================================================================

function Test-LongLivedCredentials {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "APPLICATION CREDENTIALS - LONG VALIDITY PERIODS" -Color "Yellow" -ProgressId $ProgressId
    
    # This check depends on tenant-wide application data (Graph/AAD-backed).
    # In Azure-only mode it must not trigger collection and must not report a
    # clean PASS - it is NotEvaluated.
    if ($script:State.Config.SkipEntra) {
        Write-Finding -Severity "INFO" -Status "NotEvaluated" `
                      -Message "Long-lived application credentials not evaluated (tenant identity data skipped via -SkipEntra)" `
                      -Count 0 `
                      -Service "Identity" `
                      -SubscriptionId "Tenant-wide" `
                      -SubscriptionName "Tenant-wide"
        return
    }

    # Get tenant-wide data once (populated during the collection phase)
    $tenantData = Get-TenantWideData
    if (-not $tenantData.Applications) {
        Write-Finding -Severity "INFO" -Status "NotEvaluated" `
                      -Message "Long-lived application credentials not evaluated (tenant application data unavailable)" `
                      -Count 0 `
                      -Service "Identity" `
                      -SubscriptionId "Tenant-wide" `
                      -SubscriptionName "Tenant-wide"
        return
    }
    
    $longLivedCreds = New-Object System.Collections.Generic.List[object]
    $tenantId = $tenantData.TenantId
    
    Write-Progress -Activity "Checking Long-Lived Credentials" `
                  -Status "Processing tenant-wide applications..." `
                  -PercentComplete 0 `
                  -Id $ProgressId
    
    # Check all applications in the tenant
    $appIndex = 0
    foreach ($app in $tenantData.Applications) {
        $appIndex++
        Write-Progress -Activity "Checking Long-Lived Credentials" `
                      -Status "Application $appIndex of $($tenantData.Applications.Count)" `
                      -PercentComplete (($appIndex / $tenantData.Applications.Count) * 100) `
                      -Id $ProgressId
        
        # Check password credentials
        foreach ($cred in $app.PasswordCredentials) {
            $daysValid = [math]::Round(($cred.EndDateTime - $cred.StartDateTime).TotalDays)
            if ($daysValid -gt $script:State.Config.LongCredentialDays) {
                $longLivedCreds.Add([PSCustomObject]@{
                    TenantId = $tenantId
                    SubscriptionId = "Tenant-wide"
                    SubscriptionName = "Tenant-wide"
                    ApplicationName = $app.DisplayName
                    ApplicationId = $app.ApplicationId
                    CredentialType = "Password"
                    StartDateTime = $cred.StartDateTime
                    EndDateTime = $cred.EndDateTime
                    DaysValid = $daysValid
                    ResourceId = $app.Id
                })
            }
        }
        
        # Check key credentials
        foreach ($cred in $app.KeyCredentials) {
            $daysValid = [math]::Round(($cred.EndDateTime - $cred.StartDateTime).TotalDays)
            if ($daysValid -gt $script:State.Config.LongCredentialDays) {
                $longLivedCreds.Add([PSCustomObject]@{
                    TenantId = $tenantId
                    SubscriptionId = "Tenant-wide"
                    SubscriptionName = "Tenant-wide"
                    ApplicationName = $app.DisplayName
                    ApplicationId = $app.ApplicationId
                    CredentialType = "Certificate"
                    StartDateTime = $cred.StartDateTime
                    EndDateTime = $cred.EndDateTime
                    DaysValid = $daysValid
                    ResourceId = $app.Id
                })
            }
        }
    }
    
    $remediation = "Rotate credentials with validity > $($script:State.Config.LongCredentialDays) days.`n" +
                   "Use certificates with 1-year validity or Managed Identities where possible."
    
    Write-Finding -Severity "MEDIUM" `
                  -Message "Application credentials with validity > $($script:State.Config.LongCredentialDays) days" `
                  -Count $longLivedCreds.Count `
                  -Data $longLivedCreds `
                  -Service "Identity" `
                  -Remediation $remediation `
                  -Exclusions $Exclusions `
                  -SubscriptionId "Tenant-wide" `
                  -SubscriptionName "Tenant-wide"
}

function Test-DormantServicePrincipals {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "SERVICE PRINCIPALS WITHOUT SECRETS BUT WITH RBAC ASSIGNMENTS" -Color "Yellow" -ProgressId $ProgressId
    
    # Depends on tenant-wide service principal data (Graph/AAD-backed).
    if ($script:State.Config.SkipEntra) {
        Write-Finding -Severity "INFO" -Status "NotEvaluated" `
                      -Message "Dormant service principals not evaluated (tenant identity data skipped via -SkipEntra)" `
                      -Count 0 `
                      -Service "Identity" `
                      -SubscriptionId "Tenant-wide" `
                      -SubscriptionName "Tenant-wide"
        return
    }

    # Get tenant-wide data once (populated during the collection phase)
    $tenantData = Get-TenantWideData
    if (-not $tenantData.ServicePrincipals) {
        Write-Finding -Severity "INFO" -Status "NotEvaluated" `
                      -Message "Dormant service principals not evaluated (tenant service principal data unavailable)" `
                      -Count 0 `
                      -Service "Identity" `
                      -SubscriptionId "Tenant-wide" `
                      -SubscriptionName "Tenant-wide"
        return
    }
    
    $findings = New-Object System.Collections.Generic.List[object]
    $tenantId = $tenantData.TenantId
    
    Write-Progress -Activity "Checking Service Principals" `
                  -Status "Identifying SPs without secrets/certs..." `
                  -PercentComplete 0 `
                  -Id $ProgressId
    
    # Create HashSet of SPs without credentials for O(1) lookup
    $spWithoutCreds = New-Object System.Collections.Generic.HashSet[string]
    $spIndex = 0
    foreach ($sp in $tenantData.ServicePrincipals) {
        $spIndex++
        if ($spIndex % 100 -eq 0) {
            Write-Progress -Activity "Checking Service Principals" `
                          -Status "Processing SP $spIndex of $($tenantData.ServicePrincipals.Count)" `
                          -PercentComplete (($spIndex / $tenantData.ServicePrincipals.Count) * 50) `
                          -Id $ProgressId
        }
        
        if (($sp.PasswordCredentials.Count -eq 0) -and ($sp.KeyCredentials.Count -eq 0)) {
            $null = $spWithoutCreds.Add($sp.Id)
        }
    }
    
    if ($spWithoutCreds.Count -eq 0) {
        Write-Finding -Severity "INFO" `
                      -Message "No service principals found without password/key credentials" `
                      -Count 0 `
                      -Service "Identity" `
                      -SubscriptionId "Tenant-wide" `
                      -SubscriptionName "Tenant-wide"
        return
    }
    
    # Check RBAC assignments per subscription
    $subIndex = 0
    foreach ($sub in $Subscriptions) {
        $subIndex++
        Write-Progress -Activity "Checking Service Principals" `
                      -Status "Subscription $subIndex of $($Subscriptions.Count): $($sub.Name)" `
                      -PercentComplete (50 + ($subIndex / $Subscriptions.Count) * 50) `
                      -Id $ProgressId
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        try {
            $allAssignments = Get-SubscriptionRBACAssignments -SubscriptionId $sub.Id -SubscriptionName $sub.Name
            
            # Filter for ServicePrincipal type and check against SPs without creds
            foreach ($assignment in $allAssignments | Where-Object { $_.ObjectType -eq 'ServicePrincipal' }) {
                if ($spWithoutCreds.Contains($assignment.ObjectId)) {
                    $findings.Add([PSCustomObject]@{
                        TenantId = $tenantId
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ServicePrincipalName = if ($assignment.DisplayName) { $assignment.DisplayName } else { "Unknown" }
                        ServicePrincipalId = $assignment.ObjectId
                        Scope = $assignment.Scope
                        RoleDefinitionName = $assignment.RoleDefinitionName
                        AssignmentId = $assignment.RoleAssignmentId
                        ResourceId = $assignment.ObjectId
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check service principal assignments in subscription $($sub.Name): $_" -Level ERROR
        }
    }

    # No Azure subscription scope (EntraMap): the tenant side was evaluated, but
    # the ARM RBAC correlation could not run. Mark the correlation NotEvaluated
    # instead of emitting what would read as a clean PASS for the combined check.
    if (@($Subscriptions).Count -eq 0) {
        Write-Finding -Severity "INFO" -Status "NotEvaluated" `
                      -Message "Service principals without password/key credentials identified tenant-wide; RBAC assignment correlation not evaluated (no Azure subscription scope - expected in EntraMap, which performs no subscription scanning)" `
                      -Count $spWithoutCreds.Count `
                      -Service "Identity" `
                      -SubscriptionId "Tenant-wide" `
                      -SubscriptionName "Tenant-wide"
        return
    }

    $remediation = "Review RBAC assignments for service principals without password/key credentials.`n" +
                   "Consider: 1) Adding credentials if SP is active, 2) Removing RBAC if SP is dormant, 3) Replacing with Managed Identity."
    
    Write-Finding -Severity "MEDIUM" `
                  -Message "Service principals without password/key credentials but with RBAC assignments" `
                  -Count $findings.Count `
                  -Data $findings `
                  -Service "Identity" `
                  -Remediation $remediation `
                  -Exclusions $Exclusions `
                  -SubscriptionId "Tenant-wide" `
                  -SubscriptionName "Tenant-wide"
}

function Test-ExpiredCredentials {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "CREDENTIALS - EXPIRED CREDENTIALS" -Color "Yellow" -ProgressId $ProgressId

    # Enumerates AAD applications/service principals directly (Get-AzADApplication /
    # Get-AzADServicePrincipal). In Azure-only mode these Graph/AAD-backed calls must
    # not run; report NotEvaluated instead of a clean PASS.
    if ($script:State.Config.SkipEntra) {
        Write-Finding -Severity "INFO" -Status "NotEvaluated" `
                      -Message "Expired application/service principal credentials not evaluated (tenant identity data skipped via -SkipEntra)" `
                      -Count 0 `
                      -Service "Identity" `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
        return
    }

    if (-not $Subscriptions -or $Subscriptions.Count -eq 0) {
        # No Azure subscription scope (EntraMap): this check enumerates tenant
        # app/SP credentials via Az cmdlets that ride on a subscription context,
        # which EntraMap never has. Report NotEvaluated with the reason instead
        # of vanishing silently (raw WARN only) or implying a clean PASS.
        Write-AuditLog -Message "No subscriptions available for expired credentials check." -Level WARN
        Write-Finding -Severity "INFO" -Status "NotEvaluated" `
                      -Message "Expired application/service principal credentials not evaluated (no Azure subscription scope - expected in EntraMap, which performs no subscription scanning)" `
                      -Count 0 `
                      -Service "Identity" `
                      -SubscriptionId "Tenant-wide" `
                      -SubscriptionName "Tenant-wide"
        return
    }
    
    # Use first subscription context for tenant-wide AAD queries
    $firstSub = $Subscriptions[0]
    if (-not (Set-SubscriptionContext -SubscriptionId $firstSub.Id -SubscriptionName $firstSub.Name)) {
        return
    }
    
    $now = Get-Date
    $expiredSpCreds = New-Object System.Collections.Generic.List[object]
    $expiredAppCreds = New-Object System.Collections.Generic.List[object]
    
    try {
        $servicePrincipals = Invoke-AzureCommand -Command {
            Get-AzADServicePrincipal -ErrorAction Stop
        } -CommandName "Get-ServicePrincipals"
        
        foreach ($sp in $servicePrincipals) {
            foreach ($cred in ($sp.PasswordCredentials + $sp.KeyCredentials)) {
                if ($cred.EndDateTime -lt $now) {
                    $credType = if ($cred.GetType().Name -like "*Password*") { "Password" } else { "Certificate" }
                    $expiredSpCreds.Add([PSCustomObject]@{
                        SPObjectId = $sp.Id
                        SPName = $sp.DisplayName
                        CredType = $credType
                        EndDate = $cred.EndDateTime
                    })
                }
            }
        }
    }
    catch {
        Write-AuditLog -Message "Failed to enumerate service principal credentials: $_" -Level WARN
    }
    
    try {
        $applications = Invoke-AzureCommand -Command {
            Get-AzADApplication -ErrorAction Stop
        } -CommandName "Get-Applications"
        
        foreach ($app in $applications) {
            foreach ($cred in ($app.PasswordCredentials + $app.KeyCredentials)) {
                if ($cred.EndDateTime -lt $now) {
                    $credType = if ($cred.GetType().Name -like "*Password*") { "Password" } else { "Certificate" }
                    $expiredAppCreds.Add([PSCustomObject]@{
                        AppObjectId = $app.Id
                        AppName = $app.DisplayName
                        CredType = $credType
                        EndDate = $cred.EndDateTime
                    })
                }
            }
        }
    }
    catch {
        Write-AuditLog -Message "Failed to enumerate application credentials: $_" -Level WARN
    }
    
    if ($expiredSpCreds.Count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "Expired service principal credentials" `
                      -Count ($expiredSpCreds | Select-Object -ExpandProperty SPObjectId -Unique).Count `
                      -Data ($expiredSpCreds | Sort-Object EndDate | Select-Object SPName, CredType, EndDate) `
                      -Service "Identity" `
                      -Remediation "Remove or rotate expired service principal credentials." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($expiredAppCreds.Count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "Expired application credentials" `
                      -Count ($expiredAppCreds | Select-Object -ExpandProperty AppObjectId -Unique).Count `
                      -Data ($expiredAppCreds | Sort-Object EndDate | Select-Object AppName, CredType, EndDate) `
                      -Service "Identity" `
                      -Remediation "Remove or rotate expired application credentials." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Register-EntraTenantIdentityChecks {
    [CmdletBinding()]
    param()
    @(
        @{
            CheckId         = "IDENTITY-001"
            Category        = "Entra"
            Service         = "Identity"
            Name            = "Test-LongLivedCredentials"
            Function        = "Test-LongLivedCredentials"
            DefaultSeverity = "MEDIUM"
            RequiredModules = @("Az.Accounts", "Az.Resources")
            RequiredPerms   = @()
            Phase           = "TenantWide"
            Description     = "Application credentials with validity above the configured threshold"
        }
        @{
            CheckId         = "IDENTITY-002"
            Category        = "Entra"
            Service         = "Identity"
            Name            = "Test-DormantServicePrincipals"
            Function        = "Test-DormantServicePrincipals"
            DefaultSeverity = "MEDIUM"
            RequiredModules = @("Az.Accounts", "Az.Resources")
            RequiredPerms   = @()
            Phase           = "TenantWide"
            Description     = "Service principals without credentials but with RBAC assignments (RBAC correlation degrades without Azure scope)"
        }
        @{
            CheckId         = "IDENTITY-004"
            Category        = "Entra"
            Service         = "Identity"
            Name            = "Test-ExpiredCredentials"
            Function        = "Test-ExpiredCredentials"
            DefaultSeverity = "INFO"
            RequiredModules = @("Az.Accounts", "Az.Resources")
            RequiredPerms   = @()
            Phase           = "TenantWide"
            Description     = "Expired application and service principal credentials"
        }
    )
}
