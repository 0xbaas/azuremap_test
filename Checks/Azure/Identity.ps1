# ============================================================================
# AzureMap - Identity Security Checks
# ============================================================================
# Functions:
#   Test-LongLivedCredentials
#   Test-DormantServicePrincipals
#   Test-ExcessiveRBAC
#   Test-ExpiredCredentials
#   Test-CustomRoles
#   Test-IdentityResourceMapping
#   Register-AzureIdentityChecks
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

function Test-ExcessiveRBAC {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "RBAC - EXCESSIVE PRIVILEGES AT SUBSCRIPTION SCOPE" -Color "Yellow" -ProgressId $ProgressId
    
    $rbacFindings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            Write-Progress -Activity "Checking Excessive RBAC" `
                          -Status "Subscription: $($sub.Name) (skipped)" `
                          -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                          -Id $ProgressId
            continue
        }
        
        Write-Progress -Activity "Checking Excessive RBAC" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $assignments = Get-SubscriptionRBACAssignments -SubscriptionId $sub.Id -SubscriptionName $sub.Name
            
            foreach ($assignment in $assignments) {
                # Determine scope type
                $scopeType = "Unknown"
                if ($assignment.Scope -eq "/") {
                    $scopeType = "Root"
                } elseif ($assignment.Scope -like "/providers/Microsoft.Management/managementGroups/*") {
                    $scopeType = "ManagementGroup"
                } elseif ($assignment.Scope -match "^/subscriptions/[^/]+$") {
                    $scopeType = "Subscription"
                } elseif ($assignment.Scope -match "^/subscriptions/[^/]+/resourceGroups/") {
                    if ($assignment.Scope -match "/providers/") {
                        $scopeType = "Resource"
                    } else {
                        $scopeType = "ResourceGroup"
                    }
                } else {
                    $scopeType = "Other"
                }
                
                # Only report elevated scopes
                if ($scopeType -in @("Root", "ManagementGroup", "Subscription")) {
                    $role = "$($assignment.RoleDefinitionName)"
                    $severity = "MEDIUM"  # Default for unknown roles

                    # Guard: a null/empty role name must never reach ContainsKey
                    # ("Key cannot be null") - unknown roles fall back to the
                    # scope-based default severity.
                    if (-not [string]::IsNullOrWhiteSpace($role) -and $script:State.Config.RBACSeverity.ContainsKey($role)) {
                        if ($script:State.Config.RBACSeverity[$role].ContainsKey($scopeType)) {
                            $severity = $script:State.Config.RBACSeverity[$role][$scopeType]
                        } else {
                            # Fallback: Use subscription severity for unknown scope
                            $severity = $script:State.Config.RBACSeverity[$role]["Subscription"]
                        }
                    } else {
                        # Unknown role - use scope-based default
                        $severity = switch ($scopeType) {
                            "Root" { "HIGH" }
                            "ManagementGroup" { "MEDIUM" }
                            "Subscription" { "MEDIUM" }
                            default { "LOW" }
                        }
                    }
                    
                    $principalName = if ($assignment.DisplayName) { $assignment.DisplayName } else { "Unknown" }
                    
                    $rbacFindings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        Scope = $assignment.Scope
                        ScopeType = $scopeType
                        RoleDefinitionName = $role
                        PrincipalName = $principalName
                        PrincipalType = $assignment.ObjectType
                        AssignmentId = $assignment.RoleAssignmentId
                        Severity = $severity
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check RBAC assignments in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    # If Azure RBAC could not be read for one or more subscriptions, surface a single
    # NotEvaluated finding so the check is never a misleading clean PASS.
    $rbacUnavailable = @($Subscriptions | Where-Object {
        (-not [string]::IsNullOrWhiteSpace("$($_.Id)")) -and
        $script:State.Cache.RBACUnavailable.ContainsKey($_.Id) -and $script:State.Cache.RBACUnavailable[$_.Id]
    })
    if ($rbacUnavailable.Count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "RBAC assignments could not be evaluated for one or more subscriptions (Azure RBAC read unavailable under current authentication)" `
                      -Count $rbacUnavailable.Count `
                      -Data (@($rbacUnavailable | ForEach-Object { [PSCustomObject]@{ SubscriptionName = $_.Name } })) `
                      -Service "Identity" `
                      -Status "NOTEVALUATED" `
                      -Remediation "Re-run with Azure + Entra (Graph) authentication, or ensure the ARM permission Microsoft.Authorization/roleAssignments/read is granted, to evaluate excessive privileges." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    elseif ($rbacFindings.Count -eq 0) {
        # Explicit PASS record: assignments were read (no RBACUnavailable flags)
        # and no elevated subscription-scope assignments were found. Silence is
        # never proof of evaluation.
        Write-Finding -Severity "INFO" `
                      -Message "No excessive subscription-scope RBAC assignments found" `
                      -Count 0 `
                      -Service "Identity" `
                      -Status "PASS" `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }

    # Group findings by severity
    $criticalFindings = @($rbacFindings | Where-Object { $_.Severity -eq "CRITICAL" })
    $highFindings = @($rbacFindings | Where-Object { $_.Severity -eq "HIGH" })
    $mediumFindings = @($rbacFindings | Where-Object { $_.Severity -eq "MEDIUM" })
    $lowFindings = @($rbacFindings | Where-Object { $_.Severity -eq "LOW" })
    $infoFindings = @($rbacFindings | Where-Object { $_.Severity -eq "INFO" })
    
    if ($criticalFindings.Count -gt 0) {
        $remediation = "CRITICAL: Remove Owner/User Access Administrator/Privileged Role Administrator roles from root/management group scope.`n" +
                       "Use PIM for privileged roles and assign at lower scopes where possible."
        
        Write-Finding -Severity "CRITICAL" `
                      -Message "CRITICAL RBAC assignments at root/management group scope" `
                      -Count $criticalFindings.Count `
                      -Data $criticalFindings `
                      -Service "Identity" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($highFindings.Count -gt 0) {
        $remediation = "Review high-privilege roles (Contributor, Key Vault Contributor, Network Contributor) at elevated scopes.`n" +
                       "Consider moving to resource group scope where appropriate."
        
        Write-Finding -Severity "HIGH" `
                      -Message "HIGH risk RBAC assignments at management group/subscription scope" `
                      -Count $highFindings.Count `
                      -Data $highFindings `
                      -Service "Identity" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($mediumFindings.Count -gt 0) {
        $remediation = "Review role assignments and consider implementing PIM for elevated privileges."
        
        Write-Finding -Severity "MEDIUM" `
                      -Message "MEDIUM risk RBAC assignments at elevated scopes" `
                      -Count $mediumFindings.Count `
                      -Data $mediumFindings `
                      -Service "Identity" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($lowFindings.Count -gt 0) {
        $remediation = "Informational: Reader roles at elevated scopes."
        
        Write-Finding -Severity "LOW" `
                      -Message "Reader roles at elevated scopes" `
                      -Count $lowFindings.Count `
                      -Data $lowFindings `
                      -Service "Identity" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }

    # INFO bucket (e.g. Reader at subscription scope per RBACSeverity map) must be
    # emitted too - otherwise those assignments are collected but silently dropped.
    if ($infoFindings.Count -gt 0) {
        $remediation = "Informational: Reader assignments at subscription scope. Review for least privilege."
        
        Write-Finding -Severity "INFO" `
                      -Message "Reader roles at subscription scope" `
                      -Count $infoFindings.Count `
                      -Data $infoFindings `
                      -Service "Identity" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
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
        Write-AuditLog -Message "No subscriptions available for expired credentials check." -Level WARN
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

function Test-CustomRoles {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "CUSTOM RBAC ROLES - DANGEROUS PERMISSIONS" -Color "Yellow" -ProgressId $ProgressId
    
    $dangerousPatterns = @(
        "Microsoft.Authorization/*",
        "Microsoft.ManagedIdentity/*",
        "Microsoft.KeyVault/vaults/secrets/*",
        "Microsoft.Compute/virtualMachines/runCommand/*",
        "*"
    )
    
    $findings = New-Object System.Collections.Generic.List[object]
    $rolesUnavailable = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking custom roles" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            # -ErrorAction SilentlyContinue (not Stop) + -WarningAction SilentlyContinue so that
            # Microsoft Graph principal-enrichment failures under Azure-only (-SkipEntra) do not
            # get promoted to terminating errors and re-logged per subscription (Graph auth spam).
            $customRoles = Invoke-AzureCommand -Command {
                Get-AzRoleDefinition -Custom -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $_.IsCustom -eq $true }
            } -CommandName "Get-CustomRoles"
            
            foreach ($role in $customRoles) {
                $dangerousActions = @()
                foreach ($action in $role.Actions) {
                    foreach ($pattern in $dangerousPatterns) {
                        if ($action -like $pattern) {
                            $dangerousActions += $action
                            break
                        }
                    }
                }
                
                if ($role.DataActions) {
                    foreach ($dataAction in $role.DataActions) {
                        foreach ($pattern in $dangerousPatterns) {
                            if ($dataAction -like $pattern) {
                                $dangerousActions += "[DataAction] $dataAction"
                                break
                            }
                        }
                    }
                }
                
                if ($dangerousActions.Count -gt 0) {
                    $assignmentsCount = Invoke-AzureCommand -Command {
                        (Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -RoleDefinitionId $role.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Measure-Object).Count
                    } -CommandName "Get-CustomRoleAssignments"
                    
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        RoleName = $role.Name
                        RoleId = $role.Id
                        DangerousActions = ($dangerousActions -join "; ")
                        AssignmentsCount = $assignmentsCount
                    })
                }
            }
        }
        catch {
            # A thrown error here means custom-role definitions could not be read for this
            # subscription (typically a Graph/Authentication error under Azure-only). Record
            # it so the check emits NotEvaluated for that subscription instead of a false PASS.
            $errClass = 'Unknown'
            try { $errClass = (Get-ErrorClass -ErrorRecord $_).Class } catch { }
            $rolesUnavailable.Add([PSCustomObject]@{ SubscriptionName = $sub.Name })
            Write-AuditLog -Message "Custom roles could not be evaluated for subscription $($sub.Name) [$errClass]; marked NotEvaluated." -Level WARN
        }
    }

    if ($rolesUnavailable.Count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "Custom roles could not be evaluated for one or more subscriptions (role definitions unreadable under current authentication)" `
                      -Count $rolesUnavailable.Count `
                      -Data $rolesUnavailable `
                      -Service "Identity" `
                      -Status "NOTEVALUATED" `
                      -Remediation "Re-run with Azure + Entra (Graph) authentication, or ensure Microsoft.Authorization/roleDefinitions/read is granted, to evaluate custom roles." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }

    if ($findings.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Custom roles with dangerous/wildcard permissions" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "Identity" `
                      -Remediation "Review and restrict custom role permissions; avoid wildcard actions." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    elseif ($rolesUnavailable.Count -eq 0) {
        # Explicit PASS record: role definitions were readable and no custom
        # role carried dangerous permissions. Silence is never proof.
        Write-Finding -Severity "INFO" `
                      -Message "No custom roles with dangerous/wildcard permissions found" `
                      -Count 0 `
                      -Service "Identity" `
                      -Status "PASS" `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-IdentityResourceMapping {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "P1 - IDENTITY-RESOURCE LINKAGE ANALYSIS" -Color "Red" -ProgressId $ProgressId

    $criticalFindings = New-Object System.Collections.Generic.List[object]
    $highFindings = New-Object System.Collections.Generic.List[object]
    # B1 coverage tracking: per-subscription and per-resource-type failures are
    # recorded so the check can never end as a false clean PASS after errors.
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $failures      = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    $discovered = 0
    $evaluated  = 0

    # Sanitized one-line error detail (class + first line only) - full stack stays
    # out of the console; the log keeps the short reason, not the raw dump.
    $getReason = {
        param($Err)
        $cls = 'Unknown'
        try { $cls = (Get-ErrorClass -ErrorRecord $Err).Class } catch {}
        $msg = "Line 1: $(("$($Err.Exception.Message)" -split '\r?\n')[0])"
        "$cls - $msg"
    }

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }
        $subsEvaluated.Add($sub.Name)

        Write-Progress -Activity "Checking managed identity risk mapping" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Each resource type is collected independently: one failing type degrades
        # coverage to Partial for that subscription instead of sinking all evidence.
        $resourceSets = @(
            @{ Name = 'App Service';  CommandName = 'Get-WebApps';
               Collect = { Get-AzWebApp -ErrorAction Stop };
               BadRoles = @("Owner", "Contributor", "User Access Administrator") },
            @{ Name = 'Virtual Machine'; CommandName = 'Get-VMs';
               Collect = { Get-AzVM -ErrorAction Stop };
               BadRoles = @("Owner", "Contributor", "Virtual Machine Contributor") },
            # Managed-identity mapping only needs $func.Identity.PrincipalId, which
            # Get-AzFunctionApp returns without any app-settings/secret access.
            @{ Name = 'Function App'; CommandName = 'Get-FunctionApps';
               Collect = { Get-AzFunctionApp -ErrorAction Stop -WarningAction SilentlyContinue };
               BadRoles = @("Owner", "Contributor") }
        )

        foreach ($set in $resourceSets) {
            $resources = $null
            try {
                $resources = Invoke-AzureCommand -Command $set.Collect -CommandName $set.CommandName
            }
            catch {
                $failures.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    ResourceType     = $set.Name
                    Reason           = (& $getReason $_)
                })
                continue
            }

            foreach ($res in @($resources)) {
                $discovered++
                if (-not ($res.Identity -and $res.Identity.PrincipalId)) { $evaluated++; continue }

                $assignments = $null
                try {
                    $assignments = Invoke-AzureCommand -Command {
                        Get-AzRoleAssignment -ObjectId "$($res.Identity.PrincipalId)" -ErrorAction Stop
                    } -CommandName "Get-RoleAssignments-ByIdentity"
                }
                catch {
                    $failures.Add([PSCustomObject]@{
                        SubscriptionName = $sub.Name
                        ResourceType     = $set.Name
                        ResourceName     = "$($res.Name)"
                        Reason           = (& $getReason $_)
                    })
                    continue
                }
                $evaluated++

                foreach ($assignment in @($assignments)) {
                    $roleName = "$($assignment.RoleDefinitionName)"
                    $isDataPlane = ($set.Name -eq 'Function App') -and
                        ($roleName -like "*Storage Blob Data*" -or $roleName -like "*Key Vault*")
                    if ($roleName -in $set.BadRoles) {
                        $criticalFindings.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id; SubscriptionName = $sub.Name
                            ResourceType = $set.Name; ResourceName = $res.Name
                            ResourceGroup = $res.ResourceGroupName
                            Role = $roleName; Scope = $assignment.Scope
                        })
                    } elseif ($isDataPlane) {
                        $highFindings.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id; SubscriptionName = $sub.Name
                            ResourceType = $set.Name; ResourceName = $res.Name
                            ResourceGroup = $res.ResourceGroupName
                            Role = $roleName; Scope = $assignment.Scope
                        })
                    }
                }
            }
        }
    }

    # ---- B1 explicit status + coverage ----
    $riskyTotal  = $criticalFindings.Count + $highFindings.Count
    $failedCount = $failures.Count + $subsSkipped.Count
    $complete    = ($failedCount -eq 0)
    $partial     = (-not $complete)

    if ($evaluated -eq 0 -and $failedCount -gt 0) {
        $status = 'NOTEVALUATED'
        $summary = "Could not evaluate identity-resource mapping; collection failed or permission/API unavailable."
    }
    elseif ($riskyTotal -gt 0) {
        $status  = 'FAIL'
        $summary = "$riskyTotal risky identity-resource assignment(s) across $evaluated evaluated resources" + `
                   $(if ($complete) { '; coverage complete.' } else { "; $failedCount collection(s) skipped/failed - findings may be incomplete." })
    }
    elseif ($partial) {
        $status  = 'PARTIAL'
        $summary = "$evaluated of $discovered identity-bearing resources evaluated; 0 risky; $failedCount collection(s) skipped/failed - findings may be incomplete."
    }
    elseif ($discovered -eq 0) {
        $status  = 'PASS'
        $summary = "No web apps, VMs, or function apps discovered in evaluated scope."
    }
    else {
        $status  = 'PASS'
        $summary = "$evaluated identity-bearing resources evaluated; 0 risky; coverage complete."
    }

    $coverageParams = @{
        DiscoveredResourceCount  = $discovered
        EvaluatedResourceCount   = $evaluated
        SkippedResourceCount     = $failures.Count
        FailedCollectionCount    = $failedCount
        SubscriptionsEvaluated   = @($subsEvaluated)
        SubscriptionsSkipped     = @($subsSkipped)
        CollectionStatus         = if ($complete) { 'Complete' } elseif ($evaluated -gt 0) { 'Partial' } else { 'Failed' }
        CompleteEvaluation       = $complete
        PartialEvaluation        = $partial
        CoverageSummary          = $summary
        SummaryText              = $summary
        Confidence               = if ($status -eq 'NOTEVALUATED') { 'Low' } elseif ($partial) { 'Medium' } else { 'High' }
        ManualValidationRequired = ($status -in @('PARTIAL','NOTEVALUATED'))
        ApiSources               = @('ARM Get-AzWebApp', 'ARM Get-AzVM', 'ARM Get-AzFunctionApp', 'ARM Get-AzRoleAssignment (role names only)')
        FindingType              = 'ExcessivePermissions'
    }

    if ($criticalFindings.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" -Status 'FAIL' -CheckId "IDENTITY-006" `
                      -Message "Resources with Managed Identities having Owner/Contributor RBAC (cloud takeover risk)" `
                      -Count $criticalFindings.Count -Data $criticalFindings -Service "Identity" `
                      -Remediation "Reduce MI role assignments to least privilege and scope appropriately." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                      @coverageParams
    }

    if ($highFindings.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status 'FAIL' -CheckId "IDENTITY-006" `
                      -Message "Resources with Managed Identities having data plane access" `
                      -Count $highFindings.Count -Data $highFindings -Service "Identity" `
                      -Remediation "Review data plane access and scope to required resources only." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                      @coverageParams
    }

    if ($riskyTotal -eq 0) {
        # Explicit coverage record: PASS only with proven coverage; PARTIAL /
        # NOTEVALUATED otherwise. Zero-risky records are INFO - nothing to remediate.
        $evidence = if ($failures.Count -gt 0) { $failures } else { $null }
        Write-Finding -Severity "INFO" -Status $status -CheckId "IDENTITY-006" `
                      -Message "Resources with Managed Identities having high-privilege RBAC" `
                      -Count 0 -Data $evidence -Service "Identity" `
                      -Remediation "No action required." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                      @coverageParams
    }

    # When risky findings exist AND some collections failed, keep the failure detail
    # visible as a separate NotEvaluated record so coverage loss is not hidden by FAIL.
    if ($riskyTotal -gt 0 -and $failedCount -gt 0) {
        Write-Finding -Severity "INFO" -Status 'NOTEVALUATED' -CheckId "IDENTITY-006" `
                      -Message "Identity-resource mapping could not be fully evaluated (one or more collections failed); not reported as clean" `
                      -Count $failedCount -Data $failures -Service "Identity" `
                      -Remediation "Re-run with an identity that can read web apps, VMs, function apps, and role assignments in all in-scope subscriptions." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Register-AzureIdentityChecks {
    Register-AuditCheck -CheckId "IDENTITY-001" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "Long-Lived Credentials" `
                        -Function ${function:Test-LongLivedCredentials} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -AlwaysRun $true
    
    Register-AuditCheck -CheckId "IDENTITY-002" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "Dormant Service Principals" `
                        -Function ${function:Test-DormantServicePrincipals} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -AlwaysRun $true
    
    Register-AuditCheck -CheckId "IDENTITY-003" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "Excessive RBAC Privileges" `
                        -Function ${function:Test-ExcessiveRBAC} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -AlwaysRun $true
    
    Register-AuditCheck -CheckId "IDENTITY-004" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "Expired Credentials" `
                        -Function ${function:Test-ExpiredCredentials} `
                        -DefaultSeverity "INFO" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -AlwaysRun $true
    
    Register-AuditCheck -CheckId "IDENTITY-005" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "Custom Roles with Dangerous Permissions" `
                        -Function ${function:Test-CustomRoles} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -AlwaysRun $true
    
    Register-AuditCheck -CheckId "IDENTITY-006" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "Identity-Resource Mapping" `
                        -Function ${function:Test-IdentityResourceMapping} `
                        -DefaultSeverity "CRITICAL" `
                        -RequiredModules @("Az.Accounts", "Az.Resources", "Az.Websites") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Web/sites','Microsoft.Compute/virtualMachines')
}
