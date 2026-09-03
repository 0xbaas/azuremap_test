# ============================================================================
# AzureMap - Identity Security Checks (Azure ARM/RBAC scope)
# ============================================================================
# Functions:
#   Test-ExcessiveRBAC             (IDENTITY-003)
#   Test-CustomRoles               (IDENTITY-005)
#   Test-IdentityResourceMapping   (IDENTITY-006)
#   Test-RBACDecomposition         (IDENTITY-007)
#   Register-AzureIdentityChecks
# (IDENTITY-001/002/004 - tenant credential hygiene - relocated to
#  Future/EntraMap/Checks/TenantIdentity.ps1 with the parked EntraMap product.)
# ============================================================================

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

            # Perf phase: reuse the cached subscription-scope RBAC read (shared with
            # IDENTITY-002/003/006) instead of one server-filtered Get-AzRoleAssignment
            # call per dangerous custom role. The cached list covers the subscription
            # scope and below, so a client-side RoleDefinitionId filter is equivalent.
            $subAssignments = @(Get-SubscriptionRBACAssignments -SubscriptionId $sub.Id -SubscriptionName $sub.Name)

            # Phase B2: retain slim projections of the already-fetched custom role
            # definitions (Actions/DataActions included) so the capability model can
            # reason about what custom roles grant (e.g. storage key-retrieval
            # permission) without any additional API calls. In-memory only.
            if ($null -ne $customRoles) {
                $roleProjections = [System.Collections.Generic.List[object]]::new()
                foreach ($role in @($customRoles)) {
                    $roleProjections.Add([PSCustomObject]@{
                        RoleGuid    = ("$($role.Id)" -split '/')[-1]
                        RoleName    = "$($role.Name)"
                        Actions     = @($role.Actions)
                        DataActions = @($role.DataActions)
                    })
                }
                $script:State.Cache.RoleDefinitions["$($sub.Id)"] = $roleProjections
            }

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
                    # RoleDefinitionId may be a bare GUID or a full resource id;
                    # compare on the GUID segment only.
                    $roleGuid = ("$($role.Id)" -split '/')[-1]
                    $assignmentsCount = @($subAssignments | Where-Object {
                        ("$($_.RoleDefinitionId)" -split '/')[-1] -eq $roleGuid
                    }).Count
                    
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

    # Same contract as IDENTITY-003/007: when the subscription RBAC read failed,
    # assignment counts for custom roles are unproven - surface NotEvaluated for
    # those subscriptions so the check can never end as a misleading clean PASS.
    foreach ($sub in $Subscriptions) {
        if ((-not [string]::IsNullOrWhiteSpace("$($sub.Id)")) -and
            $script:State.Cache.RBACUnavailable.ContainsKey($sub.Id) -and $script:State.Cache.RBACUnavailable[$sub.Id]) {
            $rolesUnavailable.Add([PSCustomObject]@{ SubscriptionName = $sub.Name })
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

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking managed identity risk mapping" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Each resource type is collected independently: one failing type degrades
        # coverage to Partial for that subscription instead of sinking all evidence.
        # Perf phase: lists come from the shared per-run inventory cache; role
        # assignments come from the cached subscription-scope RBAC read (shared
        # with IDENTITY-002/003/005) instead of one Get-AzRoleAssignment -ObjectId
        # call PER identity-bearing resource. The per-resource -ObjectId calls
        # were the run's worst denied-call pattern: each one burned 40-78s in
        # Graph principal-resolution latency under Azure-only auth. A sub-scope
        # -Scope read returns assignments at and below the subscription, so
        # filtering client-side by principal ObjectId is equivalent.
        $resourceSets = @(
            @{ Name = 'App Service';  Kind = 'WebApps';
               BadRoles = @("Owner", "Contributor", "User Access Administrator") },
            @{ Name = 'Virtual Machine'; Kind = 'VirtualMachines';
               BadRoles = @("Owner", "Contributor", "Virtual Machine Contributor") },
            # Managed-identity mapping only needs $func.Identity.PrincipalId, which
            # Get-AzFunctionApp returns without any app-settings/secret access.
            @{ Name = 'Function App'; Kind = 'FunctionApps';
               BadRoles = @("Owner", "Contributor") }
        )

        $rbacFetched     = $false
        $rbacAssignments = @()
        $rbacDenied      = $false

        foreach ($set in $resourceSets) {
            $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind $set.Kind
            if ($inv.Unavailable) {
                if ($inv.UnavailableReason -eq 'ContextSwitch') {
                    # Old ctx-fail semantics: whole subscription skipped.
                    if (-not $subsSkipped.Contains($sub.Name)) { $subsSkipped.Add($sub.Name) }
                    break
                }
                $failures.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    ResourceType     = $set.Name
                    Reason           = 'Collection failed (inventory fetch failed; detail in audit log)'
                })
                continue
            }
            if (-not $subsEvaluated.Contains($sub.Name)) { $subsEvaluated.Add($sub.Name) }

            foreach ($res in @($inv.Items)) {
                $discovered++
                if (-not ($res.Identity -and $res.Identity.PrincipalId)) { $evaluated++; continue }

                # Lazy, once-per-subscription RBAC read (cached across checks).
                if (-not $rbacFetched) {
                    $rbacFetched = $true
                    $rbacAssignments = @(Get-SubscriptionRBACAssignments -SubscriptionId $sub.Id -SubscriptionName $sub.Name)
                    $rbacDenied = ($script:State.Cache.ContainsKey('RBACUnavailable') -and
                                   $script:State.Cache.RBACUnavailable.ContainsKey($sub.Id) -and
                                   $script:State.Cache.RBACUnavailable[$sub.Id])
                }
                if ($rbacDenied) {
                    # Denied-call guard: classify once per subscription instead of
                    # failing (and stalling) once per resource.
                    $failures.Add([PSCustomObject]@{
                        SubscriptionName = $sub.Name
                        ResourceType     = $set.Name
                        ResourceName     = "$($res.Name)"
                        Reason           = 'Authentication - RBAC assignments unreadable under current auth (subscription-level read denied)'
                    })
                    continue
                }

                $principalId = "$($res.Identity.PrincipalId)"
                $assignments = @($rbacAssignments | Where-Object { "$($_.ObjectId)" -eq $principalId })
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
        ApiSources               = @('ARM Get-AzWebApp', 'ARM Get-AzVM', 'ARM Get-AzFunctionApp', 'ARM REST roleAssignments (role names only)')
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
                      -Message "Identity-resource mapping could not be fully evaluated (one or more collections failed)." `
                      -Count $failedCount -Data $failures -Service "Identity" `
                      -Remediation "Re-run with an identity that can read web apps, VMs, function apps, and role assignments in all in-scope subscriptions." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-RBACDecomposition {
    <#
    .SYNOPSIS
        IDENTITY-007 - colleague-parity decomposition of privileged Azure RBAC
        at elevated scopes into explicit, separate findings.
    .DESCRIPTION
        Uses the cached subscription-scope RBAC read (shared with
        IDENTITY-003/005/006) - ZERO per-principal API calls, no Graph group
        resolution. Counts are ASSIGNMENTS (CountType=RoleAssignments), never
        unique users. Management-group assignments are detected from the same
        cached read when the ARM response includes them (no separate MG-scope
        enumeration is performed).
        RBAC read failure -> NOTEVALUATED, never a misleading clean PASS.
    #>
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "RBAC - PRIVILEGED ASSIGNMENT DECOMPOSITION" -Color "Yellow" -ProgressId $ProgressId

    $privilegedRoles = @("Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator")

    $ownerSub       = New-Object System.Collections.Generic.List[object]
    $ownerMg        = New-Object System.Collections.Generic.List[object]
    $contributorSub = New-Object System.Collections.Generic.List[object]
    $uaaSub         = New-Object System.Collections.Generic.List[object]
    $rbacAdminSub   = New-Object System.Collections.Generic.List[object]
    $nonHumanPriv   = New-Object System.Collections.Generic.List[object]
    $groupPriv      = New-Object System.Collections.Generic.List[object]
    $notEval        = New-Object System.Collections.Generic.List[object]
    $subsEvaluated  = New-Object System.Collections.Generic.List[string]
    $subsSkipped    = New-Object System.Collections.Generic.List[string]
    $totalProcessed = 0
    $assignmentCount = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking RBAC decomposition" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $assignments = @(Get-SubscriptionRBACAssignments -SubscriptionId $sub.Id -SubscriptionName $sub.Name)
        if ($script:State.Cache.ContainsKey('RBACUnavailable') -and
            $script:State.Cache.RBACUnavailable.ContainsKey("$($sub.Id)") -and
            $script:State.Cache.RBACUnavailable["$($sub.Id)"]) {
            $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name })
            continue
        }
        $subsEvaluated.Add($sub.Name)

        foreach ($assignment in $assignments) {
            $scope = "$($assignment.Scope)"
            $role  = "$($assignment.RoleDefinitionName)"
            if ([string]::IsNullOrWhiteSpace($role)) { continue }

            $isSubScope = ($scope -match "^/subscriptions/[^/]+$")
            $isMgScope  = ($scope -like "/providers/Microsoft.Management/managementGroups/*")
            if (-not ($isSubScope -or $isMgScope)) { continue }

            $assignmentCount++
            $evidence = [PSCustomObject]@{
                SubscriptionId     = $sub.Id
                SubscriptionName   = $sub.Name
                RoleDefinitionName = $role
                PrincipalName      = if ($assignment.DisplayName) { "$($assignment.DisplayName)" } else { "Unknown" }
                PrincipalType      = "$($assignment.ObjectType)"
                PrincipalId        = "$($assignment.ObjectId)"
                Scope              = $scope
                ScopeType          = if ($isMgScope) { "ManagementGroup" } else { "Subscription" }
            }

            # Role-scope buckets (a sub/MG-scope assignment can ALSO contribute a
            # principal-shape signal below - the count language is "signals").
            if ($isMgScope -and $role -eq "Owner") { $ownerMg.Add($evidence) }
            if ($isSubScope) {
                if     ($role -eq "Owner")                                   { $ownerSub.Add($evidence) }
                elseif ($role -eq "Contributor")                             { $contributorSub.Add($evidence) }
                elseif ($role -eq "User Access Administrator")               { $uaaSub.Add($evidence) }
                elseif ($role -eq "Role Based Access Control Administrator") { $rbacAdminSub.Add($evidence) }
            }

            # Principal-shape signals for privileged roles at sub/MG scope.
            if ($role -in $privilegedRoles) {
                $ptype = "$($assignment.ObjectType)"
                if ($ptype -eq "Group") {
                    $groupPriv.Add($evidence)
                }
                elseif ($ptype -ne "User") {
                    $nonHumanPriv.Add($evidence)
                }
            }
        }
    }

    # NOTE: enumerate the generic Lists directly (no @(...) coercion - PS 5.1
    # throws "Argument types do not match").
    $signalTotal = $ownerSub.Count + $ownerMg.Count + $contributorSub.Count + $uaaSub.Count + `
                   $rbacAdminSub.Count + $nonHumanPriv.Count + $groupPriv.Count

    $cov = New-AzureCheckCoverage -Discovered $assignmentCount -Evaluated $assignmentCount -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $signalTotal -ResourceNoun 'elevated-scope role assignments'
    if ($signalTotal -gt 0) {
        $cov.CoverageSummary = "$assignmentCount elevated-scope role assignment(s) decomposed into $signalTotal signal(s) " +
            "($($ownerSub.Count) Owner@sub, $($ownerMg.Count) Owner@MG, $($contributorSub.Count) Contributor@sub, " +
            "$($uaaSub.Count) UAA@sub, $($rbacAdminSub.Count) RBAC-Admin@sub, $($nonHumanPriv.Count) non-human, " +
            "$($groupPriv.Count) group); counts are assignments/signals, not unique users."
    }
    $covParams = New-AzureCheckCoverageParams -Coverage $cov -Discovered $assignmentCount -Evaluated $assignmentCount `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM REST roleAssignments (subscription scope, cached)') -FindingType 'ExcessivePermissions'

    if ($notEval.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "NOTEVALUATED" -CheckId "IDENTITY-007" `
                      -Message "RBAC decomposition could not be evaluated for one or more subscriptions (Azure RBAC read unavailable under current authentication)." `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Identity" `
                      -Remediation "Ensure the ARM permission Microsoft.Authorization/roleAssignments/read is granted and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }

    if ($ownerMg.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" -Status "FAIL" -CheckId "IDENTITY-007" `
                      -Message "Owner role assignments at management group scope (assignments, not unique users)" `
                      -Count $ownerMg.Count -CountType "RoleAssignments" -Data $ownerMg -Service "Identity" `
                      -SeverityReason 'Counts assignments at MG scope observed in the cached subscription-scope read; one principal may hold several assignments.' `
                      -Remediation "Remove Owner at management group scope; use PIM and assign at lower scopes." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($ownerSub.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -CheckId "IDENTITY-007" `
                      -Message "Owner role assignments at subscription scope (assignments, not unique users)" `
                      -Count $ownerSub.Count -CountType "RoleAssignments" -Data $ownerSub -Service "Identity" `
                      -SeverityReason 'Counts assignments, not unique users; one principal may hold several assignments.' `
                      -Remediation "Review Owner assignments; use PIM for standing privileged access." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($uaaSub.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -CheckId "IDENTITY-007" `
                      -Message "User Access Administrator assignments at subscription scope (assignments, not unique users)" `
                      -Count $uaaSub.Count -CountType "RoleAssignments" -Data $uaaSub -Service "Identity" `
                      -SeverityReason 'Counts assignments, not unique users; UAA can grant any role at the scope (privilege escalation).' `
                      -Remediation "Remove User Access Administrator at subscription scope; prefer RBAC Administrator at narrower scopes." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($contributorSub.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "IDENTITY-007" `
                      -Message "Contributor role assignments at subscription scope (assignments, not unique users)" `
                      -Count $contributorSub.Count -CountType "RoleAssignments" -Data $contributorSub -Service "Identity" `
                      -SeverityReason 'Counts assignments, not unique users.' `
                      -Remediation "Review Contributor assignments and scope to resource groups where possible." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($rbacAdminSub.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "IDENTITY-007" `
                      -Message "Role Based Access Control Administrator assignments at subscription scope (assignments, not unique users)" `
                      -Count $rbacAdminSub.Count -CountType "RoleAssignments" -Data $rbacAdminSub -Service "Identity" `
                      -SeverityReason 'Counts assignments, not unique users.' `
                      -Remediation "Review RBAC Administrator assignments; constrain with delegation conditions where possible." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($nonHumanPriv.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "IDENTITY-007" `
                      -Message "Privileged Azure RBAC roles assigned to non-human principals (service principals / managed identities / unknown)" `
                      -Count $nonHumanPriv.Count -CountType "RoleAssignments" -Data $nonHumanPriv -Service "Identity" `
                      -SeverityReason 'Counts assignments, not unique principals; workload identities with privileged roles widen blast radius.' `
                      -Remediation "Verify each non-human principal still needs the privileged role; reduce to least privilege." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($groupPriv.Count -gt 0) {
        # Group-based privileged access: effective users require Entra group
        # resolution, which AzureMap deliberately does NOT perform (no Graph).
        # Clone the coverage splat so ManualValidationRequired is forced on
        # without specifying the parameter twice.
        $groupParams = $covParams.Clone()
        $groupParams['ManualValidationRequired'] = $true
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "IDENTITY-007" `
                      -Message "Privileged Azure RBAC roles assigned to groups (effective membership not resolved)" `
                      -Count $groupPriv.Count -CountType "RoleAssignments" -Data $groupPriv -Service "Identity" `
                      -SeverityReason 'Counts group assignments, not unique users; effective users are unknown without Entra group resolution.' `
                      -Remediation "Manually validate group membership in Entra ID (AzureMap does not resolve groups); prefer PIM for groups." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @groupParams
    }

    if ($signalTotal -eq 0) {
        # Explicit coverage record: PASS only with proven coverage (no RBAC
        # failures); silence is never proof of evaluation.
        $severity = if ($cov.Severity) { $cov.Severity } else { 'HIGH' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status -CheckId "IDENTITY-007" `
                      -Message "Privileged Azure RBAC decomposition (Owner/Contributor/UAA/RBAC Admin at sub/MG scope, non-human and group principals)" `
                      -Count 0 -CountType "RoleAssignments" -Data $evidence -Service "Identity" `
                      -Remediation "No action required." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
}

function Register-AzureIdentityChecks {
    Register-AuditCheck -CheckId "IDENTITY-003" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "Excessive RBAC Privileges" `
                        -Function ${function:Test-ExcessiveRBAC} `
                        -DefaultSeverity "MEDIUM" `
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

    Register-AuditCheck -CheckId "IDENTITY-007" `
                        -Category "Azure" `
                        -Service "Identity" `
                        -Name "RBAC Privileged Assignment Decomposition" `
                        -Function ${function:Test-RBACDecomposition} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -AlwaysRun $true
}
