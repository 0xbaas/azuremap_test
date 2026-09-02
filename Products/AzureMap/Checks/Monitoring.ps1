# ============================================================================
# AzureMap - Monitoring Security Checks
# ============================================================================
# Functions:
#   Test-CriticalResourceDiagnostics
#   Test-ResourceLocks
#   Test-AutomationRunAsAccounts
#   Test-ExtendedResourceDiagnostics   (MONITORING-004)
#   Register-AzureMonitoringChecks
# ============================================================================

function Test-CriticalResourceDiagnostics {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "DIAGNOSTIC SETTINGS - CRITICAL RESOURCES" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        Write-Progress -Activity "Checking diagnostic settings" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        # Two independent collections: a failure in one must not suppress the other.
        $invKv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind KeyVaults
        if ($invKv.Unavailable) {
            if ($invKv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check diagnostic settings in subscription $($sub.Name): KeyVaults inventory fetch failed" -Level ERROR
        }
        else {
            # Per-vault diagnostic settings still need the session on this
            # subscription (deduped no-op right after a fresh fetch).
            if (@($invKv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
                continue
            }
            
            try {
                foreach ($kv in $invKv.Items) {
                    $diag = Invoke-AzureCommand -Command {
                        Get-AzDiagnosticSetting -ResourceId $kv.ResourceId -ErrorAction SilentlyContinue
                    } -CommandName "Get-DiagnosticsKeyVault"
                    
                    if (-not $diag) {
                        $findings.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceType = "KeyVault"
                            ResourceName = $kv.VaultName
                            ResourceGroup = $kv.ResourceGroupName
                        })
                    }
                }
            }
            catch {
                Write-AuditLog -Message "Failed to check diagnostic settings in subscription $($sub.Name): $_" -Level ERROR
            }
        }
        
        $invSql = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind SqlServers
        if ($invSql.Unavailable) {
            if ($invSql.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check diagnostic settings in subscription $($sub.Name): SqlServers inventory fetch failed" -Level ERROR
        }
        else {
            # Per-server diagnostic settings still need the session on this
            # subscription (deduped no-op right after a fresh fetch).
            if (@($invSql.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
                continue
            }
            
            try {
                foreach ($sql in $invSql.Items) {
                    $resourceId = "/subscriptions/$($sub.Id)/resourceGroups/$($sql.ResourceGroupName)/providers/Microsoft.Sql/servers/$($sql.ServerName)"
                    $diag = Invoke-AzureCommand -Command {
                        Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction SilentlyContinue
                    } -CommandName "Get-DiagnosticsSql"
                    
                    if (-not $diag) {
                        $findings.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceType = "SQLServer"
                            ResourceName = $sql.ServerName
                            ResourceGroup = $sql.ResourceGroupName
                        })
                    }
                }
            }
            catch {
                Write-AuditLog -Message "Failed to check diagnostic settings in subscription $($sub.Name): $_" -Level ERROR
            }
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Critical resources missing diagnostic settings" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "Diagnostics" `
                      -SeverityReason 'Detection gap on sensitive resource types; context-dependent, no direct exploit path by itself.' `
                      -Remediation "Enable diagnostic settings for Key Vaults and SQL Servers to centralize logs." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-ResourceLocks {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "RESOURCE LOCKS - CRITICAL RESOURCE GROUPS" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $criticalPatterns = @("*prod*", "*prd*", "*production*", "*core*", "*shared*", "*management*")
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        Write-Progress -Activity "Checking resource locks" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind ResourceGroups
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check resource locks in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }
        
        # Per-RG lock reads still need the session on this subscription
        # (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        try {
            foreach ($rg in $inv.Items) {
                $isCritical = $false
                foreach ($pattern in $criticalPatterns) {
                    if ($rg.ResourceGroupName -like $pattern) { $isCritical = $true; break }
                }
                if (-not $isCritical) { continue }
                
                $locks = Invoke-AzureCommand -Command {
                    Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
                } -CommandName "Get-ResourceLocks"
                
                $hasDeleteLock = $locks | Where-Object { $_.Properties.Level -eq "CanNotDelete" }
                if (-not $hasDeleteLock) {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $rg.ResourceGroupName
                        Location = $rg.Location
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check resource locks in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Critical resource groups without delete locks" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "ResourceLocks" `
                      -Remediation "Apply delete locks to critical resource groups to prevent accidental deletion." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-AutomationRunAsAccounts {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "AUTOMATION ACCOUNTS - RUNAS ACCOUNT USAGE" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.Automation)) {
        Write-AuditLog -Message "Az.Automation module not installed. Skipping Automation checks." -Level WARN
        Write-Finding -Severity "INFO" -Status "NOTEVALUATED" -Count 0 `
                      -Message "Az.Automation module/cmdlets unavailable" `
                      -Service "Automation" -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
        return
    }

    $findings = New-Object System.Collections.Generic.List[object]
    $evaluatedSubs = 0
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        Write-Progress -Activity "Checking Automation RunAs accounts" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind AutomationAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check Automation RunAs accounts in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }
        $evaluatedSubs++
        
        # Per-account connection reads still need the session on this
        # subscription (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        try {
            foreach ($account in $inv.Items) {
                $runAsAccounts = Invoke-AzureCommand -Command {
                    Get-AzAutomationConnection -ResourceGroupName $account.ResourceGroupName `
                                               -AutomationAccountName $account.AutomationAccountName `
                                               -ErrorAction SilentlyContinue |
                        Where-Object { $_.ConnectionTypeName -match "AzureRunAs" }
                } -CommandName "Get-AutomationConnections"
                
                if ($runAsAccounts -and ($runAsAccounts | Measure-Object).Count -gt 0) {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $account.ResourceGroupName
                        AutomationAccount = $account.AutomationAccountName
                        RunAsAccounts = ($runAsAccounts | Measure-Object).Count
                        Location = $account.Location
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Automation RunAs accounts in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Automation accounts using deprecated RunAs accounts" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "Automation" `
                      -Remediation "Migrate RunAs accounts to managed identities for better security and supportability." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    elseif ($evaluatedSubs -gt 0) {
        # Explicit PASS record: silence is never proof of evaluation.
        Write-Finding -Severity "INFO" -Status "PASS" -Count 0 `
                      -Message "No Automation accounts using deprecated Run As connections" `
                      -Service "Automation" -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
    else {
        Write-Finding -Severity "INFO" -Status "NOTEVALUATED" -Count 0 `
                      -Message "Automation metadata unavailable (collection failed in all subscriptions)" `
                      -Service "Automation" -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-ExtendedResourceDiagnostics {
    <#
    .SYNOPSIS
        MONITORING-004 - broader diagnostic-settings coverage beyond the
        MONITORING-001 Key Vault/SQL scope: Storage accounts, Cosmos DB, App
        Service, API Management, NSGs, and Application Gateways.
    .DESCRIPTION
        Prefers ONE bulk read of microsoft.insights/diagnosticSettings per
        subscription via Azure Resource Graph + hashtable lookup (the per-
        resource Get-AzDiagnosticSetting N+1 pattern is only a fallback when
        the bulk read fails). MONITORING-001's mechanism and contract are
        untouched; Key Vault/SQL are deliberately NOT re-evaluated here (KV
        audit logging is covered inside KEYVAULT-002).
        Unreadable diagnostics -> NOTEVALUATED, never a misleading clean PASS.
    #>
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "DIAGNOSTIC SETTINGS - EXTENDED COVERAGE" -Color "Yellow" -ProgressId $ProgressId

    # Resource sets evaluated by this check (id selectors match the shared
    # inventory object shapes).
    $resourceSets = @(
        @{ Kind = 'StorageAccounts';       TypeLabel = 'Storage Account';        GetId = { param($r) "$($r.Id)" };        GetName = { param($r) "$($r.StorageAccountName)" } },
        @{ Kind = 'CosmosAccounts';        TypeLabel = 'Cosmos DB Account';      GetId = { param($r) "$($r.ResourceId)" }; GetName = { param($r) "$($r.Name)" } },
        @{ Kind = 'WebApps';               TypeLabel = 'App Service App';        GetId = { param($r) "$($r.Id)" };        GetName = { param($r) "$($r.Name)" } },
        @{ Kind = 'ApiManagementServices'; TypeLabel = 'API Management Service'; GetId = { param($r) "$($r.Id)" };        GetName = { param($r) "$($r.Name)" } },
        @{ Kind = 'NetworkSecurityGroups'; TypeLabel = 'Network Security Group'; GetId = { param($r) "$($r.Id)" };        GetName = { param($r) "$($r.Name)" } },
        @{ Kind = 'ApplicationGateways';   TypeLabel = 'Application Gateway';    GetId = { param($r) "$($r.Id)" };        GetName = { param($r) "$($r.Name)" } }
    )

    $missing   = New-Object System.Collections.Generic.List[object]
    $notEval   = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalResources = 0
    $evaluatedResources = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking extended diagnostic coverage" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Bulk read (cached per run): all diagnostic-setting scopes in this
        # subscription via one ARG query. On failure the caller falls back to
        # per-resource reads for this subscription.
        $diagScopes = $null
        if (-not $script:State.Cache.ContainsKey('DiagnosticScopes')) {
            $script:State.Cache.DiagnosticScopes = @{}
        }
        $subKey = "$($sub.Id)"
        if ($script:State.Cache.DiagnosticScopes.ContainsKey($subKey)) {
            $diagScopes = $script:State.Cache.DiagnosticScopes[$subKey]
        }
        else {
            try {
                $rows = Invoke-ResourceGraphQuery -Query 'resources | where type =~ "microsoft.insights/diagnosticsettings" | project id' `
                                                  -SubscriptionIds @($subKey)
                $set = @{}
                foreach ($row in @($rows)) {
                    $sid = "$($row.id)"
                    $idx = $sid.ToLowerInvariant().IndexOf('/providers/microsoft.insights/diagnosticsettings/')
                    if ($idx -gt 0) { $set[$sid.Substring(0, $idx).ToLowerInvariant()] = $true }
                }
                $diagScopes = $set
            }
            catch {
                Write-AuditLog -Message "Bulk diagnostic-settings read (ARG) failed in subscription $($sub.Name): $_; falling back to per-resource reads." -Level WARN
                $diagScopes = $null
            }
            $script:State.Cache.DiagnosticScopes[$subKey] = $diagScopes
        }

        $subEvaluated = $false
        foreach ($set in $resourceSets) {
            $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind $set.Kind
            if ($inv.Unavailable) {
                if ($inv.UnavailableReason -eq 'ContextSwitch') {
                    if (-not $subsSkipped.Contains($sub.Name)) { $subsSkipped.Add($sub.Name) }
                    break
                }
                $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; ResourceType = $set.TypeLabel; Reason = 'Resource collection failed' })
                continue
            }
            $subEvaluated = $true
            $totalResources += @($inv.Items).Count

            # Fallback per-resource reads need this subscription's context
            # (deduped no-op right after a fresh fetch).
            if ($null -eq $diagScopes -and @($inv.Items).Count -gt 0 -and
                -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
                if (-not $subsSkipped.Contains($sub.Name)) { $subsSkipped.Add($sub.Name) }
                break
            }

            foreach ($res in @($inv.Items)) {
                $rid  = & $set.GetId $res
                $name = & $set.GetName $res

                $hasDiag = $false
                if ($null -ne $diagScopes) {
                    # Bulk path: proven subscription-wide scope set.
                    $evaluatedResources++
                    $hasDiag = ($rid -and $diagScopes.ContainsKey($rid.ToLowerInvariant()))
                }
                else {
                    # Fallback: per-resource read (N+1, only when ARG failed).
                    try {
                        $diag = Invoke-AzureCommand -Command {
                            Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction Stop
                        } -CommandName "Get-DiagnosticsExtended" -SkipContextCheck
                        $evaluatedResources++
                        $hasDiag = ($null -ne $diag -and @($diag).Count -gt 0)
                    }
                    catch {
                        $notEval.Add([PSCustomObject]@{
                            SubscriptionName = $sub.Name; ResourceType = $set.TypeLabel; ResourceName = $name
                            Reason = 'Diagnostic settings unreadable (bulk ARG read failed and per-resource read failed)'
                        })
                        continue
                    }
                }

                if (-not $hasDiag) {
                    $missing.Add([PSCustomObject]@{
                        SubscriptionId   = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceType     = $set.TypeLabel
                        ResourceName     = $name
                        ResourceGroup    = "$($res.ResourceGroupName)"
                    })
                }
            }
        }
        if ($subEvaluated -and -not $subsEvaluated.Contains($sub.Name)) { $subsEvaluated.Add($sub.Name) }
    }

    $cov = New-AzureCheckCoverage -Discovered $totalResources -Evaluated $evaluatedResources -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $missing.Count -ResourceNoun 'resources'
    $covParams = New-AzureCheckCoverageParams -Coverage $cov -Discovered $totalResources -Evaluated $evaluatedResources `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARG microsoft.insights/diagnosticSettings (bulk per subscription)', 'ARM Get-AzDiagnosticSetting (fallback)') `
        -FindingType 'DetectionGap'

    if ($missing.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "MONITORING-004" `
                      -Message "Resources missing diagnostic settings (Storage/Cosmos/App Service/APIM/NSG/App Gateway)" `
                      -Count $missing.Count -CountType "UniqueResources" -Data $missing -Service "Diagnostics" `
                      -SeverityReason 'Detection gap on additional resource types; context-dependent, no direct exploit path by itself. Key Vault and SQL coverage lives in MONITORING-001 / KEYVAULT-002 and is not duplicated here.' `
                      -Remediation "Enable diagnostic settings for storage accounts, Cosmos DB, App Service, APIM, NSGs, and Application Gateways." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    else {
        $severity = if ($cov.Severity) { $cov.Severity } else { 'MEDIUM' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status -CheckId "MONITORING-004" `
                      -Message "Resources missing diagnostic settings (Storage/Cosmos/App Service/APIM/NSG/App Gateway)" `
                      -Count 0 -Data $evidence -Service "Diagnostics" `
                      -Remediation "Enable diagnostic settings for extended resource types." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $missing.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "NOTEVALUATED" -CheckId "MONITORING-004" `
                      -Message "Extended diagnostic coverage could not be fully evaluated (resource or diagnostic reads failed); not reported as clean" `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Diagnostics" `
                      -Remediation "Ensure microsoft.insights/diagnosticSettings/read plus per-service read permissions and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Register-AzureMonitoringChecks {
    Register-AuditCheck -CheckId "MONITORING-001" `
                        -Category "Azure" `
                        -Service "Diagnostics" `
                        -Name "Critical Resource Diagnostics" `
                        -Function ${function:Test-CriticalResourceDiagnostics} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Monitor", "Az.KeyVault", "Az.Sql") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.KeyVault/vaults','Microsoft.Sql/servers')
    
    Register-AuditCheck -CheckId "MONITORING-002" `
                        -Category "Azure" `
                        -Service "ResourceLocks" `
                        -Name "Resource Locks on Critical Groups" `
                        -Function ${function:Test-ResourceLocks} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -AlwaysRun $true
    
    # Phase B3 review: MONITORING-003 is NOT data-plane gated. It reads ARM
    # control-plane metadata only (Microsoft.Automation accounts + connections)
    # and inspects just the ConnectionTypeName/count - it never touches
    # connection FieldDefinitionValues or any credential material.
    Register-AuditCheck -CheckId "MONITORING-003" `
                        -Category "Azure" `
                        -Service "Automation" `
                        -Name "Automation RunAs Accounts" `
                        -Function ${function:Test-AutomationRunAsAccounts} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Automation") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Automation/automationAccounts')

    Register-AuditCheck -CheckId "MONITORING-004" `
                        -Category "Azure" `
                        -Service "Diagnostics" `
                        -Name "Extended Resource Diagnostics" `
                        -Function ${function:Test-ExtendedResourceDiagnostics} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Monitor") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Storage/storageAccounts','Microsoft.DocumentDb/databaseAccounts','Microsoft.Web/sites','Microsoft.ApiManagement/service','Microsoft.Network/networkSecurityGroups','Microsoft.Network/applicationGateways')
}
