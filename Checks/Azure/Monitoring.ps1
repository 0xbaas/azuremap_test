# ============================================================================
# AzureMap - Monitoring Security Checks
# ============================================================================
# Functions:
#   Test-CriticalResourceDiagnostics
#   Test-ResourceLocks
#   Test-AutomationRunAsAccounts
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
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking diagnostic settings" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $keyVaults = Invoke-AzureCommand -Command {
                Get-AzKeyVault -ErrorAction SilentlyContinue
            } -CommandName "Get-KeyVaults"
            
            foreach ($kv in $keyVaults) {
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
            
            $sqlServers = Invoke-AzureCommand -Command {
                Get-AzSqlServer -ErrorAction SilentlyContinue
            } -CommandName "Get-SqlServers"
            
            foreach ($sql in $sqlServers) {
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
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking resource locks" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $resourceGroups = Invoke-AzureCommand -Command {
                Get-AzResourceGroup -ErrorAction Stop
            } -CommandName "Get-ResourceGroups"
            
            foreach ($rg in $resourceGroups) {
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
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Automation RunAs accounts" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $accounts = Invoke-AzureCommand -Command {
                Get-AzAutomationAccount -ErrorAction Stop
            } -CommandName "Get-AutomationAccounts"
            $evaluatedSubs++
            
            foreach ($account in $accounts) {
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
}
