# ============================================================================
# AzureMap - SQL Security Checks
# ============================================================================
# Functions:
#   Test-SQLDatabaseSecurity
#   Test-SQLAdvancedSecurity
#   Register-AzureSQLChecks
# ============================================================================

function Test-SQLDatabaseSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "SQL DATABASES - BASIC SECURITY CHECKS" -Color "Yellow" -ProgressId $ProgressId
    
    $publicServers = New-Object System.Collections.Generic.List[object]
    $noAuditing = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++

        Write-Progress -Activity "Checking SQL basic security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind SqlServers
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check SQL basic security in subscription $($sub.Name): SQL server enumeration failed" -Level ERROR
            continue
        }

        # Per-server audit reads still need the session on this subscription
        # (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }

        try {
            foreach ($server in $inv.Items) {
                $auditing = Invoke-AzureCommand -Command {
                    Get-AzSqlServerAudit -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction SilentlyContinue
                } -CommandName "Get-SqlAuditing"
                
                if ($server.PublicNetworkAccess -eq "Enabled") {
                    $publicServers.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $server.ResourceGroupName
                        ServerName = $server.ServerName
                        PublicNetworkAccess = $server.PublicNetworkAccess
                        MinimalTlsVersion = if ($server.MinimalTlsVersion) { $server.MinimalTlsVersion } else { "Unknown" }
                    })
                }
                
                if (-not $auditing -or $auditing.AuditState -ne "Enabled") {
                    $noAuditing.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $server.ResourceGroupName
                        ServerName = $server.ServerName
                        AuditingEnabled = if ($auditing) { $auditing.AuditState } else { "Disabled" }
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check SQL basic security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($publicServers.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "SQL servers with public network access enabled" `
                      -Count $publicServers.Count `
                      -Data $publicServers `
                      -Service "SQL" `
                      -Remediation "Disable public access or restrict via firewall/VNet rules." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($noAuditing.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "SQL servers without server-level auditing enabled" `
                      -Count $noAuditing.Count `
                      -Data $noAuditing `
                      -Service "SQL" `
                      -Remediation "Enable SQL auditing and route logs to Log Analytics or Storage." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-SQLAdvancedSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "SQL - ADVANCED SECURITY CHECKS" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        Write-Progress -Activity "Checking SQL Advanced Security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind SqlServers
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check SQL security in subscription $($sub.Name): SQL server enumeration failed" -Level ERROR
            continue
        }

        $totalProcessed++

        # Per-server AAD-admin/TDE reads still need the session on this
        # subscription (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }

        try {
            foreach ($server in $inv.Items) {
                $serverFindings = @()
                $severity = "MEDIUM"
                
                # Check public network access
                if ($server.PublicNetworkAccess -eq "Enabled") {
                    $serverFindings += "Public network access enabled"
                    $severity = "HIGH"
                }
                
                # Check Azure AD admin
                try {
                    $aadAdmin = Invoke-AzureCommand -Command { 
                        Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction SilentlyContinue
                    } -CommandName "Get-SQLAADAdmin" -SkipContextCheck
                    
                    if (-not $aadAdmin -or -not $aadAdmin.DisplayName) {
                        $serverFindings += "No Azure AD admin configured"
                    }
                } catch { }
                
                # Check TDE
                try {
                    $tde = Invoke-AzureCommand -Command { 
                        Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction SilentlyContinue
                    } -CommandName "Get-SQLTDE" -SkipContextCheck
                    
                    if ($tde.ServerKeyType -eq "ServiceManaged") {
                        $serverFindings += "Using service-managed TDE keys"
                    }
                } catch { }
                
                if ($serverFindings.Count -gt 0) {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ServerName = $server.ServerName
                        ResourceGroup = $server.ResourceGroupName
                        Issues = $serverFindings -join "; "
                        Severity = $severity
                        ResourceId = $server.Id
                        Tags = $server.Tags
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check SQL security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    $highFindings = @($findings | Where-Object { $_.Severity -eq "HIGH" })
    $mediumFindings = @($findings | Where-Object { $_.Severity -eq "MEDIUM" })
    
    if ($highFindings.Count -gt 0) {
        $remediation = "Configure Azure AD authentication and review TDE configuration."
        
        Write-Finding -Severity "HIGH" `
                      -Message "SQL servers with public access enabled" `
                      -Count $highFindings.Count `
                      -Data $highFindings `
                      -Service "SQL" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($mediumFindings.Count -gt 0) {
        $remediation = "Configure Azure AD admin and customer-managed keys for TDE."
        
        Write-Finding -Severity "MEDIUM" `
                      -Message "SQL servers with security improvements needed" `
                      -Count $mediumFindings.Count `
                      -Data $mediumFindings `
                      -Service "SQL" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Register-AzureSQLChecks {
    Register-AuditCheck -CheckId "SQL-001" `
                        -Category "Azure" `
                        -Service "SQL" `
                        -Name "SQL Database Security" `
                        -Function ${function:Test-SQLDatabaseSecurity} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Sql") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Sql/servers')
    
    Register-AuditCheck -CheckId "SQL-002" `
                        -Category "Azure" `
                        -Service "SQL" `
                        -Name "SQL Advanced Security" `
                        -Function ${function:Test-SQLAdvancedSecurity} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Sql") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Sql/servers')
}
