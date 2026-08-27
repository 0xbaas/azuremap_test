# ============================================================================
# AzureMap - Data Platform Security Checks
# ============================================================================
# Functions:
#   Test-CosmosDBSecurity
#   Test-SynapsePublicAccess
#   Register-AzureDataPlatformChecks
# ============================================================================

function Test-CosmosDBSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "COSMOS DB - PUBLIC ACCESS, FIREWALL & BACKUP" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Cosmos DB security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $resources = Invoke-AzureCommand -Command {
                Get-AzResource -ResourceType "Microsoft.DocumentDb/databaseAccounts" -ErrorAction Stop
            } -CommandName "Get-CosmosResources"
            
            foreach ($resource in $resources) {
                try {
                    $rgName = $resource.ResourceGroupName
                    $apiPath = "/subscriptions/$($sub.Id)/resourceGroups/$rgName/providers/Microsoft.DocumentDb/databaseAccounts/$($resource.Name)?api-version=2023-04-15"
                    $response = Invoke-AzureCommand -Command {
                        Invoke-AzRestMethod -Method GET -Path $apiPath -ErrorAction Stop
                    } -CommandName "Get-CosmosRest"
                    
                    if ($response.StatusCode -ne 200) { continue }
                    
                    $details = $response.Content | ConvertFrom-Json
                    $publicAccess = if ($details.properties.publicNetworkAccess) { $details.properties.publicNetworkAccess } else { "Enabled" }
                    $ipRules = $details.properties.ipRules
                    $vnetRules = $details.properties.virtualNetworkRules
                    $hasFirewall = $ipRules -and @($ipRules).Count -gt 0
                    $hasVNet = $vnetRules -and @($vnetRules).Count -gt 0
                    $hasAllowAll = $false
                    if ($ipRules) {
                        foreach ($rule in $ipRules) {
                            if ($rule.ipAddressOrRange -eq "0.0.0.0") { $hasAllowAll = $true; break }
                        }
                    }
                    
                    $hasAAD = $false
                    if ($details.properties.capabilities) {
                        foreach ($cap in $details.properties.capabilities) {
                            if ($cap.name -eq "EnableAzureActiveDirectory") { $hasAAD = $true; break }
                        }
                    }
                    
                    $backupPolicy = if ($details.properties.backupPolicy) { $details.properties.backupPolicy.type } else { "Unknown" }
                    
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $rgName
                        AccountName = $resource.Name
                        PublicAccess = $publicAccess
                        HasFirewall = $hasFirewall
                        HasAllowAllRule = $hasAllowAll
                        HasVNet = $hasVNet
                        HasAAD = $hasAAD
                        BackupPolicy = $backupPolicy
                    })
                }
                catch {
                    Write-AuditLog -Message "Failed to query Cosmos DB account $($resource.Name): $_" -Level WARN
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Cosmos DB security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    $critical = @($findings | Where-Object { $_.PublicAccess -eq "Enabled" -and ((-not $_.HasFirewall -and -not $_.HasVNet) -or $_.HasAllowAllRule) })
    $publicAccess = @($findings | Where-Object { $_.PublicAccess -eq "Enabled" -and ($_.HasFirewall -or $_.HasVNet) })
    $noAAD = @($findings | Where-Object { $_.HasAAD -eq $false })
    $noBackup = @($findings | Where-Object { $_.BackupPolicy -notin @("Periodic", "Continuous") -or [string]::IsNullOrEmpty($_.BackupPolicy) })
    
    if ($critical.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" `
                      -Message "Cosmos DB accounts with public access and no effective restrictions" `
                      -Count $critical.Count `
                      -Data $critical `
                      -Service "CosmosDB" `
                      -Remediation "Disable public access or enforce firewall/VNet rules." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($publicAccess.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Cosmos DB accounts with public access enabled" `
                      -Count $publicAccess.Count `
                      -Data $publicAccess `
                      -Service "CosmosDB" `
                      -Remediation "Use private endpoints or restrict access with firewall rules." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($noAAD.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Cosmos DB accounts without Azure AD authentication enabled" `
                      -Count $noAAD.Count `
                      -Data $noAAD `
                      -Service "CosmosDB" `
                      -Remediation "Enable Azure AD authentication to reduce key-based access." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($noBackup.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Cosmos DB accounts without proper backup policy" `
                      -Count $noBackup.Count `
                      -Data $noBackup `
                      -Service "CosmosDB" `
                      -Remediation "Configure periodic or continuous backup policies." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-SynapsePublicAccess {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "SYNAPSE - PUBLIC ACCESS & MANAGED VNET" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.Synapse)) {
        Write-AuditLog -Message "Az.Synapse module not installed. Skipping Synapse checks." -Level WARN
        return
    }
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Synapse public access" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $workspaces = Invoke-AzureCommand -Command {
                Get-AzSynapseWorkspace -ErrorAction Stop
            } -CommandName "Get-SynapseWorkspaces"
            
            foreach ($workspace in $workspaces) {
                $publicAccess = if ($workspace.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $workspace.PublicNetworkAccess } else { "Enabled" }
                $managedVNet = -not [string]::IsNullOrEmpty($workspace.ManagedVirtualNetwork)
                
                if ($publicAccess -eq "Enabled" -and -not $managedVNet) {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $workspace.ResourceGroupName
                        WorkspaceName = $workspace.Name
                        PublicNetworkAccess = $publicAccess
                        ManagedVirtualNetwork = $managedVNet
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Synapse public access in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Synapse workspaces with public access and no managed VNet" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "Synapse" `
                      -Remediation "Enable managed virtual network and restrict public access." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Register-AzureDataPlatformChecks {
    Register-AuditCheck -CheckId "DATAPLATFORM-001" `
                        -Category "Azure" `
                        -Service "CosmosDB" `
                        -Name "Cosmos DB Security" `
                        -Function ${function:Test-CosmosDBSecurity} `
                        -DefaultSeverity "CRITICAL" `
                        -RequiredModules @("Az.Accounts", "Az.Resources") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.DocumentDB/databaseAccounts')
    
    Register-AuditCheck -CheckId "DATAPLATFORM-002" `
                        -Category "Azure" `
                        -Service "Synapse" `
                        -Name "Synapse Public Access" `
                        -Function ${function:Test-SynapsePublicAccess} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Synapse") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Synapse/workspaces')
}
