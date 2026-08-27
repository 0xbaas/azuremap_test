# ============================================================================
# AzureMap - Compute Security Checks
# ============================================================================
# Functions:
#   Test-AKSAdvancedSecurity
#   Test-AKSPrivilegeEscalation
#   Test-ContainerRegistrySecurity
#   Test-VMMonitoringAgents
#   Test-AppServiceSecurity
#   Register-AzureComputeChecks
# ============================================================================

function Test-AKSAdvancedSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "AKS - ADVANCED SECURITY POSTURE" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.Aks)) {
        Write-AuditLog -Message "Az.Aks module not installed. Skipping AKS advanced checks." -Level WARN
        return
    }
    
    $clusters = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking AKS advanced posture" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $aksClusters = Invoke-AzureCommand -Command {
                Get-AzAksCluster -ErrorAction Stop
            } -CommandName "Get-AksClusters"
            
            foreach ($aks in $aksClusters) {
                $apiAccessProfile = $aks.APIServerAccessProfile
                $networkProfile = $aks.NetworkProfile
                $aadProfile = $aks.AadProfile
                $addonProfile = $aks.AddonProfile
                $oidcIssuerProfile = $aks.OidcIssuerProfile
                
                $clusters.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $aks.ResourceGroupName
                    ClusterName = $aks.Name
                    PrivateCluster = if ($apiAccessProfile) { $apiAccessProfile.EnablePrivateCluster } else { $false }
                    AuthorizedIPRanges = if ($apiAccessProfile -and $apiAccessProfile.AuthorizedIPRanges) { "Enabled" } else { "Disabled" }
                    AADIntegration = if ($aadProfile) { if ($aadProfile.Managed) { "Managed AAD" } else { "Legacy AAD" } } else { "Disabled" }
                    NetworkPolicy = if ($networkProfile) { $networkProfile.NetworkPolicy } else { "None" }
                    AzurePolicyAddon = if ($addonProfile["azurepolicy"] -and $addonProfile["azurepolicy"].Enabled) { "Enabled" } else { "Disabled" }
                    OIDCIssuer = if ($oidcIssuerProfile -and $oidcIssuerProfile.Enabled) { "Enabled" } else { "Disabled" }
                    LocalAccountsDisabled = if ($aks.DisableLocalAccounts -eq $true) { "Yes" } else { "No" }
                    KubernetesVersion = $aks.KubernetesVersion
                })
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check AKS advanced posture in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    $publicClusters = @($clusters | Where-Object { $_.PrivateCluster -eq $false })
    $legacyAAD = @($clusters | Where-Object { $_.AADIntegration -in @("Legacy AAD", "Disabled") })
    $noPolicyAddon = @($clusters | Where-Object { $_.AzurePolicyAddon -eq "Disabled" })
    $noNetworkPolicy = @($clusters | Where-Object { $_.NetworkPolicy -in @("None", $null, "") })
    $localAccountsEnabled = @($clusters | Where-Object { $_.LocalAccountsDisabled -eq "No" })
    $oidcDisabled = @($clusters | Where-Object { $_.OIDCIssuer -eq "Disabled" })
    
    if ($publicClusters.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "AKS clusters not using private cluster mode" `
                      -Count $publicClusters.Count `
                      -Data $publicClusters `
                      -Service "AKS" `
                      -Remediation "Use private cluster mode or limit API server access to authorized IP ranges." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($legacyAAD.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "AKS clusters without managed Azure AD integration" `
                      -Count $legacyAAD.Count `
                      -Data $legacyAAD `
                      -Service "AKS" `
                      -Remediation "Enable managed Azure AD integration for centralized access control." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($noPolicyAddon.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "AKS clusters without Azure Policy add-on" `
                      -Count $noPolicyAddon.Count `
                      -Data $noPolicyAddon `
                      -Service "AKS" `
                      -Remediation "Enable Azure Policy add-on to enforce governance policies." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($noNetworkPolicy.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "AKS clusters without network policy enforcement" `
                      -Count $noNetworkPolicy.Count `
                      -Data $noNetworkPolicy `
                      -Service "AKS" `
                      -Remediation "Enable network policy (Azure/Calico) to control pod-to-pod traffic." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($localAccountsEnabled.Count -gt 0) {
        Write-Finding -Severity "LOW" `
                      -Message "AKS clusters with local accounts enabled" `
                      -Count $localAccountsEnabled.Count `
                      -Data $localAccountsEnabled `
                      -Service "AKS" `
                      -Remediation "Disable local accounts and enforce Azure AD authentication." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($oidcDisabled.Count -gt 0) {
        Write-Finding -Severity "LOW" `
                      -Message "AKS clusters without OIDC issuer enabled" `
                      -Count $oidcDisabled.Count `
                      -Data $oidcDisabled `
                      -Service "AKS" `
                      -Remediation "Enable OIDC issuer to support workload identity." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-AKSPrivilegeEscalation {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "AKS - PRIVILEGE ESCALATION RISKS" -Color "Red" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.Aks)) {
        Write-AuditLog -Message "Az.Aks module not installed. Skipping AKS privilege escalation checks." -Level WARN
        return
    }
    
    $criticalFindings = New-Object System.Collections.Generic.List[object]
    $highFindings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking AKS privilege escalation" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $aksClusters = Invoke-AzureCommand -Command {
                Get-AzAksCluster -ErrorAction Stop
            } -CommandName "Get-AksClusters"
            
            foreach ($aks in $aksClusters) {
                $apiAccessProfile = $aks.APIServerAccessProfile
                $publicNoIPRestriction = $false
                if ($apiAccessProfile -and $apiAccessProfile.EnablePrivateCluster -eq $false) {
                    if (-not $apiAccessProfile.AuthorizedIPRanges -or @($apiAccessProfile.AuthorizedIPRanges).Count -eq 0) {
                        $publicNoIPRestriction = $true
                    }
                }
                
                $aadProfile = $aks.AadProfile
                $hasAzureRBAC = $aadProfile -and $aadProfile.Managed -eq $true
                $localAccountsEnabled = ($aks.DisableLocalAccounts -eq $false)
                
                if ($publicNoIPRestriction) {
                    $criticalFindings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $aks.ResourceGroupName
                        ClusterName = $aks.Name
                        Issues = "Public API server without IP restrictions"
                        AzureRBAC = if ($hasAzureRBAC) { "Yes" } else { "No" }
                        LocalAccounts = if ($localAccountsEnabled) { "Enabled" } else { "Disabled" }
                    })
                } elseif (-not $hasAzureRBAC -or $localAccountsEnabled) {
                    $highFindings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $aks.ResourceGroupName
                        ClusterName = $aks.Name
                        Issues = if (-not $hasAzureRBAC) { "Legacy RBAC or AAD disabled" } else { "Local accounts enabled" }
                        AzureRBAC = if ($hasAzureRBAC) { "Yes" } else { "No" }
                        LocalAccounts = if ($localAccountsEnabled) { "Enabled" } else { "Disabled" }
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check AKS privilege escalation in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($criticalFindings.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" `
                      -Message "AKS clusters with public API servers and no IP restrictions" `
                      -Count $criticalFindings.Count `
                      -Data $criticalFindings `
                      -Service "AKS" `
                      -Remediation "Restrict API server access with authorized IP ranges or enable private cluster mode." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($highFindings.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "AKS clusters with privilege escalation risks (legacy RBAC or local accounts)" `
                      -Count $highFindings.Count `
                      -Data $highFindings `
                      -Service "AKS" `
                      -Remediation "Enable managed Azure AD RBAC and disable local accounts." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-ContainerRegistrySecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "CONTAINER REGISTRY - PUBLIC ACCESS & AUTHENTICATION" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.ContainerRegistry)) {
        Write-AuditLog -Message "Az.ContainerRegistry module not installed. Skipping Container Registry checks." -Level WARN
        return
    }
    
    $publicNoRules = New-Object System.Collections.Generic.List[object]
    $adminEnabled = New-Object System.Collections.Generic.List[object]
    $anonymousPull = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Container Registry security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $registries = Invoke-AzureCommand -Command {
                Get-AzContainerRegistry -ErrorAction Stop
            } -CommandName "Get-ContainerRegistries"
            
            foreach ($acr in $registries) {
                $config = Invoke-AzureCommand -Command {
                    Get-AzContainerRegistry -ResourceGroupName $acr.ResourceGroupName -Name $acr.Name -ErrorAction Stop
                } -CommandName "Get-ContainerRegistryDetails"
                
                $publicAccess = if ($config.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $config.PublicNetworkAccess } else { "Enabled" }
                $hasNetworkRules = $config.NetworkRuleSet -and $config.NetworkRuleSet.DefaultAction -eq "Deny"
                
                if ($publicAccess -eq "Enabled" -and -not $hasNetworkRules) {
                    $publicNoRules.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $acr.ResourceGroupName
                        RegistryName = $acr.Name
                        PublicNetworkAccess = $publicAccess
                    })
                }
                
                if ($config.AdminUserEnabled -eq $true) {
                    $adminEnabled.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $acr.ResourceGroupName
                        RegistryName = $acr.Name
                        AdminUserEnabled = $true
                    })
                }
                
                if ($config.PSObject.Properties.Name -contains 'AnonymousPullEnabled' -and $config.AnonymousPullEnabled -eq $true) {
                    $anonymousPull.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $acr.ResourceGroupName
                        RegistryName = $acr.Name
                        AnonymousPullEnabled = $true
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Container Registry security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($publicNoRules.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Container registries with public access and no network rules" `
                      -Count $publicNoRules.Count `
                      -Data $publicNoRules `
                      -Service "ContainerRegistry" `
                      -Remediation "Restrict registry access using private endpoints or firewall rules." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($adminEnabled.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Container registries with admin user enabled" `
                      -Count $adminEnabled.Count `
                      -Data $adminEnabled `
                      -Service "ContainerRegistry" `
                      -Remediation "Disable admin user and use managed identity or AAD RBAC." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($anonymousPull.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Container registries with anonymous pull enabled" `
                      -Count $anonymousPull.Count `
                      -Data $anonymousPull `
                      -Service "ContainerRegistry" `
                      -Remediation "Disable anonymous pull unless explicitly required for public images." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-VMMonitoringAgents {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "VIRTUAL MACHINES - MONITORING AGENTS" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking VM monitoring agents" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $vms = Invoke-AzureCommand -Command {
                Get-AzVM -Status -ErrorAction Stop
            } -CommandName "Get-VMs"
            
            foreach ($vm in $vms) {
                $extensions = Invoke-AzureCommand -Command {
                    Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue
                } -CommandName "Get-VMExtensions"
                
                $hasAma = @($extensions | Where-Object { $_.Publisher -eq "Microsoft.Azure.Monitor" -and $_.ExtensionType -in "AzureMonitorWindowsAgent","AzureMonitorLinuxAgent" })
                $hasOms = @($extensions | Where-Object { $_.Publisher -eq "Microsoft.EnterpriseCloud.Monitoring" -and $_.ExtensionType -like "OmsAgent*" })
                
                if (-not $hasAma -and -not $hasOms) {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $vm.ResourceGroupName
                        VMName = $vm.Name
                        PowerState = $vm.PowerState
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check VM monitoring agents in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Finding -Severity "LOW" `
                      -Message "Virtual machines missing monitoring agents (AMA/OMS)" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "Monitoring" `
                      -Remediation "Install Azure Monitor Agent (AMA) or OMS agent for telemetry and security visibility." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-AppServiceSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "APP SERVICE - HTTPS & AUTHENTICATION" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.Websites)) {
        Write-AuditLog -Message "Az.Websites module not installed. Skipping App Service checks." -Level WARN
        return
    }
    
    $noHttps = New-Object System.Collections.Generic.List[object]
    $noAuth = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking App Service security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $apps = Invoke-AzureCommand -Command {
                Get-AzWebApp -ErrorAction Stop
            } -CommandName "Get-WebApps"
            
            foreach ($app in $apps) {
                $authSettings = Invoke-AzureCommand -Command {
                    Get-AzWebAppAuthSetting -ResourceGroupName $app.ResourceGroupName -Name $app.Name -ErrorAction SilentlyContinue
                } -CommandName "Get-WebAppAuth"
                
                if ($app.State -eq "Running" -and $app.HttpsOnly -eq $false) {
                    $noHttps.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $app.ResourceGroupName
                        AppName = $app.Name
                        HTTPSOnly = $app.HttpsOnly
                    })
                }
                
                if ($app.State -eq "Running" -and (-not $authSettings -or -not $authSettings.Enabled)) {
                    $noAuth.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $app.ResourceGroupName
                        AppName = $app.Name
                        AuthenticationEnabled = $false
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check App Service security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($noHttps.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "App Service apps without HTTPS Only enabled" `
                      -Count $noHttps.Count `
                      -Data $noHttps `
                      -Service "AppService" `
                      -Remediation "Enable HTTPS Only for all production web apps." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($noAuth.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "App Service apps without authentication enabled" `
                      -Count $noAuth.Count `
                      -Data $noAuth `
                      -Service "AppService" `
                      -Remediation "Enable App Service authentication and enforce identity providers." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Register-AzureComputeChecks {
    Register-AuditCheck -CheckId "COMPUTE-001" `
                        -Category "Azure" `
                        -Service "AKS" `
                        -Name "AKS Advanced Security" `
                        -Function ${function:Test-AKSAdvancedSecurity} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Aks") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.ContainerService/managedClusters')
    
    Register-AuditCheck -CheckId "COMPUTE-002" `
                        -Category "Azure" `
                        -Service "AKS" `
                        -Name "AKS Privilege Escalation" `
                        -Function ${function:Test-AKSPrivilegeEscalation} `
                        -DefaultSeverity "CRITICAL" `
                        -RequiredModules @("Az.Accounts", "Az.Aks") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.ContainerService/managedClusters')
    
    Register-AuditCheck -CheckId "COMPUTE-003" `
                        -Category "Azure" `
                        -Service "ContainerRegistry" `
                        -Name "Container Registry Security" `
                        -Function ${function:Test-ContainerRegistrySecurity} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.ContainerRegistry") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.ContainerRegistry/registries')
    
    Register-AuditCheck -CheckId "COMPUTE-004" `
                        -Category "Azure" `
                        -Service "Compute" `
                        -Name "VM Monitoring Agents" `
                        -Function ${function:Test-VMMonitoringAgents} `
                        -DefaultSeverity "LOW" `
                        -RequiredModules @("Az.Accounts", "Az.Compute") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Compute/virtualMachines')
    
    Register-AuditCheck -CheckId "COMPUTE-005" `
                        -Category "Azure" `
                        -Service "AppService" `
                        -Name "App Service Security" `
                        -Function ${function:Test-AppServiceSecurity} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Websites") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Web/sites')
}
