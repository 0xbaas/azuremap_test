# ============================================================================
# AzureMap - Compute Security Checks
# ============================================================================
# Functions:
#   Test-AKSAdvancedSecurity
#   Test-AKSPrivilegeEscalation
#   Test-ContainerRegistrySecurity
#   Test-VMMonitoringAgents
#   Test-AppServiceSecurity
#   Test-AppServiceFtpState        (COMPUTE-006)
#   Test-VMBackupCoverage          (COMPUTE-007)
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

        Write-Progress -Activity "Checking AKS advanced posture" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory. ContextSwitch -> skipped sub;
        # Fetch -> failed collection (same semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind AksClusters
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check AKS advanced posture in subscription $($sub.Name): cluster collection failed" -Level ERROR
            continue
        }

        try {
            foreach ($aks in $inv.Items) {
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

        Write-Progress -Activity "Checking AKS privilege escalation" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory. ContextSwitch -> skipped sub;
        # Fetch -> failed collection (same semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind AksClusters
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check AKS privilege escalation in subscription $($sub.Name): cluster collection failed" -Level ERROR
            continue
        }

        try {
            foreach ($aks in $inv.Items) {
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

        Write-Progress -Activity "Checking Container Registry security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory. ContextSwitch -> skipped sub;
        # Fetch -> failed collection (same semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind ContainerRegistries
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check Container Registry security in subscription $($sub.Name): registry collection failed" -Level ERROR
            continue
        }

        # Nested per-registry detail calls below need this subscription's
        # context (free no-op after a fresh fetch, required on cache hits).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }

        try {
            foreach ($acr in $inv.Items) {
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

        Write-Progress -Activity "Checking VM monitoring agents" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory (the VirtualMachines kind
        # includes -Status data). ContextSwitch -> skipped sub; Fetch ->
        # failed collection (same semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind VirtualMachines
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check VM monitoring agents in subscription $($sub.Name): VM collection failed" -Level ERROR
            continue
        }

        # Nested per-VM extension calls below need this subscription's
        # context (free no-op after a fresh fetch, required on cache hits).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }

        try {
            foreach ($vm in $inv.Items) {
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

        Write-Progress -Activity "Checking App Service security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory. ContextSwitch -> skipped sub;
        # Fetch -> failed collection (same semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind WebApps
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            Write-AuditLog -Message "Failed to check App Service security in subscription $($sub.Name): web app collection failed" -Level ERROR
            continue
        }

        # Nested per-app auth setting calls below need this subscription's
        # context (free no-op after a fresh fetch, required on cache hits).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }

        try {
            foreach ($app in $inv.Items) {
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

function Test-AppServiceFtpSupported {
    <#
    .SYNOPSIS
        Detects once per session whether Get-AzWebApp is available (Az.Websites
        module support). Result is cached in script scope; tests may preset
        $script:AppServiceFtpSupported. Same feature-detection pattern as
        Test-StorageSasPolicySupported in Storage.ps1.
    #>
    [CmdletBinding()]
    param()
    $cached = Get-Variable -Name 'AppServiceFtpSupported' -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $cached) {
        return [bool]$cached
    }
    $supported = $false
    try {
        $supported = [bool](Get-Command -Name Get-AzWebApp -ErrorAction SilentlyContinue)
    }
    catch {
        $supported = $false
    }
    $script:AppServiceFtpSupported = $supported
    return $supported
}

function Test-AppServiceFtpState {
    <#
    .SYNOPSIS
        COMPUTE-006 - App Service FTP(S) state. ftpsState 'AllAllowed' permits
        plaintext FTP credential and content transfer -> MEDIUM. 'FtpsOnly' and
        'Disabled' pass. Unknown/unreadable state -> NotEvaluated, never clean.
    #>
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "APP SERVICE - FTP STATE" -Color "Yellow" -ProgressId $ProgressId

    # Feature-detect cmdlet support (older/missing Az.Websites): never a silent skip.
    if (-not (Test-AppServiceFtpSupported)) {
        Write-Finding -Severity "MEDIUM" -Status "NOTEVALUATED" -CheckId "COMPUTE-006" `
                      -Message "App Service FTP state not evaluated: Get-AzWebApp unavailable (Az.Websites module support missing)" `
                      -Count 0 -Data $null -Service "AppService" `
                      -Remediation "Install a current Az.Websites module and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
        return
    }

    $ftpOpen   = New-Object System.Collections.Generic.List[object]
    $notEval   = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalApps = 0
    $evaluatedApps = 0
    $skippedResources = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking App Service FTP state" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind WebApps
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = 'Web app collection failed' }) }
            continue
        }
        $subsEvaluated.Add($sub.Name)
        $totalApps += @($inv.Items).Count

        # Per-app detail reads (only when the list shape lacks SiteConfig) need
        # this subscription's context (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        foreach ($app in $inv.Items) {
            $ftpsState = $null
            if ($app.PSObject.Properties.Name -contains 'SiteConfig' -and $app.SiteConfig) {
                if ($app.SiteConfig -is [hashtable]) {
                    if ($app.SiteConfig.ContainsKey('FtpsState')) { $ftpsState = $app.SiteConfig['FtpsState'] }
                }
                elseif ($app.SiteConfig.PSObject.Properties.Name -contains 'FtpsState') {
                    $ftpsState = $app.SiteConfig.FtpsState
                }
            }
            if ($null -eq $ftpsState) {
                # List shape did not carry the site config: one detail read.
                try {
                    $detail = Invoke-AzureCommand -Command {
                        Get-AzWebApp -ResourceGroupName $app.ResourceGroupName -Name $app.Name -ErrorAction Stop
                    } -CommandName "Get-WebAppDetail" -SkipContextCheck
                    if ($detail -and $detail.SiteConfig) {
                        if ($detail.SiteConfig -is [hashtable]) {
                            if ($detail.SiteConfig.ContainsKey('FtpsState')) { $ftpsState = $detail.SiteConfig['FtpsState'] }
                        }
                        elseif ($detail.SiteConfig.PSObject.Properties.Name -contains 'FtpsState') {
                            $ftpsState = $detail.SiteConfig.FtpsState
                        }
                    }
                }
                catch {
                    $ftpsState = $null
                }
            }

            if ($null -eq $ftpsState -or "$ftpsState" -eq '') {
                # Read failure / property absent -> NotEvaluated, never clean.
                $notEval.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $app.ResourceGroupName
                    AppName          = $app.Name
                    Reason           = 'ftpsState unreadable or absent'
                })
                $skippedResources++
                continue
            }
            $evaluatedApps++

            if ("$ftpsState" -eq 'AllAllowed') {
                $ftpOpen.Add([PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $app.ResourceGroupName
                    AppName          = $app.Name
                    FtpsState        = "$ftpsState"
                })
            }
            # 'FtpsOnly' / 'Disabled' -> pass; any other value is unusual but not
            # plaintext-FTP-open, so it is not flagged.
        }
    }

    $cov = New-AzureCheckCoverage -Discovered $totalApps -Evaluated $evaluatedApps -SkippedResources $skippedResources `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $ftpOpen.Count -ResourceNoun 'web apps'
    $covParams = New-AzureCheckCoverageParams -Coverage $cov -Discovered $totalApps -Evaluated $evaluatedApps `
        -SkippedResources $skippedResources -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzWebApp (SiteConfig.FtpsState)') -FindingType 'Misconfiguration'

    if ($ftpOpen.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "COMPUTE-006" `
                      -Message "App Service apps with plaintext FTP allowed (ftpsState = AllAllowed)" `
                      -Count $ftpOpen.Count -CountType "UniqueResources" -Data $ftpOpen -Service "AppService" `
                      -SeverityReason 'Plaintext FTP transmits deployment credentials and content unencrypted; context-dependent exposure.' `
                      -Remediation "Set FTPS Only or Disable FTP: Update site config ftpsState to 'FtpsOnly' or 'Disabled'." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    else {
        $severity = if ($cov.Severity) { $cov.Severity } else { 'MEDIUM' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status -CheckId "COMPUTE-006" `
                      -Message "App Service apps with plaintext FTP allowed (ftpsState = AllAllowed)" `
                      -Count 0 -Data $evidence -Service "AppService" `
                      -Remediation "Set FTPS Only or Disable FTP." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $ftpOpen.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "NOTEVALUATED" -CheckId "COMPUTE-006" `
                      -Message "App Service FTP state could not be fully evaluated (collection or per-app reads failed)." `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "AppService" `
                      -Remediation "Ensure Microsoft.Web/sites/read on all in-scope subscriptions and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-RecoveryServicesBackupSupported {
    <#
    .SYNOPSIS
        Detects once per session whether the Az.RecoveryServices cmdlets needed
        for VM backup coverage are available. Result is cached in script scope;
        tests may preset $script:RecoveryServicesBackupSupported. Same
        feature-detection pattern as Test-StorageSasPolicySupported.
    #>
    [CmdletBinding()]
    param()
    $cached = Get-Variable -Name 'RecoveryServicesBackupSupported' -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $cached) {
        return [bool]$cached
    }
    $supported = $false
    try {
        $supported = [bool]((Get-Command -Name Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue) -and
                            (Get-Command -Name Get-AzRecoveryServicesBackupItem -ErrorAction SilentlyContinue))
    }
    catch {
        $supported = $false
    }
    $script:RecoveryServicesBackupSupported = $supported
    return $supported
}

function Test-VMBackupCoverage {
    <#
    .SYNOPSIS
        COMPUTE-007 - VM backup coverage. VMs without a Recovery Services vault
        backup item -> MEDIUM control-gap finding (never auto-escalated; test /
        sandbox exemptions are an operator decision). One per-subscription vault
        + protected-item enumeration (never per-VM calls). Missing module /
        cmdlet support or a failed vault/item read -> NOTEVALUATED, never clean.
    #>
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "VIRTUAL MACHINES - BACKUP COVERAGE" -Color "Yellow" -ProgressId $ProgressId

    # Feature-detect module support (Az.RecoveryServices not in RequiredModules
    # on purpose: a missing module must surface as NotEvaluated, not a skip).
    if (-not (Test-RecoveryServicesBackupSupported)) {
        Write-Finding -Severity "MEDIUM" -Status "NOTEVALUATED" -CheckId "COMPUTE-007" `
                      -Message "VM backup coverage not evaluated: Az.RecoveryServices cmdlets unavailable (module support missing)" `
                      -Count 0 -Data $null -Service "Compute" `
                      -Remediation "Install the Az.RecoveryServices module and re-run to evaluate VM backup coverage." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
        return
    }

    $unprotected = New-Object System.Collections.Generic.List[object]
    $notEval     = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalVMs = 0
    $evaluatedVMs = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking VM backup coverage" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind VirtualMachines
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = 'VM collection failed' }) }
            continue
        }

        # One per-subscription vault enumeration + one protected-item read per
        # vault (never per-VM). Any failure leaves coverage unproven for this
        # subscription -> NotEvaluated, not clean.
        $backupUnknown = $false
        $protectedVmIds = @{}
        try {
            $vaults = Invoke-AzureCommand -Command {
                Get-AzRecoveryServicesVault -ErrorAction Stop
            } -CommandName "Get-RecoveryVaults" -SkipContextCheck
            # -VaultId is the current parameter; older Az.RecoveryServices
            # versions take -ResourceGroupName/-Name instead. Feature-detect
            # once per subscription.
            $itemCmd = Get-Command -Name Get-AzRecoveryServicesBackupItem -ErrorAction SilentlyContinue
            $useVaultId = [bool]($itemCmd -and $itemCmd.Parameters -and $itemCmd.Parameters.ContainsKey('VaultId'))
            foreach ($vault in @($vaults)) {
                if ($useVaultId) {
                    $items = Invoke-AzureCommand -Command {
                        Get-AzRecoveryServicesBackupItem -VaultId $vault.ID -WorkloadType AzureVM -ErrorAction Stop
                    } -CommandName "Get-RecoveryBackupItems" -SkipContextCheck
                }
                else {
                    $items = Invoke-AzureCommand -Command {
                        Get-AzRecoveryServicesBackupItem -ResourceGroupName $vault.ResourceGroupName -Name $vault.Name -WorkloadType AzureVM -ErrorAction Stop
                    } -CommandName "Get-RecoveryBackupItems" -SkipContextCheck
                }
                foreach ($item in @($items)) {
                    $vmId = $null
                    if ($item.PSObject.Properties.Name -contains 'VirtualMachineId' -and $item.VirtualMachineId) { $vmId = "$($item.VirtualMachineId)" }
                    elseif ($item.PSObject.Properties.Name -contains 'SourceResourceId' -and $item.SourceResourceId) { $vmId = "$($item.SourceResourceId)" }
                    if ($vmId) { $protectedVmIds[$vmId.ToLowerInvariant()] = $true }
                }
            }
        }
        catch {
            Write-AuditLog -Message "Backup vault/item read failed in subscription $($sub.Name): $_" -Level WARN
            $backupUnknown = $true
        }

        if ($backupUnknown) {
            $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = 'Recovery Services vault or protected-item read failed' })
            continue
        }

        $subsEvaluated.Add($sub.Name)
        $totalVMs += @($inv.Items).Count

        foreach ($vm in $inv.Items) {
            $evaluatedVMs++
            $vmId = "$($vm.Id)".ToLowerInvariant()
            if (-not ($vmId -and $protectedVmIds.ContainsKey($vmId))) {
                $unprotected.Add([PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $vm.ResourceGroupName
                    VMName           = $vm.Name
                    PowerState       = "$($vm.PowerState)"
                })
            }
        }
    }

    $cov = New-AzureCheckCoverage -Discovered $totalVMs -Evaluated $evaluatedVMs -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $unprotected.Count -ResourceNoun 'virtual machines'
    $covParams = New-AzureCheckCoverageParams -Coverage $cov -Discovered $totalVMs -Evaluated $evaluatedVMs `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzVM', 'ARM Get-AzRecoveryServicesVault', 'ARM Get-AzRecoveryServicesBackupItem (AzureVM)') `
        -FindingType 'ControlGap'

    if ($unprotected.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "COMPUTE-007" `
                      -Message "Virtual machines without Recovery Services vault backup (control gap)" `
                      -Count $unprotected.Count -CountType "UniqueResources" -Data $unprotected -Service "Compute" `
                      -SeverityReason 'Control gap only, deliberately MEDIUM: no direct exploit path, and test/sandbox VMs may be intentionally unprotected - validate before treating as a defect.' `
                      -Remediation "Enable Azure Backup for production VMs; document intentional exclusions for test/sandbox workloads." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    else {
        $severity = if ($cov.Severity) { $cov.Severity } else { 'MEDIUM' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status -CheckId "COMPUTE-007" `
                      -Message "Virtual machines without Recovery Services vault backup (control gap)" `
                      -Count 0 -Data $evidence -Service "Compute" `
                      -Remediation "Enable Azure Backup for production VMs." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $unprotected.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "NOTEVALUATED" -CheckId "COMPUTE-007" `
                      -Message "VM backup coverage could not be fully evaluated (vault/item reads failed)." `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Compute" `
                      -Remediation "Grant Microsoft.RecoveryServices/vaults/read and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
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

    Register-AuditCheck -CheckId "COMPUTE-006" `
                        -Category "Azure" `
                        -Service "AppService" `
                        -Name "App Service FTP State" `
                        -Function ${function:Test-AppServiceFtpState} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Websites") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Web/sites')

    # Az.RecoveryServices is deliberately NOT in RequiredModules: a missing
    # module must surface as NotEvaluated from inside the check, not a skip.
    Register-AuditCheck -CheckId "COMPUTE-007" `
                        -Category "Azure" `
                        -Service "Compute" `
                        -Name "VM Backup Coverage" `
                        -Function ${function:Test-VMBackupCoverage} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Compute") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Compute/virtualMachines')
}
