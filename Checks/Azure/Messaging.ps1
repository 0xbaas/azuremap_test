# ============================================================================
# AzureMap - Messaging Security Checks
# ============================================================================
# Functions:
#   Test-EventHubPublicAccess
#   Test-ServiceBusSecurity
#   Test-APIMSecurity
#   Register-AzureMessagingChecks
# ============================================================================

function Test-EventHubPublicAccess {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "EVENT HUB - PUBLIC ACCESS & FIREWALL" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.EventHub)) {
        Write-AuditLog -Message "Az.EventHub module not installed. Skipping Event Hub checks." -Level WARN
        Write-Finding -Severity "INFO" -Status "NOTEVALUATED" -Count 0 `
                      -Message "Az.EventHub module/cmdlets unavailable" `
                      -Service "EventHub" -Exclusions $Exclusions `
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
        
        Write-Progress -Activity "Checking Event Hub network rules" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $namespaces = Invoke-AzureCommand -Command {
                Get-AzEventHubNamespace -ErrorAction Stop
            } -CommandName "Get-EventHubNamespaces"
            $evaluatedSubs++
            
            foreach ($namespace in $namespaces) {
                $networkRules = Invoke-AzureCommand -Command {
                    Get-AzEventHubNetworkRuleSet -ResourceGroupName $namespace.ResourceGroupName -Name $namespace.Name -ErrorAction SilentlyContinue
                } -CommandName "Get-EventHubNetworkRules"
                
                $publicAccess = if ($namespace.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $namespace.PublicNetworkAccess } else { "Enabled" }
                $defaultAction = if ($networkRules) { $networkRules.DefaultAction } else { "Allow" }
                
                if ($publicAccess -eq "Enabled" -and $defaultAction -eq "Allow") {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $namespace.ResourceGroupName
                        NamespaceName = $namespace.Name
                        PublicNetworkAccess = $publicAccess
                        DefaultAction = $defaultAction
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Event Hub network rules in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($findings.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Event Hub namespaces with public access and permissive firewall" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "EventHub" `
                      -Remediation "Disable public access or configure firewall/VNet rules." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    elseif ($evaluatedSubs -gt 0) {
        # Explicit PASS record: silence is never proof of evaluation.
        Write-Finding -Severity "INFO" -Status "PASS" -Count 0 `
                      -Message "No Event Hub namespaces with public access and permissive firewall" `
                      -Service "EventHub" -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
    else {
        Write-Finding -Severity "INFO" -Status "NOTEVALUATED" -Count 0 `
                      -Message "Event Hub namespaces could not be evaluated (collection failed in all subscriptions)" `
                      -Service "EventHub" -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-ServiceBusSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "SERVICE BUS - PUBLIC ACCESS & SAS POLICY HYGIENE" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.ServiceBus)) {
        Write-AuditLog -Message "Az.ServiceBus module not installed. Skipping Service Bus checks." -Level WARN
        return
    }
    
    $publicFindings = New-Object System.Collections.Generic.List[object]
    $sasFindings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Service Bus security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $namespaces = Invoke-AzureCommand -Command {
                Get-AzServiceBusNamespace -ErrorAction Stop
            } -CommandName "Get-ServiceBusNamespaces"
            
            foreach ($ns in $namespaces) {
                $networkRuleSet = Invoke-AzureCommand -Command {
                    Get-AzServiceBusNetworkRuleSet -ResourceGroupName $ns.ResourceGroupName -Namespace $ns.Name -ErrorAction SilentlyContinue
                } -CommandName "Get-ServiceBusNetworkRules"
                
                $authRules = Invoke-AzureCommand -Command {
                    Get-AzServiceBusAuthorizationRule -ResourceGroupName $ns.ResourceGroupName -Namespace $ns.Name -ErrorAction SilentlyContinue
                } -CommandName "Get-ServiceBusAuthRules"
                
                $publicAccess = if ($ns.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $ns.PublicNetworkAccess } else { "Enabled" }
                $defaultAction = if ($networkRuleSet) { $networkRuleSet.DefaultAction } else { "Allow" }
                
                if ($publicAccess -eq "Enabled" -and $defaultAction -eq "Allow") {
                    $publicFindings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $ns.ResourceGroupName
                        Namespace = $ns.Name
                        PublicNetworkAccess = $publicAccess
                        DefaultAction = $defaultAction
                    })
                }
                
                if ($authRules) {
                    $sasFindings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $ns.ResourceGroupName
                        Namespace = $ns.Name
                        SASKeyCount = ($authRules | Measure-Object).Count
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Service Bus security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($publicFindings.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Service Bus namespaces with public access and permissive firewall" `
                      -Count $publicFindings.Count `
                      -Data $publicFindings `
                      -Service "ServiceBus" `
                      -Remediation "Disable public access or configure firewall/VNet rules." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($sasFindings.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Service Bus namespaces using SAS keys (consider managed identity)" `
                      -Count $sasFindings.Count `
                      -Data $sasFindings `
                      -Service "ServiceBus" `
                      -Remediation "Reduce SAS key usage and migrate to managed identity where possible." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-APIMSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "API MANAGEMENT - EXPOSURE & CERTIFICATE HYGIENE" -Color "Yellow" -ProgressId $ProgressId
    
    if (-not (Get-Module -ListAvailable -Name Az.ApiManagement)) {
        Write-AuditLog -Message "Az.ApiManagement module not installed. Skipping APIM checks." -Level WARN
        return
    }
    
    $external = New-Object System.Collections.Generic.List[object]
    $expiredCerts = New-Object System.Collections.Generic.List[object]
    $nearExpiryCerts = New-Object System.Collections.Generic.List[object]
    $now = Get-Date
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking APIM security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $services = Invoke-AzureCommand -Command {
                Get-AzApiManagement -ErrorAction Stop
            } -CommandName "Get-ApiManagement"
            
            foreach ($apim in $services) {
                $external.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $apim.ResourceGroupName
                    APIMName = $apim.Name
                    VirtualNetworkType = $apim.VirtualNetworkType
                    IsPublicFacing = if ($apim.VirtualNetworkType -eq "Internal") { "No" } else { "Yes" }
                })
                
                $certificates = Invoke-AzureCommand -Command {
                    Get-AzApiManagementCertificate -ResourceGroupName $apim.ResourceGroupName -ServiceName $apim.Name -ErrorAction SilentlyContinue
                } -CommandName "Get-ApiManagementCertificates"
                
                foreach ($cert in $certificates) {
                    $expiryDate = $cert.ExpirationDate
                    if (-not $expiryDate) { continue }
                    $daysToExpiry = ($expiryDate - $now).Days
                    
                    if ($daysToExpiry -lt 0) {
                        $expiredCerts.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $apim.ResourceGroupName
                            APIMName = $apim.Name
                            Certificate = $cert.Subject
                            ExpiryDate = $expiryDate
                        })
                    } elseif ($daysToExpiry -lt 30) {
                        $nearExpiryCerts.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $apim.ResourceGroupName
                            APIMName = $apim.Name
                            Certificate = $cert.Subject
                            DaysToExpiry = $daysToExpiry
                            ExpiryDate = $expiryDate
                        })
                    }
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check APIM security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    $externalPublic = @($external | Where-Object { $_.IsPublicFacing -eq "Yes" })
    if ($externalPublic.Count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "External (public-facing) API Management services" `
                      -Count $externalPublic.Count `
                      -Data $externalPublic `
                      -Service "APIM" `
                      -Remediation "Review exposure and consider internal VNet deployments where possible." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($expiredCerts.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "API Management services with expired certificates" `
                      -Count $expiredCerts.Count `
                      -Data $expiredCerts `
                      -Service "APIM" `
                      -Remediation "Replace expired certificates immediately to avoid outages." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($nearExpiryCerts.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "API Management certificates expiring soon (<30 days)" `
                      -Count $nearExpiryCerts.Count `
                      -Data $nearExpiryCerts `
                      -Service "APIM" `
                      -Remediation "Rotate certificates before expiration to prevent service disruption." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Register-AzureMessagingChecks {
    Register-AuditCheck -CheckId "MESSAGING-001" `
                        -Category "Azure" `
                        -Service "EventHub" `
                        -Name "Event Hub Public Access" `
                        -Function ${function:Test-EventHubPublicAccess} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.EventHub") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.EventHub/namespaces')
    
    Register-AuditCheck -CheckId "MESSAGING-002" `
                        -Category "Azure" `
                        -Service "ServiceBus" `
                        -Name "Service Bus Security" `
                        -Function ${function:Test-ServiceBusSecurity} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.ServiceBus") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.ServiceBus/namespaces')
    
    Register-AuditCheck -CheckId "MESSAGING-003" `
                        -Category "Azure" `
                        -Service "APIM" `
                        -Name "API Management Security" `
                        -Function ${function:Test-APIMSecurity} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.ApiManagement") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.ApiManagement/service')
}
