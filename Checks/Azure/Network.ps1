# ============================================================================
# AzureMap - Network Security Checks
# ============================================================================
# Functions:
#   Test-NSGPermissiveRules
#   Test-PrivateEndpointsDNS
#   Test-PublicIPInventory
#   Test-VNetSubnetSecurity
#   Test-VNetPeeringSecurity
#   Test-AzureFirewallThreatIntel
#   Test-ApplicationGatewayWAF
#   Test-NetworkExfiltrationPaths
#   Register-AzureNetworkChecks
# ============================================================================

function Test-NSGPermissiveRules {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "NETWORK SECURITY GROUPS - OVERLY PERMISSIVE RULES" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking NSG Permissive Rules" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $nsgs = Invoke-AzureCommand -Command { 
                Get-AzNetworkSecurityGroup -ErrorAction Stop
            } -CommandName "Get-NSGs" -SkipContextCheck -Critical
            
            $totalProcessed++
            
            foreach ($nsg in $nsgs) {
                foreach ($rule in $nsg.SecurityRules) {
                    if ($rule.Access -eq "Allow" -and $rule.Direction -eq "Inbound") {
                        $sourceIsWideOpen = $false
                        
                        # Check source
                        if ($rule.SourceAddressPrefix) {
                            $sourceIsWideOpen = $rule.SourceAddressPrefix -in @("Internet", "0.0.0.0/0", "*")
                        }
                        elseif ($rule.SourceAddressPrefixes) {
                            foreach ($prefix in $rule.SourceAddressPrefixes) {
                                if ($prefix -in @("Internet", "0.0.0.0/0", "*")) {
                                    $sourceIsWideOpen = $true
                                    break
                                }
                            }
                        }
                        
                        if ($sourceIsWideOpen) {
                            $portsToCheck = @()
                            if ($rule.DestinationPortRange) {
                                $portsToCheck += $rule.DestinationPortRange
                            }
                            if ($rule.DestinationPortRanges) {
                                $portsToCheck += $rule.DestinationPortRanges
                            }
                            
                            $isAllPorts = $false
                            foreach ($portRange in $portsToCheck) {
                                if ($portRange -eq "*" -or $portRange -eq "0-65535" -or $portRange -eq "0-*") {
                                    $isAllPorts = $true
                                    break
                                }
                            }
                            
                            if ($isAllPorts) {
                                $severity = if ($rule.Protocol -in @("Tcp", "*", "All")) { "HIGH" } else { "MEDIUM" }
                                $findings.Add([PSCustomObject]@{
                                    SubscriptionId = $sub.Id
                                    SubscriptionName = $sub.Name
                                    RG = $nsg.ResourceGroupName
                                    NSGName = $nsg.Name
                                    RuleName = $rule.Name
                                    Source = if ($rule.SourceAddressPrefix) { $rule.SourceAddressPrefix } else { ($rule.SourceAddressPrefixes -join ", ") }
                                    DestinationPort = "* (all ports)"
                                    Protocol = $rule.Protocol
                                    Priority = $rule.Priority
                                    Severity = $severity
                                    ResourceId = $nsg.Id
                                    Tags = $nsg.Tags
                                })
                            } else {
                                # Check specific dangerous ports
                                foreach ($portRange in $portsToCheck) {
                                    foreach ($dangerPort in $script:State.Config.DangerousPorts) {
                                        $portMatches = $false
                                        
                                        if ($portRange -eq $dangerPort) {
                                            $portMatches = $true
                                        } elseif ($portRange -match "^\d+-\d+$") {
                                            $rangeParts = $portRange.Split("-")
                                            $portMatches = [int]$dangerPort -ge [int]$rangeParts[0] -and [int]$dangerPort -le [int]$rangeParts[1]
                                        }
                                        
                                        if ($portMatches) {
                                            $isTcpDangerPort = $dangerPort -in @("22", "3389", "1433")
                                            $severity = if ($isTcpDangerPort -and $rule.Protocol -in @("Tcp", "*", "All")) { "HIGH" } else { "MEDIUM" }
                                            
                                            $findings.Add([PSCustomObject]@{
                                                SubscriptionId = $sub.Id
                                                SubscriptionName = $sub.Name
                                                RG = $nsg.ResourceGroupName
                                                NSGName = $nsg.Name
                                                RuleName = $rule.Name
                                                Source = if ($rule.SourceAddressPrefix) { $rule.SourceAddressPrefix } else { ($rule.SourceAddressPrefixes -join ", ") }
                                                DestinationPort = $portRange
                                                Protocol = $rule.Protocol
                                                Priority = $rule.Priority
                                                Severity = $severity
                                                ResourceId = $nsg.Id
                                                Tags = $nsg.Tags
                                            })
                                            break
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check NSG rules in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    $highFindings = @($findings | Where-Object { $_.Severity -eq "HIGH" })
    $mediumFindings = @($findings | Where-Object { $_.Severity -eq "MEDIUM" })
    
    if ($highFindings.Count -gt 0) {
        $remediation = "Remove or restrict NSG rules allowing internet access to sensitive ports.`n" +
                       "Use specific source IP ranges instead of 0.0.0.0/0."
        
        Write-Finding -Severity "HIGH" `
                      -Message "NSG rules allowing internet access to sensitive ports (SSH, RDP, SQL)" `
                      -Count $highFindings.Count `
                      -Data $highFindings `
                      -Service "Network" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($mediumFindings.Count -gt 0) {
        $remediation = "Review NSG rules for unnecessary wide-open access.`n" +
                       "Implement least privilege network access."
        
        Write-Finding -Severity "MEDIUM" `
                      -Message "NSG rules allowing internet access to other ports" `
                      -Count $mediumFindings.Count `
                      -Data $mediumFindings `
                      -Service "Network" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-PrivateEndpointsDNS {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "PRIVATE ENDPOINTS - DNS ZONE LINKAGE" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Private Endpoint DNS" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $privateEndpoints = Invoke-AzureCommand -Command {
                Get-AzPrivateEndpoint -ErrorAction Stop
            } -CommandName "Get-PrivateEndpoints"
            
            foreach ($pe in $privateEndpoints) {
                $dnsZoneGroups = Invoke-AzureCommand -Command {
                    Get-AzPrivateDnsZoneGroup -ResourceGroupName $pe.ResourceGroupName `
                                             -PrivateEndpointName $pe.Name `
                                             -ErrorAction SilentlyContinue
                } -CommandName "Get-PrivateDnsZoneGroup" -SkipContextCheck
                
                if (-not $dnsZoneGroups -or ($dnsZoneGroups | Measure-Object).Count -eq 0) {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $pe.ResourceGroupName
                        PrivateEndpoint = $pe.Name
                        ResourceId = $pe.Id
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check private endpoint DNS in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($findings.Count -gt 0) {
        $remediation = "Attach private DNS zone groups to private endpoints to avoid DNS leakage and resolution failures."
        Write-Finding -Severity "MEDIUM" `
                      -Message "Private endpoints missing private DNS zone linkage (DNS leak risk)" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "Network" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-PublicIPInventory {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "NETWORK - PUBLIC IP INVENTORY" -Color "Yellow" -ProgressId $ProgressId
    
    $withDns = New-Object System.Collections.Generic.List[object]
    $basicSku = New-Object System.Collections.Generic.List[object]
    $allIps = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking public IP inventory" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $publicIps = Invoke-AzureCommand -Command {
                Get-AzPublicIpAddress -ErrorAction Stop
            } -CommandName "Get-PublicIPs"
            
            foreach ($pip in $publicIps) {
                $dnsName = if ($pip.DnsSettings) { $pip.DnsSettings.Fqdn } else { $null }
                $sku = if ($pip.Sku) { $pip.Sku.Name } else { "Basic" }
                
                $allIps.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $pip.ResourceGroupName
                    PublicIPName = $pip.Name
                    IPAddress = $pip.IpAddress
                    SKU = $sku
                    DNSEndpoint = if ($dnsName) { $dnsName } else { "None" }
                })
                
                if ($dnsName) {
                    $withDns.Add($allIps[-1])
                }
                if ($sku -eq "Basic") {
                    $basicSku.Add($allIps[-1])
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check public IPs in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($withDns.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Public IPs with DNS endpoints (exposed services)" `
                      -Count $withDns.Count `
                      -Data $withDns `
                      -Service "PublicIP" `
                      -Remediation "Review exposed services and restrict access where possible." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($basicSku.Count -gt 0) {
        Write-Finding -Severity "LOW" `
                      -Message "Public IPs using Basic SKU" `
                      -Count $basicSku.Count `
                      -Data $basicSku `
                      -Service "PublicIP" `
                      -Remediation "Migrate to Standard SKU for enhanced resilience and security." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($allIps.Count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "Public IP inventory" `
                      -Count $allIps.Count `
                      -Data $allIps `
                      -Service "PublicIP" `
                      -FindingType 'Inventory' -IsInventoryOnly $true `
                      -SeverityReason 'Inventory/context only - a public IP is not a finding by itself.' `
                      -Remediation "Inventory for exposure tracking." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-VNetSubnetSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "VIRTUAL NETWORKS - SUBNET SECURITY CONFIGURATION" -Color "Yellow" -ProgressId $ProgressId
    
    $noNSG = New-Object System.Collections.Generic.List[object]
    $largeSubnets = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking VNet subnet security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $vnets = Invoke-AzureCommand -Command {
                Get-AzVirtualNetwork -ErrorAction Stop
            } -CommandName "Get-VNets"
            
            foreach ($vnet in $vnets) {
                foreach ($subnet in $vnet.Subnets) {
                    $hasNSG = -not [string]::IsNullOrEmpty($subnet.NetworkSecurityGroup.Id)
                    $addressPrefix = $subnet.AddressPrefix
                    
                    if (-not $hasNSG) {
                        $noNSG.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $vnet.ResourceGroupName
                            VNetName = $vnet.Name
                            SubnetName = $subnet.Name
                            AddressPrefix = $addressPrefix
                        })
                    }
                    
                    if ($addressPrefix -match "/" -and [int]$addressPrefix.Split("/")[1] -lt 24) {
                        $largeSubnets.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $vnet.ResourceGroupName
                            VNetName = $vnet.Name
                            SubnetName = $subnet.Name
                            AddressPrefix = $addressPrefix
                        })
                    }
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check VNet subnet security in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($noNSG.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Virtual network subnets without Network Security Group" `
                      -Count $noNSG.Count `
                      -Data $noNSG `
                      -Service "Network" `
                      -Remediation "Associate NSGs to all subnets to enforce network controls." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($largeSubnets.Count -gt 0) {
        Write-Finding -Severity "LOW" `
                      -Message "Large subnets (bigger than /24) - potential security concern" `
                      -Count $largeSubnets.Count `
                      -Data $largeSubnets `
                      -Service "Network" `
                      -Remediation "Review large subnets and consider segmentation where appropriate." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-VNetPeeringSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "VNET PEERING - SECURITY CONFIGURATION" -Color "Yellow" -ProgressId $ProgressId
    
    $crossSubPeering = New-Object System.Collections.Generic.List[object]
    $gatewayTransit = New-Object System.Collections.Generic.List[object]
    $forwardedTraffic = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking VNet peering security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $vnets = Invoke-AzureCommand -Command {
                Get-AzVirtualNetwork -ErrorAction Stop
            } -CommandName "Get-VNets"
            
            foreach ($vnet in $vnets) {
                $peerings = Invoke-AzureCommand -Command {
                    Get-AzVirtualNetworkPeering -ResourceGroupName $vnet.ResourceGroupName `
                                               -VirtualNetworkName $vnet.Name `
                                               -ErrorAction SilentlyContinue
                } -CommandName "Get-VNetPeerings"
                
                foreach ($peering in $peerings) {
                    $remoteVNetId = $peering.RemoteVirtualNetwork.Id
                    $remoteVNetName = $remoteVNetId.Split('/')[-1]
                    $remoteSub = $remoteVNetId.Split('/')[2]
                    
                    if ($sub.Id -ne $remoteSub) {
                        $crossSubPeering.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $vnet.ResourceGroupName
                            LocalVNet = $vnet.Name
                            RemoteVNet = $remoteVNetName
                            RemoteSubscription = $remoteSub
                            PeeringState = $peering.PeeringState
                        })
                    }
                    
                    if ($peering.AllowGatewayTransit -eq $true -or $peering.UseRemoteGateways -eq $true) {
                        $gatewayTransit.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $vnet.ResourceGroupName
                            LocalVNet = $vnet.Name
                            RemoteVNet = $remoteVNetName
                            AllowGatewayTransit = $peering.AllowGatewayTransit
                            UseRemoteGateways = $peering.UseRemoteGateways
                        })
                    }
                    
                    if ($peering.AllowForwardedTraffic -eq $true) {
                        $forwardedTraffic.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $vnet.ResourceGroupName
                            LocalVNet = $vnet.Name
                            RemoteVNet = $remoteVNetName
                            AllowForwardedTraffic = $peering.AllowForwardedTraffic
                        })
                    }
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check VNet peering in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($crossSubPeering.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Cross-subscription VNet peering (requires careful review)" `
                      -Count $crossSubPeering.Count `
                      -Data $crossSubPeering `
                      -Service "Network" `
                      -Remediation "Review cross-subscription peering and ensure proper segmentation." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($gatewayTransit.Count -gt 0) {
        Write-Finding -Severity "LOW" `
                      -Message "VNet peering with gateway transit enabled" `
                      -Count $gatewayTransit.Count `
                      -Data $gatewayTransit `
                      -Service "Network" `
                      -Remediation "Review gateway transit usage and restrict if not required." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($forwardedTraffic.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "VNet peering allowing forwarded traffic" `
                      -Count $forwardedTraffic.Count `
                      -Data $forwardedTraffic `
                      -Service "Network" `
                      -Remediation "Disable forwarded traffic unless explicitly required." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-AzureFirewallThreatIntel {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "AZURE FIREWALL - THREAT INTELLIGENCE" -Color "Yellow" -ProgressId $ProgressId
    
    $noThreatIntel = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Azure Firewall threat intel" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $firewalls = Invoke-AzureCommand -Command {
                Get-AzFirewall -ErrorAction Stop
            } -CommandName "Get-Firewalls"
            
            foreach ($fw in $firewalls) {
                $threatMode = if ($fw.PSObject.Properties.Name -contains "ThreatIntelMode") { $fw.ThreatIntelMode } else { "Unknown" }
                if ($threatMode -eq "Off" -or [string]::IsNullOrEmpty($threatMode)) {
                    $noThreatIntel.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $fw.ResourceGroupName
                        FirewallName = $fw.Name
                        ThreatIntelMode = $threatMode
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Azure Firewall threat intel in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($noThreatIntel.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Azure Firewalls without threat intelligence enabled" `
                      -Count $noThreatIntel.Count `
                      -Data $noThreatIntel `
                      -Service "Network" `
                      -Remediation "Enable threat intelligence in Azure Firewall policy." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-ApplicationGatewayWAF {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "APPLICATION GATEWAYS - WAF CONFIGURATION" -Color "Yellow" -ProgressId $ProgressId
    
    $wafMissing = New-Object System.Collections.Generic.List[object]
    $basicSku = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking Application Gateway WAF" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $gateways = Invoke-AzureCommand -Command {
                Get-AzApplicationGateway -ErrorAction Stop
            } -CommandName "Get-AppGateways"
            
            foreach ($appgw in $gateways) {
                $wafConfig = $appgw.WebApplicationFirewallConfiguration
                $skuName = if ($appgw.Sku) { $appgw.Sku.Name } else { "Unknown" }
                $wafEnabled = if ($wafConfig) { $wafConfig.Enabled } else { $false }
                
                if ($skuName -match "_v2" -and -not $wafEnabled) {
                    $wafMissing.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $appgw.ResourceGroupName
                        GatewayName = $appgw.Name
                        SKU = $skuName
                        WAFEnabled = $wafEnabled
                    })
                }
                
                if ($skuName -in @("Standard_Small", "Standard_Medium", "Standard_Large", "Basic")) {
                    $basicSku.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup = $appgw.ResourceGroupName
                        GatewayName = $appgw.Name
                        SKU = $skuName
                    })
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check Application Gateway WAF in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($wafMissing.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Application Gateways (v2 SKU) without WAF enabled" `
                      -Count $wafMissing.Count `
                      -Data $wafMissing `
                      -Service "Network" `
                      -SeverityReason 'Context-dependent: HIGH when the gateway fronts internet-facing or production workloads - validate exposure before prioritizing.' `
                      -Remediation "Enable WAF on v2 Application Gateways." `
                      -ManualValidationRequired $true `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($basicSku.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Application Gateways using Basic/Standard SKU (no WAF capability)" `
                      -Count $basicSku.Count `
                      -Data $basicSku `
                      -Service "Network" `
                      -Remediation "Upgrade to WAF_v2 SKU for web application protection." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-NetworkExfiltrationPaths {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "NETWORK - DATA EXFILTRATION PATHS" -Color "Red" -ProgressId $ProgressId
    
    $outboundInternet = New-Object System.Collections.Generic.List[object]
    $defaultRoutes = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }
        
        Write-Progress -Activity "Checking network exfiltration paths" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId
        
        try {
            $nsgs = Invoke-AzureCommand -Command {
                Get-AzNetworkSecurityGroup -ErrorAction Stop
            } -CommandName "Get-NSGs"
            
            foreach ($nsg in $nsgs) {
                foreach ($rule in $nsg.SecurityRules) {
                    if ($rule.Access -ne "Allow" -or $rule.Direction -ne "Outbound") { continue }
                    
                    $destIsInternet = $false
                    $destAddress = ""
                    if ($rule.DestinationAddressPrefix) {
                        $destAddress = $rule.DestinationAddressPrefix
                        $destIsInternet = $destAddress -in @("Internet", "0.0.0.0/0", "*")
                    } elseif ($rule.PSObject.Properties.Name -contains "DestinationAddressPrefixes") {
                        $destAddress = ($rule.DestinationAddressPrefixes -join ", ")
                        if ($rule.DestinationAddressPrefixes) {
                            foreach ($prefix in $rule.DestinationAddressPrefixes) {
                                if ($prefix -in @("Internet", "0.0.0.0/0", "*")) { $destIsInternet = $true; break }
                            }
                        }
                    }
                    
                    if ($destIsInternet) {
                        $outboundInternet.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $nsg.ResourceGroupName
                            NSGName = $nsg.Name
                            RuleName = $rule.Name
                            Destination = $destAddress
                            Protocol = $rule.Protocol
                            Port = if ($rule.DestinationPortRange) { $rule.DestinationPortRange } else { "Multiple" }
                            Priority = $rule.Priority
                        })
                    }
                }
            }
            
            $routeTables = Invoke-AzureCommand -Command {
                Get-AzRouteTable -ErrorAction Stop
            } -CommandName "Get-RouteTables"
            
            foreach ($rt in $routeTables) {
                foreach ($route in $rt.Routes) {
                    if ($route.AddressPrefix -eq "0.0.0.0/0" -and $route.NextHopType -eq "Internet") {
                        $defaultRoutes.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $rt.ResourceGroupName
                            RouteTable = $rt.Name
                            RouteName = $route.Name
                            NextHop = $route.NextHopType
                        })
                    }
                }
            }
        }
        catch {
            Write-AuditLog -Message "Failed to check network exfiltration paths in subscription $($sub.Name): $_" -Level ERROR
        }
    }
    
    if ($outboundInternet.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "NSG outbound rules allowing internet access (data exfiltration path)" `
                      -Count $outboundInternet.Count `
                      -Data $outboundInternet `
                      -Service "Exfiltration" `
                      -Remediation "Restrict outbound NSG rules and route traffic through inspection points." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($defaultRoutes.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Route tables with default route (0.0.0.0/0) to Internet" `
                      -Count $defaultRoutes.Count `
                      -Data $defaultRoutes `
                      -Service "Exfiltration" `
                      -Remediation "Route outbound traffic to firewall/NVA instead of Internet." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Register-AzureNetworkChecks {
    Register-AuditCheck -CheckId "NETWORK-001" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "NSG Permissive Rules" `
                        -Function ${function:Test-NSGPermissiveRules} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/networkSecurityGroups')
    
    Register-AuditCheck -CheckId "NETWORK-002" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "Private Endpoints DNS Linkage" `
                        -Function ${function:Test-PrivateEndpointsDNS} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network", "Az.PrivateDns") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/privateEndpoints')
    
    Register-AuditCheck -CheckId "NETWORK-003" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "Public IP Inventory" `
                        -Function ${function:Test-PublicIPInventory} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/publicIPAddresses')
    
    Register-AuditCheck -CheckId "NETWORK-004" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "VNet Subnet Security" `
                        -Function ${function:Test-VNetSubnetSecurity} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/virtualNetworks')
    
    Register-AuditCheck -CheckId "NETWORK-005" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "VNet Peering Security" `
                        -Function ${function:Test-VNetPeeringSecurity} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/virtualNetworks')
    
    Register-AuditCheck -CheckId "NETWORK-006" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "Azure Firewall Threat Intelligence" `
                        -Function ${function:Test-AzureFirewallThreatIntel} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/azureFirewalls')
    
    Register-AuditCheck -CheckId "NETWORK-007" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "Application Gateway WAF" `
                        -Function ${function:Test-ApplicationGatewayWAF} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/applicationGateways')
    
    Register-AuditCheck -CheckId "NETWORK-008" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "Network Exfiltration Paths" `
                        -Function ${function:Test-NetworkExfiltrationPaths} `
                        -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/networkSecurityGroups','Microsoft.Network/routeTables')
}
