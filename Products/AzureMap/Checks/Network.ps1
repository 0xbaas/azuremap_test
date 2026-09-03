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
#   Test-AppGatewayListenerHygiene      (NETWORK-009)
#   Test-SensitivePaaSPrivateConnectivity (NETWORK-010)
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
        Write-Progress -Activity "Checking NSG Permissive Rules" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory. ContextSwitch -> skipped sub
        # (silent continue as before); Fetch -> failed collection (ERROR log).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind NetworkSecurityGroups
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check NSG rules in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        $totalProcessed++

        try {
            foreach ($nsg in $inv.Items) {
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

        Write-Progress -Activity "Checking Private Endpoint DNS" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind PrivateEndpoints
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check private endpoint DNS in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        # Per-endpoint DNS zone group calls still need the session on this
        # subscription (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }

        try {
            foreach ($pe in $inv.Items) {
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

        Write-Progress -Activity "Checking public IP inventory" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind PublicIpAddresses
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check public IPs in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        try {
            foreach ($pip in $inv.Items) {
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

        Write-Progress -Activity "Checking VNet subnet security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind VirtualNetworks
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check VNet subnet security in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        try {
            foreach ($vnet in $inv.Items) {
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

        Write-Progress -Activity "Checking VNet peering security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind VirtualNetworks
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check VNet peering in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        # Per-VNet peering calls still need the session on this subscription
        # (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            continue
        }

        try {
            foreach ($vnet in $inv.Items) {
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

        Write-Progress -Activity "Checking Azure Firewall threat intel" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind Firewalls
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check Azure Firewall threat intel in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        try {
            foreach ($fw in $inv.Items) {
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

        Write-Progress -Activity "Checking Application Gateway WAF" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind ApplicationGateways
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check Application Gateway WAF in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        try {
            foreach ($appgw in $inv.Items) {
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

function Test-AppGatewayListenerHygiene {
    <#
    .SYNOPSIS
        NETWORK-009 - Application Gateway HTTP/TLS listener hygiene.
    .DESCRIPTION
        * HTTP listener without an HTTPS redirect -> MEDIUM.
        * HTTP listener whose RedirectConfiguration targets an HTTPS listener
          (redirect-only) -> NOT flagged.
        * SSL policy below TLS 1.2 (Predefined legacy names / names containing
          TLSv1_0/TLSv1_1, or Custom minProtocolVersion TLSv1_0/TLSv1_1, or
          unspecified legacy default) -> MEDIUM, HIGH when the gateway has a
          public frontend IP.
        Inventory read failure -> NOTEVALUATED, never a misleading clean PASS.
    #>
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "APPLICATION GATEWAYS - LISTENER / TLS HYGIENE" -Color "Yellow" -ProgressId $ProgressId

    # Legacy predefined SSL policies that allow TLS below 1.2 (date-based names;
    # names literally containing TLSv1_0/TLSv1_1 are matched separately below).
    $legacyPredefinedPolicies = @('AppGwSslPolicy20150501', 'AppGwSslPolicy20170401')

    $httpNoRedirect = New-Object System.Collections.Generic.List[object]
    $weakTls        = New-Object System.Collections.Generic.List[object]
    $notEval        = New-Object System.Collections.Generic.List[object]
    $subsEvaluated  = New-Object System.Collections.Generic.List[string]
    $subsSkipped    = New-Object System.Collections.Generic.List[string]
    $totalGateways  = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking App Gateway listener hygiene" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind ApplicationGateways
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = 'Application Gateway collection failed' }) }
            continue
        }
        $subsEvaluated.Add($sub.Name)
        $totalGateways += @($inv.Items).Count

        foreach ($appgw in $inv.Items) {
            # Public-facing = any frontend IP configuration bound to a public IP.
            $isPublic = $false
            foreach ($fe in @($appgw.FrontendIPConfigurations)) {
                if ($fe -and ($fe.PSObject.Properties.Name -contains 'PublicIPAddress') -and $fe.PublicIPAddress) { $isPublic = $true; break }
            }
            $facing = if ($isPublic) { 'Public' } else { 'Private' }

            # Listener map (id -> protocol) for redirect-target resolution.
            $listenerProtoById = @{}
            foreach ($l in @($appgw.HttpListeners)) {
                if ($l -and $l.Id) { $listenerProtoById["$($l.Id)".ToLowerInvariant()] = "$($l.Protocol)" }
            }
            $redirectById = @{}
            foreach ($rc in @($appgw.RedirectConfigurations)) {
                if ($rc -and $rc.Id) { $redirectById["$($rc.Id)".ToLowerInvariant()] = $rc }
            }

            foreach ($listener in @($appgw.HttpListeners)) {
                if ("$($listener.Protocol)" -ne 'Http') { continue }

                $redirectOk = $false
                $redirectRef = $null
                if ($listener.PSObject.Properties.Name -contains 'RedirectConfiguration') { $redirectRef = $listener.RedirectConfiguration }
                if ($redirectRef) {
                    # Redirect-only configuration is acceptable only when it
                    # targets an HTTPS listener. An unresolvable reference is
                    # treated as a redirect (never a false positive).
                    $rcId = "$($redirectRef.Id)".ToLowerInvariant()
                    if ($rcId -and $redirectById.ContainsKey($rcId)) {
                        $targetId = "$($redirectById[$rcId].TargetListener.Id)".ToLowerInvariant()
                        if (-not $targetId -or -not $listenerProtoById.ContainsKey($targetId) -or
                            $listenerProtoById[$targetId] -eq 'Https') {
                            $redirectOk = $true
                        }
                    }
                    else {
                        $redirectOk = $true
                    }
                }

                if (-not $redirectOk) {
                    $httpNoRedirect.Add([PSCustomObject]@{
                        SubscriptionId   = $sub.Id
                        SubscriptionName = $sub.Name
                        ResourceGroup    = $appgw.ResourceGroupName
                        GatewayName      = $appgw.Name
                        ListenerName     = "$($listener.Name)"
                        FrontendPort     = if ($listener.FrontendPort) { "$($listener.FrontendPort.Id)" } else { $null }
                        Facing           = $facing
                    })
                }
            }

            # SSL policy: absent/unspecified means the legacy default (TLS 1.0
            # allowed) - flagged explicitly, consistent with the storage TLS
            # "unspecified is risky" semantics.
            $sp = $appgw.SslPolicy
            $weak = $false
            $tlsDetail = $null
            if ($sp) {
                $ptype = "$($sp.PolicyType)"
                if ($ptype -eq 'Predefined') {
                    $pname = "$($sp.PolicyName)"
                    if ($pname -match 'TLSv1_0|TLSv1_1' -or $legacyPredefinedPolicies -contains $pname) {
                        $weak = $true; $tlsDetail = "Predefined policy '$pname' allows TLS < 1.2"
                    }
                }
                elseif ($ptype -eq 'Custom' -or ($sp.PSObject.Properties.Name -contains 'MinProtocolVersion' -and $sp.MinProtocolVersion)) {
                    $min = "$($sp.MinProtocolVersion)"
                    if ($min -in @('TLSv1_0', 'TLSv1_1')) { $weak = $true; $tlsDetail = "Custom policy minProtocolVersion $min" }
                }
            }
            else {
                $weak = $true; $tlsDetail = 'Unspecified (legacy default policy allows TLS 1.0/1.1)'
            }

            if ($weak) {
                $weakTls.Add([PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $appgw.ResourceGroupName
                    GatewayName      = $appgw.Name
                    SslPolicy        = $tlsDetail
                    Facing           = $facing
                    Severity         = if ($isPublic) { 'HIGH' } else { 'MEDIUM' }
                })
            }
        }
    }

    $signalTotal = $httpNoRedirect.Count + $weakTls.Count
    $cov = New-AzureCheckCoverage -Discovered $totalGateways -Evaluated $totalGateways -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $signalTotal -ResourceNoun 'application gateways'
    $covParams = New-AzureCheckCoverageParams -Coverage $cov -Discovered $totalGateways -Evaluated $totalGateways `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzApplicationGateway') -FindingType 'Misconfiguration'

    if ($httpNoRedirect.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "NETWORK-009" `
                      -Message "Application Gateway HTTP listeners without HTTPS redirect" `
                      -Count $httpNoRedirect.Count -CountType "UniqueResources" -Data $httpNoRedirect -Service "Network" `
                      -SeverityReason 'Plaintext HTTP listeners accept unencrypted traffic; redirect-only listeners targeting an HTTPS listener are not flagged.' `
                      -Remediation "Add a redirect configuration from each HTTP listener to an HTTPS listener, or remove the HTTP listener." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    $weakHigh   = New-Object System.Collections.Generic.List[object]
    $weakMedium = New-Object System.Collections.Generic.List[object]
    foreach ($w in $weakTls) { if ($w.Severity -eq 'HIGH') { $weakHigh.Add($w) } else { $weakMedium.Add($w) } }
    if ($weakHigh.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -CheckId "NETWORK-009" `
                      -Message "Public-facing Application Gateways with SSL policy below TLS 1.2" `
                      -Count $weakHigh.Count -CountType "UniqueResources" -Data $weakHigh -Service "Network" `
                      -SeverityReason 'Internet-facing gateway accepting TLS < 1.2: downgrade and weak-cipher exposure.' `
                      -Remediation "Apply a predefined SSL policy requiring TLS 1.2+ (e.g. AppGwSslPolicy20220101) or a custom policy with minProtocolVersion TLSv1_2." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($weakMedium.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "NETWORK-009" `
                      -Message "Application Gateways with SSL policy below TLS 1.2 (or unspecified legacy default)" `
                      -Count $weakMedium.Count -CountType "UniqueResources" -Data $weakMedium -Service "Network" `
                      -SeverityReason 'Internal gateway accepting TLS < 1.2; context-dependent.' `
                      -Remediation "Apply a predefined SSL policy requiring TLS 1.2+ or a custom policy with minProtocolVersion TLSv1_2." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($signalTotal -eq 0) {
        $severity = if ($cov.Severity) { $cov.Severity } else { 'MEDIUM' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status -CheckId "NETWORK-009" `
                      -Message "Application Gateway listener/TLS hygiene (HTTP without redirect, SSL policy below TLS 1.2)" `
                      -Count 0 -Data $evidence -Service "Network" `
                      -Remediation "Require HTTPS listeners and TLS 1.2+ SSL policies." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $signalTotal -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "NOTEVALUATED" -CheckId "NETWORK-009" `
                      -Message "Application Gateway listener hygiene could not be evaluated for one or more subscriptions (collection failed)." `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Network" `
                      -Remediation "Ensure Microsoft.Network/applicationGateways/read on all in-scope subscriptions and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-SensitivePaaSPrivateConnectivity {
    <#
    .SYNOPSIS
        NETWORK-010 - sensitive PaaS resources with public network access and
        no linked private endpoint.
    .DESCRIPTION
        Flags resources whose publicNetworkAccess is enabled or unspecified AND
        that have no private endpoint connection linked to the resource id
        (matched from the shared PrivateEndpoints inventory, both automatic and
        manual connections). Caveats carried on the finding: a private IP alone
        does not prove a resource is private; a private endpoint must be linked
        to the resource; DNS resolution is not verified; public network access
        is a separate property from firewall rules. Firewall defaultDeny (where
        readable on the list shape) downgrades severity to LOW.
        Failed resource or private-endpoint reads -> NOTEVALUATED, never Clean.
    #>
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "SENSITIVE PAAS - PRIVATE CONNECTIVITY" -Color "Yellow" -ProgressId $ProgressId

    # Per-kind descriptors. GetPna returns 'Public' (enabled or unspecified
    # default), 'Private' (explicitly disabled / internal), or 'Unknown'.
    $resourceSets = @(
        @{ Kind = 'StorageAccounts'; TypeLabel = 'Storage Account';
           GetId = { param($r) "$($r.Id)" }; GetName = { param($r) "$($r.StorageAccountName)" };
           GetPna = { param($r) if ("$($r.PublicNetworkAccess)" -eq 'Disabled') { 'Private' } else { 'Public' } };
           FirewallDeny = { param($r) $false } }
        @{ Kind = 'KeyVaults'; TypeLabel = 'Key Vault';
           GetId = { param($r) "$($r.ResourceId)" }; GetName = { param($r) "$($r.VaultName)" };
           GetPna = { param($r) if ("$($r.PublicNetworkAccess)" -eq 'Disabled') { 'Private' } else { 'Public' } };
           FirewallDeny = { param($r) ($r.NetworkAcls -and "$($r.NetworkAcls.DefaultAction)" -eq 'Deny') } }
        @{ Kind = 'SqlServers'; TypeLabel = 'SQL Server';
           GetId = { param($r) "$($r.ResourceId)" }; GetName = { param($r) "$($r.ServerName)" };
           GetPna = { param($r) if ("$($r.PublicNetworkAccess)" -eq 'Disabled') { 'Private' } else { 'Public' } };
           FirewallDeny = { param($r) $false } }
        @{ Kind = 'CosmosAccounts'; TypeLabel = 'Cosmos DB Account';
           GetId = { param($r) "$($r.ResourceId)" }; GetName = { param($r) "$($r.Name)" };
           GetPna = { param($r)
               $p = $null
               if ($r.PSObject.Properties.Name -contains 'Properties' -and $r.Properties) {
                   if ($r.Properties -is [hashtable]) { $p = $r.Properties['publicNetworkAccess'] }
                   elseif ($r.Properties.PSObject.Properties.Name -contains 'publicNetworkAccess') { $p = $r.Properties.publicNetworkAccess }
               }
               if ("$p" -eq 'Disabled') { 'Private' } else { 'Public' } };
           FirewallDeny = { param($r) $false } }
        @{ Kind = 'ContainerRegistries'; TypeLabel = 'Container Registry';
           GetId = { param($r) "$($r.Id)" }; GetName = { param($r) "$($r.Name)" };
           GetPna = { param($r) if ("$($r.PublicNetworkAccess)" -eq 'Disabled') { 'Private' } else { 'Public' } };
           FirewallDeny = { param($r) ($r.NetworkRuleSet -and "$($r.NetworkRuleSet.DefaultAction)" -eq 'Deny') } }
        @{ Kind = 'ServiceBusNamespaces'; TypeLabel = 'Service Bus Namespace';
           GetId = { param($r) "$($r.Id)" }; GetName = { param($r) "$($r.Name)" };
           GetPna = { param($r) if ("$($r.PublicNetworkAccess)" -eq 'Disabled') { 'Private' } else { 'Public' } };
           FirewallDeny = { param($r) ($r.NetworkRuleSet -and "$($r.NetworkRuleSet.DefaultAction)" -eq 'Deny') } }
        @{ Kind = 'WebApps'; TypeLabel = 'App Service App';
           GetId = { param($r) "$($r.Id)" }; GetName = { param($r) "$($r.Name)" };
           GetPna = { param($r) if ("$($r.PublicNetworkAccess)" -eq 'Disabled') { 'Private' } else { 'Public' } };
           FirewallDeny = { param($r) $false } }
        @{ Kind = 'ApiManagementServices'; TypeLabel = 'API Management Service';
           GetId = { param($r) "$($r.Id)" }; GetName = { param($r) "$($r.Name)" };
           GetPna = { param($r)
               if ("$($r.VpnType)" -eq 'Internal' -or "$($r.VirtualNetworkType)" -eq 'Internal') { 'Private' }
               elseif ("$($r.PublicNetworkAccess)" -eq 'Disabled') { 'Private' }
               else { 'Public' } };
           FirewallDeny = { param($r) $false } }
    )

    $exposed   = New-Object System.Collections.Generic.List[object]  # MEDIUM: public, no PE
    $mitigated = New-Object System.Collections.Generic.List[object]  # LOW: public, no PE, firewall defaultDeny
    $notEval   = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalResources = 0
    $evaluatedResources = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking PaaS private connectivity" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Private endpoints first: a failed PE read means linkage can never be
        # proven for this subscription -> NotEvaluated, never Clean.
        $peInv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind PrivateEndpoints
        if ($peInv.Unavailable) {
            if ($peInv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; ResourceType = '(all)'; Reason = 'Private endpoint collection failed - linkage unproven' }) }
            continue
        }

        # Linked-resource set: every PrivateLinkServiceId referenced by any PE
        # in this subscription (automatic + manual connections).
        $linkedResourceIds = @{}
        foreach ($pe in @($peInv.Items)) {
            foreach ($conn in @($pe.PrivateLinkServiceConnections)) {
                if ($conn -and $conn.PrivateLinkServiceId) { $linkedResourceIds["$($conn.PrivateLinkServiceId)".ToLowerInvariant()] = $true }
            }
            foreach ($conn in @($pe.ManualPrivateLinkServiceConnections)) {
                if ($conn -and $conn.PrivateLinkServiceId) { $linkedResourceIds["$($conn.PrivateLinkServiceId)".ToLowerInvariant()] = $true }
            }
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

            foreach ($res in @($inv.Items)) {
                $evaluatedResources++
                $rid  = & $set.GetId $res
                $name = & $set.GetName $res
                $pna  = & $set.GetPna $res

                if ($pna -eq 'Unknown') {
                    $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; ResourceType = $set.TypeLabel; ResourceName = $name; Reason = 'publicNetworkAccess unreadable' })
                    continue
                }
                if ($pna -eq 'Private') { continue }
                if ($rid -and $linkedResourceIds.ContainsKey($rid.ToLowerInvariant())) { continue }

                $entry = [PSCustomObject]@{
                    SubscriptionId      = $sub.Id
                    SubscriptionName    = $sub.Name
                    ResourceType        = $set.TypeLabel
                    ResourceName        = $name
                    ResourceGroup       = "$($res.ResourceGroupName)"
                    PublicNetworkAccess = 'Enabled or unspecified'
                    PrivateEndpointLinked = $false
                    FirewallDefaultDeny = [bool](& $set.FirewallDeny $res)
                    ResourceId          = $rid
                }
                if ($entry.FirewallDefaultDeny) { $mitigated.Add($entry) } else { $exposed.Add($entry) }
            }
        }
        if ($subEvaluated -and -not $subsEvaluated.Contains($sub.Name)) { $subsEvaluated.Add($sub.Name) }
    }

    $signalTotal = $exposed.Count + $mitigated.Count
    $cov = New-AzureCheckCoverage -Discovered $totalResources -Evaluated $evaluatedResources -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $signalTotal -ResourceNoun 'sensitive PaaS resources'
    $covParams = New-AzureCheckCoverageParams -Coverage $cov -Discovered $totalResources -Evaluated $evaluatedResources `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzPrivateEndpoint', 'ARM per-service resource lists (cached inventory)') -FindingType 'Exposure'

    $caveats = 'Caveats: a private IP alone does not prove the resource is private - a private endpoint must be linked to the resource; DNS resolution is not verified; public network access is a separate property from firewall rules.'

    if ($exposed.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -CheckId "NETWORK-010" `
                      -Message "Sensitive PaaS resources with public network access and no linked private endpoint" `
                      -Count $exposed.Count -CountType "UniqueResources" -Data $exposed -Service "Network" `
                      -SeverityReason $caveats `
                      -Remediation "Add private endpoints and set publicNetworkAccess to Disabled where private connectivity is the intended access path. $caveats" `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($mitigated.Count -gt 0) {
        Write-Finding -Severity "LOW" -Status "FAIL" -CheckId "NETWORK-010" `
                      -Message "Sensitive PaaS resources without a linked private endpoint (public network access mitigated by firewall default deny)" `
                      -Count $mitigated.Count -CountType "UniqueResources" -Data $mitigated -Service "Network" `
                      -SeverityReason "Firewall default action Deny reduces practical exposure, so severity is LOW. $caveats" `
                      -Remediation "Consider private endpoints for defense in depth. $caveats" `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($signalTotal -eq 0) {
        $severity = if ($cov.Severity) { $cov.Severity } else { 'MEDIUM' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status -CheckId "NETWORK-010" `
                      -Message "Sensitive PaaS resources with public network access and no linked private endpoint" `
                      -Count 0 -Data $evidence -Service "Network" `
                      -Remediation "Add private endpoints and disable public network access where private connectivity is intended." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $signalTotal -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "NOTEVALUATED" -CheckId "NETWORK-010" `
                      -Message "Private connectivity could not be fully evaluated (resource or private-endpoint reads failed)." `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Network" `
                      -Remediation "Ensure Microsoft.Network/privateEndpoints/read plus per-service read permissions and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
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

        Write-Progress -Activity "Checking network exfiltration paths" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Two kinds, old independent failure semantics preserved: an NSG fetch
        # failure skips the subscription (the NSG enumeration came first); a
        # RouteTable fetch failure keeps the NSG evidence already collected
        # and only skips the route-table pass.
        $invNsg = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind NetworkSecurityGroups
        if ($invNsg.Unavailable) {
            if ($invNsg.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check network exfiltration paths in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        try {
            foreach ($nsg in $invNsg.Items) {
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
            
        }
        catch {
            Write-AuditLog -Message "Failed to check network exfiltration paths in subscription $($sub.Name): $_" -Level ERROR
        }

        $invRt = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind RouteTables
        if ($invRt.Unavailable) {
            if ($invRt.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check network exfiltration paths in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        try {
            foreach ($rt in $invRt.Items) {
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

    Register-AuditCheck -CheckId "NETWORK-009" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "App Gateway Listener Hygiene" `
                        -Function ${function:Test-AppGatewayListenerHygiene} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Network/applicationGateways')

    Register-AuditCheck -CheckId "NETWORK-010" `
                        -Category "Azure" `
                        -Service "Network" `
                        -Name "Sensitive PaaS Private Connectivity" `
                        -Function ${function:Test-SensitivePaaSPrivateConnectivity} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.Storage/storageAccounts','Microsoft.KeyVault/vaults','Microsoft.Sql/servers','Microsoft.DocumentDb/databaseAccounts','Microsoft.ContainerRegistry/registries','Microsoft.ServiceBus/namespaces','Microsoft.Web/sites','Microsoft.ApiManagement/service')
}
