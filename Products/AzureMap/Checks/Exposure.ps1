#==============================================================================
# AzureMap v2 - Products/AzureMap/Checks/Exposure.ps1
# AZURE-EXPOSURE-001  Central public exposure inventory  (PerSubscription, HIGH)
#
# READ-ONLY, CONTROL-PLANE ONLY. No data-plane calls, no probing/scanning,
# no web requests to customer endpoints, no secret/config reads.
# NotEvaluated when all sources fail; partial failures are tracked, not hidden.
#==============================================================================

$script:ExposureSensitivePorts = @('22','3389','1433','3306','5432','5985','5986','445')

function Test-ExposurePortMatch {
    param([string[]]$Ranges, [string]$Port)
    $p = [int]$Port
    foreach ($r in @($Ranges)) {
        $r = "$r".Trim()
        if ($r -eq '*' -or $r -eq '0-65535' -or $r -eq '0-*') { return $true }
        if ($r -eq "$Port") { return $true }
        if ($r -match '^\d+-\d+$') {
            $parts = $r.Split('-')
            if ($p -ge [int]$parts[0] -and $p -le [int]$parts[1]) { return $true }
        }
    }
    return $false
}

function Test-PublicExposureInventory {
    [CmdletBinding()]
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    foreach ($sub in @($Subscriptions)) {
        $exposed  = [System.Collections.Generic.List[object]]::new()
        $failures = [System.Collections.Generic.List[string]]::new()

        # --- Public IPs ---
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind PublicIpAddresses
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            [void]$failures.Add('PublicIpAddress')
        }
        else {
            foreach ($pip in @($inv.Items)) {
                $exposed.Add([PSCustomObject]@{ ResourceType='PublicIP'; ResourceName="$($pip.Name)"; ResourceId="$($pip.Id)"; ExposureType='Public IP address'; PublicEndpoint="$($pip.IpAddress)"; RiskReason='Resource has a public IP allocation'; SourceLogic='Get-AzPublicIpAddress' })
            }
        }

        # --- Storage accounts (public network access) ---
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            [void]$failures.Add('StorageAccount')
        }
        else {
            foreach ($sa in @($inv.Items)) {
                if ("$($sa.PublicNetworkAccess)" -eq 'Enabled') {
                    $exposed.Add([PSCustomObject]@{ ResourceType='StorageAccount'; ResourceName="$($sa.StorageAccountName)"; ResourceId="$($sa.Id)"; ExposureType='Public network access'; PublicEndpoint=$null; RiskReason='Storage account public network access is enabled'; SourceLogic='Get-AzStorageAccount' })
                }
            }
        }

        # --- NSG inbound sensitive ports from Internet ---
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind NetworkSecurityGroups
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            [void]$failures.Add('NetworkSecurityGroup')
        }
        else {
            foreach ($nsg in @($inv.Items)) {
                foreach ($rule in @($nsg.SecurityRules)) {
                    if ("$($rule.Access)" -ne 'Allow' -or "$($rule.Direction)" -ne 'Inbound') { continue }
                    $srcs = @()
                    if ($rule.PSObject.Properties.Name -contains 'SourceAddressPrefix' -and $rule.SourceAddressPrefix) { $srcs += "$($rule.SourceAddressPrefix)" }
                    if ($rule.PSObject.Properties.Name -contains 'SourceAddressPrefixes') { $srcs += @($rule.SourceAddressPrefixes | ForEach-Object { "$_" }) }
                    if (-not ($srcs | Where-Object { $_ -in @('Internet','*','0.0.0.0/0') })) { continue }
                    $ports = @()
                    if ($rule.PSObject.Properties.Name -contains 'DestinationPortRange' -and $rule.DestinationPortRange) { $ports += "$($rule.DestinationPortRange)" }
                    if ($rule.PSObject.Properties.Name -contains 'DestinationPortRanges') { $ports += @($rule.DestinationPortRanges | ForEach-Object { "$_" }) }
                    foreach ($sp in $script:ExposureSensitivePorts) {
                        if (Test-ExposurePortMatch -Ranges $ports -Port $sp) {
                            $exposed.Add([PSCustomObject]@{ ResourceType='NSG'; ResourceName="$($nsg.Name)"; ResourceId="$($nsg.Id)#$sp"; ExposureType="Inbound sensitive port $sp from Internet"; PublicEndpoint=$null; RiskReason="NSG rule '$($rule.Name)' allows inbound $sp from Internet"; SourceLogic='Get-AzNetworkSecurityGroup' })
                        }
                    }
                }
            }
        }

        # --- App Services (HTTP allowed) ---
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind WebApps
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            [void]$failures.Add('WebApp')
        }
        else {
            foreach ($app in @($inv.Items)) {
                $httpsOnly = $null
                if ($app.PSObject.Properties.Name -contains 'HttpsOnly') { $httpsOnly = $app.HttpsOnly }
                if ($httpsOnly -eq $false) {
                    $exposed.Add([PSCustomObject]@{ ResourceType='AppService'; ResourceName="$($app.Name)"; ResourceId="$($app.Id)"; ExposureType='HTTP allowed (HttpsOnly disabled)'; PublicEndpoint="$($app.DefaultHostName)"; RiskReason='App Service accepts plaintext HTTP'; SourceLogic='Get-AzWebApp' })
                }
            }
        }

        # --- SQL servers (public network access) ---
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind SqlServers
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            [void]$failures.Add('SqlServer')
        }
        else {
            foreach ($sql in @($inv.Items)) {
                if ("$($sql.PublicNetworkAccess)" -eq 'Enabled') {
                    $exposed.Add([PSCustomObject]@{ ResourceType='SqlServer'; ResourceName="$($sql.ServerName)"; ResourceId="$($sql.ResourceId)"; ExposureType='Public network access'; PublicEndpoint="$($sql.FullyQualifiedDomainName)"; RiskReason='SQL server public network access is enabled'; SourceLogic='Get-AzSqlServer' })
                }
            }
        }

        # --- Key Vaults (public network access / no firewall) ---
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind KeyVaults
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { continue }
            [void]$failures.Add('KeyVault')
        }
        else {
            foreach ($kv in @($inv.Items)) {
                $pna = $null
                if ($kv.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $pna = "$($kv.PublicNetworkAccess)" }
                $acls = $null
                if ($kv.PSObject.Properties.Name -contains 'NetworkAcls') { $acls = $kv.NetworkAcls }
                $defaultDeny = ($null -ne $acls -and "$($acls.DefaultAction)" -eq 'Deny')
                if ($pna -eq 'Enabled' -or (-not $defaultDeny -and $pna -ne 'Disabled')) {
                    $exposed.Add([PSCustomObject]@{ ResourceType='KeyVault'; ResourceName="$($kv.VaultName)"; ResourceId="$($kv.ResourceId)"; ExposureType='Public network access'; PublicEndpoint=$null; RiskReason='Key Vault reachable from public networks (no deny firewall)'; SourceLogic='Get-AzKeyVault' })
                }
            }
        }

        $deduped = @($exposed | Sort-Object ResourceId, ExposureType -Unique)

        if ($deduped.Count -gt 0) {
            $data = $deduped
            if ($failures.Count -gt 0) {
                $data = @($deduped) + [PSCustomObject]@{ Note = "PartialEvaluation"; FailedSources = ($failures -join ',') }
            }
            Write-Finding -CheckId "AZURE-EXPOSURE-001" -Service "Exposure" -Category "Azure" `
                -Severity "INFO" -Status "PASS" -Count $deduped.Count -Data $data `
                -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                -Message "Central public exposure inventory" `
                -FindingType 'Inventory' -IsInventoryOnly $true -Confidence 'Medium' `
                -SeverityReason 'Inventory/context only: internet-facing resources are context, not a confirmed exploit path. Dedicated checks (STORAGE-002, KEYVAULT-002, NETWORK-001, ...) rate the risky conditions.' `
                -Remediation "Review each internet-facing resource: restrict NSG inbound to required sources, disable public network access where private endpoints exist, and enforce HTTPS."
        }
        elseif ($failures.Count -gt 0) {
            Write-Finding -CheckId "AZURE-EXPOSURE-001" -Service "Exposure" -Category "Azure" `
                -Severity "INFO" -Status "NotEvaluated" -Count 0 `
                -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                -Message "Public exposure inventory could not be fully evaluated for subscription '$($sub.Name)' (failed sources: $($failures -join ','))."
        }
        else {
            Write-Finding -CheckId "AZURE-EXPOSURE-001" -Service "Exposure" -Category "Azure" `
                -Severity "INFO" -Status "PASS" -Count 0 `
                -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                -Message "No public exposure identified across evaluated services"
        }
    }
}

function Register-AzureExposureChecks {
    [CmdletBinding()]
    param()
    Register-AuditCheck -CheckId "AZURE-EXPOSURE-001" `
        -Category "Azure" `
        -Service "Exposure" `
        -Name "Public Exposure Inventory" `
        -Function "Test-PublicExposureInventory" `
        -DefaultSeverity "INFO" `
        -RequiredModules @("Az.Accounts", "Az.Network") `
        -Phase "PerSubscription" `
        -Description "Central cross-service internet-facing attack-surface inventory (control-plane only)." `
        -AlwaysRun $true
}
