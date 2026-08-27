# ============================================================================
# AzureMap - Key Vault Security Checks
# ============================================================================
# Functions:
#   Test-KeyVaultRBAC
#   Test-KeyVaultNetworkSecurity
#   Test-KeyVaultSecretsExpiry
#   Register-AzureKeyVaultChecks
# ============================================================================

function Test-KeyVaultRBAC {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "KEY VAULTS - LEGACY ACCESS POLICIES VS RBAC" -Color "Yellow" -ProgressId $ProgressId
    
    $findings = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++

        Write-Progress -Activity "Checking Key Vault RBAC" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory (one Get-AzKeyVault enumeration
        # per subscription across ALL key vault checks). ContextSwitch ->
        # skipped sub; Fetch -> failed collection (same semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind KeyVaults
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check Key Vault RBAC in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        foreach ($kv in $inv.Items) {
            if (-not $kv.EnableRbacAuthorization) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $kv.ResourceGroupName
                    VaultName = $kv.VaultName
                    EnableRbacAuthorization = $kv.EnableRbacAuthorization
                    ResourceId = $kv.ResourceId
                    Tags = $kv.Tags
                })
            }
        }
    }
    
    if ($findings.Count -gt 0) {
        $remediation = "Enable Azure RBAC authorization for Key Vaults and migrate from legacy access policies."
        
        Write-Finding -Severity "LOW" `
                      -Message "Key Vaults using legacy access policies (RBAC disabled)" `
                      -Count $findings.Count `
                      -Data $findings `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-KeyVaultNetworkSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "KEY VAULT - NETWORK SECURITY & PROTECTION" -Color "Red" -ProgressId $ProgressId
    
    $publicNoFirewall = New-Object System.Collections.Generic.List[object]
    $missingPurgeProtection = New-Object System.Collections.Generic.List[object]
    $criticalNoPrivateEndpoint = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    $criticalPatterns = @("*prod*", "*prd*", "*production*", "*secret*", "*key*", "*cert*")
    
    foreach ($sub in $Subscriptions) {
        $totalProcessed++

        Write-Progress -Activity "Checking Key Vault Network Security" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory. ContextSwitch -> skipped sub;
        # Fetch -> failed collection (same semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind KeyVaults
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'Fetch') {
                Write-AuditLog -Message "Failed to check Key Vault network security in subscription $($sub.Name): inventory fetch failed" -Level ERROR
            }
            continue
        }

        # Private endpoints from shared inventory (was a per-vault
        # Get-AzPrivateEndpoint -ResourceGroupName call). A fetch failure
        # degrades to "no private endpoints seen", matching the old per-vault
        # try/catch -> @() behavior.
        $peInv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind PrivateEndpoints
        $allPrivateEndpoints = @()
        if (-not $peInv.Unavailable) { $allPrivateEndpoints = @($peInv.Items) }

        foreach ($kv in $inv.Items) {
            $networkRuleSet = $kv.NetworkAcls
            $hasFirewall = $false
            $publicAccess = $true

            if ($networkRuleSet) {
                if ($networkRuleSet.DefaultAction -eq "Deny") {
                    $publicAccess = $false
                    $hasFirewall = $true
                }
                if ($networkRuleSet.IpAddressRanges -and $networkRuleSet.IpAddressRanges.Count -gt 0) {
                    $hasFirewall = $true
                }
                if ($networkRuleSet.VirtualNetworkResourceIds -and $networkRuleSet.VirtualNetworkResourceIds.Count -gt 0) {
                    $hasFirewall = $true
                }
            }

            $privateEndpoints = @($allPrivateEndpoints | Where-Object {
                $_.ResourceGroupName -eq $kv.ResourceGroupName -and
                $_.PrivateLinkServiceConnections.PrivateLinkServiceId -eq $kv.ResourceId
            })

            if ($publicAccess -and -not $hasFirewall) {
                $publicNoFirewall.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $kv.ResourceGroupName
                    VaultName = $kv.VaultName
                    ResourceId = $kv.ResourceId
                    Tags = $kv.Tags
                })
            }

            if (-not $kv.EnablePurgeProtection) {
                $missingPurgeProtection.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $kv.ResourceGroupName
                    VaultName = $kv.VaultName
                    ResourceId = $kv.ResourceId
                    Tags = $kv.Tags
                })
            }

            $isCritical = $false
            foreach ($pattern in $criticalPatterns) {
                if ($kv.VaultName -like $pattern) { $isCritical = $true; break }
            }
            if ($isCritical -and ($privateEndpoints | Measure-Object).Count -eq 0) {
                $criticalNoPrivateEndpoint.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $kv.ResourceGroupName
                    VaultName = $kv.VaultName
                    ResourceId = $kv.ResourceId
                    Tags = $kv.Tags
                })
            }
        }
    }
    
    if ($publicNoFirewall.Count -gt 0) {
        $remediation = "Restrict Key Vault access using firewall rules and/or private endpoints. Set default action to Deny."
        Write-Finding -Severity "CRITICAL" `
                      -Message "Key Vaults with public access and no firewall restrictions" `
                      -Count $publicNoFirewall.Count `
                      -Data $publicNoFirewall `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($missingPurgeProtection.Count -gt 0) {
        $remediation = "Enable purge protection to prevent irreversible deletion of Key Vault content."
        Write-Finding -Severity "HIGH" `
                      -Message "Key Vaults without purge protection enabled" `
                      -Count $missingPurgeProtection.Count `
                      -Data $missingPurgeProtection `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
    
    if ($criticalNoPrivateEndpoint.Count -gt 0) {
        $remediation = "Configure private endpoints for critical Key Vaults and enforce private access where possible."
        Write-Finding -Severity "MEDIUM" `
                      -Message "Critical Key Vaults without private endpoints" `
                      -Count $criticalNoPrivateEndpoint.Count `
                      -Data $criticalNoPrivateEndpoint `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }
}

function Test-KeyVaultSecretsExpiry {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )
    
    Write-Section -Title "KEY VAULT - SECRET EXPIRATION HYGIENE" -Color "Yellow" -ProgressId $ProgressId
    
    $noExpiry = New-Object System.Collections.Generic.List[object]
    $farFuture = New-Object System.Collections.Generic.List[object]
    $expired = New-Object System.Collections.Generic.List[object]
    $now = Get-Date
    $totalProcessed = 0
    # B1 coverage tracking. Secret metadata is a DATA-PLANE read; Forbidden is
    # expected for least-privilege audit identities and is reported as skipped
    # coverage (counted + summarized), never dumped to the console per vault.
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $failures      = New-Object System.Collections.Generic.List[object]
    $vaultsDiscovered = 0
    $vaultsEvaluated  = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++

        Write-Progress -Activity "Checking Key Vault secrets expiry" `
                      -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) `
                      -Id $ProgressId

        # Perf phase: shared per-run inventory. ContextSwitch -> skipped sub;
        # Fetch -> failed collection (same coverage semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind KeyVaults
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') {
                $subsSkipped.Add($sub.Name)
            }
            else {
                # Old "collection threw" path: the context switch had succeeded
                # (sub counted evaluated) and then Get-AzKeyVault failed. The
                # cache layer already logged the underlying error; it is not
                # surfaced here, so the sanitized class stays 'Unknown'.
                $subsEvaluated.Add($sub.Name)
                $failures.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    Reason           = "Vault collection failed (Unknown)"
                })
            }
            continue
        }
        $subsEvaluated.Add($sub.Name)

        # Data-plane Get-AzKeyVaultSecret per vault still needs the session on
        # this subscription (deduped no-op right after a fresh fetch; required
        # on cache hits).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        foreach ($kv in @($inv.Items)) {
            $vaultsDiscovered++
            try {
                $secrets = Invoke-AzureCommand -Command {
                    Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction Stop
                } -CommandName "Get-KeyVaultSecrets"
                $vaultsEvaluated++
            }
            catch {
                # Sanitized: error class only - no caller identity, object ids, or
                # full Forbidden payloads on the console/log.
                $cls = 'Unknown'
                try { $cls = (Get-ErrorClass -ErrorRecord $_).Class } catch {}
                $failures.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    VaultName        = "$($kv.VaultName)"
                    Reason           = "Secret metadata read denied/failed ($cls)"
                })
                continue
            }

            foreach ($secret in $secrets) {
                if (-not $secret.Enabled) { continue }

                $expiryDate = $secret.Expires
                if (-not $expiryDate) {
                    $noExpiry.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        VaultName = $kv.VaultName
                        SecretName = $secret.Name
                        CreatedDate = $secret.Created
                    })
                    continue
                }

                $daysToExpiry = [math]::Round(($expiryDate - $now).TotalDays)
                if ($daysToExpiry -lt 0) {
                    $expired.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        VaultName = $kv.VaultName
                        SecretName = $secret.Name
                        DaysToExpiry = $daysToExpiry
                        ExpiryDate = $expiryDate
                    })
                } elseif ($daysToExpiry -gt $script:State.Config.LongCredentialDays) {
                    $farFuture.Add([PSCustomObject]@{
                        SubscriptionId = $sub.Id
                        SubscriptionName = $sub.Name
                        VaultName = $kv.VaultName
                        SecretName = $secret.Name
                        DaysToExpiry = $daysToExpiry
                        ExpiryDate = $expiryDate
                    })
                }
            }
        }
    }

    # ---- B1 explicit status + coverage (secret metadata is data-plane) ----
    $issuesTotal = $noExpiry.Count + $farFuture.Count + $expired.Count
    $failedCount = $failures.Count + $subsSkipped.Count
    $complete    = ($failedCount -eq 0)

    if ($vaultsEvaluated -eq 0 -and $failedCount -gt 0) {
        $status  = 'NOTEVALUATED'
        $summary = "Could not evaluate Key Vault secret metadata; data-plane access denied or collection failed."
    }
    elseif ($issuesTotal -gt 0) {
        $status  = 'FAIL'
        $summary = "$issuesTotal secret expiry issue(s) across $vaultsEvaluated vault(s) evaluated" + `
                   $(if ($complete) { '; coverage complete.' } else { "; $failedCount vault(s)/subscription(s) skipped/denied - findings may be incomplete." })
    }
    elseif (-not $complete) {
        $status  = 'PARTIAL'
        $summary = "$vaultsEvaluated of $vaultsDiscovered vaults evaluated; 0 expiry issues; $failedCount skipped/denied - findings may be incomplete."
    }
    elseif ($vaultsDiscovered -eq 0) {
        $status  = 'PASS'
        $summary = "No key vaults discovered in evaluated scope."
    }
    else {
        $status  = 'PASS'
        $summary = "$vaultsEvaluated vaults evaluated; 0 secret expiry issues; coverage complete."
    }

    $kvCoverage = @{
        CheckId                  = 'KEYVAULT-003'
        DataPlaneRequired        = $true
        DiscoveredResourceCount  = $vaultsDiscovered
        EvaluatedResourceCount   = $vaultsEvaluated
        SkippedResourceCount     = $failures.Count
        FailedCollectionCount    = $failedCount
        SubscriptionsEvaluated   = @($subsEvaluated)
        SubscriptionsSkipped     = @($subsSkipped)
        CollectionStatus         = if ($complete) { 'Complete' } elseif ($vaultsEvaluated -gt 0) { 'Partial' } else { 'Failed' }
        CompleteEvaluation       = $complete
        PartialEvaluation        = (-not $complete)
        CoverageSummary          = $summary
        SummaryText              = $summary
        Confidence               = if ($status -eq 'NOTEVALUATED') { 'Low' } elseif (-not $complete) { 'Medium' } else { 'High' }
        ManualValidationRequired = ($status -in @('PARTIAL','NOTEVALUATED'))
        ApiSources               = @('ARM Get-AzKeyVault', 'Data-plane Get-AzKeyVaultSecret (metadata only: name/enabled/expiry - never values)')
        FindingType              = 'Misconfiguration'
    }

    if ($noExpiry.Count -gt 0) {
        $remediation = "Set expiration dates for Key Vault secrets and rotate them regularly."
        Write-Finding -Severity "MEDIUM" -Status 'FAIL' `
                      -Message "Key Vault secrets without expiration date" `
                      -Count $noExpiry.Count `
                      -Data $noExpiry `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple" `
                      @kvCoverage
    }

    if ($farFuture.Count -gt 0) {
        $remediation = "Shorten secret validity periods to reduce exposure window."
        Write-Finding -Severity "LOW" -Status 'FAIL' `
                      -Message "Key Vault secrets with far-future expiration" `
                      -Count $farFuture.Count `
                      -Data $farFuture `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple" `
                      @kvCoverage
    }

    if ($expired.Count -gt 0) {
        $remediation = "Remove or rotate expired secrets to prevent unexpected failures."
        Write-Finding -Severity "MEDIUM" -Status 'FAIL' `
                      -Message "Key Vault secrets that are expired" `
                      -Count $expired.Count `
                      -Data $expired `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple" `
                      @kvCoverage
    }

    if ($issuesTotal -eq 0) {
        # B1: explicit coverage record - PASS only with proven coverage; PARTIAL when
        # some vaults/subs were skipped or denied; NOTEVALUATED when nothing could be
        # evaluated. Zero-issue records are INFO - nothing to remediate.
        $evidence = if ($failures.Count -gt 0) { $failures } else { $null }
        Write-Finding -Severity "INFO" -Status $status `
                      -Message "Key Vault secret expiration hygiene" `
                      -Count 0 `
                      -Data $evidence `
                      -Service "KeyVault" `
                      -Remediation "No action required." `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple" `
                      @kvCoverage
    }

    # Issues found AND some vaults/subs failed: keep failure detail visible.
    if ($issuesTotal -gt 0 -and $failedCount -gt 0) {
        Write-Finding -Severity "INFO" -Status 'NOTEVALUATED' `
                      -Message "Key Vault secret expiry could not be fully evaluated (data-plane access denied or collection failed); not reported as clean" `
                      -Count $failedCount -Data $failures -Service "KeyVault" `
                      -Remediation "Grant the audit identity a data-plane role with secrets list permission (e.g. Key Vault Reader / Secrets User) and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                      -CheckId 'KEYVAULT-003' -DataPlaneRequired $true
    }
}

function Register-AzureKeyVaultChecks {
    Register-AuditCheck -CheckId "KEYVAULT-001" `
                        -Category "Azure" `
                        -Service "KeyVault" `
                        -Name "Key Vault RBAC Authorization" `
                        -Function ${function:Test-KeyVaultRBAC} `
                        -DefaultSeverity "LOW" `
                        -RequiredModules @("Az.Accounts", "Az.KeyVault") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.KeyVault/vaults')
    
    Register-AuditCheck -CheckId "KEYVAULT-002" `
                        -Category "Azure" `
                        -Service "KeyVault" `
                        -Name "Key Vault Network Security" `
                        -Function ${function:Test-KeyVaultNetworkSecurity} `
                        -DefaultSeverity "CRITICAL" `
                        -RequiredModules @("Az.Accounts", "Az.KeyVault", "Az.Network") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.KeyVault/vaults')
    
    Register-AuditCheck -CheckId "KEYVAULT-003" `
                        -Category "Azure" `
                        -Service "KeyVault" `
                        -Name "Key Vault Secrets Expiry" `
                        -Function ${function:Test-KeyVaultSecretsExpiry} `
                        -DefaultSeverity "MEDIUM" `
                        -RequiredModules @("Az.Accounts", "Az.KeyVault") `
                        -Phase "PerSubscription" `
                        -RequiredResourceTypes @('Microsoft.KeyVault/vaults') `
                        -RequiresDataPlane $true
}
