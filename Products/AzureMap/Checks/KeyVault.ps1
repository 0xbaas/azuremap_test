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
    $notEval  = New-Object System.Collections.Generic.List[object]
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
            # List-view fallback objects (per-vault GET failed -> no
            # AzureMapEnriched marker) and vaults whose property is absent
            # cannot be judged: NotEvaluated, never the legacy-access-policy
            # FAIL and never silently clean. Only an enriched object with an
            # explicit EnableRbacAuthorization bool is evaluated.
            $enriched = ($kv.PSObject.Properties.Name -contains 'AzureMapEnriched') -and $kv.AzureMapEnriched
            $hasRbacProp = $kv.PSObject.Properties.Name -contains 'EnableRbacAuthorization'
            if ($enriched -and $hasRbacProp) {
                if ($kv.EnableRbacAuthorization -eq $false) {
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
                elseif ($null -eq $kv.EnableRbacAuthorization) {
                    $notEval.Add([PSCustomObject]@{
                        SubscriptionName = $sub.Name
                        VaultName = "$($kv.VaultName)"
                        Reason = "RBAC authorization model could not be read"
                    })
                }
            }
            else {
                $notEval.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    VaultName = "$($kv.VaultName)"
                    Reason = "RBAC authorization model could not be read"
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

    if ($notEval.Count -gt 0) {
        # Unreadable RBAC model is NOT clean: explicit NotEvaluated record.
        Write-Finding -Severity "LOW" -Status "NOTEVALUATED" `
                      -Message "Key Vault RBAC authorization model could not be read." `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" `
                      -Data $notEval `
                      -Service "KeyVault" `
                      -Remediation "Ensure Microsoft.KeyVault/vaults/read on the subscriptions and re-run." `
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

    # Property-specific evidence lists. Every finding below carries ONLY the
    # vaults matching its own property - no broad shared vault list is reused
    # across findings. Unknown/unreadable properties are surfaced as
    # NotEvaluated, never treated as clean.
    $publicNetworkAccess      = New-Object System.Collections.Generic.List[object]  # (a) publicNetworkAccess enabled/unspecified
    $firewallDefaultAllow     = New-Object System.Collections.Generic.List[object]  # (b) networkAcls.defaultAction = Allow
    $publicNoFirewall         = New-Object System.Collections.Generic.List[object]  # (c) correlation: public + default Allow
    $missingPurgeProtection   = New-Object System.Collections.Generic.List[object]  # (d) purge protection disabled
    $criticalNoPrivateEndpoint = New-Object System.Collections.Generic.List[object] # (f) critical vault, no private endpoint
    $noAuditLogging           = New-Object System.Collections.Generic.List[object]  # (g) no diagnostic settings / logs
    $notEval                  = New-Object System.Collections.Generic.List[object]
    $totalProcessed = 0
    $criticalPatterns = @("*prod*", "*prd*", "*production*", "*secret*", "*key*", "*cert*")

    # Az.Monitor diagnostic read is needed for aspect (g); detect support once.
    $diagCmdAvailable = [bool](Get-Command Get-AzDiagnosticSetting -ErrorAction SilentlyContinue)

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
                $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = "Key Vault collection failed (detail in audit log)" })
            }
            else {
                $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = "Subscription context could not be entered; vaults not evaluated" })
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

        # Per-vault diagnostic setting reads still need the session on this
        # subscription (deduped no-op right after a fresh fetch; required on
        # cache hits from a different subscription).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = "Subscription context could not be entered; vaults not evaluated" })
            continue
        }

        if (-not $diagCmdAvailable -and @($inv.Items).Count -gt 0) {
            $notEval.Add([PSCustomObject]@{
                SubscriptionName = $sub.Name
                Reason = "Audit logging not evaluated (Get-AzDiagnosticSetting / Az.Monitor not available)"
            })
        }

        foreach ($kv in $inv.Items) {
            $networkRuleSet = $kv.NetworkAcls

            # (a) publicNetworkAccess. Explicit 'Disabled' is the only safe value;
            # absent/unspecified defaults to Enabled for vaults that never set it
            # (same Azure default semantics as the storage checks).
            $pnaRaw = $null
            if ($kv.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $pnaRaw = $kv.PublicNetworkAccess }
            $pnaState = if ($null -ne $pnaRaw -and "$pnaRaw" -ne '') { "$pnaRaw" } else { "Unspecified" }
            $pnaPublic = ($pnaState -ne 'Disabled')

            # (b) firewall default action. networkAcls absent = firewall config
            # unknown -> NotEvaluated for the network aspects, never clean.
            $defaultAction = $null
            if ($networkRuleSet -and ($networkRuleSet.PSObject.Properties.Name -contains 'DefaultAction')) {
                $defaultAction = "$($networkRuleSet.DefaultAction)"
            }
            $firewallUnknown = ($null -eq $networkRuleSet)
            $defaultAllow    = ($defaultAction -eq 'Allow')

            if ($pnaPublic) {
                $publicNetworkAccess.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $kv.ResourceGroupName
                    VaultName = $kv.VaultName
                    PublicNetworkAccess = if ($pnaState -eq 'Unspecified') { "Unspecified (defaults to enabled)" } else { $pnaState }
                    ResourceId = $kv.ResourceId
                    Tags = $kv.Tags
                })
            }

            if ($defaultAllow) {
                $firewallDefaultAllow.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $kv.ResourceGroupName
                    VaultName = $kv.VaultName
                    DefaultAction = $defaultAction
                    ResourceId = $kv.ResourceId
                    Tags = $kv.Tags
                })
            }
            elseif ($firewallUnknown) {
                $notEval.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    VaultName = "$($kv.VaultName)"
                    Reason = "Firewall configuration (networkAcls) could not be read; network exposure not evaluated"
                })
            }

            # (c) correlation: public endpoint AND firewall default Allow.
            if ($pnaPublic -and $defaultAllow) {
                $publicNoFirewall.Add([PSCustomObject]@{
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup = $kv.ResourceGroupName
                    VaultName = $kv.VaultName
                    PublicNetworkAccess = if ($pnaState -eq 'Unspecified') { "Unspecified (defaults to enabled)" } else { $pnaState }
                    DefaultAction = $defaultAction
                    ResourceId = $kv.ResourceId
                    Tags = $kv.Tags
                })
            }

            # (d) purge protection. On a full (enriched) vault object,
            # null/false = genuinely disabled (the vault default) -> FAIL.
            # A list-view fallback object (no AzureMapEnriched marker) or an
            # absent property means the state could not be read ->
            # NotEvaluated, never FAIL and never clean.
            $kvEnriched = ($kv.PSObject.Properties.Name -contains 'AzureMapEnriched') -and $kv.AzureMapEnriched
            $hasPurgeProp = $kv.PSObject.Properties.Name -contains 'EnablePurgeProtection'
            if ($kvEnriched -and $hasPurgeProp) {
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
            }
            else {
                $notEval.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    VaultName = "$($kv.VaultName)"
                    Reason = "Purge protection state could not be read"
                })
            }

            # (f) critical vault without a private endpoint.
            $privateEndpoints = @($allPrivateEndpoints | Where-Object {
                $_.ResourceGroupName -eq $kv.ResourceGroupName -and
                $_.PrivateLinkServiceConnections.PrivateLinkServiceId -eq $kv.ResourceId
            })
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

            # (g) audit logging via diagnostic settings (metadata only). A read
            # failure is NotEvaluated for this aspect, never clean.
            if ($diagCmdAvailable) {
                try {
                    $diagSettings = @(Invoke-AzureCommand -Command {
                        Get-AzDiagnosticSetting -ResourceId $kv.ResourceId -ErrorAction Stop
                    } -CommandName "Get-KeyVaultDiagnostics" -SkipContextCheck)
                    $hasEnabledLogs = $false
                    foreach ($ds in $diagSettings) {
                        if ($ds.PSObject.Properties.Name -contains 'Logs') {
                            foreach ($log in @($ds.Logs)) {
                                if ($log.Enabled) { $hasEnabledLogs = $true; break }
                            }
                        }
                        if ($hasEnabledLogs) { break }
                    }
                    if (-not $hasEnabledLogs) {
                        $noAuditLogging.Add([PSCustomObject]@{
                            SubscriptionId = $sub.Id
                            SubscriptionName = $sub.Name
                            ResourceGroup = $kv.ResourceGroupName
                            VaultName = $kv.VaultName
                            ResourceId = $kv.ResourceId
                            Tags = $kv.Tags
                        })
                    }
                }
                catch {
                    $notEval.Add([PSCustomObject]@{
                        SubscriptionName = $sub.Name
                        VaultName = "$($kv.VaultName)"
                        Reason = "Diagnostic settings could not be read; audit logging not evaluated"
                    })
                }
            }
        }
    }

    if ($publicNetworkAccess.Count -gt 0) {
        $remediation = "Disable public network access on the Key Vault and route traffic through private endpoints."
        Write-Finding -Severity "MEDIUM" `
                      -Message "Key Vaults with public network access enabled or unspecified (defaults to enabled)" `
                      -Count $publicNetworkAccess.Count -CountType "UniqueResources" `
                      -Data $publicNetworkAccess `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }

    if ($firewallDefaultAllow.Count -gt 0) {
        $remediation = "Set the Key Vault firewall default action to Deny and allow only required networks."
        Write-Finding -Severity "MEDIUM" `
                      -Message "Key Vaults with firewall default action Allow" `
                      -Count $firewallDefaultAllow.Count -CountType "UniqueResources" `
                      -Data $firewallDefaultAllow `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }

    if ($publicNoFirewall.Count -gt 0) {
        $remediation = "Restrict Key Vault access using firewall rules and/or private endpoints. Set default action to Deny."
        Write-Finding -Severity "CRITICAL" `
                      -Message "Key Vaults with public access and no firewall restrictions" `
                      -Count $publicNoFirewall.Count -CountType "UniqueResources" `
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
                      -Count $missingPurgeProtection.Count -CountType "UniqueResources" `
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
                      -Count $criticalNoPrivateEndpoint.Count -CountType "UniqueResources" `
                      -Data $criticalNoPrivateEndpoint `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }

    if ($noAuditLogging.Count -gt 0) {
        $remediation = "Enable diagnostic settings with the AuditEvent category on every Key Vault and send logs to a Log Analytics workspace or storage account."
        Write-Finding -Severity "MEDIUM" `
                      -Message "Key Vaults without audit logging enabled (no diagnostic settings with enabled logs)" `
                      -Count $noAuditLogging.Count -CountType "UniqueResources" `
                      -Data $noAuditLogging `
                      -Service "KeyVault" `
                      -Remediation $remediation `
                      -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" `
                      -SubscriptionName "Multiple"
    }

    if ($notEval.Count -gt 0) {
        # Failed collection / unreadable properties are NOT clean: keep the detail
        # as an explicit NotEvaluated record (no access is not "secure"). An
        # evaluation gap is never CRITICAL/HIGH - it is a coverage caveat, so the
        # severity stays LOW and the message names the actual gap(s) rather than
        # a generic "read failed" umbrella.
        $gapClauses = New-Object System.Collections.Generic.List[string]
        foreach ($e in $notEval) {
            $r = "$($e.Reason)"
            $clause = $null
            if ($r -like '*networkAcls*' -or $r -like '*Firewall configuration*') { $clause = 'firewall configuration could not be read' }
            elseif ($r -like '*Purge protection*') { $clause = 'purge protection state could not be read' }
            elseif ($r -like '*Diagnostic settings*' -or $r -like '*Audit logging*') { $clause = 'audit logging could not be evaluated' }
            elseif ($r -like '*collection failed*') { $clause = 'vault collection failed' }
            elseif ($r -like '*context could not be entered*') { $clause = 'subscription context could not be entered' }
            if (-not $clause) { $clause = 'some properties could not be read' }
            if (-not $gapClauses.Contains($clause)) { $gapClauses.Add($clause) }
        }
        $gapText = $gapClauses -join '; '
        Write-Finding -Severity "LOW" -Status "NOTEVALUATED" `
                      -Message "Key Vault network security could not be fully evaluated: $gapText." `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" `
                      -Data $notEval `
                      -Service "KeyVault" `
                      -Remediation "Ensure Microsoft.KeyVault/vaults/read and Microsoft.Insights/diagnosticSettings/read on the subscriptions and re-run." `
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
                      -Message "Key Vault secret expiry could not be fully evaluated (data-plane access denied or collection failed)." `
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
