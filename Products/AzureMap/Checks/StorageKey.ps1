#==============================================================================
# AzureMap v2 - Products/AzureMap/Checks/StorageKey.ps1
# STORAGE-006  Storage key & SAS exposure risk  (PerSubscription, HIGH)
#
# READ-ONLY, CONTROL-PLANE ONLY. Never calls Get-AzStorageAccountKey / listKeys,
# never reads secret/connection-string values, no data-plane calls.
# NotEvaluated when storage accounts (or the required RBAC data) cannot be read -
# never a false PASS.
#==============================================================================

function Get-SasExpirationDays {
    param([object]$StorageAccount)
    $policy = $null
    $props  = $StorageAccount.PSObject.Properties.Name
    if (($props -contains 'AccountSasPolicy') -and $StorageAccount.AccountSasPolicy) { $policy = $StorageAccount.AccountSasPolicy }
    elseif (($props -contains 'SasPolicy') -and $StorageAccount.SasPolicy)          { $policy = $StorageAccount.SasPolicy }
    if (-not $policy) { return $null }

    $val = $null
    if ($policy.PSObject.Properties.Name -contains 'SasExpirationPeriod') { $val = $policy.SasExpirationPeriod }
    if ($null -eq $val) { return $null }
    if ($val -is [TimeSpan]) { return [math]::Round($val.TotalDays, 2) }

    $ts = [TimeSpan]::Zero
    if ([TimeSpan]::TryParse([string]$val, [ref]$ts)) { return [math]::Round($ts.TotalDays, 2) }
    return $null
}

function Test-StorageKeyExposure {
    [CmdletBinding()]
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    # Built-in roles that can retrieve/manage storage account keys. -contains is
    # case-insensitive, so role-name casing differences are already handled. NOTE:
    # custom roles that include Microsoft.Storage/storageAccounts/listkeys/action or a
    # wildcard action are NOT detected by name here (detecting them would require
    # reading role definitions); the shared-key finding below still flags key usability.
    $keyCapableRoles = @(
        "Owner",
        "Contributor",
        "Storage Account Contributor",
        "Storage Account Key Operator Service Role"
    )

    # B1 coverage tracking (same contract as Products/AzureMap/Checks/Storage.ps1).
    $findings      = [System.Collections.Generic.List[object]]::new()
    $notEval       = [System.Collections.Generic.List[object]]::new()
    $subsEvaluated = [System.Collections.Generic.List[string]]::new()
    $subsSkipped   = [System.Collections.Generic.List[string]]::new()
    $totalAccounts = 0
    $skippedResources = 0

    foreach ($sub in @($Subscriptions)) {
        # Perf phase: shared per-run inventory (one enumeration per subscription
        # across ALL storage checks). The cache fetch feature-detects
        # -IncludeAccountSASPolicy itself (Core/Azure/InventoryCache.ps1). ContextSwitch
        # -> skipped sub; Fetch -> failed collection (same coverage semantics).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') {
                $subsSkipped.Add($sub.Name)
            }
            else {
                $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = "Storage account collection failed (detail in audit log)" })
            }
            continue
        }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($inv.Items).Count

        # -IncludeAccountSASPolicy is not supported by all Az.Storage versions;
        # 9.x removed the parameter and returns a SasPolicy property by default.
        # Detect once (cached) and degrade SAS evidence to partial, not failure.
        # Only subscriptions that actually HAVE storage accounts without any
        # SasPolicy evidence are marked: a module support gap on a subscription
        # with zero storage accounts must never count as a storage risk.
        if (@($inv.Items).Count -gt 0 -and -not (Test-StorageSasPolicySupported -SampleAccounts $inv.Items)) {
            $notEval.Add([PSCustomObject]@{
                SubscriptionName = $sub.Name
                Reason = "Account SAS expiration policy not evaluated (installed Az.Storage supports neither -IncludeAccountSASPolicy nor the SasPolicy property)"
            })
        }

        # The cached subscription-scope RBAC read still needs the session on this
        # subscription (deduped no-op right after a fresh fetch, required on
        # cache hits from a different subscription).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        # Perf+coverage fix: ONE cached subscription-scope RBAC read per
        # subscription (Get-SubscriptionRBACAssignments), filtered client-side
        # per account. The old per-account Get-AzRoleAssignment -Scope loop made
        # one raw uncached ARM call per storage account (documented to stall
        # 40-78s per call under Azure-only auth). A failed read marks the
        # subscription's RBAC unavailable -> key-role coverage is NotEvaluated
        # for every discovered account (PARTIAL, never a false clean PASS).
        $subRbacUnavailable = $false
        $subAssignments = @()
        if (@($inv.Items).Count -gt 0) {
            $subAssignments = @(Get-SubscriptionRBACAssignments -SubscriptionId $sub.Id -SubscriptionName $sub.Name)
            if ($script:State.Cache.RBACUnavailable.ContainsKey("$($sub.Id)") -and $script:State.Cache.RBACUnavailable["$($sub.Id)"]) {
                $subRbacUnavailable = $true
                $skippedResources += @($inv.Items).Count
                $notEval.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name
                    Reason = "Key-capable role assignments could not be read (RBAC read failed); $(@($inv.Items).Count) account(s) not evaluated for key-capable roles"
                })
            }
        }

        foreach ($sa in $inv.Items) {
            $saName = "$($sa.StorageAccountName)"
            $rg     = "$($sa.ResourceGroupName)"

            $ask = $null
            if ($sa.PSObject.Properties.Name -contains 'AllowSharedKeyAccess') { $ask = $sa.AllowSharedKeyAccess }
            if ($ask -ne $false) {
                $findings.Add([PSCustomObject]@{ SubscriptionId = $sub.Id; SubscriptionName = $sub.Name; StorageAccount = $saName; ResourceGroup = $rg; Risk = "Shared key access is enabled or unspecified (account keys usable)" })
            }

            $sasDays = Get-SasExpirationDays -StorageAccount $sa
            if ($null -ne $sasDays -and $sasDays -gt 30) {
                $findings.Add([PSCustomObject]@{ SubscriptionId = $sub.Id; SubscriptionName = $sub.Name; StorageAccount = $saName; ResourceGroup = $rg; Risk = "Account SAS expiration policy exceeds 30 days"; Days = $sasDays })
            }

            if ($subRbacUnavailable) { continue }

            # Effective assignments on this account: the cached sub-scope list
            # filtered to assignments whose scope IS the account or a parent of
            # it (subscription / resource group), matching the inherited-scope
            # semantics of the old Get-AzRoleAssignment -Scope per-account call.
            $saId = "$($sa.Id)".TrimEnd('/').ToLowerInvariant()
            foreach ($a in $subAssignments) {
                $sc = "$($a.Scope)".TrimEnd('/').ToLowerInvariant()
                if (-not $sc) { continue }
                if (-not ($saId -eq $sc -or $saId.StartsWith("$sc/"))) { continue }
                if ($keyCapableRoles -contains "$($a.RoleDefinitionName)") {
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId   = $sub.Id
                        SubscriptionName = $sub.Name
                        StorageAccount   = $saName
                        Principal        = "$($a.DisplayName)"
                        Role             = "$($a.RoleDefinitionName)"
                        Risk             = "Principal can retrieve/manage storage account keys"
                    })
                }
            }
        }
    }

    # Account config (shared key, SAS policy) was evaluated for every discovered
    # account; an RBAC read failure only skips the key-role portion, so it is tracked
    # via SkippedResources/failed collections, not by lowering EvaluatedResourceCount.
    # Risky for status = UNIQUE storage accounts with at least one signal; the
    # findings list counts individual risk signals (shared key, SAS policy,
    # key-capable role) - one account can contribute several.
    $riskyNames = New-Object System.Collections.Generic.List[string]
    foreach ($item in $findings) {
        $n = "$($item.StorageAccount)"
        if ($n -and -not $riskyNames.Contains($n)) { $riskyNames.Add($n) }
    }
    $riskyAccounts = $riskyNames.Count

    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $totalAccounts `
        -SkippedResources $skippedResources -CollectionFailures $notEval `
        -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated -Risky $riskyAccounts
    if ($findings.Count -gt 0) {
        $covText = if ($cov.CompleteEvaluation) { 'coverage complete.' } else { 'coverage partial; findings may be incomplete.' }
        $cov.CoverageSummary = "$totalAccounts storage accounts evaluated; $($findings.Count) risk signal(s) " +
            "across $riskyAccounts unique account(s); $covText"
    }
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts `
        -Evaluated $totalAccounts -SkippedResources $skippedResources `
        -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount -IncludeAccountSASPolicy', 'ARM REST roleAssignments (subscription scope, cached; role names only)') `
        -FindingType 'Exposure'

    # RBAC/SAS evaluation gaps are NOT affected resources: keep them in their own
    # NotEvaluated record (emitted first so the affected-items record stays the
    # primary record), never mixed into the risk evidence or counted as affected.
    if ($notEval.Count -gt 0) {
        Write-Finding -CheckId "STORAGE-006" -Service "Storage" -Category "Azure" `
            -Severity "HIGH" -Status "NOTEVALUATED" -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval `
            -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
            -Message "Storage key/SAS exposure could not be fully evaluated (collection or RBAC read failed)." `
            -Remediation "Ensure Microsoft.Storage/storageAccounts/read and Microsoft.Authorization/roleAssignments/read on the subscriptions and re-run."
    }

    # Single explicit-status record: PASS only with proven coverage; PARTIAL when some
    # subscriptions/accounts could not be fully read; NOTEVALUATED when nothing was
    # evaluated. A proven-empty scope (case 1) is reported at INFO severity.
    $severity = if ($cov.Severity) { $cov.Severity } else { 'HIGH' }
    $evidence = if ($findings.Count -gt 0) { $findings } else { $null }
    Write-Finding -CheckId "STORAGE-006" -Service "Storage" -Category "Azure" `
        -Severity $severity -Status $cov.Status -Count $findings.Count -CountType "RiskSignals" -Data $evidence `
        -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
        -Message "Storage key and SAS exposure risks" `
        -Remediation "Set AllowSharedKeyAccess=false and use Azure AD; enforce a short account SAS expiration policy; restrict Owner/Contributor/Key Operator role assignments on storage accounts." `
        @covParams
}

function Register-AzureStorageKeyChecks {
    [CmdletBinding()]
    param()
    Register-AuditCheck -CheckId "STORAGE-006" `
        -Category "Azure" `
        -Service "Storage" `
        -Name "Storage Key & SAS Exposure" `
        -Function "Test-StorageKeyExposure" `
        -DefaultSeverity "HIGH" `
        -RequiredModules @("Az.Accounts", "Az.Storage") `
        -Phase "PerSubscription" `
        -Description "Storage accounts allowing account-key auth, long SAS policies, or principals able to list keys." `
        -RequiredResourceTypes @('Microsoft.Storage/storageAccounts')
}
