#==============================================================================
# AzureMap v2 - Checks/Azure/StorageKey.ps1
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

    # B1 coverage tracking (same contract as Checks/Azure/Storage.ps1).
    $findings      = [System.Collections.Generic.List[object]]::new()
    $notEval       = [System.Collections.Generic.List[object]]::new()
    $subsEvaluated = [System.Collections.Generic.List[string]]::new()
    $subsSkipped   = [System.Collections.Generic.List[string]]::new()
    $totalAccounts = 0
    $skippedResources = 0

    foreach ($sub in @($Subscriptions)) {
        # Perf phase: shared per-run inventory (one enumeration per subscription
        # across ALL storage checks). The cache fetch feature-detects
        # -IncludeAccountSASPolicy itself (Core/InventoryCache.ps1). ContextSwitch
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

        # -IncludeAccountSASPolicy is not supported by all Az.Storage versions.
        # Detect once (cached) and degrade SAS evidence to partial, not failure.
        if (-not (Test-StorageSasPolicySupported)) {
            $notEval.Add([PSCustomObject]@{
                SubscriptionName = $sub.Name
                Reason = "Account SAS expiration policy not evaluated (installed Az.Storage does not support -IncludeAccountSASPolicy)"
            })
        }

        # Per-account Get-AzRoleAssignment calls still need the session on this
        # subscription (deduped no-op right after a fresh fetch, required on
        # cache hits from a different subscription).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
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

            try {
                $assignments = @(Get-AzRoleAssignment -Scope $sa.Id -ErrorAction Stop)
                foreach ($a in $assignments) {
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
            catch {
                # Key-capable RBAC for this account could not be read: the account's
                # config was evaluated, but key-role coverage is incomplete -> count as
                # skipped resource so the check resolves PARTIAL, never a false clean PASS.
                $skippedResources++
                $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; StorageAccount = $saName; Reason = "Key-capable role assignments could not be read (RBAC read failed)" })
            }
        }
    }

    # Account config (shared key, SAS policy) was evaluated for every discovered
    # account; an RBAC read failure only skips the key-role portion, so it is tracked
    # via SkippedResources/failed collections, not by lowering EvaluatedResourceCount.
    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $totalAccounts `
        -SkippedResources $skippedResources -CollectionFailures $notEval `
        -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated -Risky $findings.Count
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts `
        -Evaluated $totalAccounts -SkippedResources $skippedResources `
        -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount -IncludeAccountSASPolicy', 'ARM Get-AzRoleAssignment (role names only)') `
        -FindingType 'Exposure'

    # Single explicit-status record: PASS only with proven coverage; PARTIAL when some
    # subscriptions/accounts could not be fully read; NOTEVALUATED when nothing was
    # evaluated. A proven-empty scope (case 1) is reported at INFO severity.
    $severity = if ($cov.Severity) { $cov.Severity } else { 'HIGH' }
    $evidence = if ($findings.Count -gt 0) { $findings } else { $notEval }
    Write-Finding -CheckId "STORAGE-006" -Service "Storage" -Category "Azure" `
        -Severity $severity -Status $cov.Status -Count $findings.Count -Data $evidence `
        -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
        -Message "Storage key and SAS exposure risks" `
        -Remediation "Set AllowSharedKeyAccess=false and use Azure AD; enforce a short account SAS expiration policy; restrict Owner/Contributor/Key Operator role assignments on storage accounts." `
        @covParams

    # When risky evidence exists, keep the per-subscription/account failure detail as a
    # separate NotEvaluated record so incomplete coverage is not hidden by the FAIL.
    if ($notEval.Count -gt 0 -and $findings.Count -gt 0) {
        Write-Finding -CheckId "STORAGE-006" -Service "Storage" -Category "Azure" `
            -Severity "HIGH" -Status "NOTEVALUATED" -Count $notEval.Count -Data $notEval `
            -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
            -Message "Storage key/SAS exposure could not be fully evaluated (collection or RBAC read failed); not reported as clean" `
            -Remediation "Ensure Microsoft.Storage/storageAccounts/read and Microsoft.Authorization/roleAssignments/read on the subscriptions and re-run."
    }
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
