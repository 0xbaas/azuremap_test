# ============================================================================
# AzureMap - Storage Security Checks
# ============================================================================
# Functions:
#   Get-StorageAccountCollection      (shared: collect + distinguish failure)
#   Test-StorageSharedKeyAccess       STORAGE-001
#   Test-StoragePublicAccess          STORAGE-002
#   Test-StorageAdvancedSecurity      STORAGE-003
#   Test-StorageAnonymousBlobAccess   STORAGE-004
#   Test-StorageExfiltrationVectors   STORAGE-005
#   Test-StorageDoubleEncryption      STORAGE-007
#   Register-AzureStorageChecks
#
# Correctness rules (why storage was under-reporting):
#   * An EMPTY or FAILED Get-AzStorageAccount result must NOT be reported as a
#     confident clean PASS. A throw -> NotEvaluated for that subscription.
#   * Azure semantics: several security properties are RISKY when $null/unspecified
#     (not safe). AllowSharedKeyAccess $null means shared key is ALLOWED (default);
#     PublicNetworkAccess unspecified defaults to Enabled; AllowBlobPublicAccess
#     $null historically defaulted to allowed. Only an explicit-safe value PASSes.
#   * If a prerequisite read (network rule set, container list) fails, the account
#     is surfaced (risk/NotEvaluated), never silently treated as safe.
# READ-ONLY. No listKeys, no secret/connection-string reads.
#
# Phase B1 (reference implementation for coverage integrity):
#   * Every check tracks per-subscription coverage: subscriptions evaluated vs
#     skipped (failed Set-AzContext switch) vs failed collection, plus discovered
#     and evaluated resource counts.
#   * Every check emits an EXPLICIT status record (PASS / FAIL / PARTIAL /
#     NOTEVALUATED) with coverage metadata - PASS is proven, never inferred from
#     "no findings". See the status x coverage contract in Core/RunStatus.ps1.
# ============================================================================

function Test-StorageSasPolicySupported {
    <#
    .SYNOPSIS
        Detects once per session whether the installed Az.Storage supports
        -IncludeAccountSASPolicy on Get-AzStorageAccount (older versions do not).
        Result is cached in script scope; tests may preset $script:StorageSasPolicySupported.
    .DESCRIPTION
        StrictMode-safe: the cache variable is read via Get-Variable so an unset
        variable never throws (azuremap.ps1 runs under Set-StrictMode). If
        detection itself fails, fails safe to $false (callers then collect
        without the parameter and mark SAS-policy evidence unavailable).
    #>
    [CmdletBinding()]
    param()
    $cached = Get-Variable -Name 'StorageSasPolicySupported' -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $cached) {
        return [bool]$cached
    }
    $supported = $false
    try {
        $cmd = Get-Command Get-AzStorageAccount -ErrorAction SilentlyContinue
        $supported = [bool]($cmd -and $cmd.Parameters -and $cmd.Parameters.ContainsKey('IncludeAccountSASPolicy'))
    }
    catch {
        $supported = $false
    }
    $script:StorageSasPolicySupported = $supported
    return $supported
}

function Get-StorageAccountCollection {
    <#
    .SYNOPSIS
        Lists storage accounts in the current subscription context and reports
        whether the collection call FAILED (threw) versus returned an empty set.
        When SAS policy data is requested but the installed Az.Storage does not
        support -IncludeAccountSASPolicy, the accounts are still collected without
        it and SasPolicyUnavailable is flagged (partial evidence, not a failure).
    .OUTPUTS
        [hashtable] @{ Threw = [bool]; Accounts = [object[]]; SasPolicyUnavailable = [bool] }
    #>
    [CmdletBinding()]
    param([switch]$IncludeSasPolicy)

    $sasUnavailable = ($IncludeSasPolicy -and -not (Test-StorageSasPolicySupported))

    try {
        if ($IncludeSasPolicy -and -not $sasUnavailable) {
            $a = Invoke-AzureCommand -Command {
                Get-AzStorageAccount -IncludeAccountSASPolicy -ErrorAction Stop
            } -CommandName "Get-StorageAccounts" -SkipContextCheck
        }
        else {
            $a = Invoke-AzureCommand -Command {
                Get-AzStorageAccount -ErrorAction Stop
            } -CommandName "Get-StorageAccounts" -SkipContextCheck
        }
        return @{ Threw = $false; Accounts = @($a); SasPolicyUnavailable = $sasUnavailable }
    }
    catch {
        Write-AuditLog -Message "Get-AzStorageAccount failed in the current subscription context: $_" -Level WARN
        return @{ Threw = $true; Accounts = @(); SasPolicyUnavailable = $false }
    }
}

function Get-StorageAccountProperty {
    <#
    .SYNOPSIS
        Reads an optional property on a storage account object, returning $null
        when the property is absent (Windows PowerShell 5.1 StrictMode safe).
    #>
    [CmdletBinding()]
    param([object]$Account, [string]$Name)
    if ($Account -and ($Account.PSObject.Properties.Name -contains $Name)) {
        return $Account.$Name
    }
    return $null
}

function New-StorageCoverage {
    <#
    .SYNOPSIS
        Builds the Phase B1 coverage/status view for a storage check from
        per-subscription collection tracking.
    .DESCRIPTION
        Status semantics (contract in Core/RunStatus.ps1):
          * nothing evaluated + collection/context failures -> NOTEVALUATED
            (never a clean PASS)
          * evaluated subset + failures                     -> PARTIAL
            (FAIL instead when risky resources were found; PartialEvaluation
            stays $true so the incomplete coverage remains visible)
          * full coverage, 0 resources discovered           -> PASS
          * full coverage, 0 risky                          -> PASS
          * risky > 0                                       -> FAIL
    #>
    [CmdletBinding()]
    param(
        [int]$Discovered,
        [int]$Evaluated,
        [int]$SkippedResources,
        [object]$CollectionFailures,      # List[object]: per-sub/per-account failure detail
        [object]$SkippedSubscriptions,    # List[string]: sub names where Set-AzContext failed
        [object]$EvaluatedSubscriptions,  # List[string]
        [int]$Risky
    )

    # NOTE: never wrap $CollectionFailures / $SkippedSubscriptions in @(...) - under
    # Windows PowerShell 5.1, coercing a raw generic List throws "Argument types do
    # not match". Read .Count directly instead (works for List and arrays).
    $failedCount = 0
    if ($null -ne $CollectionFailures)   { $failedCount += $CollectionFailures.Count }
    if ($null -ne $SkippedSubscriptions) { $failedCount += $SkippedSubscriptions.Count }

    $status           = 'PASS'
    $collectionStatus = 'Complete'
    $complete         = $true
    $partial          = $false
    $summary          = ''

    if ($Evaluated -eq 0 -and $failedCount -gt 0) {
        $status           = 'NOTEVALUATED'
        $collectionStatus = 'Failed'
        $complete         = $false
        if ($Discovered -gt 0) {
            $summary = "Could not evaluate $Discovered storage account(s); reads failed or permission/API unavailable."
        } else {
            $summary = "Could not evaluate storage accounts; collection failed or permission/API unavailable."
        }
    }
    else {
        if ($failedCount -gt 0) {
            $collectionStatus = 'Partial'
            $complete         = $false
            $partial          = $true
        }
        if ($Risky -gt 0) {
            $status  = 'FAIL'
            $covText = if ($complete) { 'coverage complete.' } else { "coverage partial ($failedCount skipped/failed); findings may be incomplete." }
            $summary = "$Risky of $Evaluated storage accounts risky; $covText"
        }
        elseif ($partial) {
            $status  = 'PARTIAL'
            $summary = "$Evaluated of $Discovered storage accounts evaluated; 0 risky; $failedCount skipped/failed - findings may be incomplete."
        }
        elseif ($Discovered -eq 0) {
            $summary = "No storage accounts discovered in evaluated scope."
        }
        else {
            $summary = "$Evaluated storage accounts evaluated; 0 risky; coverage complete."
        }
    }

    return [PSCustomObject]@{
        Status                   = $status
        CollectionStatus         = $collectionStatus
        CompleteEvaluation       = $complete
        PartialEvaluation        = $partial
        FailedCollectionCount    = $failedCount
        CoverageSummary          = $summary
        Confidence               = if ($status -eq 'NOTEVALUATED') { 'Low' } elseif ($partial) { 'Medium' } else { 'High' }
        ManualValidationRequired = ($status -in @('PARTIAL', 'NOTEVALUATED'))
        # B1: zero-risky records are informational - there is nothing to remediate.
        # This covers both the proven-empty scope (case 1) and a partial-coverage
        # clean result; a CRITICAL/HIGH banner on a Count=0 record is misleading.
        # NOTEVALUATED keeps the check's default severity (evaluation failed).
        # $null = caller keeps the check's default severity.
        Severity                 = if ($Risky -eq 0 -and $status -in @('PASS','PARTIAL')) { 'INFO' } else { $null }
    }
}

function New-StorageCoverageParams {
    <#
    .SYNOPSIS
        Builds the splat hashtable of Phase B1 coverage/reporting parameters for
        Write-Finding, so each storage check passes identical metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Coverage,
        [int]$Discovered,
        [int]$Evaluated,
        [int]$SkippedResources,
        [object]$SkippedSubscriptions,
        [object]$EvaluatedSubscriptions,
        [string[]]$ApiSources,
        [string]$FindingType,
        [bool]$DataPlaneRequired = $false
    )

    # Enumerate explicitly (no @(...) around possible generic Lists - PS 5.1 throws
    # "Argument types do not match" on that coercion).
    $evalList = @()
    if ($null -ne $EvaluatedSubscriptions) { foreach ($s in $EvaluatedSubscriptions) { $evalList += $s } }
    $skipList = @()
    if ($null -ne $SkippedSubscriptions)   { foreach ($s in $SkippedSubscriptions)   { $skipList += $s } }

    return @{
        DiscoveredResourceCount  = $Discovered
        EvaluatedResourceCount   = $Evaluated
        SkippedResourceCount     = $SkippedResources
        FailedCollectionCount    = $Coverage.FailedCollectionCount
        SubscriptionsEvaluated   = $evalList
        SubscriptionsSkipped     = $skipList
        CollectionStatus         = $Coverage.CollectionStatus
        CompleteEvaluation       = $Coverage.CompleteEvaluation
        PartialEvaluation        = $Coverage.PartialEvaluation
        CoverageSummary          = $Coverage.CoverageSummary
        SummaryText              = $Coverage.CoverageSummary
        Confidence               = $Coverage.Confidence
        ManualValidationRequired = $Coverage.ManualValidationRequired
        ApiSources               = $ApiSources
        FindingType              = $FindingType
        DataPlaneRequired        = $DataPlaneRequired
    }
}

function Test-StorageSharedKeyAccess {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "STORAGE ACCOUNTS - SHARED KEY AUTHENTICATION" -Color "Red" -ProgressId $ProgressId

    $findings   = New-Object System.Collections.Generic.List[object]
    $notEval    = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking Storage Shared Key Access" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        # Perf phase: shared per-run inventory (one enumeration per subscription
        # across ALL storage checks). ContextSwitch -> skipped sub; Fetch ->
        # failed collection (same coverage semantics as before).
        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }) }
            continue
        }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($inv.Items).Count

        foreach ($sa in $inv.Items) {
            # Azure semantics: AllowSharedKeyAccess $null/unspecified => shared key IS
            # allowed (the account default). Only an explicit $false is safe.
            $ask = Get-StorageAccountProperty -Account $sa -Name 'AllowSharedKeyAccess'
            if ($ask -ne $false) {
                $state = if ($null -eq $ask) { "Unspecified (defaults to enabled)" } else { "Enabled" }
                $findings.Add([PSCustomObject]@{
                    SubscriptionId       = $sub.Id
                    SubscriptionName     = $sub.Name
                    ResourceGroupName    = $sa.ResourceGroupName
                    StorageAccountName   = $sa.StorageAccountName
                    AllowSharedKeyAccess = $state
                    ResourceId           = $sa.Id
                    Tags                 = $sa.Tags
                })
            }
        }
    }

    $remediation = "Disable shared key authentication and use Azure AD authentication or SAS tokens instead.`n" +
                   "Set-AzStorageAccount -ResourceGroupName <rg> -Name <sa> -AllowSharedKeyAccess `$false"

    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $totalAccounts -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $findings.Count
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts -Evaluated $totalAccounts `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount') -FindingType 'Misconfiguration'

    # Single explicit-status record: PASS only when coverage was proven; PARTIAL when
    # some subscriptions failed; NOTEVALUATED when nothing could be evaluated.
    # B1 case 1: a proven-empty scope is reported at INFO severity.
    $severity = if ($cov.Severity) { $cov.Severity } else { 'HIGH' }
    $evidence = if ($findings.Count -gt 0) { $findings } else { $notEval }
    Write-Finding -Severity $severity -Status $cov.Status `
                  -Message "Storage accounts allowing shared key authentication (enabled or unspecified)" `
                  -Count $findings.Count -CountType "UniqueResources" -Data $evidence -Service "Storage" -CheckId "STORAGE-001" `
                  -Remediation $remediation -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                  @covParams

    # When the main record carries risky evidence, keep the per-subscription failure
    # detail as a separate NotEvaluated record so it is not lost.
    if ($notEval.Count -gt 0 -and $findings.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "NOTEVALUATED" -CheckId "STORAGE-001" `
                      -Message "Shared key authentication could not be evaluated for one or more subscriptions (storage account collection failed)" `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Storage" `
                      -Remediation "Ensure the audit identity has Microsoft.Storage/storageAccounts/read on the subscription and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-StoragePublicAccess {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "STORAGE ACCOUNTS - PUBLIC NETWORK ACCESS" -Color "Red" -ProgressId $ProgressId

    $exposed = New-Object System.Collections.Generic.List[object]
    $notEval = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking Storage Public Access" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }) }
            continue
        }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($inv.Items).Count

        # Per-account network rule sets still need the session on this
        # subscription (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        foreach ($sa in $inv.Items) {
            $net = Invoke-AzureCommand -Command {
                Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $sa.ResourceGroupName -Name $sa.StorageAccountName -ErrorAction SilentlyContinue
            } -CommandName "Get-StorageNetworkRules" -SkipContextCheck

            $pnaRaw = Get-StorageAccountProperty -Account $sa -Name 'PublicNetworkAccess'
            $pna    = if ($null -ne $pnaRaw) { "$pnaRaw" } else { "Enabled" }  # unspecified defaults to Enabled
            $blob   = Get-StorageAccountProperty -Account $sa -Name 'AllowBlobPublicAccess'

            $exposedFlag = $false
            $unknownFlag = $false
            $reasons     = @()

            if ($pna -eq 'Disabled') {
                # Network access disabled -> not publicly reachable at the network layer.
            }
            else {
                # Enabled (or unspecified -> treated as Enabled).
                if (-not $net) {
                    $unknownFlag = $true
                    $reasons += "Public network access enabled but firewall rules could not be read (not confirmed private)"
                }
                else {
                    $da = "$(Get-StorageAccountProperty -Account $net -Name 'DefaultAction')"
                    if ($da -eq 'Allow') {
                        $exposedFlag = $true
                        $reasons += "Public network access enabled + firewall default action = Allow"
                    }
                    elseif ($da -eq 'Deny') {
                        $wide = $false
                        foreach ($rule in @($net.IpRules)) {
                            if ("$($rule.IPAddressOrRange)" -eq '0.0.0.0/0') { $wide = $true; break }
                        }
                        if ($wide) { $exposedFlag = $true; $reasons += "Public network access enabled + IP rule 0.0.0.0/0" }
                    }
                    else {
                        $unknownFlag = $true
                        $reasons += "Public network access enabled; firewall default action unknown ('$da')"
                    }
                }
            }

            # Blob anonymous access: $true = exposed; $null = unspecified (historically
            # defaulted to allowed) -> surface explicitly; $false = safe.
            if ($blob -eq $true)      { $exposedFlag = $true; $reasons += "Blob public access enabled" }
            elseif ($null -eq $blob)  { $unknownFlag = $true; $reasons += "Blob public access unspecified (may default to enabled)" }

            if ($exposedFlag -or $unknownFlag) {
                $severity = if ($exposedFlag) { "HIGH" } else { "MEDIUM" }
                $exposed.Add([PSCustomObject]@{
                    SubscriptionId      = $sub.Id
                    SubscriptionName    = $sub.Name
                    RG                  = $sa.ResourceGroupName
                    StorageAccount      = $sa.StorageAccountName
                    PublicNetworkAccess = $pna
                    DefaultAction       = if ($net) { "$(Get-StorageAccountProperty -Account $net -Name 'DefaultAction')" } else { "Unknown" }
                    NetworkRulesRead    = [bool]$net
                    BlobPublicAccess    = if ($null -eq $blob) { "Unspecified" } else { "$blob" }
                    Confirmed           = $exposedFlag
                    Reasons             = ($reasons -join "; ")
                    Severity            = $severity
                    ResourceId          = $sa.Id
                    Tags                = $sa.Tags
                })
            }
        }
    }

    $remediation = "Disable public network access or configure firewall rules; disable blob public access unless explicitly required.`n" +
                   "Set-AzStorageAccountNetworkRuleSet -ResourceGroupName <rg> -AccountName <sa> -DefaultAction Deny`n" +
                   "Set-AzStorageAccount -ResourceGroupName <rg> -Name <sa> -PublicNetworkAccess Disabled -AllowBlobPublicAccess `$false"

    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $totalAccounts -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $exposed.Count
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts -Evaluated $totalAccounts `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount', 'ARM Get-AzStorageAccountNetworkRuleSet') -FindingType 'Exposure'

    $severity = if ($cov.Severity) { $cov.Severity } else { 'HIGH' }
    $evidence = if ($exposed.Count -gt 0) { $exposed } else { $notEval }
    Write-Finding -Severity $severity -Status $cov.Status `
                  -Message "Storage accounts with public network exposure, blob public access, or unverified firewall" `
                  -Count $exposed.Count -CountType "UniqueResources" -Data $evidence -Service "Storage" -CheckId "STORAGE-002" `
                  -Remediation $remediation -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                  @covParams

    if ($notEval.Count -gt 0 -and $exposed.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "NOTEVALUATED" -CheckId "STORAGE-002" `
                      -Message "Public network access could not be evaluated for one or more subscriptions (storage account collection failed)" `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Storage" `
                      -Remediation "Ensure the audit identity has Microsoft.Storage/storageAccounts/read and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-StorageAdvancedSecurity {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "STORAGE - ADVANCED SECURITY CHECKS" -Color "Yellow" -ProgressId $ProgressId

    # Property-specific lists: TLS and HTTPS-only findings are counted and
    # reported separately from the broader weak-config list, so a summary can
    # never claim "N risky" when only a few TLS issues exist.
    $tlsIssues    = New-Object System.Collections.Generic.List[object]
    $httpsIssues  = New-Object System.Collections.Generic.List[object]
    $crossTenant  = New-Object System.Collections.Generic.List[object]
    $notEval  = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking Storage Advanced Security" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }) }
            continue
        }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($inv.Items).Count

        foreach ($sa in $inv.Items) {
            # Secure transfer (HTTPS-only). Newer object shape uses EnableHttpsTrafficOnly;
            # some shapes expose SupportsHttpsTrafficOnly. Only flag an EXPLICIT $false
            # (null/absent is the enabled default; flagging it would be a false positive).
            $https = Get-StorageAccountProperty -Account $sa -Name 'EnableHttpsTrafficOnly'
            if ($null -eq $https) { $https = Get-StorageAccountProperty -Account $sa -Name 'SupportsHttpsTrafficOnly' }
            if ($https -eq $false) {
                $httpsIssues.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; StorageAccount=$sa.StorageAccountName
                    ResourceGroup=$sa.ResourceGroupName; Issue="Secure transfer (HTTPS-only) disabled"
                    ResourceId=$sa.Id; Tags=$sa.Tags
                })
            }

            # Minimum TLS version. Absent/unspecified is risky (older accounts default to TLS1_0).
            $tls = Get-StorageAccountProperty -Account $sa -Name 'MinimumTlsVersion'
            if ($null -eq $tls -or ("$tls" -notin @("TLS1_2","TLS1_3"))) {
                $tlsIssues.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; StorageAccount=$sa.StorageAccountName
                    ResourceGroup=$sa.ResourceGroupName; Issue="Minimum TLS version below 1.2 or unspecified"
                    CurrentVersion=if ($null -eq $tls) { "Unspecified" } else { "$tls" }
                    ResourceId=$sa.Id; Tags=$sa.Tags
                })
            }

            if ((Get-StorageAccountProperty -Account $sa -Name 'AllowCrossTenantReplication') -eq $true) {
                $crossTenant.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; StorageAccount=$sa.StorageAccountName
                    ResourceGroup=$sa.ResourceGroupName; Issue="Cross-tenant replication allowed"
                    ResourceId=$sa.Id; Tags=$sa.Tags
                })
            }
        }
    }

    # Risky must be UNIQUE storage accounts - one account can carry several of
    # these issues, so summing list counts would overstate the account total.
    # NOTE: no @(...) around the generic Lists - PS 5.1 throws "Argument types
    # do not match" on that coercion; enumerate them directly.
    $issueTotal = $tlsIssues.Count + $httpsIssues.Count + $crossTenant.Count
    $riskyNames = New-Object System.Collections.Generic.List[string]
    foreach ($bucket in @($tlsIssues, $httpsIssues, $crossTenant)) {
        foreach ($item in $bucket) {
            $n = "$($item.StorageAccount)"
            if ($n -and -not $riskyNames.Contains($n)) { $riskyNames.Add($n) }
        }
    }
    $riskyAccounts = $riskyNames.Count

    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $totalAccounts -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $riskyAccounts
    if ($issueTotal -gt 0) {
        $covText = if ($cov.CompleteEvaluation) { 'coverage complete.' } else { 'coverage partial; findings may be incomplete.' }
        $cov.CoverageSummary = "$totalAccounts storage accounts evaluated; $issueTotal issue(s) " +
            "($($tlsIssues.Count) TLS version, $($httpsIssues.Count) HTTPS-only disabled, $($crossTenant.Count) cross-tenant replication) " +
            "across $riskyAccounts unique account(s); $covText"
    }
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts -Evaluated $totalAccounts `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount') -FindingType 'Misconfiguration'

    if ($tlsIssues.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -Message "Storage accounts with minimum TLS version below 1.2 or unspecified" `
                      -Count $tlsIssues.Count -CountType "UniqueResources" -Data $tlsIssues -Service "Storage" -CheckId "STORAGE-003" `
                      -Remediation "Set the minimum TLS version to 1.2." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($httpsIssues.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -Message "Storage accounts with secure transfer (HTTPS-only) disabled" `
                      -Count $httpsIssues.Count -CountType "UniqueResources" -Data $httpsIssues -Service "Storage" -CheckId "STORAGE-003" `
                      -Remediation "Enable secure transfer (HTTPS-only)." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($crossTenant.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -Message "Storage accounts allowing cross-tenant replication" `
                      -Count $crossTenant.Count -CountType "UniqueResources" -Data $crossTenant -Service "Storage" -CheckId "STORAGE-003" `
                      -Remediation "Disable cross-tenant replication unless required." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($issueTotal -eq 0) {
        # B1: explicit coverage record - PASS (proven clean) / PARTIAL / NOTEVALUATED,
        # never silence. Carries the failure detail when nothing was risky.
        # A proven-empty scope (case 1) is reported at INFO severity.
        $severity = if ($cov.Severity) { $cov.Severity } else { 'HIGH' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status `
                      -Message "Storage accounts with security misconfigurations (HTTPS/TLS)" `
                      -Count 0 -Data $evidence -Service "Storage" -CheckId "STORAGE-003" `
                      -Remediation "Enable HTTPS-only and set minimum TLS 1.2." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $issueTotal -gt 0) {
        Write-Finding -Severity "HIGH" -Status "NOTEVALUATED" -CheckId "STORAGE-003" `
                      -Message "Storage advanced security could not be evaluated for one or more subscriptions (collection failed)" `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Storage" `
                      -Remediation "Ensure Microsoft.Storage/storageAccounts/read and re-run." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-StorageAnonymousBlobAccess {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "STORAGE ACCOUNTS - ANONYMOUS BLOB ACCESS" -Color "Red" -ProgressId $ProgressId

    # Phase B3 hard gate: container enumeration is a DATA-PLANE operation and
    # runs ONLY behind -IncludeDataPlane. The orchestrator normally skips this
    # check when the switch is absent; when invoked directly without the opt-in,
    # record NOTEVALUATED (never a clean PASS) and stop. Even when enabled, the
    # evaluation is metadata-only: Entra/OAuth (data-plane RBAC) auth via the
    # account's own context - NO account keys, NO SAS, NO blob content listing.
    if (-not $script:State.Config.IncludeDataPlane) {
        Write-Finding -Severity "INFO" -Status "NOTEVALUATED" -CheckId "STORAGE-004" `
                      -Message "Anonymous blob access not evaluated: data-plane container enumeration requires -IncludeDataPlane (not reported as clean)" `
                      -Count 0 -Data $null -Service "Storage" `
                      -Remediation "Re-run with -IncludeDataPlane to enable metadata-only container public-access evaluation (Entra/OAuth data-plane auth only; never account keys or blob content)." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                      -DataPlaneRequired $true
        return
    }

    $findings = New-Object System.Collections.Generic.List[object]
    $accountLevelAllowed = New-Object System.Collections.Generic.List[object]
    $notEval  = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $evaluatedAccounts = 0
    $skippedResources  = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking anonymous blob access" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = "Storage account collection failed" }) }
            continue
        }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($inv.Items).Count

        foreach ($sa in $inv.Items) {
            # Account-level guard: if blob public access is disabled at the account, no
            # container can be anonymous - a clean, evaluated PASS for this account.
            $blob = Get-StorageAccountProperty -Account $sa -Name 'AllowBlobPublicAccess'

            $ctx = $sa.Context
            $enumOk = $false
            $containers = $null
            try {
                $containers = Invoke-AzureCommand -Command {
                    Get-AzStorageContainer -Context $ctx -ErrorAction Stop
                } -CommandName "Get-StorageContainers" -SkipContextCheck
                $enumOk = $true
            }
            catch {
                # Container enumeration failed (permissions / network / data-plane).
                # Do NOT treat as clean - record NotEvaluated for this account.
                $notEval.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name; StorageAccount = $sa.StorageAccountName
                    Reason = "Container enumeration failed (blob public access = $(if ($null -eq $blob){'Unspecified'}else{"$blob"}))"
                })
                $skippedResources++
            }

            if ($enumOk) {
                $evaluatedAccounts++
                $publicContainers = @()
                foreach ($container in @($containers)) {
                    $pa = Get-StorageAccountProperty -Account $container -Name 'PublicAccess'
                    if ($pa -and "$pa" -ne "Off") { $publicContainers += "$($container.Name) ($pa)" }
                }
                if ($publicContainers.Count -gt 0) {
                    # CONFIRMED public container access (data-plane verified). The
                    # account-level AllowBlobPublicAccess flag is only the enabling
                    # control-plane signal; keep both on the evidence so the
                    # distinction survives into the exports.
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; ResourceGroup=$sa.ResourceGroupName
                        StorageAccount=$sa.StorageAccountName; PublicContainersCount=$publicContainers.Count
                        PublicContainers=($publicContainers -join "; ")
                        AccountAllowBlobPublicAccess=if ($null -eq $blob) { "Unspecified" } else { "$blob" }
                        Confirmation="Data-plane confirmed"
                    })
                }
                elseif ($blob -eq $true) {
                    # Control-plane signal only: the account ALLOWS blob public
                    # access, but data-plane enumeration confirmed no public
                    # containers right now.
                    $accountLevelAllowed.Add([PSCustomObject]@{
                        SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; ResourceGroup=$sa.ResourceGroupName
                        StorageAccount=$sa.StorageAccountName
                        AccountAllowBlobPublicAccess="$blob"
                        Confirmation="Control-plane signal only; no public containers confirmed"
                    })
                }
            }
        }
    }

    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $evaluatedAccounts -SkippedResources $skippedResources `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $findings.Count
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts -Evaluated $evaluatedAccounts `
        -SkippedResources $skippedResources -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount', 'Data-plane Get-AzStorageContainer (AAD/OAuth context, container metadata only)') `
        -FindingType 'Exposure' -DataPlaneRequired $true

    if ($findings.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" -Status "FAIL" -Message "Storage accounts with CONFIRMED anonymous/public blob containers (data-plane verified)" `
                      -Count $findings.Count -CountType "UniqueResources" -Data $findings -Service "Storage" -CheckId "STORAGE-004" `
                      -Remediation "Disable public access on the containers and on the account (AllowBlobPublicAccess = false)." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    else {
        # B1: explicit coverage record - PASS / PARTIAL / NOTEVALUATED, never silence.
        # A proven-empty scope (case 1) is reported at INFO severity.
        $severity = if ($cov.Severity) { $cov.Severity } else { 'CRITICAL' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status `
                      -Message "Storage accounts with anonymous/public blob containers" `
                      -Count 0 -Data $evidence -Service "Storage" -CheckId "STORAGE-004" `
                      -Remediation "Disable public access on the containers and on the account (AllowBlobPublicAccess = false)." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($accountLevelAllowed.Count -gt 0) {
        # Control-plane signal, distinct from the data-plane CONFIRMED finding
        # above: public access is ALLOWED at account level but no public
        # containers were confirmed by enumeration.
        Write-Finding -Severity "LOW" -Status "FAIL" -Message "Storage accounts allowing blob public access at account level (control-plane signal; no public containers confirmed)" `
                      -Count $accountLevelAllowed.Count -CountType "UniqueResources" -Data $accountLevelAllowed -Service "Storage" -CheckId "STORAGE-004" `
                      -Remediation "Set AllowBlobPublicAccess = false unless anonymous container access is explicitly required." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
    if ($notEval.Count -gt 0 -and $findings.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" -Status "NOTEVALUATED" -CheckId "STORAGE-004" `
                      -Message "Anonymous blob access could not be fully evaluated (container enumeration or collection failed); not reported as clean" `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Storage" `
                      -Remediation "Grant the audit identity Reader + Storage Blob Data Reader (or Storage Account Contributor for control-plane container listing) and re-run." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-StorageExfiltrationVectors {
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "STORAGE - DATA EXFILTRATION VECTORS" -Color "Red" -ProgressId $ProgressId

    $critical = New-Object System.Collections.Generic.List[object]
    $high     = New-Object System.Collections.Generic.List[object]
    $medium   = New-Object System.Collections.Generic.List[object]
    $notEval  = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking storage exfiltration vectors" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }) }
            continue
        }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($inv.Items).Count

        # SAS policy evidence unavailable on this Az.Storage version: the account set
        # was still collected and all other vectors are evaluated, but the SAS-expiry
        # vector is unproven -> record once per subscription so status degrades to
        # PARTIAL instead of pretending full coverage.
        if (-not (Test-StorageSasPolicySupported)) {
            $notEval.Add([PSCustomObject]@{
                SubscriptionName = $sub.Name
                Reason = "Account SAS expiration policy not evaluated (installed Az.Storage does not support -IncludeAccountSASPolicy)"
            })
        }

        # Per-account network rule sets still need the session on this
        # subscription (deduped no-op right after a fresh fetch).
        if (@($inv.Items).Count -gt 0 -and -not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        foreach ($sa in $inv.Items) {
            $networkRuleSet = Invoke-AzureCommand -Command {
                Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $sa.ResourceGroupName -AccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
            } -CommandName "Get-StorageNetworkRules" -SkipContextCheck

            $sasPolicy = Get-StorageAccountProperty -Account $sa -Name 'AccountSasPolicy'
            $sasExpiryDays = 0
            $hasLongSASPolicy = $false
            if ($sasPolicy -and ($sasPolicy.PSObject.Properties.Name -contains 'SasExpirationPeriod') -and $sasPolicy.SasExpirationPeriod) {
                $sp = $sasPolicy.SasExpirationPeriod
                if ($sp -is [TimeSpan]) { $sasExpiryDays = [math]::Round($sp.TotalDays) }
                else {
                    $ts = [TimeSpan]::Zero
                    if ([TimeSpan]::TryParse("$sp", [ref]$ts)) { $sasExpiryDays = [math]::Round($ts.TotalDays) }
                }
                $hasLongSASPolicy = $sasExpiryDays -gt 30
            }

            $bypassTrustedServices = $false
            if ($networkRuleSet -and $networkRuleSet.Bypass) { $bypassTrustedServices = ($networkRuleSet.Bypass -contains "AzureServices") }

            $allowCrossTenant = ((Get-StorageAccountProperty -Account $sa -Name 'AllowCrossTenantReplication') -eq $true)
            $publicEnabled    = ("$(Get-StorageAccountProperty -Account $sa -Name 'PublicNetworkAccess')" -ne 'Disabled')  # enabled or unspecified
            $sharedKeyRisky   = ((Get-StorageAccountProperty -Account $sa -Name 'AllowSharedKeyAccess') -ne $false)          # enabled or unspecified
            $defaultAllow     = (-not $networkRuleSet -or "$(Get-StorageAccountProperty -Account $networkRuleSet -Name 'DefaultAction')" -eq "Allow")

            if ($sharedKeyRisky -and $publicEnabled -and $defaultAllow) {
                $critical.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; ResourceGroup=$sa.ResourceGroupName
                    StorageAccount=$sa.StorageAccountName
                    Issue="Public/unspecified network + shared key enabled/unspecified + no restrictive firewall"
                })
            }
            if ($hasLongSASPolicy -or $allowCrossTenant) {
                $high.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; ResourceGroup=$sa.ResourceGroupName
                    StorageAccount=$sa.StorageAccountName; LongSASPolicyDays=$sasExpiryDays
                    CrossTenantReplication=if ($allowCrossTenant) { "Yes" } else { "No" }
                })
            }
            if ($bypassTrustedServices -and $networkRuleSet -and "$(Get-StorageAccountProperty -Account $networkRuleSet -Name 'DefaultAction')" -eq "Deny") {
                $medium.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; ResourceGroup=$sa.ResourceGroupName
                    StorageAccount=$sa.StorageAccountName; Issue="Trusted services bypass enabled"
                })
            }
        }
    }

    $riskyTotal = $critical.Count + $high.Count + $medium.Count
    # Risky must be UNIQUE storage accounts - one account can appear in several
    # severity buckets, so summing bucket counts yields impossible text like
    # "92 of 60 storage accounts risky". Signals are reported separately.
    # NOTE: no @(...) around the generic Lists - PS 5.1 throws "Argument types
    # do not match" on that coercion; enumerate them directly.
    $riskyNames = New-Object System.Collections.Generic.List[string]
    foreach ($bucket in @($critical, $high, $medium)) {
        foreach ($item in $bucket) {
            $n = "$($item.StorageAccount)"
            if ($n -and -not $riskyNames.Contains($n)) { $riskyNames.Add($n) }
        }
    }
    $riskyAccounts = $riskyNames.Count
    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $totalAccounts -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $riskyAccounts
    if ($riskyTotal -gt 0) {
        $covText = if ($cov.CompleteEvaluation) { 'coverage complete.' } else { 'coverage partial; findings may be incomplete.' }
        $cov.CoverageSummary = "$totalAccounts storage accounts evaluated; $riskyTotal risk signals found " +
            "($($critical.Count) critical combinations, $($high.Count) SAS/cross-tenant risks, " +
            "$($medium.Count) trusted-services bypass observations) across $riskyAccounts unique account(s); $covText"
    }
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts -Evaluated $totalAccounts `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount -IncludeAccountSASPolicy', 'ARM Get-AzStorageAccountNetworkRuleSet') `
        -FindingType 'Exposure'

    if ($critical.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" -Status "FAIL" -Message "Storage accounts with public/unspecified access, shared key, and no firewall" `
                      -Count $critical.Count -CountType "UniqueResources" -Data $critical -Service "Exfiltration" -CheckId "STORAGE-005" `
                      -Remediation "Disable shared key, restrict public access, and enforce firewall rules." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($high.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -Message "Storage accounts with long SAS policies or cross-tenant replication" `
                      -Count $high.Count -CountType "RiskSignals" -Data $high -Service "Exfiltration" -CheckId "STORAGE-005" `
                      -Remediation "Reduce SAS expiration and disable cross-tenant replication." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($medium.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -Message "Storage accounts with trusted services bypass enabled" `
                      -Count $medium.Count -CountType "Observations" -Data $medium -Service "Exfiltration" -CheckId "STORAGE-005" `
                      -Remediation "Review trusted services bypass and restrict if not required." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($riskyTotal -eq 0) {
        # B1: explicit coverage record - PASS / PARTIAL / NOTEVALUATED, never silence.
        # A proven-empty scope (case 1) is reported at INFO severity.
        $severity = if ($cov.Severity) { $cov.Severity } else { 'CRITICAL' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status `
                      -Message "Storage accounts with public/unspecified access, shared key, and no firewall" `
                      -Count 0 -Data $evidence -Service "Exfiltration" -CheckId "STORAGE-005" `
                      -Remediation "Disable shared key, restrict public access, and enforce firewall rules." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $riskyTotal -gt 0) {
        Write-Finding -Severity "CRITICAL" -Status "NOTEVALUATED" -CheckId "STORAGE-005" `
                      -Message "Data exfiltration vectors could not be evaluated for one or more subscriptions (collection failed); not reported as clean" `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Exfiltration" `
                      -Remediation "Ensure Microsoft.Storage/storageAccounts/read and re-run." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Test-StorageDoubleEncryption {
    <#
    .SYNOPSIS
        STORAGE-007 - infrastructure (double) encryption. INFO/control-gap ONLY
        when infrastructure encryption is explicitly not enabled; never
        escalated. Azure Storage is ALWAYS encrypted at rest by default with
        Microsoft-managed keys - this finding matters only where a baseline or
        regulation requires double encryption. Unknown/absent property ->
        NotEvaluated, never a misleading clean PASS.
    #>
    param(
        [array]$Subscriptions,
        [hashtable]$Exclusions,
        [int]$ProgressId = 0
    )

    Write-Section -Title "STORAGE ACCOUNTS - INFRASTRUCTURE (DOUBLE) ENCRYPTION" -Color "Yellow" -ProgressId $ProgressId

    $notEnabled = New-Object System.Collections.Generic.List[object]
    $notEval    = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $evaluatedAccounts = 0
    $skippedResources = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        Write-Progress -Activity "Checking storage double encryption" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $inv = Get-SubscriptionInventory -SubscriptionId $sub.Id -SubscriptionName $sub.Name -TenantId $sub.TenantId -Kind StorageAccounts
        if ($inv.Unavailable) {
            if ($inv.UnavailableReason -eq 'ContextSwitch') { $subsSkipped.Add($sub.Name) }
            else { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = 'Storage account collection failed' }) }
            continue
        }
        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($inv.Items).Count

        foreach ($sa in $inv.Items) {
            $enc = Get-StorageAccountProperty -Account $sa -Name 'Encryption'
            $rie = $null
            if ($enc -and ($enc.PSObject.Properties.Name -contains 'RequireInfrastructureEncryption')) {
                $rie = $enc.RequireInfrastructureEncryption
            }

            if ($null -eq $rie) {
                # Property absent/unknown on this API surface -> NotEvaluated,
                # never silently treated as either enabled or disabled.
                $notEval.Add([PSCustomObject]@{
                    SubscriptionName = $sub.Name; StorageAccount = $sa.StorageAccountName
                    Reason = 'Encryption.RequireInfrastructureEncryption property absent (older API surface)'
                })
                $skippedResources++
                continue
            }
            $evaluatedAccounts++

            if ($rie -eq $false) {
                $notEnabled.Add([PSCustomObject]@{
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    ResourceGroup    = $sa.ResourceGroupName
                    StorageAccount   = $sa.StorageAccountName
                    RequireInfrastructureEncryption = "$rie"
                    ResourceId       = $sa.Id
                })
            }
        }
    }

    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $evaluatedAccounts -SkippedResources $skippedResources `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $notEnabled.Count
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts -Evaluated $evaluatedAccounts `
        -SkippedResources $skippedResources -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount') -FindingType 'ControlGap'

    $infoText = 'Azure Storage data is still encrypted at rest by default with Microsoft-managed keys; infrastructure (double) encryption is a defense-in-depth control relevant only where a baseline or regulation explicitly requires it.'

    if ($notEnabled.Count -gt 0) {
        # INFO by design: control gap only, never escalated.
        Write-Finding -Severity "INFO" -Status "FAIL" -CheckId "STORAGE-007" `
                      -Message "Storage accounts without infrastructure (double) encryption - data is still encrypted at rest by default" `
                      -Count $notEnabled.Count -CountType "UniqueResources" -Data $notEnabled -Service "Storage" `
                      -SeverityReason "Control gap only, never escalated. $infoText" `
                      -Remediation "No action required unless a baseline/regulation mandates double encryption; if required, it can only be enabled at account creation. $infoText" `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    else {
        $severity = if ($cov.Severity) { $cov.Severity } else { 'INFO' }
        $evidence = if ($notEval.Count -gt 0) { $notEval } else { $null }
        Write-Finding -Severity $severity -Status $cov.Status -CheckId "STORAGE-007" `
                      -Message "Storage accounts without infrastructure (double) encryption" `
                      -Count 0 -Data $evidence -Service "Storage" `
                      -SeverityReason $infoText `
                      -Remediation "No action required unless a baseline/regulation mandates double encryption." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($notEval.Count -gt 0 -and $notEnabled.Count -gt 0) {
        Write-Finding -Severity "INFO" -Status "NOTEVALUATED" -CheckId "STORAGE-007" `
                      -Message "Infrastructure encryption could not be fully evaluated (property absent or collection failed); not reported as clean" `
                      -Count $notEval.Count -CountType "NotEvaluatedItems" -Data $notEval -Service "Storage" `
                      -Remediation "Re-run with a current Az.Storage version so Encryption.RequireInfrastructureEncryption is returned." `
                      -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple"
    }
}

function Register-AzureStorageChecks {
    Register-AuditCheck -CheckId "STORAGE-001" -Category "Azure" -Service "Storage" -Name "Shared Key Authentication" `
                        -Function ${function:Test-StorageSharedKeyAccess} -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Storage") -Phase "PerSubscription" -RequiredResourceTypes @('Microsoft.Storage/storageAccounts')

    Register-AuditCheck -CheckId "STORAGE-002" -Category "Azure" -Service "Storage" -Name "Public Network Access" `
                        -Function ${function:Test-StoragePublicAccess} -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Storage") -Phase "PerSubscription" -RequiredResourceTypes @('Microsoft.Storage/storageAccounts')

    Register-AuditCheck -CheckId "STORAGE-003" -Category "Azure" -Service "Storage" -Name "Advanced Security Checks" `
                        -Function ${function:Test-StorageAdvancedSecurity} -DefaultSeverity "HIGH" `
                        -RequiredModules @("Az.Accounts", "Az.Storage") -Phase "PerSubscription" -RequiredResourceTypes @('Microsoft.Storage/storageAccounts')

    Register-AuditCheck -CheckId "STORAGE-004" -Category "Azure" -Service "Storage" -Name "Anonymous Blob Access" `
                        -Function ${function:Test-StorageAnonymousBlobAccess} -DefaultSeverity "CRITICAL" `
                        -RequiredModules @("Az.Accounts", "Az.Storage") -Phase "PerSubscription" -RequiredResourceTypes @('Microsoft.Storage/storageAccounts') -RequiresDataPlane $true

    Register-AuditCheck -CheckId "STORAGE-005" -Category "Azure" -Service "Storage" -Name "Data Exfiltration Vectors" `
                        -Function ${function:Test-StorageExfiltrationVectors} -DefaultSeverity "CRITICAL" `
                        -RequiredModules @("Az.Accounts", "Az.Storage") -Phase "PerSubscription" -RequiredResourceTypes @('Microsoft.Storage/storageAccounts')

    # INFO-only control gap by design (double encryption is defense in depth;
    # storage is encrypted at rest by default) - never escalated.
    Register-AuditCheck -CheckId "STORAGE-007" -Category "Azure" -Service "Storage" -Name "Infrastructure (Double) Encryption" `
                        -Function ${function:Test-StorageDoubleEncryption} -DefaultSeverity "INFO" `
                        -RequiredModules @("Az.Accounts", "Az.Storage") -Phase "PerSubscription" -RequiredResourceTypes @('Microsoft.Storage/storageAccounts')
}
