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
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            Write-Progress -Activity "Checking Storage Shared Key Access" -Status "Subscription: $($sub.Name) (skipped)" `
                          -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId
            # B1: a failed context switch is recorded as skipped coverage, not silently dropped.
            $subsSkipped.Add($sub.Name)
            continue
        }
        Write-Progress -Activity "Checking Storage Shared Key Access" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $col = Get-StorageAccountCollection
        if ($col.Threw) { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }); continue }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($col.Accounts).Count

        foreach ($sa in $col.Accounts) {
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
                  -Count $findings.Count -Data $evidence -Service "Storage" -CheckId "STORAGE-001" `
                  -Remediation $remediation -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                  @covParams

    # When the main record carries risky evidence, keep the per-subscription failure
    # detail as a separate NotEvaluated record so it is not lost.
    if ($notEval.Count -gt 0 -and $findings.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "NOTEVALUATED" -CheckId "STORAGE-001" `
                      -Message "Shared key authentication could not be evaluated for one or more subscriptions (storage account collection failed)" `
                      -Count $notEval.Count -Data $notEval -Service "Storage" `
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
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            Write-Progress -Activity "Checking Storage Public Access" -Status "Subscription: $($sub.Name) (skipped)" `
                          -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId
            $subsSkipped.Add($sub.Name)
            continue
        }
        Write-Progress -Activity "Checking Storage Public Access" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $col = Get-StorageAccountCollection
        if ($col.Threw) { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }); continue }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($col.Accounts).Count

        foreach ($sa in $col.Accounts) {
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
                  -Count $exposed.Count -Data $evidence -Service "Storage" -CheckId "STORAGE-002" `
                  -Remediation $remediation -Exclusions $Exclusions -SubscriptionId "Multiple" -SubscriptionName "Multiple" `
                  @covParams

    if ($notEval.Count -gt 0 -and $exposed.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "NOTEVALUATED" -CheckId "STORAGE-002" `
                      -Message "Public network access could not be evaluated for one or more subscriptions (storage account collection failed)" `
                      -Count $notEval.Count -Data $notEval -Service "Storage" `
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

    $findings = New-Object System.Collections.Generic.List[object]
    $notEval  = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        Write-Progress -Activity "Checking Storage Advanced Security" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $col = Get-StorageAccountCollection
        if ($col.Threw) { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }); continue }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($col.Accounts).Count

        foreach ($sa in $col.Accounts) {
            # Secure transfer (HTTPS-only). Newer object shape uses EnableHttpsTrafficOnly;
            # some shapes expose SupportsHttpsTrafficOnly. Only flag an EXPLICIT $false
            # (null/absent is the enabled default; flagging it would be a false positive).
            $https = Get-StorageAccountProperty -Account $sa -Name 'EnableHttpsTrafficOnly'
            if ($null -eq $https) { $https = Get-StorageAccountProperty -Account $sa -Name 'SupportsHttpsTrafficOnly' }
            if ($https -eq $false) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; StorageAccount=$sa.StorageAccountName
                    ResourceGroup=$sa.ResourceGroupName; Issue="Secure transfer (HTTPS-only) disabled"; Severity="HIGH"
                    ResourceId=$sa.Id; Tags=$sa.Tags
                })
            }

            # Minimum TLS version. Absent/unspecified is risky (older accounts default to TLS1_0).
            $tls = Get-StorageAccountProperty -Account $sa -Name 'MinimumTlsVersion'
            if ($null -eq $tls -or ("$tls" -notin @("TLS1_2","TLS1_3"))) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; StorageAccount=$sa.StorageAccountName
                    ResourceGroup=$sa.ResourceGroupName; Issue="Minimum TLS version below 1.2 or unspecified"
                    CurrentVersion=if ($null -eq $tls) { "Unspecified" } else { "$tls" }; Severity="HIGH"
                    ResourceId=$sa.Id; Tags=$sa.Tags
                })
            }

            if ((Get-StorageAccountProperty -Account $sa -Name 'AllowCrossTenantReplication') -eq $true) {
                $findings.Add([PSCustomObject]@{
                    SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; StorageAccount=$sa.StorageAccountName
                    ResourceGroup=$sa.ResourceGroupName; Issue="Cross-tenant replication allowed"; Severity="MEDIUM"
                    ResourceId=$sa.Id; Tags=$sa.Tags
                })
            }
        }
    }

    $highFindings   = @($findings | Where-Object { $_.Severity -eq "HIGH" })
    $mediumFindings = @($findings | Where-Object { $_.Severity -eq "MEDIUM" })

    $cov = New-StorageCoverage -Discovered $totalAccounts -Evaluated $totalAccounts -SkippedResources 0 `
        -CollectionFailures $notEval -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -Risky $findings.Count
    $covParams = New-StorageCoverageParams -Coverage $cov -Discovered $totalAccounts -Evaluated $totalAccounts `
        -SkippedResources 0 -SkippedSubscriptions $subsSkipped -EvaluatedSubscriptions $subsEvaluated `
        -ApiSources @('ARM Get-AzStorageAccount') -FindingType 'Misconfiguration'

    if ($highFindings.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -Message "Storage accounts with security misconfigurations (HTTPS/TLS)" `
                      -Count $highFindings.Count -Data $highFindings -Service "Storage" -CheckId "STORAGE-003" `
                      -Remediation "Enable HTTPS-only and set minimum TLS 1.2." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($mediumFindings.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -Message "Storage accounts allowing cross-tenant replication" `
                      -Count $mediumFindings.Count -Data $mediumFindings -Service "Storage" -CheckId "STORAGE-003" `
                      -Remediation "Disable cross-tenant replication unless required." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($findings.Count -eq 0) {
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
    if ($notEval.Count -gt 0 -and $findings.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "NOTEVALUATED" -CheckId "STORAGE-003" `
                      -Message "Storage advanced security could not be evaluated for one or more subscriptions (collection failed)" `
                      -Count $notEval.Count -Data $notEval -Service "Storage" `
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

    $findings = New-Object System.Collections.Generic.List[object]
    $notEval  = New-Object System.Collections.Generic.List[object]
    $subsEvaluated = New-Object System.Collections.Generic.List[string]
    $subsSkipped   = New-Object System.Collections.Generic.List[string]
    $totalAccounts = 0
    $evaluatedAccounts = 0
    $skippedResources  = 0
    $totalProcessed = 0

    foreach ($sub in $Subscriptions) {
        $totalProcessed++
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        Write-Progress -Activity "Checking anonymous blob access" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $col = Get-StorageAccountCollection
        if ($col.Threw) { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name; Reason = "Storage account collection failed" }); continue }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($col.Accounts).Count

        foreach ($sa in $col.Accounts) {
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
                    $findings.Add([PSCustomObject]@{
                        SubscriptionId=$sub.Id; SubscriptionName=$sub.Name; ResourceGroup=$sa.ResourceGroupName
                        StorageAccount=$sa.StorageAccountName; PublicContainersCount=$publicContainers.Count
                        PublicContainers=($publicContainers -join "; ")
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
        Write-Finding -Severity "CRITICAL" -Status "FAIL" -Message "Storage accounts with anonymous/public blob containers" `
                      -Count $findings.Count -Data $findings -Service "Storage" -CheckId "STORAGE-004" `
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
    if ($notEval.Count -gt 0 -and $findings.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" -Status "NOTEVALUATED" -CheckId "STORAGE-004" `
                      -Message "Anonymous blob access could not be fully evaluated (container enumeration or collection failed); not reported as clean" `
                      -Count $notEval.Count -Data $notEval -Service "Storage" `
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
        if (-not (Set-SubscriptionContext -SubscriptionId $sub.Id -SubscriptionName $sub.Name)) {
            $subsSkipped.Add($sub.Name)
            continue
        }

        Write-Progress -Activity "Checking storage exfiltration vectors" -Status "Subscription: $($sub.Name)" `
                      -PercentComplete (Get-SafeProgressPercent -Current $totalProcessed -Total $Subscriptions.Count) -Id $ProgressId

        $col = Get-StorageAccountCollection -IncludeSasPolicy
        if ($col.Threw) { $notEval.Add([PSCustomObject]@{ SubscriptionName = $sub.Name }); continue }

        $subsEvaluated.Add($sub.Name)
        $totalAccounts += @($col.Accounts).Count

        # SAS policy evidence unavailable on this Az.Storage version: the account set
        # was still collected and all other vectors are evaluated, but the SAS-expiry
        # vector is unproven -> record once per subscription so status degrades to
        # PARTIAL instead of pretending full coverage.
        if ($col.SasPolicyUnavailable) {
            $notEval.Add([PSCustomObject]@{
                SubscriptionName = $sub.Name
                Reason = "Account SAS expiration policy not evaluated (installed Az.Storage does not support -IncludeAccountSASPolicy)"
            })
        }

        foreach ($sa in $col.Accounts) {
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
                      -Count $critical.Count -Data $critical -Service "Exfiltration" -CheckId "STORAGE-005" `
                      -Remediation "Disable shared key, restrict public access, and enforce firewall rules." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($high.Count -gt 0) {
        Write-Finding -Severity "HIGH" -Status "FAIL" -Message "Storage accounts with long SAS policies or cross-tenant replication" `
                      -Count $high.Count -Data $high -Service "Exfiltration" -CheckId "STORAGE-005" `
                      -Remediation "Reduce SAS expiration and disable cross-tenant replication." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple" @covParams
    }
    if ($medium.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" -Status "FAIL" -Message "Storage accounts with trusted services bypass enabled" `
                      -Count $medium.Count -Data $medium -Service "Exfiltration" -CheckId "STORAGE-005" `
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
                      -Count $notEval.Count -Data $notEval -Service "Exfiltration" `
                      -Remediation "Ensure Microsoft.Storage/storageAccounts/read and re-run." -Exclusions $Exclusions `
                      -SubscriptionId "Multiple" -SubscriptionName "Multiple"
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
}
