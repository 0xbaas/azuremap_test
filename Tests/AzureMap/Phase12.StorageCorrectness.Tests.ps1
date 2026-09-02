#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase12.StorageCorrectness.Tests.ps1
# Live-shape fixture tests for the storage under-reporting fix.
# Proves: risky accounts FAIL, safe accounts PASS, null/unspecified properties are
# treated as risky (not silently safe), and failed collection/enumeration becomes
# NotEvaluated (never a false clean PASS). Also exercises the New-AzureMapFinding
# raw-List[object] normalization (must not throw "Argument types do not match").
# Mocked/local only. No live Azure, no Graph, no listKeys, no secret reads.
#
# Fixture state uses $global: scope so the global Az cmdlet stubs (which resolve
# $global:) and the BeforeEach setup agree.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Products\AzureMap\Core\InventoryCache.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Storage.ps1"
    . "$projectRoot\Products\AzureMap\Checks\StorageKey.ps1"

    function global:Set-AzContext {
        param([string]$SubscriptionId, [string]$TenantId, [Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxContextFailSubs -contains $SubscriptionId) { throw "no access to subscription $SubscriptionId" }
    }
    function global:Get-AzStorageAccount {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxAccountsThrow) { throw "403 AuthorizationFailed listing storage accounts" }
        return $global:FxAccounts
    }
    function global:Get-AzStorageAccountNetworkRuleSet { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxNet }
    function global:Get-AzStorageContainer {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxContainersThrow) { throw "403 AuthorizationFailed listing containers" }
        return $global:FxContainers
    }
    function global:Get-AzRoleAssignment { param([Parameter(ValueFromRemainingArguments)]$r) @() }

    function global:New-SA {
        param([hashtable]$Props = @{})
        $base = @{ StorageAccountName='sa1'; ResourceGroupName='rg1'; Id='/subscriptions/S1/rg1/sa1'; Tags=@{}; Context=([PSCustomObject]@{ Name='ctx' }) }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [PSCustomObject]$base
    }

    # Array-safe, script-scoped lookup helpers. Explicit foreach + comma-return:
    # no pipeline-unrolling ambiguity across Pester scopes, no global functions.
    function script:Get-Fin {
        param([string]$CheckId)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ($item.CheckId -eq $CheckId) { $items += $item }
        }
        return ,$items
    }
    function script:Get-MainFin {
        param([string]$CheckId, [string]$Like)
        $items = @()
        foreach ($item in (script:Get-Fin -CheckId $CheckId)) {
            if ("$($item.Finding)" -like $Like) { $items += $item }
        }
        return ,$items
    }
    function script:Get-NotEval {
        param([string]$CheckId)
        $items = @()
        foreach ($item in (script:Get-Fin -CheckId $CheckId)) {
            if ("$($item.Status)".ToUpperInvariant() -eq 'NOTEVALUATED') { $items += $item }
        }
        return ,$items
    }

    $global:FxSub = [PSCustomObject]@{ Id='S1'; Name='n1'; TenantId='T1' }
}

Describe "Storage correctness fixtures" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        # Tests emulate an Az.Storage version WITH -IncludeAccountSASPolicy support
        # (unsupported-version behavior is covered in Phase15).
        $script:StorageSasPolicySupported = $true
        $global:FxAccounts        = @()
        $global:FxAccountsThrow   = $false
        $global:FxNet             = $null
        $global:FxContainers      = @()
        $global:FxContainersThrow = $false
        $global:FxContextFailSubs = @()
    }

    Context "STORAGE-001 shared key authentication" {
        It "AllowSharedKeyAccess = true -> FAIL" {
            $global:FxAccounts = @(New-SA @{ AllowSharedKeyAccess = $true })
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            [int]$m[0].Count | Should -Be 1
        }
        It "AllowSharedKeyAccess = false -> clean PASS (Count 0)" {
            $global:FxAccounts = @(New-SA @{ AllowSharedKeyAccess = $false })
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            [int]$m[0].Count | Should -Be 0
        }
        It "AllowSharedKeyAccess = null/unspecified -> NOT a clean pass (flagged)" {
            $global:FxAccounts = @(New-SA @{ AllowSharedKeyAccess = $null })
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            [int]$m[0].Count | Should -Be 1
        }
        It "storage account collection throws -> NotEvaluated, not clean PASS" {
            $global:FxAccountsThrow = $true
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'STORAGE-001').Count | Should -BeGreaterThan 0
        }
    }

    Context "STORAGE-002 public network access" {
        It "PublicNetworkAccess Enabled + DefaultAction Allow -> FAIL" {
            $global:FxNet      = [PSCustomObject]@{ DefaultAction='Allow'; IpRules=@(); Bypass=@() }
            $global:FxAccounts = @(New-SA @{ PublicNetworkAccess='Enabled'; AllowBlobPublicAccess=$false })
            Test-StoragePublicAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-002' '*public network exposure*'
            [int]$m[0].Count | Should -Be 1
        }
        It "PublicNetworkAccess Disabled + blob false -> clean PASS" {
            $global:FxNet      = [PSCustomObject]@{ DefaultAction='Deny'; IpRules=@(); Bypass=@() }
            $global:FxAccounts = @(New-SA @{ PublicNetworkAccess='Disabled'; AllowBlobPublicAccess=$false })
            Test-StoragePublicAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-002' '*public network exposure*'
            [int]$m[0].Count | Should -Be 0
        }
        It "NetworkRuleSet null while Enabled -> NOT clean pass (unknown surfaced)" {
            $global:FxNet      = $null
            $global:FxAccounts = @(New-SA @{ PublicNetworkAccess='Enabled'; AllowBlobPublicAccess=$false })
            Test-StoragePublicAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-002' '*public network exposure*'
            [int]$m[0].Count | Should -Be 1
        }
        It "AllowBlobPublicAccess = true -> FAIL" {
            $global:FxNet      = [PSCustomObject]@{ DefaultAction='Deny'; IpRules=@(); Bypass=@() }
            $global:FxAccounts = @(New-SA @{ PublicNetworkAccess='Disabled'; AllowBlobPublicAccess=$true })
            Test-StoragePublicAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-002' '*public network exposure*'
            [int]$m[0].Count | Should -Be 1
        }
        It "AllowBlobPublicAccess = null -> handled explicitly (not silently safe)" {
            $global:FxNet      = [PSCustomObject]@{ DefaultAction='Deny'; IpRules=@(); Bypass=@() }
            $global:FxAccounts = @(New-SA @{ PublicNetworkAccess='Disabled'; AllowBlobPublicAccess=$null })
            Test-StoragePublicAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-002' '*public network exposure*'
            [int]$m[0].Count | Should -Be 1
        }
        It "collection throws -> STORAGE-002 NotEvaluated" {
            $global:FxAccountsThrow = $true
            Test-StoragePublicAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'STORAGE-002').Count | Should -BeGreaterThan 0
        }
    }

    Context "STORAGE-004 anonymous blob access" {
        BeforeEach {
            # Data-plane evaluation is strictly opt-in (Phase B3): tests that
            # exercise container enumeration must pass the gate explicitly.
            $script:State.Config.IncludeDataPlane = $true
        }
        It "without -IncludeDataPlane the check is NOTEVALUATED (never Clean) and does not enumerate" {
            $script:State.Config.IncludeDataPlane = $false
            $global:FxAccounts   = @(New-SA @{ AllowBlobPublicAccess=$true })
            $global:FxContainers = @([PSCustomObject]@{ Name='c1'; PublicAccess='Blob' })
            Test-StorageAnonymousBlobAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $r = $script:State.Results[-1]
            "$($r.Status)".ToUpper() | Should -Be 'NOTEVALUATED'
            $r.DataPlaneRequired | Should -BeTrue
            "$($r.Finding)" | Should -BeLike '*-IncludeDataPlane*'
            [int]$r.Count | Should -Be 0
            @($script:State.Results | Where-Object { [int]$_.Count -gt 0 }).Count | Should -Be 0
        }
        It "container enumeration throws 403 -> NotEvaluated (not clean PASS)" {
            $global:FxAccounts        = @(New-SA @{ AllowBlobPublicAccess=$true })
            $global:FxContainersThrow = $true
            Test-StorageAnonymousBlobAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'STORAGE-004').Count | Should -BeGreaterThan 0
        }
        It "public container detected -> CRITICAL FAIL (data-plane confirmed)" {
            $global:FxAccounts   = @(New-SA @{ AllowBlobPublicAccess=$true })
            $global:FxContainers = @([PSCustomObject]@{ Name='c1'; PublicAccess='Blob' })
            Test-StorageAnonymousBlobAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'STORAGE-004' | Where-Object { [int]$_.Count -gt 0 -and "$($_.Status)".ToUpper() -ne 'NOTEVALUATED' })
            $m.Count | Should -BeGreaterThan 0
            "$($m[0].Finding)" | Should -BeLike '*CONFIRMED*data-plane*'
            "$($m[0].Evidence[0].Confirmation)" | Should -Be 'Data-plane confirmed'
            $m[0].CountType | Should -Be 'UniqueResources'
        }
        It "account-level AllowBlobPublicAccess with no public containers -> control-plane signal, NOT the confirmed finding" {
            $global:FxAccounts   = @(New-SA @{ AllowBlobPublicAccess=$true })
            $global:FxContainers = @([PSCustomObject]@{ Name='c1'; PublicAccess='Off' })
            Test-StorageAnonymousBlobAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            # Query Results directly: the file's comma-return Get-Fin helper does
            # not compose with Where-Object when several findings exist.
            $confirmed = @($script:State.Results | Where-Object { $_.CheckId -eq 'STORAGE-004' -and "$($_.Finding)" -like 'Storage accounts with CONFIRMED*' })
            $confirmed.Count | Should -Be 0
            $cp = @($script:State.Results | Where-Object { $_.CheckId -eq 'STORAGE-004' -and "$($_.Finding)" -like '*control-plane signal*' })
            $cp.Count | Should -Be 1
            [int]$cp[0].Count | Should -Be 1
            "$($cp[0].Severity)" | Should -Be 'LOW'
        }
    }

    Context "STORAGE-003 count semantics (TLS separated from the weak-config list)" {
        It "TLS-only issues produce a TLS finding with its own count and evidence" {
            $global:FxAccounts = @(
                (New-SA @{ MinimumTlsVersion='TLS1_0'; EnableHttpsTrafficOnly=$true; AllowCrossTenantReplication=$false })
                (New-SA @{ StorageAccountName='sa2'; MinimumTlsVersion='TLS1_2'; EnableHttpsTrafficOnly=$true; AllowCrossTenantReplication=$false })
                (New-SA @{ StorageAccountName='sa3'; MinimumTlsVersion='TLS1_2'; EnableHttpsTrafficOnly=$true; AllowCrossTenantReplication=$false })
            )
            Test-StorageAdvancedSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $tls = @(Get-MainFin 'STORAGE-003' '*minimum TLS*')
            $tls.Count | Should -Be 1
            [int]$tls[0].Count | Should -Be 1              # 1 TLS issue - NOT "3 risky"
            $tls[0].CountType | Should -Be 'UniqueResources'
            @($tls[0].Evidence).Count | Should -Be 1       # only its own matching evidence
            "$($tls[0].SummaryText)" | Should -BeLike '*1 issue(s)*across 1 unique account(s)*coverage complete.*'
        }
        It "TLS, HTTPS-only and cross-tenant are separate findings; the summary counts unique accounts" {
            $global:FxAccounts = @(
                (New-SA @{ MinimumTlsVersion=$null; EnableHttpsTrafficOnly=$false; AllowCrossTenantReplication=$true })
            )
            Test-StorageAdvancedSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $tls   = @(Get-MainFin 'STORAGE-003' '*minimum TLS*')
            $https = @(Get-MainFin 'STORAGE-003' '*HTTPS-only*')
            $ct    = @(Get-MainFin 'STORAGE-003' '*cross-tenant*')
            $tls.Count   | Should -Be 1
            $https.Count | Should -Be 1
            $ct.Count    | Should -Be 1
            # 3 issues on 1 account: summary must say "across 1 unique account(s)",
            # never "3 of 1 storage accounts risky".
            "$($tls[0].SummaryText)" | Should -BeLike '*3 issue(s)*across 1 unique account(s)*'
            @($https[0].Evidence[0].PSObject.Properties.Name) | Should -Not -Contain 'CurrentVersion'
        }
    }

    Context "STORAGE-005 exfiltration composite handles null shared key" {
        It "shared key unspecified + public enabled + no firewall -> CRITICAL FAIL" {
            $global:FxNet      = $null
            $global:FxAccounts = @(New-SA @{ PublicNetworkAccess='Enabled'; AllowSharedKeyAccess=$null })
            Test-StorageExfiltrationVectors -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'STORAGE-005' | Where-Object { "$($_.Severity)".ToUpper() -eq 'CRITICAL' -and [int]$_.Count -gt 0 })
            $m.Count | Should -BeGreaterThan 0
        }
        It "collection throws -> STORAGE-005 NotEvaluated" {
            $global:FxAccountsThrow = $true
            Test-StorageExfiltrationVectors -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'STORAGE-005').Count | Should -BeGreaterThan 0
        }
    }

    Context "Regression: known-risky fixture produces at least one FAIL" {
        It "risky account (shared key + public + allow + blob) yields a FAIL finding" {
            $global:FxNet      = [PSCustomObject]@{ DefaultAction='Allow'; IpRules=@(); Bypass=@() }
            $global:FxAccounts = @(New-SA @{ AllowSharedKeyAccess=$true; PublicNetworkAccess='Enabled'; AllowBlobPublicAccess=$true })
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            Test-StoragePublicAccess    -Subscriptions @($global:FxSub) -Exclusions @{}
            $fails = @($script:State.Results | Where-Object { [int]$_.Count -gt 0 -and "$($_.Status)".ToUpper() -eq 'FAIL' })
            $fails.Count | Should -BeGreaterThan 0
        }
    }

    Context "New-AzureMapFinding accepts a raw List[object] without throwing" {
        It "does not throw 'Argument types do not match' for a non-empty List[object]" {
            $lst = New-Object System.Collections.Generic.List[object]
            $lst.Add([PSCustomObject]@{ A = 1 })
            $lst.Add([PSCustomObject]@{ A = 2 })
            { New-AzureMapFinding -Severity 'HIGH' -Message 'raw list' -Count $lst.Count -Data $lst -Service 'Storage' -CheckId 'RAW-01' } | Should -Not -Throw
            $f = New-AzureMapFinding -Severity 'HIGH' -Message 'raw list' -Count $lst.Count -Data $lst -Service 'Storage' -CheckId 'RAW-01'
            [int]$f.EvidenceCount | Should -Be 2
            [int]$f.Count | Should -Be 2
        }
    }

    Context "Phase B1 coverage metadata (storage reference implementation)" {
        It "clean evaluation -> explicit PASS with complete, proven coverage" {
            $global:FxAccounts = @(New-SA @{ AllowSharedKeyAccess = $false })
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
            $m[0].CompleteEvaluation | Should -BeTrue
            $m[0].PartialEvaluation  | Should -BeFalse
            [int]$m[0].DiscoveredResourceCount | Should -Be 1
            [int]$m[0].EvaluatedResourceCount  | Should -Be 1
            [int]$m[0].FailedCollectionCount   | Should -Be 0
            $m[0].CollectionStatus | Should -Be 'Complete'
            $m[0].CoverageSummary  | Should -BeLike '*0 risky; coverage complete.*'
            @($m[0].SubscriptionsEvaluated) | Should -Contain 'n1'
        }

        It "zero accounts in scope -> PASS 'No storage accounts discovered in evaluated scope.'" {
            $global:FxAccounts = @()
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
            $m[0].CoverageSummary | Should -Be 'No storage accounts discovered in evaluated scope.'
            [int]$m[0].DiscoveredResourceCount | Should -Be 0
            [int]$m[0].EvaluatedResourceCount  | Should -Be 0
            $m[0].CompleteEvaluation | Should -BeTrue
        }

        It "collection throws -> NOTEVALUATED with FailedCollectionCount, never a clean PASS" {
            $global:FxAccountsThrow = $true
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            "$($m[0].Status)".ToUpper() | Should -Be 'NOTEVALUATED'
            $m[0].CollectionStatus | Should -Be 'Failed'
            [int]$m[0].FailedCollectionCount | Should -Be 1
            $m[0].CompleteEvaluation | Should -BeFalse
            $m[0].ManualValidationRequired | Should -BeTrue
            $m[0].CoverageSummary | Should -BeLike 'Could not evaluate storage accounts*'
        }

        It "one unreachable subscription among two -> PARTIAL with SubscriptionsSkipped recorded" {
            $global:FxContextFailSubs = @('S2')
            $global:FxAccounts = @(New-SA @{ AllowSharedKeyAccess = $false })
            $sub2 = [PSCustomObject]@{ Id='S2'; Name='n2'; TenantId='T1' }
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub, $sub2) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            "$($m[0].Status)".ToUpper() | Should -Be 'PARTIAL'
            $m[0].PartialEvaluation  | Should -BeTrue
            $m[0].CompleteEvaluation | Should -BeFalse
            [int]$m[0].FailedCollectionCount | Should -Be 1
            @($m[0].SubscriptionsSkipped)   | Should -Contain 'n2'
            @($m[0].SubscriptionsEvaluated) | Should -Contain 'n1'
            $m[0].Confidence | Should -Be 'Medium'
        }

        It "risky + complete coverage -> FAIL with coverage complete summary" {
            $global:FxAccounts = @(New-SA @{ AllowSharedKeyAccess = $true })
            Test-StorageSharedKeyAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-001' '*shared key*'
            "$($m[0].Status)".ToUpper() | Should -Be 'FAIL'
            [int]$m[0].Count | Should -Be 1
            $m[0].CoverageSummary | Should -BeLike '1 of 1 storage accounts risky; coverage complete.*'
            $m[0].CompleteEvaluation | Should -BeTrue
        }

        It "STORAGE-004 container enumeration failure counts as skipped resource (partial coverage)" {
            # Data-plane evaluation is strictly opt-in (Phase B3).
            $script:State.Config.IncludeDataPlane = $true
            $global:FxAccounts = @(
                (New-SA @{ AllowBlobPublicAccess = $false })
                (New-SA @{ StorageAccountName = 'sa2'; AllowBlobPublicAccess = $false })
            )
            # sa1 enumerates fine, sa2 fails: make the stub fail only once
            $global:FxContainersThrow = $false
            $script:enumCalls = 0
            function global:Get-AzStorageContainer {
                param([Parameter(ValueFromRemainingArguments)]$r)
                $script:enumCalls++
                if ($script:enumCalls -eq 2) { throw "403 AuthorizationFailed listing containers" }
                return @()
            }
            Test-StorageAnonymousBlobAccess -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = Get-MainFin 'STORAGE-004' '*anonymous/public blob*'
            "$($m[0].Status)".ToUpper() | Should -Be 'PARTIAL'
            [int]$m[0].DiscoveredResourceCount | Should -Be 2
            [int]$m[0].EvaluatedResourceCount  | Should -Be 1
            [int]$m[0].SkippedResourceCount    | Should -Be 1
            $m[0].DataPlaneRequired | Should -BeTrue
        }
    }
}
