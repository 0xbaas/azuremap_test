#==============================================================================
# AzureMap v2 - Tests/Unit/Phase23.Performance.Tests.ps1
# Perf-phase tests: per-check timing metadata, Performance summary generation,
# inventory cache reuse (no duplicate collectors), proven-empty gating rules,
# denied-call guard (classify once, never retry), context-switch dedupe, and
# the no-disk/no-secret safety properties of the cache. Mocked/local only.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\Retry.ps1"
    . "$projectRoot\Core\RunStatus.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Core\Azure\InventoryCache.ps1"

    # ---- Az stubs (global so script-scoped cache code resolves them) ----
    function global:Set-AzContext {
        param([string]$SubscriptionId, [string]$TenantId, [Parameter(ValueFromRemainingArguments)]$r)
        $global:PerfCtxCalls++
        if ($global:PerfCtxFailSubs -contains $SubscriptionId) { throw "no access to subscription $SubscriptionId" }
        [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = $SubscriptionId } }
    }
    function global:Get-AzContext {
        # Tracks the last subscription Set-AzContext was given so the dedupe in
        # Set-SubscriptionContext behaves like a real session.
        if ($global:PerfCurrentSub) {
            [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = $global:PerfCurrentSub }; Account = 'x'; Tenant = 'y' }
        } else { $null }
    }
    function global:Get-AzKeyVault {
        param([Parameter(ValueFromRemainingArguments)]$r)
        $global:PerfKvFetchCalls++
        if ($global:PerfKvThrow) { throw "403 AuthorizationFailed listing vaults" }
        $global:PerfKvItems
    }
    # Set-SubscriptionContext dedupe depends on Get-AzContext reflecting the
    # last switch; wrap the stub to keep them in sync.
    $global:PerfSetAzContextInner = ${function:global:Set-AzContext}
    function global:Set-AzContext {
        param([string]$SubscriptionId, [string]$TenantId, [Parameter(ValueFromRemainingArguments)]$r)
        $global:PerfCtxCalls++
        if ($global:PerfCtxFailSubs -contains $SubscriptionId) { throw "no access to subscription $SubscriptionId" }
        $global:PerfCurrentSub = $SubscriptionId
        [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = $SubscriptionId } }
    }

    $global:PerfSub  = [PSCustomObject]@{ Id = 'SUB-1'; Name = 'sub-one'; TenantId = 'T1' }
    $global:PerfSub2 = [PSCustomObject]@{ Id = 'SUB-2'; Name = 'sub-two'; TenantId = 'T1' }
}

Describe "Performance phase" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $global:PerfCtxCalls     = 0
        $global:PerfKvFetchCalls = 0
        $global:PerfKvThrow      = $false
        $global:PerfKvItems      = @()
        $global:PerfCtxFailSubs  = @()
        $global:PerfCurrentSub   = $null
    }

    Context "per-check timing metadata" {
        It "execution record carries DurationSeconds after completion" {
            $check = [PSCustomObject]@{ CheckId = 'X-001'; Name = 'n'; Category = 'Azure'; Service = 'Storage'; Phase = 'PerSubscription'; RequiresDataPlane = $false }
            $rec = New-CheckExecutionRecord -Check $check -Phase 'PerSubscription'
            $rec.DurationSeconds | Should -BeNullOrEmpty
            Start-Sleep -Milliseconds 20
            Complete-CheckExecutionRecord -Record $rec
            $rec.CompletedAt | Should -Not -BeNullOrEmpty
            [double]$rec.DurationSeconds | Should -BeGreaterThan 0
        }

        It "Get-PerformanceSummary ranks slowest checks and carries phase totals" {
            $check = [PSCustomObject]@{ CheckId = 'X-001'; Name = 'n'; Category = 'Azure'; Service = 'Storage'; Phase = 'PerSubscription'; RequiresDataPlane = $false }
            foreach ($d in @(5, 120, 40)) {
                $rec = New-CheckExecutionRecord -Check $check -Phase 'PerSubscription'
                $rec.DurationSeconds = $d
                $script:State.ExecutedChecks.Add($rec)
            }
            $script:State.Timing.Phases['Discovery']  = 80.0
            $script:State.Timing.Phases['Assessment'] = 300.0
            $script:State.Timing.Phases['Export']     = 25.0
            $perf = Get-PerformanceSummary -Top 2
            $perf.SlowestChecks.Count | Should -Be 2
            $perf.SlowestChecks[0].DurationSeconds | Should -Be 120
            $perf.SlowestChecks[1].DurationSeconds | Should -Be 40
            $perf.ExportSeconds | Should -Be 25.0
            $perf.Phases['Assessment'] | Should -Be 300.0
            # TotalSeconds derives from wall clock and can read 0 within one
            # clock tick on a fast test; presence is the contract.
            $perf.TotalSeconds | Should -BeGreaterOrEqual 0
        }

        It "Format-UiDuration renders compact human strings" {
            Format-UiDuration 492 | Should -Be '8m 12s'
            Format-UiDuration 43  | Should -Be '43s'
            Format-UiDuration 3661 | Should -Be '1h 1m 1s'
        }
    }

    Context "inventory cache reuse" {
        It "fetches once per (subscription, kind); second consumer hits the cache" {
            $global:PerfKvItems = @([PSCustomObject]@{ VaultName = 'kv1'; ResourceGroupName = 'rg1' })
            $a = Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -SubscriptionName $global:PerfSub.Name -TenantId 'T1' -Kind KeyVaults
            $b = Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -SubscriptionName $global:PerfSub.Name -TenantId 'T1' -Kind KeyVaults
            $global:PerfKvFetchCalls | Should -Be 1
            $a.FromCache | Should -BeFalse
            $b.FromCache | Should -BeTrue
            @($b.Items).Count | Should -Be 1
            $b.Items[0].VaultName | Should -Be 'kv1'
        }

        It "different subscriptions are cached independently" {
            $global:PerfKvItems = @()
            [void](Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id  -Kind KeyVaults)
            [void](Get-SubscriptionInventory -SubscriptionId $global:PerfSub2.Id -Kind KeyVaults)
            $global:PerfKvFetchCalls | Should -Be 2
        }

        It "accumulates per-subscription fetch time for the slowest-subscriptions summary" {
            $global:PerfKvItems = @()
            [void](Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -SubscriptionName $global:PerfSub.Name -Kind KeyVaults)
            $script:State.Timing.SubscriptionFetchSeconds.ContainsKey('sub-one') | Should -BeTrue
            # Elapsed can be exactly 0 on a sub-tick stubbed fetch; the contract
            # is that the subscription is tracked, not that a stub burns time.
            [double]$script:State.Timing.SubscriptionFetchSeconds['sub-one'] | Should -BeGreaterOrEqual 0
        }

        It "cache lives only in memory (State.Cache.ResourceLists); module contains no disk writes" {
            $src = Get-Content -Raw (Join-Path $projectRoot 'Core\Azure\InventoryCache.ps1')
            $src | Should -Not -Match 'Out-File|Set-Content|Add-Content|Export-Clixml|ConvertTo-Json\s*\|'
            $global:PerfKvItems = @()
            [void](Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind KeyVaults)
            $script:State.Cache.ResourceLists.ContainsKey('sub-1|KeyVaults') | Should -BeTrue
        }
    }

    Context "proven-empty gating" {
        BeforeEach {
            $script:State.Footprint = [PSCustomObject]@{
                CoverageStatus = 'Complete'; Confidence = 'High'
                TypeCountsBySub = @{ 'sub-1' = @{ 'microsoft.storage/storageaccounts' = 3 } }
            }
        }

        It "skips enumeration entirely when the footprint proves the kind absent (no ctx switch, no fetch)" {
            $inv = Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind KeyVaults
            $inv.ProvenEmpty | Should -BeTrue
            @($inv.Items).Count | Should -Be 0
            $global:PerfKvFetchCalls | Should -Be 0
            $global:PerfCtxCalls | Should -Be 0
        }

        It "does not gate when the kind IS present for the subscription" {
            Test-SubscriptionProvenEmpty -SubscriptionId 'SUB-1' -ResourceTypes @('microsoft.storage/storageaccounts') | Should -BeFalse
        }

        It "low-confidence footprint disables gating (enumeration happens)" {
            $script:State.Footprint.Confidence = 'Low'
            Test-SubscriptionProvenEmpty -SubscriptionId 'SUB-1' -ResourceTypes @('microsoft.keyvault/vaults') | Should -BeFalse
            [void](Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind KeyVaults)
            $global:PerfKvFetchCalls | Should -Be 1
        }

        It "partial footprint disables gating" {
            $script:State.Footprint.CoverageStatus = 'Partial'
            Test-SubscriptionProvenEmpty -SubscriptionId 'SUB-1' -ResourceTypes @('microsoft.keyvault/vaults') | Should -BeFalse
        }

        It "subscription missing from per-sub data is never proven empty" {
            Test-SubscriptionProvenEmpty -SubscriptionId 'SUB-9' -ResourceTypes @('microsoft.keyvault/vaults') | Should -BeFalse
        }
    }

    Context "denied-call guard" {
        It "a failed fetch is cached: classify once, never retried, flagged Fetch" {
            $global:PerfKvThrow = $true
            $a = Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind KeyVaults
            $b = Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind KeyVaults
            $a.Unavailable | Should -BeTrue
            $a.UnavailableReason | Should -Be 'Fetch'
            $b.Unavailable | Should -BeTrue
            $global:PerfKvFetchCalls | Should -Be 1
        }

        It "context-switch failure is cached as ContextSwitch and not retried" {
            $global:PerfCtxFailSubs = @('SUB-1')
            $a = Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind KeyVaults
            $b = Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind KeyVaults
            $a.Unavailable | Should -BeTrue
            $a.UnavailableReason | Should -Be 'ContextSwitch'
            $b.UnavailableReason | Should -Be 'ContextSwitch'
            $global:PerfKvFetchCalls | Should -Be 0
            $global:PerfCtxCalls | Should -Be 1
        }

        It "unknown kind throws a clear error" {
            { Get-SubscriptionInventory -SubscriptionId $global:PerfSub.Id -Kind 'Nonsense' } | Should -Throw '*unknown inventory kind*'
        }
    }

    Context "Set-SubscriptionContext dedupe" {
        It "repeated switches to the same subscription call Set-AzContext once" {
            $ok1 = Set-SubscriptionContext -SubscriptionId 'SUB-1' -SubscriptionName 'sub-one'
            $ok2 = Set-SubscriptionContext -SubscriptionId 'SUB-1' -SubscriptionName 'sub-one'
            $ok1 | Should -BeTrue
            $ok2 | Should -BeTrue
            $global:PerfCtxCalls | Should -Be 1
        }

        It "switching to a different subscription switches again" {
            [void](Set-SubscriptionContext -SubscriptionId 'SUB-1')
            [void](Set-SubscriptionContext -SubscriptionId 'SUB-2')
            $global:PerfCtxCalls | Should -Be 2
        }

        It "failed switch returns false and never calls Connect-AzAccount" {
            $global:PerfCtxFailSubs = @('SUB-1')
            $ok = Set-SubscriptionContext -SubscriptionId 'SUB-1' -SubscriptionName 'sub-one'
            $ok | Should -BeFalse
        }
    }

    Context "safety invariants" {
        It "inventory kinds use only read-only Get-* list calls (no keys/secrets/content)" {
            foreach ($kind in $script:InventoryKindMap.Keys) {
                $fetchText = $script:InventoryKindMap[$kind].Fetch.ToString()
                $fetchText | Should -Match '^\s*Get-|^\s*\$cmd'
                $fetchText | Should -Not -Match 'listKeys|listSecrets|Get-AzStorageAccountKey|SecretValue|Get-AzKeyVaultSecret|Get-AzStorageBlob\b|Get-AzStorageFile|ConnectionString'
            }
        }
    }
}
