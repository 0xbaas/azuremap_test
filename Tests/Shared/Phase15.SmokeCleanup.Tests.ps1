#==============================================================================
# AzureMap v2 - Tests/Shared/Phase15.SmokeCleanup.Tests.ps1
# B1 smoke-run cleanup regressions:
#   * IDENTITY-006 must never end PASS when collections failed (null-key guard,
#     per-resource-type failure isolation, explicit Partial/NotEvaluated).
#   * STORAGE-005/006 tolerate Az.Storage without -IncludeAccountSASPolicy
#     (Partial, not failure; everything else still evaluated).
#   * KEYVAULT-003 data-plane metadata: Forbidden -> counted coverage failure,
#     DataPlaneRequired metadata, no raw Forbidden dumps in finding messages.
#   * No repo code calls Invoke-WebRequest (PS 5.1 interactive-prompt risk).
# Mocked/local only. No live Azure, no Graph, no listKeys, no secret reads.
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
    . "$projectRoot\Future\EntraMap\Core\TenantWide.ps1"
    . "$projectRoot\Products\AzureMap\Core\InventoryCache.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Storage.ps1"
    . "$projectRoot\Products\AzureMap\Checks\StorageKey.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Identity.ps1"
    . "$projectRoot\Products\AzureMap\Checks\KeyVault.ps1"

    # --- global Az stubs (reconfigurable via $global:Fx*) ---
    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }
    function global:Get-AzContext { [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'S1' }; Account = 'test' } }

    function global:Get-AzWebApp      { param([Parameter(ValueFromRemainingArguments)]$r) if ($global:FxWebAppsThrow) { throw "403 AuthorizationFailed" }; $global:FxWebApps }
    function global:Get-AzVM          { param([Parameter(ValueFromRemainingArguments)]$r) if ($global:FxVMsThrow) { throw "403 AuthorizationFailed" }; $global:FxVMs }
    function global:Get-AzFunctionApp { param([Parameter(ValueFromRemainingArguments)]$r) if ($global:FxFuncsThrow) { throw "403 AuthorizationFailed" }; $global:FxFuncs }
    function global:Get-AzRoleAssignment { param([Parameter(ValueFromRemainingArguments)]$r) if ($global:FxRbacThrow) { throw "403 AuthorizationFailed" }; $global:FxRbac }

    function global:Get-AzStorageAccount {
        param([switch]$IncludeAccountSASPolicy, [Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxAccountsThrow) { throw "403 AuthorizationFailed listing storage accounts" }
        $global:FxAccounts
    }
    function global:Get-AzStorageAccountNetworkRuleSet { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxNet }

    function global:Get-AzKeyVault       { param([Parameter(ValueFromRemainingArguments)]$r) if ($global:FxVaultsThrow) { throw "403 AuthorizationFailed listing vaults" }; $global:FxVaults }
    function global:Get-AzKeyVaultSecret {
        param([string]$VaultName, [Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxSecretsThrow) { throw "Forbidden: caller is not authorized" }
        if ($global:FxSecretsDeny -contains $VaultName) { throw "Forbidden" }
        $global:FxSecrets
    }

    function global:New-TestApp {
        param([string]$Name, [object]$PrincipalId = '__none__')
        $o = [PSCustomObject]@{ Name = $Name; ResourceGroupName = 'rg1' }
        if ($PrincipalId -ne '__none__') {
            $o | Add-Member -NotePropertyName Identity -NotePropertyValue ([PSCustomObject]@{ PrincipalId = $PrincipalId })
        }
        $o
    }

    # Array-safe, script-scoped result lookup (no global pipeline helpers).
    function script:Get-Res {
        param([string]$CheckId)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ($item.CheckId -eq $CheckId) { $items += $item }
        }
        return ,$items
    }
    function script:Get-Main {
        param([string]$CheckId)
        # The primary coverage record carries SummaryText; side records do not.
        $items = @()
        foreach ($item in (script:Get-Res -CheckId $CheckId)) {
            if (($item.PSObject.Properties.Name -contains 'SummaryText') -and $item.SummaryText) { $items += $item }
        }
        return ,$items
    }

    $global:FxSub = [PSCustomObject]@{ Id = 'S1'; Name = 'sub1'; TenantId = 'T1' }
}

Describe "Phase15 - B1 smoke cleanup" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State = Initialize-EntraAuditState -State $script:State
        $script:State.Config.Quiet = $true
        $script:StorageSasPolicySupported = $true
        $global:FxWebApps = @(); $global:FxWebAppsThrow = $false
        $global:FxVMs     = @(); $global:FxVMsThrow     = $false
        $global:FxFuncs   = @(); $global:FxFuncsThrow   = $false
        $global:FxRbac    = @(); $global:FxRbacThrow    = $false
        $global:FxAccounts = @(); $global:FxAccountsThrow = $false
        $global:FxNet = $null
        $global:FxVaults = @(); $global:FxVaultsThrow = $false
        $global:FxSecrets = @(); $global:FxSecretsThrow = $false; $global:FxSecretsDeny = @()
    }

    Context "IDENTITY-006 identity-resource mapping" {
        It "all collections fail -> NOTEVALUATED, never PASS" {
            $global:FxWebAppsThrow = $true; $global:FxVMsThrow = $true; $global:FxFuncsThrow = $true
            Test-IdentityResourceMapping -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'IDENTITY-006')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'NOTEVALUATED'
            $m[0].CompleteEvaluation | Should -BeFalse
            $m[0].FailedCollectionCount | Should -BeGreaterThan 0
        }

        It "one resource type fails -> PARTIAL with coverage summary" {
            $global:FxWebApps = @(New-TestApp -Name 'app1')   # no identity: evaluated, not risky
            $global:FxVMsThrow = $true
            Test-IdentityResourceMapping -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'IDENTITY-006')
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'PARTIAL'
            $m[0].PartialEvaluation | Should -BeTrue
            "$($m[0].Severity)".ToUpperInvariant() | Should -Be 'INFO'
            $m[0].SummaryText | Should -Match 'skipped/failed'
        }

        It "clean run -> PASS at INFO with proven coverage" {
            $global:FxWebApps = @(New-TestApp -Name 'app1')
            Test-IdentityResourceMapping -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'IDENTITY-006')
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'PASS'
            $m[0].CompleteEvaluation | Should -BeTrue
            $m[0].EvaluatedResourceCount | Should -Be 1
        }

        It "null PrincipalId is skipped safely (no null-key crash, still PASS)" {
            $global:FxWebApps = @(New-TestApp -Name 'app-null' -PrincipalId $null)
            { Test-IdentityResourceMapping -Subscriptions @($global:FxSub) -Exclusions @{} } | Should -Not -Throw
            $m = (script:Get-Main -CheckId 'IDENTITY-006')
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'PASS'
        }

        It "risky assignment -> FAIL even when another collection also failed" {
            $global:FxWebApps = @(New-TestApp -Name 'app1' -PrincipalId '11111111-1111-1111-1111-111111111111')
            $global:FxRbac = @([PSCustomObject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; RoleDefinitionName = 'Owner'; Scope = '/subscriptions/S1' })
            $global:FxVMsThrow = $true
            Test-IdentityResourceMapping -Subscriptions @($global:FxSub) -Exclusions @{}
            $all = (script:Get-Res -CheckId 'IDENTITY-006')
            $fail = @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'FAIL' })
            $fail.Count | Should -BeGreaterThan 0
            # failure detail rides on a separate NotEvaluated record
            $ne = @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'NOTEVALUATED' })
            $ne.Count | Should -Be 1
        }
    }

    Context "STORAGE-005/006 - Az.Storage without -IncludeAccountSASPolicy" {
        BeforeEach {
            $script:StorageSasPolicySupported = $false
        }

        It "STORAGE-005 clean accounts -> PARTIAL (SAS evidence unavailable), not PASS/NOTEVALUATED" {
            $global:FxAccounts = @([PSCustomObject]@{
                StorageAccountName = 'sa1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/rg1/sa1'
                AllowSharedKeyAccess = $false; PublicNetworkAccess = 'Disabled'
            })
            Test-StorageExfiltrationVectors -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'STORAGE-005')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'PARTIAL'
            $m[0].PartialEvaluation | Should -BeTrue
            $m[0].SummaryText | Should -Match 'skipped/failed'
        }

        It "STORAGE-005 risky accounts still FAIL when SAS unsupported" {
            $global:FxAccounts = @([PSCustomObject]@{
                StorageAccountName = 'sa1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/rg1/sa1'
                # shared key unspecified + public enabled + no firewall -> critical vector
            })
            Test-StorageExfiltrationVectors -Subscriptions @($global:FxSub) -Exclusions @{}
            $all = (script:Get-Res -CheckId 'STORAGE-005')
            $fail = @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'FAIL' })
            $fail.Count | Should -BeGreaterThan 0
        }

        It "STORAGE-006 still evaluates shared key + RBAC when SAS unsupported" {
            $global:FxAccounts = @([PSCustomObject]@{
                StorageAccountName = 'sa1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/rg1/sa1'
                AllowSharedKeyAccess = $false
            })
            Test-StorageKeyExposure -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'STORAGE-006')
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'PARTIAL'
            $m[0].EvaluatedResourceCount | Should -Be 1
        }

        It "STORAGE-006 supported version keeps clean PASS" {
            $script:StorageSasPolicySupported = $true
            $global:FxAccounts = @([PSCustomObject]@{
                StorageAccountName = 'sa1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/rg1/sa1'
                AllowSharedKeyAccess = $false
            })
            Test-StorageKeyExposure -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'STORAGE-006')
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'PASS'
            $m[0].CompleteEvaluation | Should -BeTrue
        }
    }

    Context "Test-StorageSasPolicySupported - StrictMode safety (azuremap.ps1 runs Set-StrictMode 1.0)" {
        It "unset cache variable under StrictMode does not throw and detects support" {
            Remove-Variable -Name 'StorageSasPolicySupported' -Scope Script -ErrorAction SilentlyContinue
            try {
                Set-StrictMode -Version 1.0
                $threw = $false
                $result = $null
                try { $result = Test-StorageSasPolicySupported } catch { $threw = $true }
                $threw | Should -BeFalse
                # the stubbed Get-AzStorageAccount declares -IncludeAccountSASPolicy
                $result | Should -BeTrue
            } finally { Set-StrictMode -Off }
        }

        It "unset cache with cmdlet lacking the parameter fails safe to false (no throw)" {
            Remove-Variable -Name 'StorageSasPolicySupported' -Scope Script -ErrorAction SilentlyContinue
            # temporarily replace the stub with one that lacks the parameter
            function global:Get-AzStorageAccount { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxAccounts }
            try {
                Set-StrictMode -Version 1.0
                $threw = $false
                $result = $true
                try { $result = Test-StorageSasPolicySupported } catch { $threw = $true }
                $threw | Should -BeFalse
                $result | Should -BeFalse
            } finally {
                Set-StrictMode -Off
                function global:Get-AzStorageAccount {
                    param([switch]$IncludeAccountSASPolicy, [Parameter(ValueFromRemainingArguments)]$r)
                    if ($global:FxAccountsThrow) { throw "403 AuthorizationFailed listing storage accounts" }
                    $global:FxAccounts
                }
            }
        }
    }

    Context "KEYVAULT-003 secret metadata (data-plane)" {
        It "all vaults Forbidden -> NOTEVALUATED with DataPlaneRequired, not silence/PASS" {
            $global:FxVaults = @([PSCustomObject]@{ VaultName = 'kv1' })
            $global:FxSecretsThrow = $true
            Test-KeyVaultSecretsExpiry -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'KEYVAULT-003')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'NOTEVALUATED'
            $m[0].DataPlaneRequired | Should -BeTrue
            $m[0].FailedCollectionCount | Should -BeGreaterThan 0
            # sanitized: no raw Forbidden payload in the summary
            $m[0].SummaryText | Should -Not -Match 'caller'
        }

        It "one vault denied, one clean -> PARTIAL with counts" {
            $global:FxVaults = @(
                [PSCustomObject]@{ VaultName = 'kv-denied' },
                [PSCustomObject]@{ VaultName = 'kv-ok' }
            )
            $global:FxSecretsDeny = @('kv-denied')
            Test-KeyVaultSecretsExpiry -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = (script:Get-Main -CheckId 'KEYVAULT-003')
            "$($m[0].Status)".ToUpperInvariant() | Should -Be 'PARTIAL'
            $m[0].DiscoveredResourceCount | Should -Be 2
            $m[0].EvaluatedResourceCount | Should -Be 1
            $m[0].DataPlaneRequired | Should -BeTrue
        }

        It "expired secret -> FAIL" {
            $global:FxVaults = @([PSCustomObject]@{ VaultName = 'kv1' })
            $global:FxSecrets = @([PSCustomObject]@{
                Name = 'sec1'; Enabled = $true; Expires = (Get-Date).AddDays(-5)
            })
            Test-KeyVaultSecretsExpiry -Subscriptions @($global:FxSub) -Exclusions @{}
            $all = (script:Get-Res -CheckId 'KEYVAULT-003')
            $fail = @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'FAIL' })
            $fail.Count | Should -BeGreaterThan 0
        }
    }

    Context "Non-interactive runtime guard" {
        It "repo runtime code contains no Invoke-WebRequest and startup pins UseBasicParsing" {
            $repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
            # Module code only: the product entrypoints are excluded here because
            # their PS 5.1 hardening block names Invoke-WebRequest/Invoke-RestMethod
            # to pin UseBasicParsing (asserted separately below).
            $files = @()
            $files += Get-ChildItem (Join-Path $repoRoot 'Products') -Filter *.ps1 -Recurse |
                Where-Object { $_.Name -notin @('azuremap.ps1', 'entramap.ps1') }
            $files += Get-ChildItem (Join-Path $repoRoot 'Shared') -Filter *.ps1 -Recurse
            foreach ($f in $files) {
                ($f | Get-Content -Raw) | Should -Not -Match 'Invoke-WebRequest'
            }
            # azuremap.ps1 pins UseBasicParsing defaults for both web cmdlets, so any
            # module-internal web call under PS 5.1 stays non-interactive.
            $entrypoint = Get-Content (Join-Path $repoRoot 'Products\AzureMap\azuremap.ps1') -Raw
            $entrypoint | Should -Match 'Invoke-WebRequest:UseBasicParsing'
            $entrypoint | Should -Match 'Invoke-RestMethod:UseBasicParsing'
        }

        It "every Invoke-RestMethod call site passes -UseBasicParsing explicitly" {
            # Belt-and-braces over the session pin: the PS 5.1 "Script Execution
            # Risk" Y/A/N prompt must be impossible even if the pin is lost.
            $repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
            $graph = Get-Content (Join-Path $repoRoot 'Future\EntraMap\Core\Graph.ps1') -Raw
            $callCount = ([regex]::Matches($graph, 'Invoke-RestMethod')).Count
            $callCount | Should -BeGreaterThan 0
            ([regex]::Matches($graph, 'UseBasicParsing')).Count | Should -BeGreaterOrEqual $callCount
        }

        It "repo runtime code has no interactive input primitives" {
            $repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
            $files = @()
            $files += Get-ChildItem (Join-Path $repoRoot 'Products') -Filter *.ps1 -Recurse
            $files += Get-ChildItem (Join-Path $repoRoot 'Shared') -Filter *.ps1 -Recurse
            $files += Get-Item (Join-Path $repoRoot 'Products\AzureMap\azuremap.ps1')
            foreach ($f in $files) {
                ($f | Get-Content -Raw) | Should -Not -Match '\bRead-Host\b'
                ($f | Get-Content -Raw) | Should -Not -Match 'PromptForCredential'
                ($f | Get-Content -Raw) | Should -Not -Match '\$Host\.UI\.Prompt'
            }
        }
    }

    Context "Console WARN/ERROR dedupe (CLI stays summary-driven)" {
        It "identical repeats are counted and every occurrence stays in the log buffer" {
            Write-AuditLog -Message 'same failure for resource X' -Level WARN
            Write-AuditLog -Message 'same failure for resource X' -Level WARN
            Write-AuditLog -Message 'same failure for resource X' -Level WARN
            $script:State.LogConsoleSeen['WARN|same failure for resource X'] | Should -Be 3
            @($script:State.LogBuffer | Where-Object { $_ -match 'same failure for resource X' }).Count | Should -Be 3
        }

        It "console prints an identical ERROR once plus a single suppression note" {
            $script:State.Config.Quiet = $false
            $script:State.Config.DebugOutput = $true   # raw WARN/ERROR lines are debug-mode only
            Mock Write-Host {}
            Write-AuditLog -Message 'boom identical' -Level ERROR
            Write-AuditLog -Message 'boom identical' -Level ERROR
            Write-AuditLog -Message 'boom identical' -Level ERROR
            Assert-MockCalled Write-Host -Times 2 -Exactly
        }

        It "distinct messages are not deduped" {
            $script:State.Config.Quiet = $false
            $script:State.Config.DebugOutput = $true
            Mock Write-Host {}
            Write-AuditLog -Message 'failure A' -Level WARN
            Write-AuditLog -Message 'failure B' -Level WARN
            Assert-MockCalled Write-Host -Times 2 -Exactly
        }

        It "normal output never shows raw WARN/ERROR lines (log file only)" {
            $script:State.Config.Quiet = $false
            Mock Write-Host {}
            Write-AuditLog -Message 'raw boom should stay in log' -Level ERROR
            Write-AuditLog -Message 'raw warn should stay in log' -Level WARN
            Assert-MockCalled Write-Host -Times 0
            @($script:State.LogBuffer | Where-Object { $_ -match 'raw boom should stay in log' }).Count | Should -Be 1
            @($script:State.LogBuffer | Where-Object { $_ -match 'raw warn should stay in log' }).Count | Should -Be 1
        }

        It "INFO lines appear only under VerboseOutput or DebugOutput" {
            $script:State.Config.Quiet = $false
            Mock Write-Host {}
            Write-AuditLog -Message 'info line normal' -Level INFO
            Assert-MockCalled Write-Host -Times 0
            $script:State.Config.VerboseOutput = $true
            Write-AuditLog -Message 'info line verbose' -Level INFO
            Assert-MockCalled Write-Host -Times 1 -Exactly
        }
    }
}

