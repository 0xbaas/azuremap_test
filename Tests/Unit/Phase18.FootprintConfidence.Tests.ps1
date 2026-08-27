#==============================================================================
# AzureMap v2 - Tests/Unit/Phase18.FootprintConfidence.Tests.ps1
# Footprint scoping/confidence: ARG must cover ALL in-scope subscriptions,
# partial/low-confidence footprints must never produce NOTAPPLICABLE,
# inventory-only checks never display plain PASS, subscription-scope preflight
# abort, and legacy section banners hidden in normal output.
# Mocked/local only. No Azure, no Graph, no data-plane.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\Retry.ps1"
    . "$projectRoot\Core\RunStatus.ps1"
    . "$projectRoot\Core\Footprint.ps1"
    . "$projectRoot\Core\Preflight.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Core\Console.ps1"

    function global:Get-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) $null }

    function script:New-Sub {
        param([string]$Id, [string]$Name)
        [PSCustomObject]@{ Id = $Id; Name = $Name; TenantId = 't-1'; SubscriptionId = $Id }
    }

    function script:New-Fp {
        param([hashtable]$TypeCounts, [string]$Coverage = 'Complete', [string]$Confidence = 'High')
        [PSCustomObject]@{
            Subscriptions = 3; ResourceGroups = 4; Resources = 10
            ResourceTypeCount = $TypeCounts.Count; RegionCount = 1; Regions = @('westeurope')
            TopTypes = @(); TypeCounts = $TypeCounts; Source = 'ResourceGraph'
            SubscriptionsExpected = 3; SubscriptionsCovered = 3
            CoverageStatus = $Coverage; Confidence = $Confidence; Note = ''
        }
    }
}

Describe "Get-EnvironmentFootprint ARG scoping" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:ArgSubscriptionParam = $null
        $script:CtxHistory = @()

        function global:Set-AzContext {
            param([string]$SubscriptionId, [Parameter(ValueFromRemainingArguments)]$r)
            $script:CtxHistory += $SubscriptionId
        }
    }

    It "passes every in-scope subscription ID to Resource Graph" {
        function global:Search-AzGraph {
            param([string]$Query, [string[]]$Subscription, [Parameter(ValueFromRemainingArguments)]$r)
            $script:ArgSubscriptionParam = @($Subscription)
            if ($Query -match 'project subscriptionId') {
                return @($Subscription | ForEach-Object { [PSCustomObject]@{ subscriptionId = $_ } })
            }
            if ($Query -match 'resourcegroups') { return @([PSCustomObject]@{ Count = 9 }) }
            if ($Query -match 'by location')    { return @([PSCustomObject]@{ location = 'westeurope'; Count = 5 }) }
            if ($Query -match 'by type')        { return @([PSCustomObject]@{ type = 'microsoft.storage/storageaccounts'; Count = 7 }, [PSCustomObject]@{ type = 'microsoft.keyvault/vaults'; Count = 3 }) }
            return @()
        }
        $subs = @((script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000001' 's1'),
                  (script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000002' 's2'),
                  (script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000003' 's3'))
        $fp = Get-EnvironmentFootprint -Subscriptions $subs
        $script:ArgSubscriptionParam.Count | Should -Be 3
        $script:ArgSubscriptionParam | Should -Contain 'aaaaaaaa-0000-0000-0000-000000000002'
        $fp.Source | Should -Be 'ResourceGraph'
        $fp.CoverageStatus | Should -Be 'Complete'
        $fp.Confidence | Should -Be 'High'
    }

    It "ARG data from only 1 of 3 subscriptions yields Partial/Low and ARM-merges the rest" {
        function global:Search-AzGraph {
            param([string]$Query, [string[]]$Subscription, [Parameter(ValueFromRemainingArguments)]$r)
            if ($Query -match 'project subscriptionId') {
                # ARG only covered the first subscription (e.g. wrong tenant scope).
                return @([PSCustomObject]@{ subscriptionId = 'aaaaaaaa-0000-0000-0000-000000000001' })
            }
            if ($Query -match 'resourcegroups') { return @([PSCustomObject]@{ Count = 1 }) }
            if ($Query -match 'by location')    { return @([PSCustomObject]@{ location = 'westeurope'; Count = 80 }) }
            if ($Query -match 'by type')        { return @([PSCustomObject]@{ type = 'microsoft.network/privatednszones/virtualnetworklinks'; Count = 80 }) }
            return @()
        }
        function global:Get-AzResource {
            param([Parameter(ValueFromRemainingArguments)]$r)
            return @([PSCustomObject]@{ ResourceType = 'Microsoft.Storage/storageAccounts'; Location = 'westeurope'; ResourceGroupName = 'rg-x' })
        }
        $subs = @((script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000001' 's1'),
                  (script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000002' 's2'),
                  (script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000003' 's3'))
        $fp = Get-EnvironmentFootprint -Subscriptions $subs
        # fallback ran for the two uncovered subscriptions
        $script:CtxHistory | Should -Contain 'aaaaaaaa-0000-0000-0000-000000000002'
        $script:CtxHistory | Should -Contain 'aaaaaaaa-0000-0000-0000-000000000003'
        # merged evidence: storage accounts discovered via ARM fallback
        $fp.TypeCounts.ContainsKey('microsoft.storage/storageaccounts') | Should -BeTrue
        $fp.TypeCounts['microsoft.storage/storageaccounts'] | Should -Be 2
        $fp.Source | Should -Be 'ResourceGraph+Get-AzResource'
        $fp.CoverageStatus | Should -Be 'Complete'   # all 3 subs covered after merge
        $fp.Confidence | Should -Be 'High'
    }

    It "stays Partial/Low when uncovered subscriptions also fail the ARM fallback" {
        function global:Search-AzGraph {
            param([string]$Query, [string[]]$Subscription, [Parameter(ValueFromRemainingArguments)]$r)
            if ($Query -match 'project subscriptionId') { return @([PSCustomObject]@{ subscriptionId = 'aaaaaaaa-0000-0000-0000-000000000001' }) }
            if ($Query -match 'resourcegroups') { return @([PSCustomObject]@{ Count = 1 }) }
            if ($Query -match 'by location')    { return @([PSCustomObject]@{ location = 'westeurope'; Count = 80 }) }
            if ($Query -match 'by type')        { return @([PSCustomObject]@{ type = 'microsoft.network/privatednszones/virtualnetworklinks'; Count = 80 }) }
            return @()
        }
        function global:Get-AzResource { param([Parameter(ValueFromRemainingArguments)]$r) throw "denied" }
        $subs = @((script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000001' 's1'),
                  (script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000002' 's2'),
                  (script:New-Sub 'aaaaaaaa-0000-0000-0000-000000000003' 's3'))
        $fp = Get-EnvironmentFootprint -Subscriptions $subs
        $fp.CoverageStatus | Should -Be 'Partial'
        $fp.Confidence | Should -Be 'Low'
        $fp.SubscriptionsCovered | Should -Be 1
        $fp.SubscriptionsExpected | Should -Be 3
        $fp.Note | Should -Match 'applicability gating is disabled'
    }

    It "flags a suspiciously narrow footprint as Low confidence" {
        function global:Search-AzGraph {
            param([string]$Query, [string[]]$Subscription, [Parameter(ValueFromRemainingArguments)]$r)
            if ($Query -match 'project subscriptionId') {
                return @($Subscription | ForEach-Object { [PSCustomObject]@{ subscriptionId = $_ } })
            }
            if ($Query -match 'resourcegroups') { return @([PSCustomObject]@{ Count = 1 }) }
            if ($Query -match 'by location')    { return @([PSCustomObject]@{ location = 'westeurope'; Count = 80 }) }
            if ($Query -match 'by type')        { return @([PSCustomObject]@{ type = 'microsoft.network/privatednszones/virtualnetworklinks'; Count = 80 }) }
            return @()
        }
        $subs = 1..5 | ForEach-Object { script:New-Sub "aaaaaaaa-0000-0000-0000-00000000000$_" "s$_" }
        $fp = Get-EnvironmentFootprint -Subscriptions $subs
        $fp.CoverageStatus | Should -Be 'Complete'
        $fp.Confidence | Should -Be 'Low'
        $fp.Note | Should -Match 'suspiciously narrow'
    }
}

Describe "Get-CheckApplicability confidence gating" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $check = [PSCustomObject]@{ CheckId = 'STORAGE-001'; Name = 'x'; RequiredResourceTypes = @('microsoft.storage/storageaccounts'); AlwaysRun = $false }
        $script:StorageCheck = $check
    }

    It "high-confidence footprint without the type -> NotApplicable" {
        $script:State.Footprint = script:New-Fp -TypeCounts @{ 'microsoft.keyvault/vaults' = 4 }
        $r = Get-CheckApplicability -Check $script:StorageCheck
        $r.Applicable | Should -BeFalse
        $r.Reason | Should -Match 'storageaccounts'
    }

    It "low-confidence (partial) footprint without the type -> still Applicable (fail-safe)" {
        $script:State.Footprint = script:New-Fp -TypeCounts @{ 'microsoft.network/privatednszones/virtualnetworklinks' = 80 } -Coverage 'Partial' -Confidence 'Low'
        $r = Get-CheckApplicability -Check $script:StorageCheck
        $r.Applicable | Should -BeTrue
    }

    It "high-confidence footprint with storageaccounts -> storage check applicable" {
        $script:State.Footprint = script:New-Fp -TypeCounts @{ 'microsoft.storage/storageaccounts' = 60 }
        (Get-CheckApplicability -Check $script:StorageCheck).Applicable | Should -BeTrue
    }

    It "high-confidence footprint with vaults -> keyvault check applicable" {
        $script:State.Footprint = script:New-Fp -TypeCounts @{ 'microsoft.keyvault/vaults' = 41 }
        $kv = [PSCustomObject]@{ CheckId = 'KEYVAULT-002'; Name = 'x'; RequiredResourceTypes = @('microsoft.keyvault/vaults'); AlwaysRun = $false }
        (Get-CheckApplicability -Check $kv).Applicable | Should -BeTrue
    }

    It "narrow low-confidence footprint (complete but suspicious) -> still Applicable" {
        $script:State.Footprint = script:New-Fp -TypeCounts @{ 'microsoft.network/privatednszones/virtualnetworklinks' = 80 } -Coverage 'Complete' -Confidence 'Low'
        (Get-CheckApplicability -Check $script:StorageCheck).Applicable | Should -BeTrue
    }
}

Describe "Test-AzureSubscriptionScope preflight guard" {

    It "no subscriptions and not Entra-only -> not usable with actionable message" {
        $r = Test-AzureSubscriptionScope -Subscriptions @()
        $r.Usable | Should -BeFalse
        $r.Message | Should -Match 'Connect-AzAccount'
    }

    It "subscriptions present -> usable" {
        $r = Test-AzureSubscriptionScope -Subscriptions @((script:New-Sub 'x' 's1'))
        $r.Usable | Should -BeTrue
    }

    It "Entra-only run without subscriptions -> usable" {
        $r = Test-AzureSubscriptionScope -Subscriptions @() -EntraOnly
        $r.Usable | Should -BeTrue
    }
}

Describe "Inventory-only checks never display plain PASS" {

    It "all-inventory findings resolve to Inventory" {
        $findings = @(
            [PSCustomObject]@{ Status = 'PASS'; Count = 70; Severity = 'INFO'; IsInventoryOnly = $true }
        )
        Resolve-CheckStatus -ProducedFindings $findings | Should -Be 'Inventory'
    }

    It "inventory mixed with a real finding resolves to Fail" {
        $findings = @(
            [PSCustomObject]@{ Status = 'PASS'; Count = 70; Severity = 'INFO'; IsInventoryOnly = $true },
            [PSCustomObject]@{ Status = 'FAIL'; Count = 2; Severity = 'HIGH'; IsInventoryOnly = $false }
        )
        Resolve-CheckStatus -ProducedFindings $findings | Should -Be 'Fail'
    }

    It "clean empty record without inventory flag still resolves to Pass" {
        $findings = @(
            [PSCustomObject]@{ Status = 'PASS'; Count = 0; Severity = 'INFO'; IsInventoryOnly = $false }
        )
        Resolve-CheckStatus -ProducedFindings $findings | Should -Be 'Pass'
    }

    It "status line shows INVENTORY, not PASS" {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
        $script:State.Config.NoColor = $true
        $script:captured = New-Object System.Collections.Generic.List[string]
        Mock Write-Host { param($Object) [void]$script:captured.Add("$Object") }
        $check  = [PSCustomObject]@{ CheckId = 'AZURE-EXPOSURE-001'; Name = 'Public Exposure Inventory' }
        $record = [PSCustomObject]@{ Status = 'Inventory'; SummaryText = '70 public endpoints inventoried' }
        Write-CheckStatusLine -Index 1 -Total 41 -Check $check -Record $record
        $line = ($script:captured -join '')
        $line | Should -Match '\bINVENTORY\b'
        $line | Should -Not -Match '\bPASS\b'
    }

    It "run diagnostics counts Inventory separately from Passed" {
        $script:State = Initialize-AuditState
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId = 'E-1'; Name = 'x'; Status = 'Inventory' })
        $script:State.ExecutedChecks.Add([PSCustomObject]@{ CheckId = 'P-1'; Name = 'y'; Status = 'Pass' })
        $diag = Get-RunDiagnostics
        $diag.Inventory | Should -Be 1
        $diag.Passed | Should -Be 1
    }
}

Describe "Legacy section banners are hidden in normal output" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $false
    }

    It "no banner without VerboseOutput" {
        $script:State.Config.VerboseOutput = $false
        Mock Write-Host {}
        Write-Section -Title 'APPLICATION CREDENTIALS - LONG VALIDITY PERIODS'
        Assert-MockCalled Write-Host -Times 0 -ParameterFilter { "$Object" -match 'LONG VALIDITY' }
    }

    It "banner stays hidden under VerboseOutput (normal product output)" {
        $script:State.Config.VerboseOutput = $true
        Mock Write-Host {}
        Write-Section -Title 'APPLICATION CREDENTIALS - LONG VALIDITY PERIODS'
        Assert-MockCalled Write-Host -Times 0 -ParameterFilter { "$Object" -match 'LONG VALIDITY' }
    }

    It "banner renders under DebugOutput (legacy diagnostic mode)" {
        $script:State.Config.DebugOutput = $true
        Mock Write-Host {}
        Write-Section -Title 'APPLICATION CREDENTIALS - LONG VALIDITY PERIODS'
        Assert-MockCalled Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'LONG VALIDITY' }
    }
}
