#==============================================================================
# Phase 9 - STORAGE-006 Storage key/SAS exposure. Mocked/local only.
# Verifies read-only behavior: no listKeys / Get-AzStorageAccountKey / data-plane.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Checks\Azure\Storage.ps1"     # New-StorageCoverage helpers used by STORAGE-006
    . "$projectRoot\Checks\Azure\StorageKey.ps1"

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet = $true
    $script:Subs = @([PSCustomObject]@{ Id='s1'; Name='sub1' })

    function Get-AzStorageAccount     { param([Parameter(ValueFromRemainingArguments)]$r) }
    function Get-AzRoleAssignment     { param([Parameter(ValueFromRemainingArguments)]$r) }
    function Get-AzStorageAccountKey  { param([Parameter(ValueFromRemainingArguments)]$r) }

    function New-SA {
        param([string]$Name, [object]$Ask='__none__', [int]$SasDays=0)
        $o = [PSCustomObject]@{ StorageAccountName=$Name; ResourceGroupName='rg'; Id="/subscriptions/s1/rg/$Name" }
        if ($Ask -ne '__none__') { $o | Add-Member -NotePropertyName AllowSharedKeyAccess -NotePropertyValue $Ask }
        if ($SasDays -gt 0) { $o | Add-Member -NotePropertyName AccountSasPolicy -NotePropertyValue ([PSCustomObject]@{ SasExpirationPeriod = (New-TimeSpan -Days $SasDays) }) }
        $o
    }
}

Describe "STORAGE-006 Storage key/SAS exposure" {
    BeforeEach {
        $script:State.Results.Clear()
        # Tests emulate an Az.Storage version WITH -IncludeAccountSASPolicy support
        # (unsupported-version behavior is covered in Phase15).
        $script:StorageSasPolicySupported = $true
        Mock Set-SubscriptionContext { $true }
        Mock Get-AzRoleAssignment { @() }
        Mock Get-AzStorageAccountKey { @() }
    }

    It "FAILs when AllowSharedKeyAccess is true" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $true) ) }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        Should -Not -Invoke Get-AzStorageAccountKey
    }

    It "FAILs when AllowSharedKeyAccess property is absent (unspecified)" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1') ) }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'FAIL'
    }

    It "FAILs when the account SAS policy exceeds 30 days" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false -SasDays 45) ) }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Risk) -join ' ') | Should -BeLike '*SAS expiration*'
    }

    It "FAILs when a key-capable role is assigned" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false) ) }
        Mock Get-AzRoleAssignment { @( [PSCustomObject]@{ RoleDefinitionName='Owner'; DisplayName='Someone' } ) }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Risk) -join ' ') | Should -BeLike '*retrieve/manage storage account keys*'
    }

    It "PASSes when shared key disabled and no key-capable roles" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false) ) }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'PASS'
        Should -Not -Invoke Get-AzStorageAccountKey
    }

    It "is NotEvaluated when storage account collection fails" {
        Mock Get-AzStorageAccount { throw "403" }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
        $script:State.Results[-1].CollectionStatus | Should -Be 'Failed'
        $script:State.Results[-1].FailedCollectionCount | Should -Be 1
        $script:State.Results[-1].CompleteEvaluation | Should -BeFalse
    }

    It "registers STORAGE-006" {
        $script:State.CheckRegistry.Clear()
        Register-AzureStorageKeyChecks
        ($script:State.CheckRegistry.CheckId) | Should -Contain 'STORAGE-006'
        ($script:State.CheckRegistry | Where-Object CheckId -eq 'STORAGE-006').Function | Should -BeOfType [scriptblock]
    }

    # ---- Phase B1 coverage contract ----

    It "PASSes at INFO with DiscoveredResourceCount=0 when the scope is proven empty" {
        Mock Get-AzStorageAccount { @() }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $r = $script:State.Results[-1]
        $r.Status | Should -Be 'PASS'
        $r.Severity | Should -Be 'INFO'
        $r.DiscoveredResourceCount | Should -Be 0
        $r.EvaluatedResourceCount | Should -Be 0
        $r.CompleteEvaluation | Should -BeTrue
        $r.SummaryText | Should -BeLike 'No storage accounts discovered in evaluated scope.*'
    }

    It "reports proven coverage on a clean PASS" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false) ) }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $r = $script:State.Results[-1]
        $r.Status | Should -Be 'PASS'
        $r.EvaluatedResourceCount | Should -Be 1
        $r.CompleteEvaluation | Should -BeTrue
        $r.SummaryText | Should -BeLike '*1 storage accounts evaluated; 0 risky; coverage complete.*'
    }

    It "is PARTIAL when key-capable RBAC cannot be read" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false) ) }
        Mock Get-AzRoleAssignment { throw "403" }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $r = $script:State.Results[-1]
        $r.Status | Should -Be 'PARTIAL'
        $r.PartialEvaluation | Should -BeTrue
        $r.SkippedResourceCount | Should -Be 1
        $r.ManualValidationRequired | Should -BeTrue
    }
}
