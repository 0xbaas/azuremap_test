#==============================================================================
# Phase 9 - STORAGE-006 Storage key/SAS exposure. Mocked/local only.
# Verifies read-only behavior: no listKeys / Get-AzStorageAccountKey / data-plane.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Products\AzureMap\Core\InventoryCache.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Storage.ps1"     # New-StorageCoverage helpers used by STORAGE-006
    . "$projectRoot\Products\AzureMap\Checks\StorageKey.ps1"

    $script:State = Initialize-AzureAuditState
    $script:State.Config.Quiet = $true
    $script:Subs = @([PSCustomObject]@{ Id='s1'; Name='sub1' })

    function Get-AzStorageAccount     { param([Parameter(ValueFromRemainingArguments)]$r) }
    function Get-AzStorageAccountKey  { param([Parameter(ValueFromRemainingArguments)]$r) }

    # The RBAC helper now reads ARM REST (Invoke-AzRestMethod), never
    # Get-AzRoleAssignment (its Graph principal enrichment fails under ARM-only
    # auth). This stub serves both RBAC endpoints from $script:Fx* fixtures.
    function Invoke-AzRestMethod {
        param([string]$Path, [string]$Method, [Parameter(ValueFromRemainingArguments)]$r)
        if ($script:FxRbacThrow) { throw "403" }
        if ("$Path" -match 'roleDefinitions') {
            return [PSCustomObject]@{ StatusCode = 200; Content = (@{ value = @($script:FxRoleDefs) } | ConvertTo-Json -Depth 6) }
        }
        if ($null -ne $script:FxRbacAssignCalls) { [void]$script:FxRbacAssignCalls.Add("$Path") }
        [PSCustomObject]@{ StatusCode = 200; Content = (@{ value = @($script:FxRoleAssignments) } | ConvertTo-Json -Depth 6) }
    }

    # Converts old-shape assignment fixtures (@{ RoleDefinitionName; Scope; ... })
    # into ARM REST-shaped assignment/definition responses, deriving a
    # deterministic role-definition GUID per role name (MD5 of the name).
    function Set-FxRbac {
        param([array]$Assignments)
        $guidFor = @{}
        $defs = @()
        $ras  = @()
        $i = 0
        foreach ($a in @($Assignments)) {
            $i++
            $n = "$($a.RoleDefinitionName)"
            if (-not $guidFor.ContainsKey($n)) {
                $md5 = [System.Security.Cryptography.MD5]::Create()
                try { $guidFor[$n] = ([guid]$md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($n))).Guid }
                finally { $md5.Dispose() }
                $defs += [PSCustomObject]@{ id = "/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/$($guidFor[$n])"; properties = [PSCustomObject]@{ roleName = $n } }
            }
            $ras += [PSCustomObject]@{
                id = "/subscriptions/s1/providers/Microsoft.Authorization/roleAssignments/ra-$i"
                properties = [PSCustomObject]@{
                    scope            = $a.Scope
                    roleDefinitionId = "/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/$($guidFor[$n])"
                    principalId      = $a.ObjectId
                    principalType    = $a.ObjectType
                }
            }
        }
        $script:FxRoleAssignments = $ras
        $script:FxRoleDefs        = $defs
    }

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
        # Fresh state per test: re-initializing also resets the shared per-run
        # inventory cache, so each test's Get-AzStorageAccount mock is enumerated.
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $script:State.Results.Clear()
        # Tests emulate an Az.Storage version WITH -IncludeAccountSASPolicy support
        # (unsupported-version behavior is covered in Phase15).
        $script:StorageSasPolicySupported = $true
        $script:FxRbacThrow = $false
        $script:FxRbacAssignCalls = $null
        Set-FxRbac @()
        Mock Set-SubscriptionContext { $true }
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
        # The RBAC data comes from the cached subscription-scope ARM REST read, so
        # the assignment carries its Scope. Effective at the account: scope == account id.
        Set-FxRbac @( [PSCustomObject]@{ RoleDefinitionName='Owner'; Scope='/subscriptions/s1/rg/sa1' } )
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Risk) -join ' ') | Should -BeLike '*retrieve/manage storage account keys*'
    }

    It "FAILs when a key-capable role is inherited from the subscription scope" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false) ) }
        Set-FxRbac @( [PSCustomObject]@{ RoleDefinitionName='Contributor'; Scope='/subscriptions/s1' } )
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Risk) -join ' ') | Should -BeLike '*retrieve/manage storage account keys*'
    }

    It "does NOT flag key-capable roles assigned on an unrelated scope" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false) ) }
        Set-FxRbac @( [PSCustomObject]@{ RoleDefinitionName='Owner'; Scope='/subscriptions/s1/rg/other-sa' } )
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'PASS'
    }

    It "makes ONE cached subscription-scope RBAC read regardless of account count (no per-account RBAC fetch)" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false), (New-SA -Name 'sa2' -Ask $false), (New-SA -Name 'sa3' -Ask $false) ) }
        $script:FxRbacAssignCalls = New-Object System.Collections.Generic.List[string]
        Test-StorageKeyExposure -Subscriptions $script:Subs
        # Regression pin for the StorageKey.ps1 perf+coverage fix: the old code
        # made one raw uncached RBAC read PER account (documented 40-78s/call
        # stalls under Azure-only auth).
        $script:FxRbacAssignCalls.Count | Should -Be 1
        $script:FxRbacAssignCalls[0] | Should -BeLike '/subscriptions/s1/providers/Microsoft.Authorization/roleAssignments*'
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
        $script:FxRbacThrow = $true
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $r = $script:State.Results[-1]
        $r.Status | Should -Be 'PARTIAL'
        $r.PartialEvaluation | Should -BeTrue
        $r.SkippedResourceCount | Should -Be 1
        $r.ManualValidationRequired | Should -BeTrue
    }

    It "SAS-policy gap is NotEvaluated evidence, never counted as affected risk" {
        $script:StorageSasPolicySupported = $false
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $false) ) }
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $main = $script:State.Results[-1]
        $main.Status | Should -Be 'PARTIAL'
        [int]$main.Count | Should -Be 0   # the SAS gap is NOT an affected resource
        $ne = @($script:State.Results | Where-Object { $_.CheckId -eq 'STORAGE-006' -and "$($_.Status)".ToUpper() -eq 'NOTEVALUATED' })
        $ne.Count | Should -Be 1
        $ne[0].CountType | Should -Be 'NotEvaluatedItems'
        (($ne[0].Evidence.Reason) -join ' ') | Should -BeLike '*IncludeAccountSASPolicy*'
    }

    It "affected risk signals stay separate from RBAC NotEvaluated items" {
        Mock Get-AzStorageAccount { @( (New-SA -Name 'sa1' -Ask $true) ) }
        $script:FxRbacThrow = $true
        Test-StorageKeyExposure -Subscriptions $script:Subs
        $main = $script:State.Results[-1]
        $main.Status | Should -Be 'FAIL'
        $main.CountType | Should -Be 'RiskSignals'
        [int]$main.Count | Should -Be 1
        (($main.Evidence.Risk) -join ' ') | Should -BeLike '*Shared key*'
        (($main.Evidence.Risk) -join ' ') | Should -Not -BeLike '*could not be read*'
        $ne = @($script:State.Results | Where-Object { $_.CheckId -eq 'STORAGE-006' -and "$($_.Status)".ToUpper() -eq 'NOTEVALUATED' })
        $ne.Count | Should -Be 1
        $ne[0].CountType | Should -Be 'NotEvaluatedItems'
        (($ne[0].Evidence.Reason) -join ' ') | Should -BeLike '*role assignments could not be read*'
    }
}
