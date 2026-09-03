#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase33.RbacRest.Tests.ps1
# Phase 33 - RBAC via ARM REST + Az.Storage 9.x SAS detection:
#   * Get-SubscriptionRBACAssignments reads roleAssignments/roleDefinitions via
#     Invoke-AzRestMethod (ARM only - Get-AzRoleAssignment's Graph enrichment
#     fails under ARM-only auth and returned ZERO rows, a false clean PASS).
#   * Object shape/role-name mapping, pagination, definitions caching, and the
#     RBACUnavailable failure contract (failure -> NOTEVALUATED, never PASS).
#   * Test-StorageSasPolicySupported: supported when the account objects carry a
#     SasPolicy property (9.x) even without -IncludeAccountSASPolicy; empty
#     subscriptions never get a SAS NotEvaluated entry.
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
    . "$projectRoot\Products\AzureMap\Core\InventoryCache.ps1"
    . "$projectRoot\Products\AzureMap\Core\CheckCoverage.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Identity.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Storage.ps1"
    . "$projectRoot\Products\AzureMap\Checks\StorageKey.ps1"

    # --- global Az stubs (reconfigurable via $global:Fx*) ---
    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }
    function global:Get-AzContext { [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'S1' }; Account = 'test' } }

    # ARM REST stub: serves the RBAC endpoints from fixtures (optionally paged
    # via $global:FxAssignPages); every requested path is recorded.
    function global:Invoke-AzRestMethod {
        param([string]$Path, [string]$Method, [Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxRestThrow) { throw "403 AuthorizationFailed" }
        if ($null -ne $global:FxRestPaths) { [void]$global:FxRestPaths.Add("$Path") }
        if ("$Path" -match 'roleDefinitions') {
            return [PSCustomObject]@{ StatusCode = 200; Content = (@{ value = @($global:FxRoleDefs) } | ConvertTo-Json -Depth 8) }
        }
        if ("$Path" -match 'roleAssignments') {
            if ($global:FxAssignPages) {
                $page = $global:FxAssignPages[0]
                $global:FxAssignPages = @($global:FxAssignPages | Select-Object -Skip 1)
                return [PSCustomObject]@{ StatusCode = 200; Content = ($page | ConvertTo-Json -Depth 8) }
            }
            return [PSCustomObject]@{ StatusCode = 200; Content = (@{ value = @($global:FxRoleAssignments) } | ConvertTo-Json -Depth 8) }
        }
        throw "Unexpected Invoke-AzRestMethod path: $Path"
    }

    function global:Get-AzRoleDefinition { param([switch]$Custom, [Parameter(ValueFromRemainingArguments)]$r) @() }
    function global:Get-AzWebApp       { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxWebApps }
    function global:Get-AzVM           { param([Parameter(ValueFromRemainingArguments)]$r) @() }
    function global:Get-AzFunctionApp  { param([Parameter(ValueFromRemainingArguments)]$r) @() }
    # Az.Storage 9.x shape: NO -IncludeAccountSASPolicy parameter.
    function global:Get-AzStorageAccount { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxAccounts }

    # --- REST fixture builders ---
    function global:New-RestRA {
        param([string]$Scope, [string]$RoleGuid, [string]$PrincipalId = 'oid-1', [string]$PrincipalType = 'User', [string]$Name = 'ra-1')
        [PSCustomObject]@{
            id         = "/subscriptions/S1/providers/Microsoft.Authorization/roleAssignments/$Name"
            properties = [PSCustomObject]@{
                scope            = $Scope
                roleDefinitionId = "/subscriptions/S1/providers/Microsoft.Authorization/roleDefinitions/$RoleGuid"
                principalId      = $PrincipalId
                principalType    = $PrincipalType
            }
        }
    }
    function global:New-RestDef {
        param([string]$Guid, [string]$RoleName)
        [PSCustomObject]@{
            id         = "/subscriptions/S1/providers/Microsoft.Authorization/roleDefinitions/$Guid"
            properties = [PSCustomObject]@{ roleName = $RoleName }
        }
    }
    function global:New-TestApp {
        param([string]$Name, [object]$PrincipalId = '__none__')
        $o = [PSCustomObject]@{ Name = $Name; ResourceGroupName = 'rg1' }
        if ($PrincipalId -ne '__none__') {
            $o | Add-Member -NotePropertyName Identity -NotePropertyValue ([PSCustomObject]@{ PrincipalId = $PrincipalId })
        }
        $o
    }
    function global:New-SA {
        param([hashtable]$Props = @{})
        $base = @{ StorageAccountName = 'sa1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/rg1/sa1'; AllowSharedKeyAccess = $false }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [PSCustomObject]$base
    }

    # Array-safe, script-scoped result lookups (plain emission - compose with @();
    # a comma-return would emit an EMPTY array as one object and fake Count=1).
    function script:Get-Res {
        param([string]$CheckId)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ($item.CheckId -eq $CheckId) { $items += $item }
        }
        return $items
    }
    function script:Get-Find {
        param([string]$Like)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ("$($item.Finding)" -like $Like) { $items += $item }
        }
        return $items
    }

    $global:FxSub = [PSCustomObject]@{ Id = 'S1'; Name = 'sub1'; TenantId = 'T1' }
    # Real built-in role definition GUIDs (consumers match on these names).
    $script:OwnerGuid       = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    $script:ContributorGuid = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
    $script:UaaGuid         = '18d7d88d-d35e-4fb5-a5c3-7773ae20da72'
}

Describe "Phase33 - RBAC via ARM REST + SAS 9.x detection" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $global:FxRestThrow        = $false
        $global:FxRestPaths        = $null
        $global:FxRoleAssignments  = @()
        $global:FxRoleDefs         = @()
        $global:FxAssignPages      = $null
        $global:FxWebApps          = @()
        $global:FxAccounts         = @()
    }

    Context "Get-SubscriptionRBACAssignments - ARM REST fetch" {
        It "returns the consumer object shape with role names resolved from roleDefinitions" {
            $global:FxRoleDefs = @(
                (New-RestDef -Guid $script:OwnerGuid -RoleName 'Owner')
                (New-RestDef -Guid $script:ContributorGuid -RoleName 'Contributor')
                (New-RestDef -Guid $script:UaaGuid -RoleName 'User Access Administrator')
            )
            $global:FxRoleAssignments = @(
                (New-RestRA -Scope '/subscriptions/S1' -RoleGuid $script:OwnerGuid -PrincipalId 'oid-user' -PrincipalType 'User' -Name 'ra-1')
                (New-RestRA -Scope '/subscriptions/S1' -RoleGuid $script:ContributorGuid -PrincipalId 'oid-sp' -PrincipalType 'ServicePrincipal' -Name 'ra-2')
                (New-RestRA -Scope '/subscriptions/S1/resourceGroups/rg1' -RoleGuid $script:UaaGuid -PrincipalId 'oid-grp' -PrincipalType 'Group' -Name 'ra-3')
            )
            $res = @(Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'sub1')
            $res.Count | Should -Be 3
            $res[0].Scope              | Should -Be '/subscriptions/S1'
            $res[0].RoleDefinitionName | Should -Be 'Owner'
            $res[0].ObjectType         | Should -Be 'User'
            $res[0].ObjectId           | Should -Be 'oid-user'
            $res[0].DisplayName        | Should -BeNullOrEmpty
            $res[0].RoleAssignmentId   | Should -Be '/subscriptions/S1/providers/Microsoft.Authorization/roleAssignments/ra-1'
            $res[1].RoleDefinitionName | Should -Be 'Contributor'
            $res[2].RoleDefinitionName | Should -Be 'User Access Administrator'
            $script:State.Cache.RBACUnavailable['S1'] | Should -BeFalse
        }

        It "falls back to the GUID string for a role definition the endpoint did not list" {
            $unknownGuid = '11111111-2222-3333-4444-555555555555'
            $global:FxRoleDefs = @()
            $global:FxRoleAssignments = @( (New-RestRA -Scope '/subscriptions/S1' -RoleGuid $unknownGuid -Name 'ra-x') )
            $res = @(Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'sub1')
            $res.Count | Should -Be 1
            $res[0].RoleDefinitionName | Should -Be $unknownGuid
            $script:State.Cache.RBACUnavailable['S1'] | Should -BeFalse
        }

        It "marks the subscription RBACUnavailable and returns empty when the REST call throws" {
            $global:FxRestThrow = $true
            $res = @(Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'sub1')
            $res.Count | Should -Be 0
            $script:State.Cache.RBACUnavailable['S1'] | Should -BeTrue
        }

        It "treats a successful empty page as proven empty (flag stays false, PASS allowed downstream)" {
            $global:FxRoleAssignments = @()
            $global:FxRoleDefs        = @()
            $res = @(Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'sub1')
            $res.Count | Should -Be 0
            $script:State.Cache.RBACUnavailable['S1'] | Should -BeFalse
        }

        It "follows nextLink pagination on the assignments endpoint (absolute URL stripped to a relative path)" {
            $global:FxRestPaths = New-Object System.Collections.Generic.List[string]
            $ra1 = New-RestRA -Scope '/subscriptions/S1' -RoleGuid $script:OwnerGuid -Name 'ra-p1'
            $ra2 = New-RestRA -Scope '/subscriptions/S1' -RoleGuid $script:OwnerGuid -PrincipalId 'oid-2' -Name 'ra-p2'
            $global:FxAssignPages = @(
                @{ value = @($ra1); nextLink = 'https://management.azure.com/subscriptions/S1/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$skipToken=abc' },
                @{ value = @($ra2) }
            )
            $res = @(Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'sub1')
            $res.Count | Should -Be 2
            @($global:FxRestPaths | Where-Object { $_ -match 'skipToken=abc' }).Count | Should -Be 1
            @($global:FxRestPaths | Where-Object { $_ -match '^https?://' }).Count | Should -Be 0
        }

        It "caches role definitions per subscription (one definitions call across forced refetches)" {
            $global:FxRestPaths = New-Object System.Collections.Generic.List[string]
            $global:FxRoleDefs = @( (New-RestDef -Guid $script:OwnerGuid -RoleName 'Owner') )
            $null = Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'sub1'
            $null = Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'sub1' -ForceRefresh
            @($global:FxRestPaths | Where-Object { $_ -match 'roleDefinitions' }).Count | Should -Be 1
            @($global:FxRestPaths | Where-Object { $_ -match 'roleAssignments' }).Count | Should -Be 2
        }
    }

    Context "IDENTITY-007 decomposition over REST fixtures (DisplayName always null)" {
        It "decomposes Owner/Contributor/UAA at subscription scope plus non-human and group signals" {
            $global:FxRoleDefs = @(
                (New-RestDef -Guid $script:OwnerGuid -RoleName 'Owner')
                (New-RestDef -Guid $script:ContributorGuid -RoleName 'Contributor')
                (New-RestDef -Guid $script:UaaGuid -RoleName 'User Access Administrator')
            )
            $global:FxRoleAssignments = @(
                (New-RestRA -Scope '/subscriptions/S1' -RoleGuid $script:OwnerGuid -PrincipalId 'oid-1' -PrincipalType 'User' -Name 'ra-1')
                (New-RestRA -Scope '/subscriptions/S1' -RoleGuid $script:ContributorGuid -PrincipalId 'oid-2' -PrincipalType 'Group' -Name 'ra-2')
                (New-RestRA -Scope '/subscriptions/S1' -RoleGuid $script:UaaGuid -PrincipalId 'oid-3' -PrincipalType 'ServicePrincipal' -Name 'ra-3')
            )
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}

            $owner = @(script:Get-Find '*Owner role assignments at subscription scope*')
            $owner.Count | Should -Be 1
            "$($owner[0].Status)" | Should -Be 'FAIL'
            $owner[0].CountType | Should -Be 'RoleAssignments'
            [int]$owner[0].Count | Should -Be 1
            "$($owner[0].Evidence[0].PrincipalName)" | Should -Be 'Unknown'
            "$($owner[0].Evidence[0].PrincipalType)" | Should -Be 'User'

            @(script:Get-Find '*Contributor role assignments at subscription scope*').Count | Should -Be 1
            @(script:Get-Find '*User Access Administrator assignments at subscription scope*').Count | Should -Be 1

            $nonHuman = @(script:Get-Find '*non-human principals*')
            $nonHuman.Count | Should -Be 1
            $nonHuman[0].CountType | Should -Be 'RoleAssignments'
            [int]$nonHuman[0].Count | Should -Be 1
            "$($nonHuman[0].Evidence[0].PrincipalType)" | Should -Be 'ServicePrincipal'

            $group = @(script:Get-Find '*assigned to groups*')
            $group.Count | Should -Be 1
            [int]$group[0].Count | Should -Be 1
            "$($group[0].Evidence[0].PrincipalName)" | Should -Be 'Unknown'
        }
    }

    Context "RBACUnavailable -> NOTEVALUATED/PARTIAL, never PASS" {
        BeforeEach { $global:FxRestThrow = $true }

        It "IDENTITY-003 emits NotEvaluated and never a clean PASS" {
            Test-ExcessiveRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            @(script:Get-Find '*RBAC assignments could not be evaluated*').Count | Should -Be 1
            @(script:Get-Find '*No excessive subscription-scope RBAC assignments found*').Count | Should -Be 0
        }

        It "IDENTITY-005 emits NotEvaluated and never a clean PASS (flag check on cached RBAC read)" {
            Test-CustomRoles -Subscriptions @($global:FxSub) -Exclusions @{}
            @(script:Get-Find '*Custom roles could not be evaluated*').Count | Should -Be 1
            @(script:Get-Find '*No custom roles with dangerous*').Count | Should -Be 0
        }

        It "IDENTITY-006 is NOTEVALUATED with an identity-bearing resource and failed RBAC read" {
            $global:FxWebApps = @(New-TestApp -Name 'app1' -PrincipalId '11111111-1111-1111-1111-111111111111')
            Test-IdentityResourceMapping -Subscriptions @($global:FxSub) -Exclusions @{}
            $all = @(script:Get-Res 'IDENTITY-006')
            @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'PASS' }).Count | Should -Be 0
            @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'NOTEVALUATED' }).Count | Should -BeGreaterThan 0
        }

        It "IDENTITY-007 emits NotEvaluated and never a clean PASS" {
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $all = @(script:Get-Res 'IDENTITY-007')
            @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'PASS' }).Count | Should -Be 0
            @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'NOTEVALUATED' }).Count | Should -BeGreaterThan 0
        }

        It "STORAGE-006 is NOTEVALUATED/PARTIAL, never Clean, when RBAC cannot be read" {
            $script:StorageSasPolicySupported = $true
            $global:FxAccounts = @( (New-SA) )
            Test-StorageKeyExposure -Subscriptions @($global:FxSub) -Exclusions @{}
            $all = @(script:Get-Res 'STORAGE-006')
            @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'PASS' }).Count | Should -Be 0
            @($all | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'NOTEVALUATED' }).Count | Should -BeGreaterThan 0
        }
    }

    Context "SAS policy detection (Az.Storage 9.x: no -IncludeAccountSASPolicy, SasPolicy property)" {
        BeforeEach {
            Remove-Variable -Name 'StorageSasPolicySupported' -Scope Script -ErrorAction SilentlyContinue
        }

        It "is supported when an account carries a SasPolicy property even though the parameter is gone" {
            $global:FxAccounts = @( (New-SA @{ SasPolicy = [PSCustomObject]@{ SasExpirationPeriod = (New-TimeSpan -Days 10) } }) )
            (Test-StorageSasPolicySupported -SampleAccounts $global:FxAccounts) | Should -BeTrue
            Test-StorageKeyExposure -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(script:Get-Res 'STORAGE-006' | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'NOTEVALUATED' })
            $ne.Count | Should -Be 0
            $script:State.Results[-1].Status | Should -Be 'PASS'
        }

        It "zero-arg behavior is unchanged (parameter-only check) for existing callers" {
            (Test-StorageSasPolicySupported) | Should -BeFalse
            # a parameter-only negative is NOT cached: samples may still prove support
            $global:FxAccounts = @( (New-SA @{ SasPolicy = $null }) )
            (Test-StorageSasPolicySupported -SampleAccounts $global:FxAccounts) | Should -BeTrue
        }

        It "accounts exist but none expose SasPolicy and the parameter is absent -> NOTEVALUATED" {
            $global:FxAccounts = @( (New-SA) )
            (Test-StorageSasPolicySupported -SampleAccounts $global:FxAccounts) | Should -BeFalse
            Test-StorageKeyExposure -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(script:Get-Res 'STORAGE-006' | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'NOTEVALUATED' })
            $ne.Count | Should -Be 1
            (($ne[0].Evidence.Reason) -join ' ') | Should -BeLike '*SAS expiration policy not evaluated*'
            $script:State.Results[-1].Status | Should -Be 'PARTIAL'
            [int]$script:State.Results[-1].Count | Should -Be 0   # module gap is never an affected risk
        }

        It "subscription with ZERO storage accounts gets no SAS NotEvaluated entry" {
            $global:FxAccounts = @()
            Test-StorageKeyExposure -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(script:Get-Res 'STORAGE-006' | Where-Object { "$($_.Status)".ToUpperInvariant() -eq 'NOTEVALUATED' })
            $ne.Count | Should -Be 0
            $script:State.Results[-1].Status | Should -Be 'PASS'
            $script:State.Results[-1].DiscoveredResourceCount | Should -Be 0
        }
    }
}
