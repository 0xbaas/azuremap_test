#==============================================================================
# AzureMap v2 - Tests/EntraMap/Phase26.EntraProduct.Tests.ps1
# Phase 26 - EntraMap product baseline. Mocked/local only: no Azure, no Graph,
# no authentication. All Graph-facing behavior is verified with stubs.
#
# Covers:
#   (a) Build-EntraFootprint from stubbed Graph data (counts, tenant, account)
#   (b) per-dimension degradation on 403-class errors (no throw, marked
#       unavailable, permission class queried once then skipped)
#   (c) reuse of already-collected data (no double-fetch)
#   (d) Assessment scope + Discovery block rendering for EntraMap
#   (e) product grouping map: all 15 registered Entra-side checks land in the
#       six human groups exactly once; display-name table covers all 15
#   (f) assessment plan permission-limited count (and no faked count when
#       scopes are undecodable)
#   (g) execution permission gate: limited checks -> "Could not check" with a
#       clear permission reason, granted/unknown -> check runs
#   (h) AzureMap rendering unchanged (legacy 'Identity' bucket, data-plane
#       plan line, no permission-limited line)
#==============================================================================

BeforeAll {
    # Parked under Future/EntraMap/Tests: repo root is three levels up.
    $projectRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Future\EntraMap\Core\Graph.ps1"
    . "$projectRoot\Future\EntraMap\Core\Footprint.Entra.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"

    # Session hygiene: other test files in the same Pester session may leave a
    # GLOBAL stub function shadowing Invoke-RestMethod (a parameterless stub
    # created via Set-Item function:global:). Pester then derives its mock
    # proxy from the stub instead of the cmdlet and the mock scriptblock
    # receives no usable -Uri/-Method arguments. A container-scoped function
    # with the parameter types the mocks bind (note [switch]$UseBasicParsing)
    # shadows any leaked global, gives Pester proper metadata to mock, and
    # does not leak state to other files. These tests never want a real web
    # call, so shadowing the cmdlet here is safe.
    function script:Invoke-RestMethod {
        param([string]$Uri, [string]$Method, $Headers, [switch]$UseBasicParsing, [Parameter(ValueFromRemainingArguments)]$r)
    }

    # Entra check modules (registration metadata + target functions).
    Get-ChildItem -Path "$projectRoot\Future\EntraMap\Checks\*.ps1" -File | ForEach-Object { . $_.FullName }

    function script:Register-AllEntraChecks {
        foreach ($regFunc in Get-Command -Name 'Register-Entra*Checks' -ErrorAction SilentlyContinue) {
            foreach ($def in @(& $regFunc.Name)) {
                if ($def -is [hashtable]) { Register-CheckDefinition -Definition $def }
            }
        }
    }

    function script:New-EntraState {
        $script:State = Initialize-EntraAuditState
        $script:State.Config.Quiet = $true
        $script:State.LogFile = Join-Path $TestDrive 'EntraMap-test.log'
    }
}

Describe "Build-EntraFootprint - stubbed Graph data" {

    BeforeEach {
        New-EntraState
        Mock Get-GraphToken { 'fake-opaque-token' }
        Mock Get-AzContext {
            [PSCustomObject]@{
                Account = [PSCustomObject]@{ Id = 'analyst@example.com' }
                Tenant  = [PSCustomObject]@{ Id = 'tenant-123' }
            }
        }
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $UseBasicParsing)
            if ("$Method" -ne 'GET') { throw "non-GET must never happen in discovery: $Method $Uri" }
            if ($Uri -match 'users/\$count')              { return 120 }
            if ($Uri -match 'groups/\$count')             { return 45 }
            if ($Uri -match 'servicePrincipals/\$count')  { return 67 }
            if ($Uri -match 'applications/\$count')       { return 89 }
            if ($Uri -match 'roleDefinitions')            { return [PSCustomObject]@{ '@odata.count' = 63 } }
            if ($Uri -match 'roleAssignments')            { return [PSCustomObject]@{ '@odata.count' = 412 } }
            if ($Uri -match 'conditionalAccess/policies') { return [PSCustomObject]@{ '@odata.count' = 7 } }
            if ($Uri -match 'authenticationMethodsPolicy') { return [PSCustomObject]@{ id = 'amp-1' } }
            if ($Uri -match "users\?.*Guest")             { return [PSCustomObject]@{ '@odata.count' = 12 } }
            if ($Uri -match 'applications\?')             {
                return [PSCustomObject]@{
                    value = @(
                        [PSCustomObject]@{ id = 'app-1'; passwordCredentials = @('c1', 'c2'); keyCredentials = @('k1') }
                    )
                }
            }
            throw "unexpected Graph uri in test: $Uri"
        }
    }

    It "builds the full footprint with all dimensions available" {
        $fp = Build-EntraFootprint
        $fp.GraphAccess | Should -Be 'Available'
        $fp.TenantId    | Should -Be 'tenant-123'
        $fp.Account     | Should -Be 'analyst@example.com'
        $fp.Dimensions['Users'].Value                     | Should -Be 120
        $fp.Dimensions['Groups'].Value                    | Should -Be 45
        $fp.Dimensions['ServicePrincipals'].Value         | Should -Be 67
        $fp.Dimensions['AppRegistrations'].Value          | Should -Be 89
        $fp.Dimensions['DirectoryRoles'].Value            | Should -Be 63
        $fp.Dimensions['RoleAssignments'].Value           | Should -Be 412
        $fp.Dimensions['ConditionalAccessPolicies'].Value | Should -Be 7
        $fp.Dimensions['GuestUsers'].Value                | Should -Be 12
        $fp.Dimensions['AppCredentials'].Value            | Should -Be 3
        foreach ($k in $fp.Dimensions.Keys) { $fp.Dimensions[$k].Status | Should -Be 'Available' }
    }

    It "reports authentication-methods policy as an availability flag, not a count" {
        $fp = Build-EntraFootprint
        $fp.Dimensions['AuthenticationMethodsPolicy'].Value | Should -Be 'available'
    }

    It "caches the footprint in state and never writes it to disk" {
        $fp = Build-EntraFootprint
        $script:State.EntraFootprint | Should -Be $fp
        @((Get-ChildItem -Path $TestDrive -File -ErrorAction SilentlyContinue) |
            Where-Object { $_.Name -match 'footprint|Footprint' }).Count | Should -Be 0
        # Second call returns the cached object without new Graph calls.
        $fp2 = Build-EntraFootprint
        $fp2 | Should -Be $fp
    }

    It "degrades every dimension cleanly when Graph denies with 403 (no throw, all unavailable)" {
        Mock Invoke-RestMethod { throw 'Response status code does not indicate success: 403 (Forbidden).' }
        $fp = Build-EntraFootprint
        $fp.GraphAccess | Should -Be 'Available'   # token exists; dimensions are permission-limited
        foreach ($k in $fp.Dimensions.Keys) {
            $fp.Dimensions[$k].Status | Should -Be 'Unavailable'
            $fp.Dimensions[$k].Reason | Should -Match 'missing Graph permission'
        }
        $fp.Note | Should -Match 'unavailable'
    }

    It "classifies a 403 once per permission class and does not re-query that class" {
        Mock Invoke-RestMethod { throw 'Response status code does not indicate success: 403 (Forbidden).' }
        $fp = Build-EntraFootprint
        # 4 permission classes -> exactly 4 Graph calls; the other 6 dimensions
        # are marked unavailable without another request (no retry spam).
        Assert-MockCalled Invoke-RestMethod -Times 4 -Exactly
        $fp.Dimensions['Users'].Reason            | Should -Match 'User\.Read\.All'
        $fp.Dimensions['Groups'].Reason           | Should -Match 'Group\.Read\.All'
        $fp.Dimensions['ServicePrincipals'].Reason | Should -Match 'Application\.Read\.All'
        $fp.Dimensions['ConditionalAccessPolicies'].Reason | Should -Match 'Policy\.Read\.All'
    }

    It "degrades only the denied permission class when a single class is denied" {
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $UseBasicParsing)
            if ($Uri -match 'conditionalAccess|authenticationMethodsPolicy') {
                throw 'Response status code does not indicate success: 403 (Forbidden).'
            }
            if ($Uri -match 'users/\$count')             { return 120 }
            if ($Uri -match 'groups/\$count')            { return 45 }
            if ($Uri -match 'servicePrincipals/\$count') { return 67 }
            if ($Uri -match 'applications/\$count')      { return 89 }
            if ($Uri -match 'roleDefinitions')           { return [PSCustomObject]@{ '@odata.count' = 63 } }
            if ($Uri -match 'roleAssignments')           { return [PSCustomObject]@{ '@odata.count' = 412 } }
            if ($Uri -match "users\?.*Guest")            { return [PSCustomObject]@{ '@odata.count' = 12 } }
            if ($Uri -match 'applications\?')            { return [PSCustomObject]@{ value = @() } }
            throw "unexpected Graph uri in test: $Uri"
        }
        $fp = Build-EntraFootprint
        $fp.Dimensions['ConditionalAccessPolicies'].Status  | Should -Be 'Unavailable'
        $fp.Dimensions['AuthenticationMethodsPolicy'].Status | Should -Be 'Unavailable'
        $fp.Dimensions['Users'].Value | Should -Be 120
        $fp.Dimensions['RoleAssignments'].Value | Should -Be 412
        # The second PolicyRead dimension was not queried (class already denied).
        Assert-MockCalled Invoke-RestMethod -Times 0 -ParameterFilter { $Uri -match 'authenticationMethodsPolicy' }
    }

    It "marks non-permission query failures as unavailable with a generic reason (no raw error text)" {
        $script:State.Config.MaxRetryAttempts = 0   # no transient-retry sleeps in tests
        Mock Invoke-RestMethod { throw 'The remote server returned an error: (500) Internal Server Error.' }
        $fp = Build-EntraFootprint
        foreach ($k in $fp.Dimensions.Keys) {
            $fp.Dimensions[$k].Status | Should -Be 'Unavailable'
            $fp.Dimensions[$k].Reason | Should -Be 'query failed'
        }
    }

    It "reuses already-collected Entra data instead of double-fetching" {
        $script:State.Entra = @{
            Groups            = @('g1', 'g2', 'g3')
            ServicePrincipals = @('sp1', 'sp2')
            Applications      = @([PSCustomObject]@{ id = 'a1'; passwordCredentials = @('c1'); keyCredentials = @() })
            RoleDefinitions   = @('rd1')
            RoleAssignments   = @('ra1', 'ra2', 'ra3', 'ra4')
        }
        $fp = Build-EntraFootprint
        $fp.Dimensions['Groups'].Value            | Should -Be 3
        $fp.Dimensions['Groups'].Source           | Should -Be 'Collected'
        $fp.Dimensions['ServicePrincipals'].Value | Should -Be 2
        $fp.Dimensions['AppRegistrations'].Value  | Should -Be 1
        $fp.Dimensions['DirectoryRoles'].Value    | Should -Be 1
        $fp.Dimensions['RoleAssignments'].Value   | Should -Be 4
        $fp.Dimensions['AppCredentials'].Value    | Should -Be 1
        Assert-MockCalled Invoke-RestMethod -Times 0 -ParameterFilter { $Uri -match 'groups/\$count' }
        Assert-MockCalled Invoke-RestMethod -Times 0 -ParameterFilter { $Uri -match 'roleManagement' }
    }

    It "degrades to a skipped discovery (no throw) when no Graph token exists" {
        Mock Get-GraphToken { throw 'user interaction is required' }
        $fp = Build-EntraFootprint
        $fp.GraphAccess | Should -Be 'Unavailable'
        foreach ($k in $fp.Dimensions.Keys) {
            $fp.Dimensions[$k].Status | Should -Be 'Unavailable'
            $fp.Dimensions[$k].Reason | Should -Be 'no Graph access'
        }
    }
}

Describe "EntraMap scope + discovery rendering" {

    BeforeEach {
        New-EntraState
        $script:State.Config.Quiet  = $false
        $script:State.Config.NoColor = $true
        $script:ui = New-Object System.Collections.Generic.List[string]
        Mock Write-UiHost { param($Text, $Color, $NoNewline) [void]$script:ui.Add("$Text") }
    }

    It "renders the Assessment scope block with Entra-only labels" {
        Mock Get-AzContext {
            [PSCustomObject]@{
                Account = [PSCustomObject]@{ Id = 'analyst@example.com' }
                Tenant  = [PSCustomObject]@{ Id = 'tenant-123' }
            }
        }
        $script:State.Auth = [PSCustomObject]@{ GraphTokenAcquired = $true }
        Show-EntraAssessmentScope
        $all = $script:ui -join "`n"
        $all | Should -Match 'Assessment scope'
        $all | Should -Match 'Entra-only'
        $all | Should -Match 'tenant-123'
        $all | Should -Match 'analyst@example\.com'
        $all | Should -Match 'Graph access:\s+available'
        $all | Should -Match 'Azure subscriptions:\s+not scanned'
    }

    It "renders the Discovery block with counts and muted unavailable rows" {
        $fp = [PSCustomObject]@{
            TenantId = 't'; Account = 'a'; GraphAccess = 'Available'; Source = 'MicrosoftGraph'
            Note = ''; FetchedAt = Get-Date
            Dimensions = [ordered]@{
                Users = [PSCustomObject]@{ Label = 'Users'; Value = 5663; Status = 'Available'; Reason = ''; Source = 'MicrosoftGraph' }
                GuestUsers = [PSCustomObject]@{ Label = 'Guest users'; Value = $null; Status = 'Unavailable'; Reason = 'missing Graph permission (User.Read.All)'; Source = 'None' }
            }
        }
        Show-EntraFootprint -Footprint $fp
        $all = $script:ui -join "`n"
        $all | Should -Match 'Discovery'
        $all | Should -Match 'Users'
        $all | Should -Match '5,663'
        $all | Should -Match 'unavailable \(missing Graph permission \(User\.Read\.All\)\)'
    }

    It "renders a clean unavailable discovery block when Graph access is missing" {
        $fp = [PSCustomObject]@{
            TenantId = 't'; Account = 'a'; GraphAccess = 'Unavailable'; Source = 'MicrosoftGraph'
            Note = 'note'; FetchedAt = Get-Date; Dimensions = [ordered]@{}
        }
        Show-EntraFootprint -Footprint $fp
        ($script:ui -join "`n") | Should -Match 'Tenant discovery unavailable'
    }
}

Describe "EntraMap product grouping" {

    BeforeEach { New-EntraState }

    It "covers all 15 registered Entra-side checks in the six human groups exactly once" {
        Register-AllEntraChecks
        $script:State.CheckRegistry.Count | Should -Be 15
        $expectedGroups = @('Identity & roles', 'Applications', 'Conditional Access', 'Authentication', 'Collaboration', 'Workload identity')
        $seen = @{}
        foreach ($c in @($script:State.CheckRegistry)) {
            $domain = Get-CheckDomain -Check $c
            $domain | Should -Not -Be 'Other'
            $domain | Should -Not -Be 'Identity'
            $expectedGroups | Should -Contain $domain
            if (-not $seen.ContainsKey($domain)) { $seen[$domain] = 0 }
            $seen[$domain]++
        }
        # Every group is non-empty and every check landed in exactly one group.
        foreach ($g in $expectedGroups) { $seen[$g] | Should -BeGreaterThan 0 }
        ($seen.Values | Measure-Object -Sum).Sum | Should -Be 15
    }

    It "maps the specified checks to their specified groups" {
        Register-AllEntraChecks
        $byId = @{}
        foreach ($c in @($script:State.CheckRegistry)) { $byId[$c.CheckId] = (Get-CheckDomain -Check $c) }
        $byId['ENTRA-01'] | Should -Be 'Identity & roles'
        $byId['ENTRA-02'] | Should -Be 'Identity & roles'
        $byId['ENTRA-05'] | Should -Be 'Identity & roles'
        $byId['ENTRA-11'] | Should -Be 'Identity & roles'
        $byId['ENTRA-03'] | Should -Be 'Applications'
        $byId['ENTRA-04'] | Should -Be 'Applications'
        $byId['ENTRA-06'] | Should -Be 'Applications'
        $byId['ENTRA-07'] | Should -Be 'Applications'
        $byId['IDENTITY-001'] | Should -Be 'Applications'
        $byId['IDENTITY-002'] | Should -Be 'Applications'
        $byId['IDENTITY-004'] | Should -Be 'Applications'
        $byId['ENTRA-09'] | Should -Be 'Conditional Access'
        $byId['ENTRA-10'] | Should -Be 'Authentication'
        $byId['ENTRA-08'] | Should -Be 'Collaboration'
        $byId['ENTRA-12'] | Should -Be 'Workload identity'
    }

    It "has a curated human display name for every registered Entra-side check" {
        Register-AllEntraChecks
        foreach ($c in @($script:State.CheckRegistry)) {
            $script:CheckDisplayNames.ContainsKey($c.CheckId) | Should -BeTrue -Because "$($c.CheckId) must have a curated CLI name"
            (Get-CheckDisplayName -Check $c) | Should -Be $script:CheckDisplayNames[$c.CheckId]
        }
    }
}

Describe "Show-AssessmentPlan - EntraMap permission-limited count" {

    BeforeEach {
        New-EntraState
        $script:State.Config.Quiet = $false
        Mock Write-UiHost {}
        Mock Get-Module { [PSCustomObject]@{ Name = 'Az.Accounts' } }
        Register-AllEntraChecks
    }

    It "counts permission-limited checks when token scopes decode" {
        Mock Get-GraphTokenScopeInfo {
            [PSCustomObject]@{ GrantedScopes = @('Application.Read.All', 'Policy.Read.All'); DecodeSucceeded = $true }
        }
        Show-AssessmentPlan -Services @('All')
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '15 checks planned' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '10 relevant to this environment' }
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '5 limited \(missing Graph permissions\)' }
    }

    It "hides the Azure-only data-plane line for the EntraMap product" {
        Mock Get-GraphTokenScopeInfo {
            [PSCustomObject]@{ GrantedScopes = @('Application.Read.All', 'Policy.Read.All'); DecodeSucceeded = $true }
        }
        Show-AssessmentPlan -Services @('All')
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'Data-plane' }
    }

    It "never fakes a limited count when token scopes cannot be determined" {
        Mock Get-GraphTokenScopeInfo {
            [PSCustomObject]@{ GrantedScopes = @(); DecodeSucceeded = $false }
        }
        Show-AssessmentPlan -Services @('All')
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match '15 relevant to this environment' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'limited' }
    }
}

Describe "Invoke-AuditChecks - Graph permission gate (degradation behavior)" {

    BeforeEach {
        New-EntraState
        $script:permGatedRan = $false
        function global:Test-PermGatedCheck { $script:permGatedRan = $true }
    }

    It "records 'Could not check' with the missing permission instead of running a limited check" {
        Mock Get-GraphTokenScopeInfo {
            [PSCustomObject]@{ GrantedScopes = @('Policy.Read.All'); DecodeSucceeded = $true }
        }
        Register-AuditCheck -CheckId 'ZZ-ENT-PERM' -Category 'Entra' -Service 'EntraRoles' -Name 'Test-PermGatedCheck' `
            -Function 'Test-PermGatedCheck' -Phase 'TenantWide' -RequiredPerms @('RoleManagement.Read.Directory')
        Invoke-AuditChecks -Phase TenantWide -Subscriptions @() -Exclusions @{} -Services @('All')
        $script:permGatedRan | Should -BeFalse
        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'ZZ-ENT-PERM' })[0]
        $rec.Status | Should -Be 'NotEvaluated'
        $rec.Detail | Should -Match 'Missing Graph permission'
        $rec.Detail | Should -Match 'RoleManagement\.Read\.Directory'
        # The human CLI label for NotEvaluated is "Could not check".
        (Get-StatusDisplayInfo -Status $rec.Status).Label | Should -Be 'Could not check'
    }

    It "runs the check when its required scopes are granted" {
        Mock Get-GraphTokenScopeInfo {
            [PSCustomObject]@{ GrantedScopes = @('RoleManagement.Read.Directory'); DecodeSucceeded = $true }
        }
        Register-AuditCheck -CheckId 'ZZ-ENT-OK' -Category 'Entra' -Service 'EntraRoles' -Name 'Test-PermGatedCheck' `
            -Function 'Test-PermGatedCheck' -Phase 'TenantWide' -RequiredPerms @('RoleManagement.Read.Directory')
        Invoke-AuditChecks -Phase TenantWide -Subscriptions @() -Exclusions @{} -Services @('All')
        $script:permGatedRan | Should -BeTrue
    }

    It "fails open (check runs) when token scopes cannot be decoded" {
        Mock Get-GraphTokenScopeInfo {
            [PSCustomObject]@{ GrantedScopes = @(); DecodeSucceeded = $false }
        }
        Register-AuditCheck -CheckId 'ZZ-ENT-UNK' -Category 'Entra' -Service 'EntraRoles' -Name 'Test-PermGatedCheck' `
            -Function 'Test-PermGatedCheck' -Phase 'TenantWide' -RequiredPerms @('RoleManagement.Read.Directory')
        Invoke-AuditChecks -Phase TenantWide -Subscriptions @() -Exclusions @{} -Services @('All')
        $script:permGatedRan | Should -BeTrue
    }

    It "keeps Azure-category checks untouched by the Graph permission gate" {
        Mock Get-GraphTokenScopeInfo {
            [PSCustomObject]@{ GrantedScopes = @(); DecodeSucceeded = $true }
        }
        Register-AuditCheck -CheckId 'ZZ-AZ-PERM' -Category 'Azure' -Service 'Identity' -Name 'Test-PermGatedCheck' `
            -Function 'Test-PermGatedCheck' -Phase 'TenantWide' -RequiredPerms @('RoleManagement.Read.Directory')
        Invoke-AuditChecks -Phase TenantWide -Subscriptions @() -Exclusions @{} -Services @('All')
        $script:permGatedRan | Should -BeTrue
    }
}

Describe "Shared-Core guards" {

    BeforeEach { New-EntraState }

    It "Resolve-CheckApplicability fails open when the Azure footprint module is not loaded" {
        # Products/AzureMap/Core/Footprint.ps1 is NOT dot-sourced in this test session.
        Get-Command -Name 'Get-CheckApplicability' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        $r = Resolve-CheckApplicability -Check ([PSCustomObject]@{ CheckId = 'X'; RequiredResourceTypes = @('microsoft.storage/storageaccounts') })
        $r.Applicable | Should -BeTrue
    }

    It "Get-GraphTokenScopeInfo decodes roles/scp claims from a synthetic JWT" {
        # Cached-token path: the real Get-GraphToken returns State.GraphToken.
        $payload = (@{ scp = 'User.Read Policy.Read.All'; roles = @('Application.Read.All') } | ConvertTo-Json -Compress)
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $script:State.GraphToken = "header.$b64.signature"
        $script:State.GraphTokenExpiry = (Get-Date).AddHours(1)
        $info = Get-GraphTokenScopeInfo
        $info.DecodeSucceeded | Should -BeTrue
        $info.GrantedScopes | Should -Contain 'Policy.Read.All'
        $info.GrantedScopes | Should -Contain 'Application.Read.All'
        $info.GrantedScopes | Should -Contain 'User.Read'
    }

    It "Get-GraphTokenScopeInfo reports DecodeSucceeded=false for an opaque token (fail-open)" {
        $script:State.GraphToken = 'not-a-jwt'
        $script:State.GraphTokenExpiry = (Get-Date).AddHours(1)
        $info = Get-GraphTokenScopeInfo
        $info.DecodeSucceeded | Should -BeFalse
        $info.GrantedScopes.Count | Should -Be 0
    }
}

Describe "AzureMap rendering unchanged" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet  = $false
        $script:State.Config.NoColor = $true
        $script:State.LogFile = Join-Path $TestDrive 'AzureMap-test.log'
        Mock Write-UiHost {}
    }

    It "keeps the legacy single 'Identity' domain for Entra-category checks" {
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'EntraRoles'; Category = 'Entra' })) | Should -Be 'Identity'
        (Get-CheckDomain -Check ([PSCustomObject]@{ Service = 'EntraConditionalAccess'; Category = 'Entra' })) | Should -Be 'Identity'
    }

    It "keeps the Azure domain order list" {
        ((Get-CheckDomainOrderList) -join '|') | Should -Be ($script:CheckDomainOrder -join '|')
    }

    It "assessment plan keeps the data-plane line and never reports permission-limited checks" {
        function global:Test-AzPlanProbe { param([array]$Subscriptions) }
        Register-AuditCheck -CheckId 'ZZ-AZ-PLAN' -Category 'Azure' -Service 'Storage' -Name 'probe' `
            -Function 'Test-AzPlanProbe' -Phase 'PerSubscription' -AlwaysRun $true
        Show-AssessmentPlan -Services @('All')
        Assert-MockCalled Write-UiHost -ParameterFilter { "$Text" -match 'Data-plane checks' }
        Assert-MockCalled Write-UiHost -Times 0 -ParameterFilter { "$Text" -match 'limited \(missing Graph' }
    }
}
