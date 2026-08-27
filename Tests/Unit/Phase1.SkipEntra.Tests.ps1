#==============================================================================
# AzureMap v2 - Tests/Unit/Phase1.SkipEntra.Tests.ps1
# Phase 1 - mocked/local only. No Azure, no Graph, no authentication.
#
# Covers:
#   * -SkipEntra does not call Get-GraphToken
#   * -SkipEntra does not call Invoke-EntraCollection
#   * -SkipEntra does not call Get-TenantWideData
#   * tenant-dependent identity checks become NotEvaluated when tenant data
#     is unavailable (via -SkipEntra or missing dataset)
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Core\Collection.ps1"
    . "$projectRoot\Checks\Azure\Identity.ps1"

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet         = $true
    $script:State.Config.SeverityLevel = "All"

    $script:EmptyExclusions = @{ Resources = @(); Findings = @(); Subscriptions = @(); Tags = @() }

    # Stubs so Get-Command finds these (Collection.ps1 guards with Get-Command),
    # and so identity checks have their console/context helpers available.
    function Get-GraphToken        { param([switch]$ForceRefresh) "stub-token" }
    function Invoke-EntraCollection { param([switch]$UseGraphBeta) }
    function Write-Section         { param($Title, $Color, $ProgressId) }
    function Write-Progress        { param($Activity, $Status, $PercentComplete, $Id, [switch]$Completed) }
    function Set-SubscriptionContext { param($SubscriptionId, $SubscriptionName) $true }
    function Invoke-AzureCommand   { param($Command, $CommandName, [switch]$SkipContextCheck, [switch]$Critical) @() }
}

Describe "Invoke-AzureMapCollection - Azure-only gating" {

    BeforeEach {
        $script:State.Config.SkipEntra = $false
        $script:State.TenantWideData   = @{ Applications = $null; ServicePrincipals = $null; TenantId = $null; FetchedAt = $null }

        Mock Get-GraphToken        { "stub-token" }
        Mock Invoke-EntraCollection { }
        Mock Get-TenantWideData    { $script:State.TenantWideData }
    }

    It "-SkipEntra does NOT acquire a Graph token" {
        Invoke-AzureMapCollection -SkipEntra
        Should -Not -Invoke Get-GraphToken
    }

    It "-SkipEntra does NOT run Entra collection" {
        Invoke-AzureMapCollection -SkipEntra
        Should -Not -Invoke Invoke-EntraCollection
    }

    It "-SkipEntra does NOT run tenant-wide identity collection" {
        Invoke-AzureMapCollection -SkipEntra
        Should -Not -Invoke Get-TenantWideData
    }

    It "without -SkipEntra runs token, Entra collection, and tenant-wide collection" {
        Invoke-AzureMapCollection
        Should -Invoke Get-GraphToken     -Times 1
        Should -Invoke Invoke-EntraCollection -Times 1
        Should -Invoke Get-TenantWideData -Times 1
    }
}

Describe "Tenant-dependent identity checks are NotEvaluated (never clean PASS)" {

    BeforeEach {
        $script:State.Results.Clear()
        $script:State.Config.SkipEntra = $true
        $script:State.TenantWideData   = @{ Applications = $null; ServicePrincipals = $null; TenantId = $null; FetchedAt = $null }
        # If any of these are called under -SkipEntra the test must fail.
        Mock Get-TenantWideData { throw "Get-TenantWideData must not be called under -SkipEntra" }
        Mock Invoke-AzureCommand { throw "No Azure/AAD command must run under -SkipEntra" }
    }

    It "IDENTITY-001 Long-Lived Credentials -> NotEvaluated, no tenant collection" {
        Test-LongLivedCredentials -Subscriptions @() -Exclusions $script:EmptyExclusions
        $script:State.Results[-1].Status | Should -Be "NotEvaluated"
        Should -Not -Invoke Get-TenantWideData
    }

    It "IDENTITY-002 Dormant Service Principals -> NotEvaluated, no tenant collection" {
        Test-DormantServicePrincipals -Subscriptions @() -Exclusions $script:EmptyExclusions
        $script:State.Results[-1].Status | Should -Be "NotEvaluated"
        Should -Not -Invoke Get-TenantWideData
    }

    It "IDENTITY-004 Expired Credentials -> NotEvaluated, no AAD calls" {
        $sub = [PSCustomObject]@{ Id = "sub-id"; Name = "sub-name" }
        Test-ExpiredCredentials -Subscriptions @($sub) -Exclusions $script:EmptyExclusions
        $script:State.Results[-1].Status | Should -Be "NotEvaluated"
        Should -Not -Invoke Invoke-AzureCommand
    }

    It "IDENTITY-002 -> NotEvaluated when dataset missing even without -SkipEntra" {
        $script:State.Config.SkipEntra = $false
        Mock Get-TenantWideData { $script:State.TenantWideData }   # returns empty (ServicePrincipals = null)
        Test-DormantServicePrincipals -Subscriptions @() -Exclusions $script:EmptyExclusions
        $script:State.Results[-1].Status | Should -Be "NotEvaluated"
    }
}
