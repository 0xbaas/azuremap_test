#==============================================================================
# Phase 9 - ENTRA-12 Workload identity federated credentials. Mocked/local only.
#==============================================================================

BeforeAll {
    # Parked under Future/EntraMap/Tests: repo root is three levels up.
    $projectRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Future\EntraMap\Checks\WorkloadIdentity.ps1"

    $script:State = Initialize-EntraAuditState
    $script:State.Config.Quiet = $true

    function Invoke-GraphCommand { param([string]$Uri, [switch]$AllPages, [string]$CommandName, [string]$Method='GET', [hashtable]$Body, [string]$ApiVersion='v1.0', [switch]$AllowNonGet) }

    function Set-Apps { param([object[]]$Apps) $script:State.Entra = @{ Applications = $Apps } }
    $script:OneApp = @([PSCustomObject]@{ id='a1'; appId='app-1'; displayName='CI App' })
}

Describe "ENTRA-12 Workload identity federated credentials" {
    BeforeEach { $script:State.Results.Clear() }

    It "FAILs on GitHub OIDC with a main-branch subject" {
        Set-Apps $script:OneApp
        Mock Invoke-GraphCommand { @([PSCustomObject]@{ issuer='https://token.actions.githubusercontent.com'; subject='repo:org/repo:ref:refs/heads/main'; audiences=@('api://AzureADTokenExchange'); _secret='PLANTEDFIC' }) }
        Test-EntraWorkloadIdentityFederatedCredentials
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'FAIL'
        ($f.Evidence.Risk -join ' ') | Should -BeLike '*GitHub Actions OIDC*'
    }

    It "PASSes when collected apps have no federated credentials" {
        Set-Apps $script:OneApp
        Mock Invoke-GraphCommand { @() }
        Test-EntraWorkloadIdentityFederatedCredentials
        $script:State.Results[-1].Status | Should -Be 'PASS'
    }

    It "is NotEvaluated when applications were not collected" {
        $script:State.Entra = @{ Applications = $null }
        Test-EntraWorkloadIdentityFederatedCredentials
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "is NotEvaluated (partial) when FIC reads fail and no findings exist" {
        Set-Apps $script:OneApp
        Mock Invoke-GraphCommand { throw "403 on FIC read" }
        Test-EntraWorkloadIdentityFederatedCredentials
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'NotEvaluated'
        $f.Finding | Should -BeLike '*partially evaluated*'
    }

    It "does not dump raw credential objects" {
        Set-Apps $script:OneApp
        Mock Invoke-GraphCommand { @([PSCustomObject]@{ issuer='https://token.actions.githubusercontent.com'; subject='*'; audiences=@('api://AzureADTokenExchange'); _secret='PLANTEDFIC' }) }
        Test-EntraWorkloadIdentityFederatedCredentials
        ($script:State.Results[-1].Evidence | ConvertTo-Json -Depth 6) | Should -Not -BeLike '*PLANTEDFIC*'
    }

    It "registers ENTRA-12" {
        $def = @(Register-EntraWorkloadIdentityChecks)[0]
        $def.CheckId | Should -Be 'ENTRA-12'
        Get-Command -Name $def.Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
