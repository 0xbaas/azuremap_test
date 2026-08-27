#==============================================================================
# Phase 9 - ENTRA-10 Authentication Methods. Mocked/local only. No live Graph.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Checks\Entra\AuthMethods.ps1"

    $script:State = Initialize-EntraAuditState
    $script:State.Config.Quiet = $true

    function Invoke-GraphCommand { param([string]$Uri, [switch]$AllPages, [string]$CommandName, [string]$Method='GET', [hashtable]$Body, [string]$ApiVersion='v1.0', [switch]$AllowNonGet) }

    function New-AmPolicy {
        param([hashtable]$States)  # e.g. @{ Sms='enabled'; Voice='disabled' }
        $configs = foreach ($k in $States.Keys) { [PSCustomObject]@{ id=$k; state=$States[$k]; _extra='PLANTEDPOLICYBLOB' } }
        [PSCustomObject]@{ id='authenticationMethodsPolicy'; authenticationMethodConfigurations = @($configs) }
    }
}

Describe "ENTRA-10 Authentication Methods" {
    BeforeEach { $script:State.Results.Clear() }

    It "FAILs when SMS is enabled" {
        Mock Invoke-GraphCommand { New-AmPolicy -States @{ Sms='enabled'; MicrosoftAuthenticator='enabled' } }
        Test-EntraAuthenticationMethods
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'FAIL'
        ($f.Evidence.Method -join ',') | Should -BeLike '*Sms*'
    }

    It "FAILs when Voice is enabled" {
        Mock Invoke-GraphCommand { New-AmPolicy -States @{ Voice='enabled' } }
        Test-EntraAuthenticationMethods
        $script:State.Results[-1].Status | Should -Be 'FAIL'
    }

    It "PASSes when weak methods are disabled" {
        Mock Invoke-GraphCommand { New-AmPolicy -States @{ Sms='disabled'; Voice='disabled'; Fido2='enabled' } }
        Test-EntraAuthenticationMethods
        $script:State.Results[-1].Status | Should -Be 'PASS'
    }

    It "is NotEvaluated on Graph failure" {
        Mock Invoke-GraphCommand { throw "Graph error" }
        Test-EntraAuthenticationMethods
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "is NotEvaluated when no policy data returned" {
        Mock Invoke-GraphCommand { @() }
        Test-EntraAuthenticationMethods
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "does not dump the full policy object" {
        Mock Invoke-GraphCommand { New-AmPolicy -States @{ Sms='enabled' } }
        Test-EntraAuthenticationMethods
        ($script:State.Results[-1].Evidence | ConvertTo-Json -Depth 6) | Should -Not -BeLike '*PLANTEDPOLICYBLOB*'
    }

    It "registers ENTRA-10" {
        $def = @(Register-EntraAuthMethodsChecks)[0]
        $def.CheckId | Should -Be 'ENTRA-10'
        Get-Command -Name $def.Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
