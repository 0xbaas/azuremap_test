#==============================================================================
# Phase 9 - ENTRA-09 Conditional Access. Mocked/local only. No live Graph.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Checks\Entra\ConditionalAccess.ps1"

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet = $true

    function Invoke-GraphCommand { param([string]$Uri, [switch]$AllPages, [string]$CommandName, [string]$Method='GET', [hashtable]$Body, [string]$ApiVersion='v1.0', [switch]$AllowNonGet) }

    function New-CaPolicy {
        param([string]$Name, [string]$State, [string[]]$Controls, [string[]]$IncludeRoles=@(), [string[]]$IncludeUsers=@(), [string[]]$ClientAppTypes=@('all'), [string[]]$ExcludeUsers=@(), [string]$Secret=$null)
        [PSCustomObject]@{
            displayName   = $Name
            state         = $State
            _secret       = $Secret
            grantControls = [PSCustomObject]@{ builtInControls = $Controls; operator = 'OR' }
            conditions    = [PSCustomObject]@{
                clientAppTypes = $ClientAppTypes
                users = [PSCustomObject]@{ includeRoles=$IncludeRoles; includeUsers=$IncludeUsers; excludeUsers=$ExcludeUsers; excludeGroups=@(); excludeRoles=@() }
            }
        }
    }

    $script:AdminPol  = New-CaPolicy -Name 'Admin MFA'  -State 'enabled' -Controls @('mfa')   -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10')
    $script:LegacyPol = New-CaPolicy -Name 'Block legacy' -State 'enabled' -Controls @('block') -ClientAppTypes @('exchangeActiveSync','other') -IncludeUsers @('All')
    $script:GuestPol  = New-CaPolicy -Name 'Guest MFA'  -State 'enabled' -Controls @('mfa')   -IncludeUsers @('GuestsOrExternalUsers')
}

Describe "ENTRA-09 Conditional Access" {
    BeforeEach { $script:State.Results.Clear() }

    It "FAILs when no policies exist" {
        Mock Invoke-GraphCommand { @() }
        Test-EntraConditionalAccess
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'FAIL'
        ($f.Evidence.Gap -join ' ') | Should -BeLike '*No Conditional Access policies*'
    }

    It "FAILs when only report-only policies exist" {
        Mock Invoke-GraphCommand { @( (New-CaPolicy -Name 'RO' -State 'enabledForReportingButNotEnforced' -Controls @('mfa') -IncludeRoles @('x')) ) }
        Test-EntraConditionalAccess
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Gap) -join ' ') | Should -BeLike '*Report-only*'
    }

    It "FAILs when no enabled admin-MFA policy is identifiable" {
        Mock Invoke-GraphCommand { @($script:LegacyPol, $script:GuestPol) }  # legacy+guest but no admin-roles MFA
        Test-EntraConditionalAccess
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Gap) -join ' ') | Should -BeLike '*MFA for directory (admin) roles*'
    }

    It "PASSes when admin MFA, legacy blocking, and guest MFA are all covered" {
        Mock Invoke-GraphCommand { @($script:AdminPol, $script:LegacyPol, $script:GuestPol) }
        Test-EntraConditionalAccess
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'PASS'
        $f.Count  | Should -Be 0
    }

    It "is NotEvaluated on Graph failure" {
        Mock Invoke-GraphCommand { throw "403 Forbidden" }
        Test-EntraConditionalAccess
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "does not dump raw policy objects (no secret leakage)" {
        $leak = New-CaPolicy -Name 'Leaky' -State 'enabled' -Controls @('mfa') -IncludeRoles @('x') -Secret 'PLANTEDSECRET'
        Mock Invoke-GraphCommand { @($leak) }   # missing legacy+guest => FAIL with evidence
        Test-EntraConditionalAccess
        ($script:State.Results[-1].Evidence | ConvertTo-Json -Depth 6) | Should -Not -BeLike '*PLANTEDSECRET*'
    }

    It "registers ENTRA-09 with a resolvable function" {
        $def = @(Register-EntraConditionalAccessChecks)[0]
        $def.CheckId  | Should -Be 'ENTRA-09'
        $def.Phase    | Should -Be 'TenantWide'
        Get-Command -Name $def.Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
