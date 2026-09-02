#==============================================================================
# Phase 9 - ENTRA-11 Break-glass / GA hygiene. Mocked/local only. No live Graph.
#==============================================================================

BeforeAll {
    # Parked under Future/EntraMap/Tests: repo root is three levels up.
    $projectRoot = Split-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Future\EntraMap\Checks\BreakGlass.ps1"

    $script:State = Initialize-EntraAuditState
    $script:State.Config.Quiet = $true

    $script:GAID = '62e90394-69f5-4237-9190-012177145e10'
    function New-GA { param([string]$PrincipalId) [PSCustomObject]@{ principalId=$PrincipalId; roleDefinitionId=$script:GAID } }

    function Set-Entra {
        param([object[]]$Assignments, [hashtable]$Cache)
        $script:State.Entra = @{ RoleAssignments = $Assignments; RoleDefinitions = @(); PrincipalCache = $Cache }
    }
}

Describe "ENTRA-11 Break-glass / GA hygiene" {
    BeforeEach { $script:State.Results.Clear() }

    It "FAILs when Global Administrators exceed five" {
        $cache = @{}
        $as = 1..6 | ForEach-Object { $cache["p$_"] = @{ displayName="User$_"; upn="u$_@x"; accountEnabled=$true }; New-GA "p$_" }
        $cache['p1'] = @{ displayName='breakglass-01'; upn='bg@x'; accountEnabled=$true }
        Set-Entra -Assignments $as -Cache $cache
        Test-EntraBreakGlassHygiene
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'FAIL'
        ($f.Evidence.Risk -join ' ') | Should -BeLike '*More than five*'
    }

    It "FAILs when fewer than two Global Administrators" {
        $cache = @{ 'p1' = @{ displayName='breakglass'; upn='bg@x'; accountEnabled=$true } }
        Set-Entra -Assignments @((New-GA 'p1')) -Cache $cache
        Test-EntraBreakGlassHygiene
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Risk) -join ' ') | Should -BeLike '*Fewer than two*'
    }

    It "FAILs when no obvious break-glass account is found" {
        $cache = @{ 'p1'=@{displayName='Alice';upn='a@x';accountEnabled=$true}; 'p2'=@{displayName='Bob';upn='b@x';accountEnabled=$true}; 'p3'=@{displayName='Carol';upn='c@x';accountEnabled=$true} }
        Set-Entra -Assignments @((New-GA 'p1'),(New-GA 'p2'),(New-GA 'p3')) -Cache $cache
        Test-EntraBreakGlassHygiene
        $script:State.Results[-1].Status | Should -Be 'FAIL'
        (($script:State.Results[-1].Evidence.Risk) -join ' ') | Should -BeLike '*No obvious break-glass*'
    }

    It "PASSes with 2-5 GAs and a break-glass account present" {
        $cache = @{ 'p1'=@{displayName='breakglass-01';upn='bg@x';accountEnabled=$true}; 'p2'=@{displayName='Bob';upn='b@x';accountEnabled=$true}; 'p3'=@{displayName='Carol';upn='c@x';accountEnabled=$true} }
        Set-Entra -Assignments @((New-GA 'p1'),(New-GA 'p2'),(New-GA 'p3')) -Cache $cache
        Test-EntraBreakGlassHygiene
        $script:State.Results[-1].Status | Should -Be 'PASS'
    }

    It "is NotEvaluated when role assignments were not collected" {
        $script:State.Entra = @{ RoleAssignments = $null }
        Test-EntraBreakGlassHygiene
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "does not leak principal UPNs/names into evidence" {
        $cache = @{ 'p1'=@{displayName='Alice';upn='secret.user@contoso';accountEnabled=$true} }
        Set-Entra -Assignments @((New-GA 'p1')) -Cache $cache
        Test-EntraBreakGlassHygiene
        ($script:State.Results[-1].Evidence | ConvertTo-Json -Depth 6) | Should -Not -BeLike '*secret.user@contoso*'
    }

    It "registers ENTRA-11" {
        $def = @(Register-EntraBreakGlassChecks)[0]
        $def.CheckId | Should -Be 'ENTRA-11'
        Get-Command -Name $def.Function -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
