#==============================================================================
# AzureMap v2 - Tests/Unit/Phase4.EntraRegistration.Tests.ps1
# Phase 4 - mocked/local only. No Azure, no Graph, no authentication.
#
# Verifies that Entra check definitions (returned as hashtables) are actually
# registered via Register-CheckDefinition, and that resolution fails loudly.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"

    # Load Entra check + registration functions (definitions + target functions).
    Get-ChildItem -Path "$projectRoot\Checks\Entra\*.ps1" -File | ForEach-Object { . $_.FullName }

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet = $true

    function Invoke-EntraRegistration {
        foreach ($regFunc in Get-Command -Name 'Register-Entra*Checks' -ErrorAction SilentlyContinue) {
            foreach ($def in @(& $regFunc.Name)) {
                if ($def -is [hashtable]) { Register-CheckDefinition -Definition $def }
            }
        }
    }
}

Describe "Entra check registration" {

    BeforeEach { $script:State.CheckRegistry.Clear() }

    It "registers ENTRA-01" {
        Invoke-EntraRegistration
        $script:State.CheckRegistry.CheckId | Should -Contain 'ENTRA-01'
    }

    It "registers ENTRA-08" {
        Invoke-EntraRegistration
        $script:State.CheckRegistry.CheckId | Should -Contain 'ENTRA-08'
    }

    It "registers all twelve Entra checks (ENTRA-01..ENTRA-12)" {
        Invoke-EntraRegistration
        1..12 | ForEach-Object {
            $id = "ENTRA-{0:d2}" -f $_
            $script:State.CheckRegistry.CheckId | Should -Contain $id
        }
    }

    It "registers the relocated tenant-identity checks (IDENTITY-001/002/004)" {
        Invoke-EntraRegistration
        'IDENTITY-001', 'IDENTITY-002', 'IDENTITY-004' | ForEach-Object {
            $script:State.CheckRegistry.CheckId | Should -Contain $_
        }
    }

    It "registers relocated tenant-identity checks as Category 'Entra', Phase 'TenantWide'" {
        Invoke-EntraRegistration
        foreach ($id in 'IDENTITY-001', 'IDENTITY-002', 'IDENTITY-004') {
            $def = $script:State.CheckRegistry | Where-Object { $_.CheckId -eq $id }
            $def.Category | Should -Be 'Entra'
            $def.Phase    | Should -Be 'TenantWide'
        }
    }

    It "stores the check Function as a ScriptBlock, not a string" {
        Invoke-EntraRegistration
        $entra01 = $script:State.CheckRegistry | Where-Object { $_.CheckId -eq 'ENTRA-01' }
        $entra01.Function | Should -BeOfType [scriptblock]
    }
}

Describe "Register-CheckDefinition failure handling" {

    BeforeEach { $script:State.CheckRegistry.Clear() }

    It "throws clearly when the Function name cannot be resolved" {
        $badDef = @{
            CheckId  = 'ENTRA-BAD'
            Category = 'Entra'
            Service  = 'EntraRoles'
            Name     = 'Nonexistent check'
            Function = 'Test-DoesNotExist-12345'
            Phase    = 'TenantWide'
        }
        { Register-CheckDefinition -Definition $badDef } |
            Should -Throw -ExpectedMessage '*could not be resolved*'
    }

    It "throws when CheckId is missing" {
        { Register-CheckDefinition -Definition @{ Function = 'Test-EntraPrivilegedRoleAssignments' } } |
            Should -Throw -ExpectedMessage "*missing a required 'CheckId'*"
    }
}
