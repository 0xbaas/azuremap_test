#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase1.Subscription.Tests.ps1
# Phase 1 - mocked/local only. No Azure, no Graph, no authentication.
#
# Covers:
#   * ConvertTo-AzureMapSubscription normalizes Get-AzSubscription shape
#   * ConvertTo-AzureMapSubscription normalizes Get-AzContext shape
#   * bad shape fails clearly (throws) before checks run
#   * empty input yields an empty array (no throw)
#   * PerSubscription checks receive normalized objects with Id and Name
#
# NOTE: no real subscription/tenant identifiers are used - all values are
# synthetic placeholders.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet = $true
}

Describe "ConvertTo-AzureMapSubscription" {

    It "maps a Get-AzSubscription-shaped object (.Id/.Name/.TenantId)" {
        $raw = [PSCustomObject]@{ Id = "AAAA"; Name = "sub-alpha"; TenantId = "TTTT"; SubscriptionId = "AAAA" }
        $out = ConvertTo-AzureMapSubscription -InputObject $raw

        @($out).Count | Should -Be 1
        $out[0].Id       | Should -Be "AAAA"
        $out[0].Name     | Should -Be "sub-alpha"
        $out[0].TenantId | Should -Be "TTTT"
    }

    It "maps a Get-AzContext-shaped object (.Subscription.Id/.Name, .Tenant.Id)" {
        $ctx = [PSCustomObject]@{
            Subscription = [PSCustomObject]@{ Id = "BBBB"; Name = "sub-beta" }
            Tenant       = [PSCustomObject]@{ Id = "UUUU" }
            Account      = [PSCustomObject]@{ Id = "user@example.test" }
        }
        $out = ConvertTo-AzureMapSubscription -InputObject $ctx

        $out[0].Id       | Should -Be "BBBB"
        $out[0].Name     | Should -Be "sub-beta"
        $out[0].TenantId | Should -Be "UUUU"
    }

    It "always exposes Id and Name for every result" {
        $raw = @(
            [PSCustomObject]@{ Id = "C1"; Name = "one";  TenantId = "T" }
            [PSCustomObject]@{ Id = "C2"; Name = "two";  TenantId = "T" }
        )
        $out = ConvertTo-AzureMapSubscription -InputObject $raw
        foreach ($s in $out) {
            $s.PSObject.Properties.Name | Should -Contain "Id"
            $s.PSObject.Properties.Name | Should -Contain "Name"
            [string]::IsNullOrWhiteSpace($s.Id)   | Should -BeFalse
            [string]::IsNullOrWhiteSpace($s.Name) | Should -BeFalse
        }
    }

    It "throws clearly when the object matches no supported shape" {
        $bad = [PSCustomObject]@{ Foo = "bar"; Baz = 1 }
        { ConvertTo-AzureMapSubscription -InputObject $bad } |
            Should -Throw -ExpectedMessage "*does not match a supported shape*"
    }

    It "returns an empty array for empty input (no throw)" {
        $out = ConvertTo-AzureMapSubscription -InputObject @()
        @($out).Count | Should -Be 0
    }
}

Describe "PerSubscription checks receive normalized subscription objects" {

    BeforeAll {
        # Capture into $global: so the value is visible regardless of whether the
        # fake check runs in the global (function-defined) or test script scope.
        function global:Test-CaptureSub {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            $global:CapturedSubs = $Subscriptions
        }
    }

    BeforeEach {
        $script:State.CheckRegistry.Clear()
        Remove-Variable -Name CapturedSubs -Scope Global -ErrorAction SilentlyContinue
    }

    It "forwards normalized {Id,Name} objects to the check function" {
        $normalized = ConvertTo-AzureMapSubscription -InputObject ([PSCustomObject]@{ Id = "S1"; Name = "n1"; TenantId = "T1" })

        Register-AuditCheck -CheckId "CAP-01" -Category "Azure" -Service "Storage" `
            -Name "Test-CaptureSub" -Function "Test-CaptureSub" -Phase "PerSubscription"

        $null = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] `
            -Subscriptions $normalized -Exclusions @{} -Services @("All")

        $global:CapturedSubs         | Should -Not -BeNullOrEmpty
        $global:CapturedSubs[0].Id   | Should -Be "S1"
        $global:CapturedSubs[0].Name | Should -Be "n1"
    }

    AfterAll {
        Remove-Item -Path Function:\Test-CaptureSub -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedSubs -Scope Global -ErrorAction SilentlyContinue
    }
}
