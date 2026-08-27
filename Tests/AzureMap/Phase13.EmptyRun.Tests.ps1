#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase13.EmptyRun.Tests.ps1
# Regression tests for a run that discovers no subscriptions / produces no findings:
#   * The exporters must accept an EMPTY Results collection without a
#     "Cannot bind argument to parameter 'Results' because it is an empty
#     collection" binding failure (Show-AuditSummary previously crashed).
#   * The subscription-discovery fallback path: a context-only subscription object
#     (identity denied Get-AzSubscription enumeration) normalizes correctly.
# Mocked/local only. No live Azure. Files are written to $TestDrive (auto-cleaned).
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Redaction.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Shared\Export\Csv.ps1"
    . "$projectRoot\Shared\Export\Json.ps1"
}

Describe "Empty run does not crash export/summary" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
    }

    It "Export-ResultsJson accepts empty Results (0 findings) without a binding error" {
        $base = Join-Path $TestDrive 'empty-json'
        { Export-ResultsJson -Results @() -BaseName $base } | Should -Not -Throw
        Test-Path "$base.json" | Should -BeTrue
    }

    It "Export-ResultsCsv accepts empty Results without a binding error" {
        $base = Join-Path $TestDrive 'empty-csv'
        { Export-ResultsCsv -Results @() -BaseName $base } | Should -Not -Throw
    }

    It "JSON summary of an empty run reports zero findings and zero affected resources" {
        $s = Get-JsonSummaryBlock -Results @()
        [int]$s.TotalFindings     | Should -Be 0
        [int]$s.AffectedResources | Should -Be 0
    }
}

Describe "Subscription discovery fallback normalizes a context-only subscription" {
    It "ConvertTo-AzureMapSubscription maps a context .Subscription object to Id/Name" {
        # This is the object the azuremap.ps1 fallback passes when Get-AzSubscription
        # returns nothing but (Get-AzContext).Subscription is present.
        $ctxSub = [PSCustomObject]@{ Id='S9'; Name='ctx-sub'; TenantId='T9' }
        $out = @(ConvertTo-AzureMapSubscription -InputObject $ctxSub)
        $out.Count   | Should -Be 1
        $out[0].Id   | Should -Be 'S9'
        $out[0].Name | Should -Be 'ctx-sub'
    }

    It "returns an empty array (no throw) when discovery yields nothing" {
        { ConvertTo-AzureMapSubscription -InputObject @() } | Should -Not -Throw
        @(ConvertTo-AzureMapSubscription -InputObject @()).Count | Should -Be 0
    }
}
