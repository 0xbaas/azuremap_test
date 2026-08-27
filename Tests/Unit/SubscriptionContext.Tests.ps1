#==============================================================================
# AzureMap v2 - Tests/Unit/SubscriptionContext.Tests.ps1
# Mocked/local only. No Azure, no Graph, no authentication.
#
# Verifies Set-SubscriptionContext switches only the local Az session context,
# returns $true/$false, never signs in, and never issues write operations.
# All identifiers used here are synthetic placeholders.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"

    $script:State = Initialize-AuditState
    $script:State.Config.Quiet = $true

    # Stubs so Mock can attach (no real Azure). Set-AzContext declares the real
    # parameter names so Pester -ParameterFilter can bind -SubscriptionId/-TenantId.
    function Set-AzContext {
        param(
            [string]$SubscriptionId,
            [string]$TenantId,
            [Parameter(ValueFromRemainingArguments)]$Rest
        )
    }
    function Select-AzSubscription { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function Connect-AzAccount    { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function New-AzResourceGroup  { param([Parameter(ValueFromRemainingArguments)]$Rest) }
    function Remove-AzResourceGroup { param([Parameter(ValueFromRemainingArguments)]$Rest) }
}

Describe "Set-SubscriptionContext" {

    BeforeEach {
        $script:State.LogBuffer.Clear()
        Mock Set-AzContext         { }
        Mock Connect-AzAccount     { }
        Mock New-AzResourceGroup   { }
        Mock Remove-AzResourceGroup { }
    }

    It "switches local context via Set-AzContext with the subscription id and returns true" {
        $result = Set-SubscriptionContext -SubscriptionId "SUB-PLACEHOLDER" -SubscriptionName "n1"

        $result | Should -BeTrue
        Should -Invoke Set-AzContext -Times 1 -ParameterFilter { $SubscriptionId -eq "SUB-PLACEHOLDER" }
    }

    It "passes TenantId through when provided" {
        $null = Set-SubscriptionContext -SubscriptionId "SUB-PLACEHOLDER" -SubscriptionName "n1" -TenantId "TEN-PLACEHOLDER"
        Should -Invoke Set-AzContext -Times 1 -ParameterFilter { $TenantId -eq "TEN-PLACEHOLDER" }
    }

    It "returns false and logs a clean warning on failure (no throw)" {
        Mock Set-AzContext { throw "no access to subscription" }

        $result = $null
        { $result = Set-SubscriptionContext -SubscriptionId "SUB-PLACEHOLDER" -SubscriptionName "n1" } | Should -Not -Throw
        $result | Should -BeFalse

        $log = ($script:State.LogBuffer -join "`n")
        $log | Should -BeLike "*Unable to switch Azure session context*"
        # Never emit the subscription id or tenant id in output.
        $log | Should -Not -BeLike "*SUB-PLACEHOLDER*"
        $log | Should -Not -BeLike "*TEN-PLACEHOLDER*"
    }

    It "never calls Connect-AzAccount" {
        $null = Set-SubscriptionContext -SubscriptionId "SUB-PLACEHOLDER" -SubscriptionName "n1"
        Should -Not -Invoke Connect-AzAccount
    }

    It "never calls write/create/delete cmdlets" {
        Mock Set-AzContext { throw "boom" }   # even on the failure path
        $null = Set-SubscriptionContext -SubscriptionId "SUB-PLACEHOLDER" -SubscriptionName "n1"

        Should -Not -Invoke Connect-AzAccount
        Should -Not -Invoke New-AzResourceGroup
        Should -Not -Invoke Remove-AzResourceGroup
    }
}
