#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase11.SmokeFixes.Tests.ps1
# Regression tests for the Azure-only smoke-test fixes:
#   * Get-SafeProgressPercent - clamps to [0,100], scalarizes, no divide-by-zero
#     (fixes STORAGE-002 "PercentComplete > 100" and hardens the progress line).
#   * Check error records capture ScriptStackTrace (diagnoses "Argument types" #2).
#   * RBAC helper avoids Microsoft Graph and flags NotEvaluated on failure (#3).
#   * Write-Finding still records PASS (Count=0) findings for export while quiet
#     on the console by default (#4).
#   * Top Findings dedup renders without error (#4).
# Mocked/local only. No live Azure, no Graph, no authentication.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent

    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Products\EntraMap\Core\Graph.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Products\AzureMap\Core\Footprint.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"

    $script:State = Initialize-AzureAuditState
    $script:State = Initialize-EntraAuditState -State $script:State
    $script:State.Config.Quiet = $true
}

Describe "Get-SafeProgressPercent" {
    It "returns 100 when processed exceeds total (no ValidateRange > 100 error)" {
        Get-SafeProgressPercent -Current 104 -Total 100 | Should -Be 100
    }
    It "returns 0 when total is zero (no divide-by-zero)" {
        Get-SafeProgressPercent -Current 5 -Total 0 | Should -Be 0
    }
    It "computes a normal percentage as a scalar int" {
        (Get-SafeProgressPercent -Current 1 -Total 4) | Should -Be 25
    }
    It "collapses an array-shaped Total to a scalar (guards int / array division)" {
        { Get-SafeProgressPercent -Current 1 -Total (@(4)) } | Should -Not -Throw
        (Get-SafeProgressPercent -Current 1 -Total (@(4))) | Should -Be 25
    }
    It "clamps a negative result to 0" {
        Get-SafeProgressPercent -Current -5 -Total 100 | Should -Be 0
    }
    It "always yields a value Write-Progress -PercentComplete accepts (0..100)" {
        $p = Get-SafeProgressPercent -Current 999 -Total 3
        {
            Write-Progress -Activity 'test' -PercentComplete $p -Id 99
            Write-Progress -Activity 'test' -Id 99 -Completed
        } | Should -Not -Throw
    }
}

Describe "Check error records capture a script stack trace" {
    It "records Status=Error and a non-empty StackTrace when a check throws" {
        $script:State = Initialize-AzureAuditState
        $script:State = Initialize-EntraAuditState -State $script:State
        $script:State.Config.Quiet = $true

        function global:Test-ThrowsCheck {
            param([array]$Subscriptions, [hashtable]$Exclusions, [int]$ProgressId = 0)
            throw "Argument types do not match"
        }
        Register-AuditCheck -CheckId 'THROW-01' -Category 'Azure' -Service 'Storage' -Name 'thrower' -Function 'Test-ThrowsCheck' -Phase 'PerSubscription'

        $sub = ConvertTo-AzureMapSubscription -InputObject ([PSCustomObject]@{ Id='S1'; Name='n1'; TenantId='T1' })
        Invoke-AuditChecks -Phase PerSubscription -Subscriptions $sub -Exclusions @{} -Services @('All')

        $rec = @($script:State.ExecutedChecks | Where-Object { $_.CheckId -eq 'THROW-01' })[0]
        $rec.Status              | Should -Be 'Error'
        $rec.StackTrace          | Should -Not -BeNullOrEmpty
        "$($rec.StackTrace)"     | Should -BeLike '*Test-ThrowsCheck*'
    }
}

Describe "RBAC helper avoids Microsoft Graph and flags NotEvaluated" {
    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State = Initialize-EntraAuditState -State $script:State
        $script:State.Config.Quiet = $true
        $script:GraphWasCalled = $false
        function global:Get-GraphToken { param([switch]$ForceRefresh) $script:GraphWasCalled = $true; 'stub-token' }
    }

    It "does not acquire a Graph token while reading RBAC assignments" {
        function global:Get-AzRoleAssignment { param([Parameter(ValueFromRemainingArguments)]$r) @() }
        $null = Get-SubscriptionRBACAssignments -SubscriptionId 'S1' -SubscriptionName 'n1'
        $script:GraphWasCalled | Should -BeFalse
        $script:State.Cache.RBACUnavailable['S1'] | Should -BeFalse
    }

    It "flags the subscription NotEvaluated (empty, unavailable) on a Graph auth error, without calling Connect-AzAccount" {
        function global:Connect-AzAccount { param([Parameter(ValueFromRemainingArguments)]$r) throw "Connect-AzAccount must not be called" }
        function global:Get-AzRoleAssignment {
            param([Parameter(ValueFromRemainingArguments)]$r)
            throw "Authentication failed against resource MicrosoftGraphEndpointResourceId"
        }
        $res = Get-SubscriptionRBACAssignments -SubscriptionId 'S2' -SubscriptionName 'n2'
        @($res).Count | Should -Be 0
        $script:State.Cache.RBACUnavailable['S2'] | Should -BeTrue
    }
}

Describe "PASS findings are recorded for export but quiet on the console" {
    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State = Initialize-EntraAuditState -State $script:State
        $script:State.Config.Quiet         = $false
        $script:State.Config.VerboseOutput = $true
        $script:State.Config.DebugOutput   = $false
    }

    It "records a Count=0 PASS finding in Results (CSV/JSON export unchanged)" {
        Write-Finding -Severity 'INFO' -Message 'No public exposure identified' -Count 0 -Service 'Exposure' -Status 'PASS'
        @($script:State.Results | Where-Object { $_.Finding -eq 'No public exposure identified' }).Count | Should -Be 1
    }

    It "still records a real FAIL finding" {
        Write-Finding -Severity 'HIGH' -Message 'exposed resource' -Count 3 -Data @(1,2,3) -Service 'Storage'
        @($script:State.Results | Where-Object { $_.Finding -eq 'exposed resource' }).Count | Should -Be 1
    }
}

Describe "Top Findings dedup renders without error" {
    It "groups duplicate identical findings and renders without throwing" {
        $script:State = Initialize-AzureAuditState
        $script:State = Initialize-EntraAuditState -State $script:State
        $script:State.Config.Quiet = $false
        1..3 | ForEach-Object {
            Write-Finding -Severity 'HIGH' -Message 'duplicate finding across subs' -Count 2 -Data @(1,2) -Service 'Network' -SubscriptionId 'Multiple'
        }
        { Show-AuditConsole -ExportedFiles @() } | Should -Not -Throw
    }
}
