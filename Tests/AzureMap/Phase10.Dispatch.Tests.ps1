#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase10.Dispatch.Tests.ps1
# Regression tests for the two live-smoke blockers:
#   * PerSubscription dispatch forwards typed subscription values (string Id /
#     object) and Set-SubscriptionContext coerces defensively.
#   * Graph interactive/MFA/Conditional-Access auth errors classify as
#     Authentication and do NOT retry (shared Retry classifier).
# The -SkipEntra collection-gating regressions moved with the parked product
# to Future/EntraMap/Tests/Phase1.SkipEntra.Tests.ps1.
# Mocked/local only. No live Azure/Graph, no auth.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"

    $script:State = Initialize-AzureAuditState
    $script:State = Initialize-EntraAuditState -State $script:State
    $script:State.Config.Quiet = $true

    # Fake per-subscription checks capturing what the engine forwarded.
    function global:Test-CaptureSubId  { param([string]$SubscriptionId) $global:CapSubId = $SubscriptionId }
    function global:Test-CaptureSubObj { param($Subscription)           $global:CapSubObj = $Subscription }

    # Az stubs for the context-coercion and auth-classification regressions.
    function Connect-AzAccount      { param([Parameter(ValueFromRemainingArguments)]$r) }
    function Set-AzContext          { param([string]$SubscriptionId, [string]$TenantId, [Parameter(ValueFromRemainingArguments)]$r) }

    $script:NormSub = ConvertTo-AzureMapSubscription -InputObject ([PSCustomObject]@{ Id='S1'; Name='n1'; TenantId='T1' })
}

Describe "PerSubscription dispatch - typed forwarding" {
    BeforeEach {
        $script:State.CheckRegistry.Clear()
        Remove-Variable -Name CapSubId  -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name CapSubObj -Scope Global -ErrorAction SilentlyContinue
    }

    It '1. check declaring [string]$SubscriptionId receives only the string Id' {
        Register-AuditCheck -CheckId 'DISP-01' -Category 'Azure' -Service 'Storage' -Name 'cap' -Function 'Test-CaptureSubId' -Phase 'PerSubscription'
        $null = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions $script:NormSub -Exclusions @{} -Services @('All')
        $global:CapSubId | Should -Be 'S1'
        $global:CapSubId | Should -BeOfType [string]
    }

    It '2. check declaring $Subscription receives the normalized object' {
        Register-AuditCheck -CheckId 'DISP-02' -Category 'Azure' -Service 'Storage' -Name 'cap' -Function 'Test-CaptureSubObj' -Phase 'PerSubscription'
        $null = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions $script:NormSub -Exclusions @{} -Services @('All')
        $global:CapSubObj      | Should -Not -BeNullOrEmpty
        $global:CapSubObj.Id   | Should -Be 'S1'
        $global:CapSubObj.Name | Should -Be 'n1'
    }

    It '3. [string]$SubscriptionId never receives a PSCustomObject' {
        Register-AuditCheck -CheckId 'DISP-03' -Category 'Azure' -Service 'Storage' -Name 'cap' -Function 'Test-CaptureSubId' -Phase 'PerSubscription'
        $null = Invoke-AzureMapCheck -Check $script:State.CheckRegistry[0] -Subscriptions $script:NormSub -Exclusions @{} -Services @('All')
        $global:CapSubId.GetType().Name | Should -Be 'String'
    }
}

Describe "Set-SubscriptionContext - defensive coercion" {
    BeforeEach { Mock Set-AzContext { } }

    It "accepts a plain string id" {
        (Set-SubscriptionContext -SubscriptionId 'S1' -SubscriptionName 'n1') | Should -BeTrue
        Should -Invoke Set-AzContext -Times 1 -ParameterFilter { $SubscriptionId -eq 'S1' }
    }

    It "coerces a subscription OBJECT to its scalar Id (no transformation error)" {
        $obj = [PSCustomObject]@{ Id='S1'; Name='n1' }
        { Set-SubscriptionContext -SubscriptionId $obj -SubscriptionName 'n1' } | Should -Not -Throw
        Should -Invoke Set-AzContext -Times 1 -ParameterFilter { $SubscriptionId -eq 'S1' }
    }

    It "coerces a single-element array id to a scalar string" {
        { Set-SubscriptionContext -SubscriptionId @('S1') -SubscriptionName 'n1' } | Should -Not -Throw
        Should -Invoke Set-AzContext -Times 1 -ParameterFilter { $SubscriptionId -eq 'S1' }
    }

    It "returns false (no throw) when the id cannot be resolved" {
        { Set-SubscriptionContext -SubscriptionId $null -SubscriptionName 'n1' } | Should -Not -Throw
        (Set-SubscriptionContext -SubscriptionId $null) | Should -BeFalse
    }
}

Describe "ConvertTo-AzureMapSubscription - scalarization" {
    It "yields a scalar-string Id even if the source .Id is an array" {
        $out = ConvertTo-AzureMapSubscription -InputObject ([PSCustomObject]@{ Id=@('S9'); Name='n9' })
        $out[0].Id | Should -Be 'S9'
        $out[0].Id | Should -BeOfType [string]
    }
}

Describe "Graph interactive/MFA auth error classification" {
    It "classifies the interactive/MFA/Conditional-Access failure as Authentication" {
        $msg = "Authentication failed against resource https://graph.microsoft.com. User interaction is required. To sign in, rerun Connect-AzAccount -AuthScope https://graph.microsoft.com"
        $err = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new($msg), 'x',
            [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
        (Get-ErrorClass -ErrorRecord $err).Class | Should -Be 'Authentication'
    }

    It "does not retry an Authentication error (no 2s/4s loop) and never calls Connect-AzAccount" {
        $script:State = Initialize-AzureAuditState
        $script:State = Initialize-EntraAuditState -State $script:State
        $script:State.Config.Quiet = $true
        Mock Connect-AzAccount { }
        $script:Attempts = 0
        $threw = $false
        try {
            Invoke-AzureCommand -CommandName 'GraphToken' -Critical -SkipContextCheck -Command {
                $script:Attempts++
                throw (New-Object System.Exception "Authentication failed against resource https://graph.microsoft.com. User interaction is required. rerun Connect-AzAccount -AuthScope https://graph.microsoft.com")
            }
        } catch { $threw = $true }

        $threw           | Should -BeTrue
        $script:Attempts | Should -Be 1        # invoked once => no retry loop
        Should -Not -Invoke Connect-AzAccount
    }
}
