#==============================================================================
# Phase 9 - AZURE-GOV-001 Defender/Policy coverage. Mocked/local only.
# No writes, no Graph.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Governance.ps1"

    $script:State = Initialize-AzureAuditState
    $script:State.Config.Quiet = $true
    $script:Subs = @([PSCustomObject]@{ Id='s1'; Name='sub1' })

    function Invoke-AzRestMethod   { param([Parameter(ValueFromRemainingArguments)]$r) }
    function Get-AzPolicyAssignment { param([Parameter(ValueFromRemainingArguments)]$r) }
    function Invoke-GraphCommand    { param([Parameter(ValueFromRemainingArguments)]$r) }

    $script:AllPlans = @('VirtualMachines','StorageAccounts','SqlServers','Containers','KeyVaults','AppServices')
    function New-Pricing {
        param([string]$DefaultTier='Standard', [hashtable]$Overrides=@{})
        $vals = foreach ($n in $script:AllPlans) {
            $tier = if ($Overrides.ContainsKey($n)) { $Overrides[$n] } else { $DefaultTier }
            @{ name=$n; properties=@{ pricingTier=$tier } }
        }
        [PSCustomObject]@{ StatusCode=200; Content=(@{ value=$vals } | ConvertTo-Json -Depth 5) }
    }
}

Describe "AZURE-GOV-001 Defender/Policy coverage" {
    BeforeEach {
        $script:State.Results.Clear()
        Mock Set-SubscriptionContext { $true }
        Mock Get-AzPolicyAssignment { @( [PSCustomObject]@{ Name='baseline' } ) }
        Mock Invoke-GraphCommand { @() }
    }

    It "FAILs when an important Defender plan is not Standard" {
        Mock Invoke-AzRestMethod { New-Pricing -Overrides @{ VirtualMachines='Free' } }
        Test-DefenderAndPolicyCoverage -Subscriptions $script:Subs
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'FAIL'
        ($f.Evidence.Plan -join ',') | Should -BeLike '*VirtualMachines*'
        Should -Not -Invoke Invoke-GraphCommand
    }

    It "PASSes when important plans are Standard and policy assignments exist" {
        Mock Invoke-AzRestMethod { New-Pricing }
        Test-DefenderAndPolicyCoverage -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'PASS'
    }

    It "FAILs when there are no policy assignments" {
        Mock Invoke-AzRestMethod { New-Pricing }
        Mock Get-AzPolicyAssignment { @() }
        Test-DefenderAndPolicyCoverage -Subscriptions $script:Subs
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'FAIL'
        (($f.Evidence.Control) -join ' ') | Should -BeLike '*PolicyAssignment*'
    }

    It "is NotEvaluated on REST failure (exception)" {
        Mock Invoke-AzRestMethod { throw '500' }
        Test-DefenderAndPolicyCoverage -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "is NotEvaluated on REST failure (>=400 status)" {
        Mock Invoke-AzRestMethod { [PSCustomObject]@{ StatusCode=403; Content='{}' } }
        Test-DefenderAndPolicyCoverage -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "registers AZURE-GOV-001" {
        $script:State.CheckRegistry.Clear()
        Register-AzureGovernanceChecks
        ($script:State.CheckRegistry.CheckId) | Should -Contain 'AZURE-GOV-001'
    }
}
