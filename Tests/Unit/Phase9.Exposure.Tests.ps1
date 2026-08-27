#==============================================================================
# Phase 9 - AZURE-EXPOSURE-001 Public exposure inventory. Mocked/local only.
# Verifies control-plane only: no active scanning / web requests / data-plane.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Core\Azure\Rbac.ps1"
    . "$projectRoot\Core\Retry.ps1"
    . "$projectRoot\Core\Azure\InventoryCache.ps1"
    . "$projectRoot\Checks\Azure\Exposure.ps1"

    $script:State = Initialize-AzureAuditState
    $script:State.Config.Quiet = $true
    $script:Subs = @([PSCustomObject]@{ Id='s1'; Name='sub1' })

    foreach ($c in 'Get-AzPublicIpAddress','Get-AzStorageAccount','Get-AzNetworkSecurityGroup','Get-AzWebApp','Get-AzSqlServer','Get-AzKeyVault','Invoke-WebRequest','Invoke-RestMethod') {
        Set-Item -Path "function:global:$c" -Value ([scriptblock]::Create('param([Parameter(ValueFromRemainingArguments)]$r)'))
    }

    function New-Nsg { param([object[]]$Rules) [PSCustomObject]@{ Name='nsg1'; Id='/subs/s1/nsg1'; SecurityRules=@($Rules) } }
    function New-Rule { param([string]$Port) [PSCustomObject]@{ Name="r$Port"; Access='Allow'; Direction='Inbound'; SourceAddressPrefix='Internet'; DestinationPortRange=$Port } }
}

Describe "AZURE-EXPOSURE-001 Public exposure inventory" {
    BeforeEach {
        $script:State.Results.Clear()
        # Per-test isolation: State is created once in BeforeAll, so the per-run
        # inventory cache must be reset explicitly between tests.
        $script:State.Cache.ResourceLists = @{}
        Mock Set-SubscriptionContext { $true }
        Mock Get-AzPublicIpAddress { @() }
        Mock Get-AzStorageAccount { @() }
        Mock Get-AzNetworkSecurityGroup { @() }
        Mock Get-AzWebApp { @() }
        Mock Get-AzSqlServer { @() }
        Mock Get-AzKeyVault { @() }
        Mock Invoke-WebRequest { }
        Mock Invoke-RestMethod { }
    }

    It "records a public IP as INFO inventory (not a FAIL finding)" {
        Mock Get-AzPublicIpAddress { @( [PSCustomObject]@{ Name='pip1'; Id='/subs/s1/pip1'; IpAddress='203.0.113.10' } ) }
        Test-PublicExposureInventory -Subscriptions $script:Subs
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'PASS'
        $f.Severity | Should -Be 'INFO'
        $f.IsInventoryOnly | Should -BeTrue
        ($f.Evidence.ResourceType -join ',') | Should -BeLike '*PublicIP*'
        Should -Not -Invoke Invoke-WebRequest
        Should -Not -Invoke Invoke-RestMethod
    }

    It "records storage public network access as INFO inventory" {
        Mock Get-AzStorageAccount { @( [PSCustomObject]@{ StorageAccountName='sa1'; Id='/subs/s1/sa1'; PublicNetworkAccess='Enabled' } ) }
        Test-PublicExposureInventory -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'PASS'
        $script:State.Results[-1].IsInventoryOnly | Should -BeTrue
    }

    It "records NSG inbound sensitive port from Internet as INFO inventory" {
        Mock Get-AzNetworkSecurityGroup { @( (New-Nsg -Rules @((New-Rule '3389'))) ) }
        Test-PublicExposureInventory -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'PASS'
        (($script:State.Results[-1].Evidence.ExposureType) -join ' ') | Should -BeLike '*3389*'
    }

    It "de-duplicates identical exposures" {
        Mock Get-AzNetworkSecurityGroup { @( (New-Nsg -Rules @((New-Rule '3389'),(New-Rule '3389'))) ) }
        Test-PublicExposureInventory -Subscriptions $script:Subs
        $script:State.Results[-1].Count | Should -Be 1
    }

    It "PASSes when all sources collected and nothing exposed" {
        Test-PublicExposureInventory -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'PASS'
    }

    It "is NotEvaluated when all sources fail" {
        Mock Get-AzPublicIpAddress { throw 'x' }
        Mock Get-AzStorageAccount { throw 'x' }
        Mock Get-AzNetworkSecurityGroup { throw 'x' }
        Mock Get-AzWebApp { throw 'x' }
        Mock Get-AzSqlServer { throw 'x' }
        Mock Get-AzKeyVault { throw 'x' }
        Test-PublicExposureInventory -Subscriptions $script:Subs
        $script:State.Results[-1].Status | Should -Be 'NotEvaluated'
    }

    It "captures partial evaluation when some sources fail but exposure found" {
        Mock Get-AzPublicIpAddress { @( [PSCustomObject]@{ Name='pip1'; Id='/subs/s1/pip1'; IpAddress='203.0.113.10' } ) }
        Mock Get-AzKeyVault { throw 'kv fail' }
        Test-PublicExposureInventory -Subscriptions $script:Subs
        $f = $script:State.Results[-1]
        $f.Status | Should -Be 'PASS'
        $f.IsInventoryOnly | Should -BeTrue
        ($f.Evidence | ConvertTo-Json -Depth 6) | Should -BeLike '*PartialEvaluation*'
    }

    It "registers AZURE-EXPOSURE-001" {
        $script:State.CheckRegistry.Clear()
        Register-AzureExposureChecks
        ($script:State.CheckRegistry.CheckId) | Should -Contain 'AZURE-EXPOSURE-001'
    }
}
