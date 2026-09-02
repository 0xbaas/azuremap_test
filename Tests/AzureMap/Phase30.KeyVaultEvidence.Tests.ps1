#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase30.KeyVaultEvidence.Tests.ps1
# Key Vault evidence split (reliability+parity pass, chunk A):
# every KEYVAULT-002 finding carries ONLY the vaults matching its own property
# (publicNetworkAccess / firewall defaultAction / correlation / purge /
# critical-no-PE / audit logging), and unknown/failed reads become
# NotEvaluated - never Clean. Mocked/local only. No Azure, no secret values.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Products\AzureMap\Core\InventoryCache.ps1"
    . "$projectRoot\Products\AzureMap\Checks\KeyVault.ps1"

    function global:Set-AzContext { param([Parameter(ValueFromRemainingArguments)]$r) }
    function global:Get-AzContext { $null }
    function global:Get-AzKeyVault {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxVaultsThrow) { throw "403 AuthorizationFailed listing vaults" }
        $global:FxVaults
    }
    function global:Get-AzPrivateEndpoint { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxPEs }
    function global:Get-AzDiagnosticSetting {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxDiagThrow) { throw "403 AuthorizationFailed reading diagnostic settings" }
        $global:FxDiag
    }

    function global:New-KV {
        param([hashtable]$Props = @{})
        $base = @{
            VaultName              = 'kv1'
            ResourceGroupName      = 'rg1'
            ResourceId             = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1'
            EnableRbacAuthorization = $true
            EnablePurgeProtection  = $true
            Tags                   = @{}
            NetworkAcls            = [PSCustomObject]@{ DefaultAction='Deny'; Bypass='AzureServices'; IpAddressRanges=@(); VirtualNetworkResourceIds=@() }
            # PublicNetworkAccess intentionally absent by default (= unspecified).
        }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [PSCustomObject]$base
    }

    function script:Get-Fin {
        param([string]$Like)
        # Plain emission (no comma-return): @(Get-Fin ...).Count must be 0 when
        # nothing matches; `return ,$items` would yield a single nested-array
        # element and break count assertions.
        $items = @()
        foreach ($item in $script:State.Results) {
            if ("$($item.Finding)" -like $Like) { $items += $item }
        }
        return $items
    }
    function script:Get-NotEval {
        $items = @()
        foreach ($item in $script:State.Results) {
            if ("$($item.Status)".ToUpperInvariant() -eq 'NOTEVALUATED') { $items += $item }
        }
        return $items
    }

    $global:FxSub = [PSCustomObject]@{ Id='S1'; Name='n1'; TenantId='T1' }
}

Describe "Key Vault evidence split (KEYVAULT-001/002)" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $global:FxVaults      = @()
        $global:FxVaultsThrow = $false
        $global:FxPEs         = @()
        $global:FxDiag        = @()
        $global:FxDiagThrow   = $false
    }

    Context "(a) publicNetworkAccess" {
        It "Enabled -> finding with ONLY the enabled vault as evidence" {
            $global:FxVaults = @(
                (New-KV @{ PublicNetworkAccess='Enabled' })
                (New-KV @{ VaultName='kv2'; PublicNetworkAccess='Disabled' })
            )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*public network access enabled or unspecified*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
            @($m[0].Evidence).Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
            "$($m[0].Severity)" | Should -Be 'MEDIUM'
        }
        It "Disabled -> no public-network-access finding" {
            $global:FxVaults = @( (New-KV @{ PublicNetworkAccess='Disabled' }) )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*public network access enabled or unspecified*').Count | Should -Be 0
        }
        It "absent/unspecified -> flagged (defaults to enabled), never silently clean" {
            $global:FxVaults = @( (New-KV @{}) )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*public network access enabled or unspecified*')
            $m.Count | Should -Be 1
            "$($m[0].Evidence[0].PublicNetworkAccess)" | Should -BeLike 'Unspecified*'
        }
    }

    Context "(b) firewall defaultAction" {
        It "Allow -> finding with ONLY the Allow vault" {
            $global:FxVaults = @(
                (New-KV @{ NetworkAcls=[PSCustomObject]@{ DefaultAction='Allow'; IpAddressRanges=@(); VirtualNetworkResourceIds=@() } })
                (New-KV @{ VaultName='kv2' })
            )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*firewall default action Allow*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
        }
        It "Deny -> no default-action finding" {
            $global:FxVaults = @( (New-KV @{}) )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*firewall default action Allow*').Count | Should -Be 0
        }
        It "networkAcls unreadable (null) -> NotEvaluated, never Clean" {
            $global:FxVaults = @( (New-KV @{ NetworkAcls=$null }) )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(Get-NotEval)
            $ne.Count | Should -BeGreaterThan 0
            (($ne.Evidence.Reason) -join ' ') | Should -BeLike '*networkAcls*'
            @(Get-Fin '*firewall default action Allow*').Count | Should -Be 0
        }
    }

    Context "(c) correlation: public access + firewall default Allow" {
        It "CRITICAL finding contains ONLY vaults matching BOTH properties" {
            $global:FxVaults = @(
                # matches both -> CRITICAL evidence
                (New-KV @{ VaultName='kv-both'; PublicNetworkAccess='Enabled'; NetworkAcls=[PSCustomObject]@{ DefaultAction='Allow'; IpAddressRanges=@(); VirtualNetworkResourceIds=@() } })
                # firewall restricted -> NOT in the correlation evidence
                (New-KV @{ VaultName='kv-deny'; PublicNetworkAccess='Enabled' })
                # private endpoint -> NOT in the correlation evidence
                (New-KV @{ VaultName='kv-priv'; PublicNetworkAccess='Disabled'; EnablePurgeProtection=$false; NetworkAcls=[PSCustomObject]@{ DefaultAction='Allow'; IpAddressRanges=@(); VirtualNetworkResourceIds=@() } })
            )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*public access and no firewall restrictions*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'CRITICAL'
            [int]$m[0].Count | Should -Be 1
            @($m[0].Evidence).Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv-both'
            # the purge-only vault must not bleed into the network evidence
            "$($m[0].Evidence.VaultName -join ',')" | Should -Not -BeLike '*kv-priv*'
        }
    }

    Context "(d) purge protection" {
        It "false -> HIGH finding; true -> none" {
            $global:FxVaults = @(
                (New-KV @{ EnablePurgeProtection=$false })
                (New-KV @{ VaultName='kv2'; EnablePurgeProtection=$true })
            )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*without purge protection*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'HIGH'
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
        }
    }

    Context "(e) legacy access-policy model (KEYVAULT-001)" {
        It "EnableRbacAuthorization false -> finding with only that vault" {
            $global:FxVaults = @(
                (New-KV @{ EnableRbacAuthorization=$false })
                (New-KV @{ VaultName='kv2'; EnableRbacAuthorization=$true })
            )
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*legacy access policies*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
        }
        It "EnableRbacAuthorization absent (null) -> still flagged (never silently clean)" {
            $kv = New-KV @{}
            $kv.PSObject.Properties.Remove('EnableRbacAuthorization')
            $global:FxVaults = @( $kv )
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*legacy access policies*').Count | Should -Be 1
        }
        It "EnableRbacAuthorization true -> no finding" {
            $global:FxVaults = @( (New-KV @{ EnableRbacAuthorization=$true }) )
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*legacy access policies*').Count | Should -Be 0
        }
    }

    Context "(f) critical vault without private endpoint" {
        It "critical name + no PE -> MEDIUM finding" {
            $global:FxVaults = @( (New-KV @{ VaultName='kv-prod-secrets' }) )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*without private endpoints*')
            $m.Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv-prod-secrets'
        }
        It "non-critical name -> no finding" {
            $global:FxVaults = @( (New-KV @{ VaultName='kv1' }) )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*without private endpoints*').Count | Should -Be 0
        }
    }

    Context "(g) audit logging (diagnostic settings)" {
        It "no diagnostic settings -> finding" {
            $global:FxVaults = @( (New-KV @{}) )
            $global:FxDiag   = @()
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*without audit logging*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
        }
        It "enabled AuditEvent logs -> no finding" {
            $global:FxVaults = @( (New-KV @{}) )
            $global:FxDiag   = @( [PSCustomObject]@{ Logs = @( [PSCustomObject]@{ Category='AuditEvent'; Enabled=$true } ) } )
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*without audit logging*').Count | Should -Be 0
        }
        It "diagnostic read failure -> NotEvaluated, never Clean" {
            $global:FxVaults    = @( (New-KV @{}) )
            $global:FxDiagThrow = $true
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(Get-NotEval)
            $ne.Count | Should -BeGreaterThan 0
            (($ne.Evidence.Reason) -join ' ') | Should -BeLike '*Diagnostic settings could not be read*'
            @(Get-Fin '*without audit logging*').Count | Should -Be 0
        }
    }

    Context "failed collection" {
        It "vault listing throws -> explicit NOTEVALUATED record (never silence/Clean)" {
            $global:FxVaultsThrow = $true
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(Get-NotEval)
            $ne.Count | Should -Be 1
            [int]$ne[0].Count | Should -Be 1
            $ne[0].CountType | Should -Be 'NotEvaluatedItems'
            (($ne[0].Evidence.Reason) -join ' ') | Should -BeLike '*collection failed*'
            # no property finding may claim a result
            @(Get-Fin '*firewall default action Allow*').Count | Should -Be 0
            @(Get-Fin '*without purge protection*').Count | Should -Be 0
        }
    }
}
