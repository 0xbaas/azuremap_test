#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase34.KeyVaultAbsentProperty.Tests.ps1
# Key Vault per-vault enrichment + absent-property contract:
# the list view does not populate NetworkAcls / EnableRbacAuthorization /
# EnablePurgeProtection, so the inventory fetch re-reads each vault with a
# per-vault GET and tags it AzureMapEnriched=$true. Checks must only FAIL on
# properties that were actually read: unenriched (GET failed) or absent
# properties become precise per-vault NOTEVALUATED evidence (LOW/INFO, never
# CRITICAL/HIGH), never a FAIL and never silently clean. Mocked/local only.
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
        param([string]$VaultName, [string]$ResourceGroupName, [Parameter(ValueFromRemainingArguments)]$r)
        # Enriched flow: per-vault GET (-VaultName) returns the matching full
        # vault object, or throws for vaults whose enrichment is denied; the
        # bare list call returns the list-view objects.
        if ($VaultName) {
            if ($global:FxVaultGetDeny -contains $VaultName) { throw "403 AuthorizationFailed reading vault $VaultName" }
            $m = @($global:FxVaults | Where-Object { $_.VaultName -eq $VaultName })
            if ($global:FxVaultsFull -and $global:FxVaultsFull.ContainsKey($VaultName)) {
                return $global:FxVaultsFull[$VaultName]
            }
            if ($m.Count -gt 0) { return $m[0] }
            throw "ResourceNotFound: vault $VaultName not found"
        }
        if ($global:FxVaultsThrow) { throw "403 AuthorizationFailed listing vaults" }
        $global:FxVaults
    }
    function global:Get-AzPrivateEndpoint { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxPEs }
    function global:Get-AzDiagnosticSetting { param([Parameter(ValueFromRemainingArguments)]$r) $global:FxDiag }

    # List-view shape: only what plain Get-AzKeyVault populates. None of the
    # security-relevant properties (NetworkAcls / RBAC / purge) are present.
    function global:New-KVListView {
        param([string]$Name = 'kv1')
        [PSCustomObject]@{
            VaultName         = $Name
            ResourceGroupName = 'rg1'
            ResourceId        = "/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/$Name"
            Location          = 'westeurope'
            Tags              = @{}
        }
    }
    # Full (per-vault GET) shape: all security properties explicitly set.
    function global:New-KVFull {
        param([hashtable]$Props = @{})
        $base = @{
            VaultName              = 'kv1'
            ResourceGroupName      = 'rg1'
            ResourceId             = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1'
            EnableRbacAuthorization = $true
            EnablePurgeProtection  = $true
            PublicNetworkAccess    = 'Disabled'
            Tags                   = @{}
            NetworkAcls            = [PSCustomObject]@{ DefaultAction='Deny'; Bypass='AzureServices'; IpAddressRanges=@(); VirtualNetworkResourceIds=@() }
        }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [PSCustomObject]$base
    }

    function script:Get-Fin {
        param([string]$Like)
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

Describe "Key Vault enrichment and absent-property contract (Phase34)" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        $global:FxVaults       = @()
        $global:FxVaultsFull   = $null
        $global:FxVaultsThrow  = $false
        $global:FxVaultGetDeny = @()
        $global:FxPEs          = @()
        # Audit logging aspect quiet by default (enabled AuditEvent log).
        $global:FxDiag         = @( [PSCustomObject]@{ Logs = @( [PSCustomObject]@{ Category='AuditEvent'; Enabled=$true } ) } )
    }

    Context "inventory enrichment fetch" {
        It "successful per-vault GETs tag items AzureMapEnriched and carry full properties" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = (New-KVFull @{}) }
            $inv = Get-SubscriptionInventory -SubscriptionId $global:FxSub.Id -SubscriptionName $global:FxSub.Name -TenantId 'T1' -Kind KeyVaults
            $inv.Unavailable | Should -BeFalse
            @($inv.Items).Count | Should -Be 1
            $inv.Items[0].AzureMapEnriched | Should -BeTrue
            $inv.Items[0].EnableRbacAuthorization | Should -BeTrue
            "$($inv.Items[0].NetworkAcls.DefaultAction)" | Should -Be 'Deny'
        }

        It "failed per-vault GET keeps the list-view object (no marker) and never fails the fetch" {
            $global:FxVaults = @( (New-KVListView 'kv1'), (New-KVListView 'kv2') )
            $global:FxVaultsFull = @{ kv2 = (New-KVFull @{ VaultName='kv2' }) }
            $global:FxVaultGetDeny = @('kv1')
            $inv = Get-SubscriptionInventory -SubscriptionId $global:FxSub.Id -SubscriptionName $global:FxSub.Name -TenantId 'T1' -Kind KeyVaults
            $inv.Unavailable | Should -BeFalse
            @($inv.Items).Count | Should -Be 2
            $kv1 = @($inv.Items | Where-Object { $_.VaultName -eq 'kv1' })[0]
            $kv2 = @($inv.Items | Where-Object { $_.VaultName -eq 'kv2' })[0]
            ($kv1.PSObject.Properties.Name -contains 'AzureMapEnriched') | Should -BeFalse
            $kv2.AzureMapEnriched | Should -BeTrue
        }
    }

    Context "KEYVAULT-001 RBAC authorization model" {
        It "unenriched vault (GET failed) -> NOTEVALUATED, NO legacy access policy FAIL" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultGetDeny = @('kv1')
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*legacy access policies*').Count | Should -Be 0
            $ne = @(Get-NotEval)
            $ne.Count | Should -Be 1
            (($ne.Evidence.Reason) -join ' ') | Should -BeLike '*RBAC authorization model could not be read*'
            "$($ne[0].Severity)" | Should -Be 'LOW'
        }

        It "enriched vault with EnableRbacAuthorization=false -> legacy access policy FAIL" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = (New-KVFull @{ EnableRbacAuthorization=$false }) }
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*legacy access policies*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
            @(Get-NotEval).Count | Should -Be 0
        }

        It "enriched vault with EnableRbacAuthorization=true -> clean (no FAIL, no NOTEVALUATED)" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = (New-KVFull @{ EnableRbacAuthorization=$true }) }
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*legacy access policies*').Count | Should -Be 0
            @(Get-NotEval).Count | Should -Be 0
        }

        It "a vault never appears in both FAIL and NOTEVALUATED for the RBAC property" {
            $global:FxVaults = @( (New-KVListView 'kv-fail'), (New-KVListView 'kv-unknown') )
            $global:FxVaultsFull = @{ 'kv-fail' = (New-KVFull @{ VaultName='kv-fail'; EnableRbacAuthorization=$false }) }
            $global:FxVaultGetDeny = @('kv-unknown')
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            $fail = @(Get-Fin '*legacy access policies*')
            $ne   = @(Get-NotEval)
            $fail.Count | Should -Be 1
            $ne.Count | Should -Be 1
            $failNames = @($fail.Evidence | ForEach-Object { "$($_.VaultName)" })
            $neNames   = @($ne.Evidence   | ForEach-Object { "$($_.VaultName)" })
            $failNames | Should -Contain 'kv-fail'
            $neNames   | Should -Contain 'kv-unknown'
            @($failNames | Where-Object { $neNames -contains $_ }).Count | Should -Be 0
        }
    }

    Context "KEYVAULT-002 aspect (d) purge protection" {
        It "unenriched vault -> purge NOTEVALUATED, NO purge FAIL" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultGetDeny = @('kv1')
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*without purge protection*').Count | Should -Be 0
            $ne = @(Get-NotEval)
            $ne.Count | Should -BeGreaterThan 0
            (($ne.Evidence.Reason) -join ' ') | Should -BeLike '*Purge protection state could not be read*'
        }

        It "enriched vault with EnablePurgeProtection=false -> purge protection FAIL" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = (New-KVFull @{ EnablePurgeProtection=$false }) }
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*without purge protection*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'HIGH'
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
        }

        It "enriched vault with EnablePurgeProtection=null -> purge protection FAIL (null = disabled)" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = (New-KVFull @{ EnablePurgeProtection=$null }) }
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*without purge protection*')
            $m.Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
        }

        It "enriched vault with EnablePurgeProtection=true -> no purge FAIL, no purge NOTEVALUATED" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = (New-KVFull @{ EnablePurgeProtection=$true }) }
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-Fin '*without purge protection*').Count | Should -Be 0
            $ne = @(Get-NotEval)
            (($ne.Evidence.Reason) -join ' ') | Should -Not -BeLike '*Purge protection*'
        }
    }

    Context "KEYVAULT-002 aspects (b)/(c) firewall" {
        It "vault without NetworkAcls -> NOTEVALUATED for the firewall aspect only" {
            # Full object minus NetworkAcls: purge/RBAC were read and are clean,
            # so the ONLY evaluation gap may be the firewall aspect.
            $full = New-KVFull @{}
            $full.PSObject.Properties.Remove('NetworkAcls')
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = $full }
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(Get-NotEval)
            $ne.Count | Should -BeGreaterThan 0
            $reasons = ($ne.Evidence.Reason) -join ' '
            $reasons | Should -BeLike '*networkAcls*'
            $reasons | Should -Not -BeLike '*Purge protection*'
            $reasons | Should -Not -BeLike '*RBAC authorization*'
            @(Get-Fin '*without purge protection*').Count | Should -Be 0
            @(Get-Fin '*firewall default action Allow*').Count | Should -Be 0
        }

        It "enriched vault with NetworkAcls.defaultAction=Allow -> firewall FAIL" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = (New-KVFull @{ NetworkAcls=[PSCustomObject]@{ DefaultAction='Allow'; IpAddressRanges=@(); VirtualNetworkResourceIds=@() } }) }
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin '*firewall default action Allow*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].VaultName)" | Should -Be 'kv1'
        }

        It "a vault never appears in both FAIL and NOTEVALUATED for the firewall property" {
            $global:FxVaults = @( (New-KVListView 'kv-allow'), (New-KVListView 'kv-unknown') )
            $global:FxVaultsFull = @{
                'kv-allow' = (New-KVFull @{ VaultName='kv-allow'; NetworkAcls=[PSCustomObject]@{ DefaultAction='Allow'; IpAddressRanges=@(); VirtualNetworkResourceIds=@() } })
            }
            $global:FxVaultGetDeny = @('kv-unknown')
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $fw = @(Get-Fin '*firewall default action Allow*')
            $fw.Count | Should -Be 1
            $fwNames = @($fw.Evidence | ForEach-Object { "$($_.VaultName)" })
            $neFirewallNames = @()
            foreach ($n in @(Get-NotEval)) {
                foreach ($e in @($n.Evidence)) {
                    if ("$($e.Reason)" -like '*networkAcls*') { $neFirewallNames += "$($e.VaultName)" }
                }
            }
            $fwNames | Should -Contain 'kv-allow'
            $neFirewallNames | Should -Contain 'kv-unknown'
            @($fwNames | Where-Object { $neFirewallNames -contains $_ }).Count | Should -Be 0
        }
    }

    Context "NOTEVALUATED presentation" {
        It "evaluation gaps are LOW/INFO, never CRITICAL/HIGH" {
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultGetDeny = @('kv1')
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            Test-KeyVaultRBAC -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(Get-NotEval)
            $ne.Count | Should -BeGreaterThan 0
            foreach ($n in $ne) {
                "$($n.Severity)".ToUpperInvariant() | Should -BeIn @('LOW', 'INFO')
            }
        }

        It "the finding message names the actual gap(s), not the umbrella text" {
            $full = New-KVFull @{}
            $full.PSObject.Properties.Remove('NetworkAcls')
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = $full }
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(Get-NotEval)
            $ne.Count | Should -BeGreaterThan 0
            "$($ne[0].Finding)" | Should -BeLike '*firewall configuration could not be read*'
            "$($ne[0].Finding)" | Should -Not -BeLike '*not reported as clean*'
            "$($ne[0].Finding)" | Should -Not -BeLike '*collection or property read failed*'
        }

        It "purge gap -> message names purge protection" {
            $full = New-KVFull @{}
            $full.PSObject.Properties.Remove('EnablePurgeProtection')
            $global:FxVaults = @( (New-KVListView 'kv1') )
            $global:FxVaultsFull = @{ kv1 = $full }
            Test-KeyVaultNetworkSecurity -Subscriptions @($global:FxSub) -Exclusions @{}
            $ne = @(Get-NotEval)
            (($ne.Evidence.Reason) -join ' ') | Should -BeLike '*Purge protection state could not be read*'
            "$($ne[0].Finding)" | Should -BeLike '*purge protection state could not be read*'
        }
    }
}
