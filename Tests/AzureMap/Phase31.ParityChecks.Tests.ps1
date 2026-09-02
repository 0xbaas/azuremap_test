#==============================================================================
# AzureMap v2 - Tests/AzureMap/Phase31.ParityChecks.Tests.ps1
# Colleague-parity checks (reliability+parity pass, chunk B):
#   IDENTITY-007  RBAC privileged assignment decomposition
#   COMPUTE-006   App Service FTP state
#   COMPUTE-007   VM backup coverage
#   NETWORK-009   App Gateway HTTP/TLS listener hygiene
#   NETWORK-010   Sensitive PaaS without private connectivity
#   MONITORING-004 Extended diagnostic settings coverage
#   STORAGE-007   Infrastructure (double) encryption
# Proves: risky fixtures FAIL, safe fixtures PASS, unknown/null state becomes
# NotEvaluated (never a false clean PASS), failed collection becomes
# NotEvaluated, and every check is registered with a curated display name.
# Mocked/local only. No live Azure, no Graph, no keys/secrets/content reads.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Shared\Core\State.ps1"
    . "$projectRoot\Shared\Core\Logging.ps1"
    . "$projectRoot\Shared\Core\Exclusions.ps1"
    . "$projectRoot\Shared\Core\Retry.ps1"
    . "$projectRoot\Shared\Core\RunStatus.ps1"
    . "$projectRoot\Shared\Core\CheckRegistry.ps1"
    . "$projectRoot\Shared\Core\Console.ps1"
    . "$projectRoot\Products\AzureMap\Core\Rbac.ps1"
    . "$projectRoot\Products\AzureMap\Core\InventoryCache.ps1"
    . "$projectRoot\Products\AzureMap\Core\ResourceGraph.ps1"
    . "$projectRoot\Products\AzureMap\Core\CheckCoverage.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Identity.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Compute.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Network.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Monitoring.ps1"
    . "$projectRoot\Products\AzureMap\Checks\Storage.ps1"

    function global:Set-AzContext {
        param([string]$SubscriptionId, [string]$TenantId, [Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxContextFailSubs -contains $SubscriptionId) { throw "no access to subscription $SubscriptionId" }
    }
    function global:Get-AzContext { $null }

    function global:Get-AzRoleAssignment {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxRbacThrow) { throw "403 AuthorizationFailed reading role assignments" }
        $global:FxRbac
    }
    function global:Get-AzWebApp {
        param([string]$ResourceGroupName, [string]$Name, [Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxWebAppsThrow) { throw "403 AuthorizationFailed listing web apps" }
        if ($Name) { return $global:FxWebAppDetail }
        $global:FxWebApps
    }
    function global:Get-AzApplicationGateway {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxAppGwThrow) { throw "403 AuthorizationFailed listing application gateways" }
        $global:FxAppGws
    }
    function global:Get-AzStorageAccount {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxAccountsThrow) { throw "403 AuthorizationFailed listing storage accounts" }
        $global:FxAccounts
    }
    function global:Get-AzKeyVault {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxKvThrow) { throw "403 AuthorizationFailed listing vaults" }
        $global:FxKVs
    }
    function global:Get-AzSqlServer {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxSqlThrow) { throw "403 AuthorizationFailed listing SQL servers" }
        $global:FxSqls
    }
    function global:Get-AzResource {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxGenericThrow) { throw "403 AuthorizationFailed listing generic resources" }
        $global:FxGeneric
    }
    function global:Get-AzContainerRegistry {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxAcrThrow) { throw "403 AuthorizationFailed listing registries" }
        $global:FxAcrs
    }
    function global:Get-AzServiceBusNamespace {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxSbThrow) { throw "403 AuthorizationFailed listing service bus namespaces" }
        $global:FxSbs
    }
    function global:Get-AzApiManagement {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxApimThrow) { throw "403 AuthorizationFailed listing APIM services" }
        $global:FxApims
    }
    function global:Get-AzNetworkSecurityGroup {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxNsgThrow) { throw "403 AuthorizationFailed listing NSGs" }
        $global:FxNsgs
    }
    function global:Get-AzPrivateEndpoint {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxPeThrow) { throw "403 AuthorizationFailed listing private endpoints" }
        $global:FxPEs
    }
    function global:Get-AzVM {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxVmThrow) { throw "403 AuthorizationFailed listing VMs" }
        $global:FxVMs
    }
    function global:Get-AzRecoveryServicesVault {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxVaultThrow) { throw "403 AuthorizationFailed listing recovery vaults" }
        $global:FxVaults
    }
    function global:Get-AzRecoveryServicesBackupItem {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxBackupItemThrow) { throw "403 AuthorizationFailed listing backup items" }
        $global:FxBackupItems
    }
    function global:Get-AzDiagnosticSetting {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxDiagThrow) { throw "403 AuthorizationFailed reading diagnostic settings" }
        $global:FxDiag
    }
    function global:Search-AzGraph {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxArgThrow) { throw "ARG unavailable" }
        $global:FxArgRows
    }
    function global:Invoke-AzRestMethod {
        param([Parameter(ValueFromRemainingArguments)]$r)
        if ($global:FxArgThrow) { throw "ARG unavailable" }
        $payload = @{ data = @($global:FxArgRows) } | ConvertTo-Json -Depth 6 -Compress
        [PSCustomObject]@{ StatusCode = 200; Content = $payload }
    }

    # ---- Fixture builders ----
    function global:New-RA {
        param([string]$Role, [string]$Scope, [string]$Type = 'User', [string]$Display = 'principal1', [string]$Oid = 'obj-1')
        [PSCustomObject]@{
            RoleDefinitionName = $Role; Scope = $Scope; ObjectType = $Type
            ObjectId = $Oid; DisplayName = $Display; RoleDefinitionId = "/defs/$Role"
        }
    }
    function global:New-App {
        param([hashtable]$Props = @{})
        $base = @{ Name = 'app1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.Web/sites/app1'; State = 'Running' }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [PSCustomObject]$base
    }
    function global:New-AppGw {
        param([hashtable]$Props = @{})
        $base = @{
            Name = 'agw1'; ResourceGroupName = 'rg1'; Id = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.Network/applicationGateways/agw1'
            HttpListeners = @(); RedirectConfigurations = @(); SslPolicy = $null; FrontendIPConfigurations = @()
        }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [PSCustomObject]$base
    }
    function global:New-Listener {
        param([string]$Name = 'l-http', [string]$Protocol = 'Http', [object]$Redirect = $null)
        [PSCustomObject]@{
            Name = $Name; Protocol = $Protocol
            Id = "/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.Network/applicationGateways/agw1/httpListeners/$Name"
            FrontendPort = [PSCustomObject]@{ Id = '/ports/80' }
            RedirectConfiguration = $Redirect
        }
    }
    function global:New-SA {
        param([hashtable]$Props = @{})
        $base = @{
            StorageAccountName = 'sa1'; ResourceGroupName = 'rg1'
            Id = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1'
            Tags = @{}
        }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [PSCustomObject]$base
    }
    function global:New-FxVm {
        param([string]$Name = 'vm1')
        [PSCustomObject]@{
            Name = $Name; ResourceGroupName = 'rg1'
            Id = "/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/$Name"
            PowerState = 'VM running'
        }
    }
    function global:New-PE {
        param([string]$LinkedResourceId)
        [PSCustomObject]@{
            Name = 'pe1'; ResourceGroupName = 'rg1'
            PrivateLinkServiceConnections = @([PSCustomObject]@{ PrivateLinkServiceId = $LinkedResourceId })
            ManualPrivateLinkServiceConnections = @()
        }
    }

    # Array-safe, script-scoped lookup helpers (plain emission - compose with @()).
    function script:Get-Fin {
        param([string]$CheckId)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ($item.CheckId -eq $CheckId) { $items += $item }
        }
        return $items
    }
    function script:Get-MainFin {
        param([string]$CheckId, [string]$Like)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ($item.CheckId -eq $CheckId -and "$($item.Finding)" -like $Like) { $items += $item }
        }
        return $items
    }
    function script:Get-NotEval {
        param([string]$CheckId)
        $items = @()
        foreach ($item in $script:State.Results) {
            if ($item.CheckId -eq $CheckId -and "$($item.Status)".ToUpperInvariant() -eq 'NOTEVALUATED') { $items += $item }
        }
        return $items
    }

    $global:FxSub = [PSCustomObject]@{ Id = 'S1'; Name = 'n1'; TenantId = 'T1' }
}

Describe "Phase31 colleague-parity checks" {

    BeforeEach {
        $script:State = Initialize-AzureAuditState
        $script:State.Config.Quiet = $true
        # Tests emulate an environment WITH cmdlet support (the stubs exist);
        # the missing-module cases preset these to $false explicitly.
        $script:AppServiceFtpSupported = $true
        $script:RecoveryServicesBackupSupported = $true
        $global:FxContextFailSubs = @()
        $global:FxRbac = @();            $global:FxRbacThrow = $false
        $global:FxWebApps = @();         $global:FxWebAppsThrow = $false; $global:FxWebAppDetail = $null
        $global:FxAppGws = @();          $global:FxAppGwThrow = $false
        $global:FxAccounts = @();        $global:FxAccountsThrow = $false
        $global:FxKVs = @();             $global:FxKvThrow = $false
        $global:FxSqls = @();            $global:FxSqlThrow = $false
        $global:FxGeneric = @();         $global:FxGenericThrow = $false
        $global:FxAcrs = @();            $global:FxAcrThrow = $false
        $global:FxSbs = @();             $global:FxSbThrow = $false
        $global:FxApims = @();           $global:FxApimThrow = $false
        $global:FxNsgs = @();            $global:FxNsgThrow = $false
        $global:FxPEs = @();             $global:FxPeThrow = $false
        $global:FxVMs = @();             $global:FxVmThrow = $false
        $global:FxVaults = @();          $global:FxVaultThrow = $false
        $global:FxBackupItems = @();     $global:FxBackupItemThrow = $false
        $global:FxDiag = $null;          $global:FxDiagThrow = $false
        $global:FxArgRows = @();         $global:FxArgThrow = $false
    }

    Context "IDENTITY-007 RBAC decomposition" {
        It "Owner at subscription scope -> explicit HIGH finding (RoleAssignments, evidence carries principal/scope)" {
            $global:FxRbac = @(New-RA -Role 'Owner' -Scope '/subscriptions/S1')
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'IDENTITY-007' '*Owner role assignments at subscription scope*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'HIGH'
            "$($m[0].Status)" | Should -Be 'FAIL'
            $m[0].CountType | Should -Be 'RoleAssignments'
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].PrincipalType)" | Should -Be 'User'
            "$($m[0].Evidence[0].PrincipalId)" | Should -Be 'obj-1'
            "$($m[0].Evidence[0].Scope)" | Should -Be '/subscriptions/S1'
        }
        It "Owner at management group scope -> explicit CRITICAL finding" {
            $global:FxRbac = @(New-RA -Role 'Owner' -Scope '/providers/Microsoft.Management/managementGroups/mg1')
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'IDENTITY-007' '*management group scope*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'CRITICAL'
        }
        It "Contributor, UAA and RBAC Administrator at subscription scope -> three separate findings" {
            $global:FxRbac = @(
                (New-RA -Role 'Contributor' -Scope '/subscriptions/S1')
                (New-RA -Role 'User Access Administrator' -Scope '/subscriptions/S1')
                (New-RA -Role 'Role Based Access Control Administrator' -Scope '/subscriptions/S1')
            )
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-MainFin 'IDENTITY-007' '*Contributor role assignments at subscription scope*').Count | Should -Be 1
            @(Get-MainFin 'IDENTITY-007' '*User Access Administrator assignments at subscription scope*').Count | Should -Be 1
            @(Get-MainFin 'IDENTITY-007' '*Role Based Access Control Administrator assignments at subscription scope*').Count | Should -Be 1
        }
        It "privileged role held by a service principal -> separate non-human principals finding" {
            $global:FxRbac = @(New-RA -Role 'Owner' -Scope '/subscriptions/S1' -Type 'ServicePrincipal' -Display 'spn-app')
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'IDENTITY-007' '*non-human principals*')
            $m.Count | Should -Be 1
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].PrincipalType)" | Should -Be 'ServicePrincipal'
        }
        It "privileged role held by a group -> group finding flagged for manual validation (no Graph resolution)" {
            $global:FxRbac = @(New-RA -Role 'Contributor' -Scope '/subscriptions/S1' -Type 'Group' -Display 'sg-admins')
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'IDENTITY-007' '*assigned to groups*')
            $m.Count | Should -Be 1
            $m[0].ManualValidationRequired | Should -BeTrue
            "$($m[0].Remediation)" | Should -BeLike '*does not resolve groups*'
        }
        It "summary language says assignments/signals, not unique users" {
            $global:FxRbac = @(New-RA -Role 'Owner' -Scope '/subscriptions/S1')
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'IDENTITY-007' '*Owner role assignments at subscription scope*')
            "$($m[0].SummaryText)" | Should -BeLike '*not unique users*'
        }
        It "resource-group-scope assignments are not reported as elevated" {
            $global:FxRbac = @(New-RA -Role 'Owner' -Scope '/subscriptions/S1/resourceGroups/rg1')
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'IDENTITY-007' | Where-Object { [int]$_.Count -gt 0 })
            $m.Count | Should -Be 0
        }
        It "RBAC read failure -> NOTEVALUATED, never a clean PASS" {
            $global:FxRbacThrow = $true
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'IDENTITY-007').Count | Should -BeGreaterThan 0
            @(Get-Fin 'IDENTITY-007' | Where-Object { "$($_.Status)".ToUpper() -eq 'PASS' }).Count | Should -Be 0
        }
        It "no elevated assignments -> explicit PASS coverage record" {
            $global:FxRbac = @()
            Test-RBACDecomposition -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'IDENTITY-007')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
            [int]$m[0].Count | Should -Be 0
        }
    }

    Context "COMPUTE-006 App Service FTP state" {
        It "ftpsState AllAllowed -> MEDIUM FAIL with per-app evidence" {
            $global:FxWebApps = @((New-App @{ SiteConfig = [PSCustomObject]@{ FtpsState = 'AllAllowed' } }))
            Test-AppServiceFtpState -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'COMPUTE-006' '*plaintext FTP allowed*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'MEDIUM'
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].AppName)" | Should -Be 'app1'
            "$($m[0].Evidence[0].FtpsState)" | Should -Be 'AllAllowed'
            $m[0].CountType | Should -Be 'UniqueResources'
        }
        It "ftpsState FtpsOnly -> clean PASS" {
            $global:FxWebApps = @((New-App @{ SiteConfig = [PSCustomObject]@{ FtpsState = 'FtpsOnly' } }))
            Test-AppServiceFtpState -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'COMPUTE-006' '*plaintext FTP allowed*')
            [int]$m[0].Count | Should -Be 0
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
        }
        It "ftpsState Disabled -> clean PASS" {
            $global:FxWebApps = @((New-App @{ SiteConfig = [PSCustomObject]@{ FtpsState = 'Disabled' } }))
            Test-AppServiceFtpState -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'COMPUTE-006' '*plaintext FTP allowed*')
            [int]$m[0].Count | Should -Be 0
        }
        It "list shape without SiteConfig falls back to the per-app detail read" {
            $global:FxWebApps = @((New-App @{}))
            $global:FxWebAppDetail = New-App @{ SiteConfig = [PSCustomObject]@{ FtpsState = 'AllAllowed' } }
            Test-AppServiceFtpState -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'COMPUTE-006' '*plaintext FTP allowed*')
            [int]$m[0].Count | Should -Be 1
        }
        It "ftpsState unreadable (no SiteConfig anywhere) -> NOTEVALUATED, not clean" {
            $global:FxWebApps = @((New-App @{}))
            $global:FxWebAppDetail = $null
            Test-AppServiceFtpState -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'COMPUTE-006').Count | Should -BeGreaterThan 0
            @(Get-Fin 'COMPUTE-006' | Where-Object { "$($_.Status)".ToUpper() -eq 'PASS' }).Count | Should -Be 0
        }
        It "web app collection failure -> NOTEVALUATED" {
            $global:FxWebAppsThrow = $true
            Test-AppServiceFtpState -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'COMPUTE-006').Count | Should -BeGreaterThan 0
        }
        It "missing Az.Websites cmdlet support -> NOTEVALUATED (feature-detected)" {
            $script:AppServiceFtpSupported = $false
            Test-AppServiceFtpState -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-NotEval 'COMPUTE-006')
            $m.Count | Should -Be 1
            "$($m[0].Finding)" | Should -BeLike '*Az.Websites*'
        }
    }

    Context "COMPUTE-007 VM backup coverage" {
        It "VM without a backup item -> MEDIUM control-gap finding (never escalated)" {
            $global:FxVMs = @((New-FxVm 'vm1'))
            $global:FxVaults = @([PSCustomObject]@{ Name = 'rsv1'; ID = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/rsv1' })
            $global:FxBackupItems = @()
            Test-VMBackupCoverage -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'COMPUTE-007' '*without Recovery Services vault backup*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'MEDIUM'
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].VMName)" | Should -Be 'vm1'
            "$($m[0].SeverityReason)" | Should -BeLike '*test/sandbox*'
        }
        It "VM with a matching backup item -> clean PASS" {
            $vm = New-FxVm 'vm1'
            $global:FxVMs = @($vm)
            $global:FxVaults = @([PSCustomObject]@{ Name = 'rsv1'; ID = '/v' })
            $global:FxBackupItems = @([PSCustomObject]@{ VirtualMachineId = $vm.Id })
            Test-VMBackupCoverage -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'COMPUTE-007' '*without Recovery Services vault backup*')
            [int]$m[0].Count | Should -Be 0
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
        }
        It "vault read failure -> NOTEVALUATED, never clean" {
            $global:FxVMs = @((New-FxVm 'vm1'))
            $global:FxVaultThrow = $true
            Test-VMBackupCoverage -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'COMPUTE-007').Count | Should -BeGreaterThan 0
            @(Get-Fin 'COMPUTE-007' | Where-Object { "$($_.Status)".ToUpper() -eq 'PASS' }).Count | Should -Be 0
        }
        It "protected-item read failure -> NOTEVALUATED, never clean" {
            $global:FxVMs = @((New-FxVm 'vm1'))
            $global:FxVaults = @([PSCustomObject]@{ Name = 'rsv1'; ID = '/v' })
            $global:FxBackupItemThrow = $true
            Test-VMBackupCoverage -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'COMPUTE-007').Count | Should -BeGreaterThan 0
        }
        It "missing Az.RecoveryServices cmdlets -> NOTEVALUATED (feature-detected)" {
            $script:RecoveryServicesBackupSupported = $false
            Test-VMBackupCoverage -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-NotEval 'COMPUTE-007')
            $m.Count | Should -Be 1
            "$($m[0].Finding)" | Should -BeLike '*Az.RecoveryServices*'
        }
    }

    Context "NETWORK-009 App Gateway listener hygiene" {
        It "HTTP listener without redirect -> MEDIUM finding" {
            $global:FxAppGws = @((New-AppGw @{
                HttpListeners = @((New-Listener -Name 'l-http' -Protocol 'Http'))
                SslPolicy = [PSCustomObject]@{ PolicyType = 'Predefined'; PolicyName = 'AppGwSslPolicy20220101' }
            }))
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'NETWORK-009' '*HTTP listeners without HTTPS redirect*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'MEDIUM'
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].ListenerName)" | Should -Be 'l-http'
        }
        It "HTTP listener with redirect-only configuration to an HTTPS listener is NOT flagged" {
            $redirect = [PSCustomObject]@{ Id = '/rc/rd1' }
            $rc = [PSCustomObject]@{ Id = '/rc/rd1'; TargetListener = [PSCustomObject]@{ Id = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.Network/applicationGateways/agw1/httpListeners/l-https' } }
            $global:FxAppGws = @((New-AppGw @{
                HttpListeners = @(
                    (New-Listener -Name 'l-http' -Protocol 'Http' -Redirect $redirect)
                    (New-Listener -Name 'l-https' -Protocol 'Https')
                )
                RedirectConfigurations = @($rc)
                SslPolicy = [PSCustomObject]@{ PolicyType = 'Predefined'; PolicyName = 'AppGwSslPolicy20220101' }
            }))
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-MainFin 'NETWORK-009' '*HTTP listeners without HTTPS redirect*').Count | Should -Be 0
            $pass = @(Get-Fin 'NETWORK-009' | Where-Object { "$($_.Status)".ToUpper() -eq 'PASS' })
            $pass.Count | Should -Be 1
        }
        It "custom SSL policy with minProtocolVersion TLSv1_0 (private gateway) -> MEDIUM" {
            $global:FxAppGws = @((New-AppGw @{
                SslPolicy = [PSCustomObject]@{ PolicyType = 'Custom'; MinProtocolVersion = 'TLSv1_0' }
            }))
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'NETWORK-009' '*SSL policy below TLS 1.2*or unspecified legacy default*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'MEDIUM'
            "$($m[0].Evidence[0].Facing)" | Should -Be 'Private'
        }
        It "weak TLS on a public-facing gateway -> HIGH" {
            $global:FxAppGws = @((New-AppGw @{
                SslPolicy = [PSCustomObject]@{ PolicyType = 'Custom'; MinProtocolVersion = 'TLSv1_1' }
                FrontendIPConfigurations = @([PSCustomObject]@{ PublicIPAddress = [PSCustomObject]@{ Id = '/pip/pip1' } })
            }))
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'NETWORK-009' '*Public-facing Application Gateways with SSL policy below TLS 1.2*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'HIGH'
        }
        It "legacy predefined policy name is flagged as below TLS 1.2" {
            $global:FxAppGws = @((New-AppGw @{
                SslPolicy = [PSCustomObject]@{ PolicyType = 'Predefined'; PolicyName = 'AppGwSslPolicy20170401' }
            }))
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-MainFin 'NETWORK-009' '*SSL policy below TLS 1.2*').Count | Should -BeGreaterThan 0
        }
        It "absent SSL policy -> flagged explicitly as unspecified legacy default (not silently safe)" {
            $global:FxAppGws = @((New-AppGw @{}))
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'NETWORK-009' '*SSL policy below TLS 1.2*')
            $m.Count | Should -Be 1
            "$($m[0].Evidence[0].SslPolicy)" | Should -BeLike 'Unspecified*'
        }
        It "TLS 1.2+ policy and HTTPS-only listeners -> PASS" {
            $global:FxAppGws = @((New-AppGw @{
                HttpListeners = @((New-Listener -Name 'l-https' -Protocol 'Https'))
                SslPolicy = [PSCustomObject]@{ PolicyType = 'Predefined'; PolicyName = 'AppGwSslPolicy20220101' }
            }))
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'NETWORK-009')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
        }
        It "gateway collection failure -> NOTEVALUATED" {
            $global:FxAppGwThrow = $true
            Test-AppGatewayListenerHygiene -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'NETWORK-009').Count | Should -BeGreaterThan 0
        }
    }

    Context "NETWORK-010 sensitive PaaS private connectivity" {
        It "public storage account without a linked private endpoint -> MEDIUM finding" {
            $global:FxAccounts = @((New-SA @{ PublicNetworkAccess = 'Enabled' }))
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'NETWORK-010' '*public network access and no linked private endpoint*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'MEDIUM'
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].ResourceName)" | Should -Be 'sa1'
            $m[0].CountType | Should -Be 'UniqueResources'
        }
        It "public storage account WITH a linked private endpoint -> not flagged" {
            $sa = New-SA @{ PublicNetworkAccess = 'Enabled' }
            $global:FxAccounts = @($sa)
            $global:FxPEs = @((New-PE $sa.Id))
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'NETWORK-010' | Where-Object { [int]$_.Count -gt 0 })
            $m.Count | Should -Be 0
        }
        It "Key Vault public with firewall default deny and no PE -> LOW (mitigated), still not clean" {
            $global:FxKVs = @([PSCustomObject]@{
                VaultName = 'kv1'; ResourceGroupName = 'rg1'
                ResourceId = '/subscriptions/S1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1'
                PublicNetworkAccess = 'Enabled'
                NetworkAcls = [PSCustomObject]@{ DefaultAction = 'Deny' }
            })
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'NETWORK-010' '*mitigated by firewall default deny*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'LOW'
        }
        It "publicNetworkAccess Disabled -> PASS" {
            $global:FxAccounts = @((New-SA @{ PublicNetworkAccess = 'Disabled' }))
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'NETWORK-010')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
        }
        It "unspecified publicNetworkAccess is treated as public (flagged, not silently safe)" {
            $global:FxAccounts = @((New-SA @{}))
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-MainFin 'NETWORK-010' '*public network access and no linked private endpoint*').Count | Should -Be 1
        }
        It "finding carries the required caveats (private IP / linked PE / DNS / separate PNA property)" {
            $global:FxAccounts = @((New-SA @{ PublicNetworkAccess = 'Enabled' }))
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'NETWORK-010' '*public network access and no linked private endpoint*')
            "$($m[0].SeverityReason)" | Should -BeLike '*private IP alone does not prove*'
            "$($m[0].SeverityReason)" | Should -BeLike '*DNS resolution is not verified*'
            "$($m[0].SeverityReason)" | Should -BeLike '*separate property*'
        }
        It "private endpoint collection failure -> NOTEVALUATED, never Clean" {
            $global:FxAccounts = @((New-SA @{ PublicNetworkAccess = 'Enabled' }))
            $global:FxPeThrow = $true
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'NETWORK-010').Count | Should -BeGreaterThan 0
            @(Get-Fin 'NETWORK-010' | Where-Object { "$($_.Status)".ToUpper() -eq 'PASS' }).Count | Should -Be 0
        }
        It "resource collection failure -> NOTEVALUATED, never Clean" {
            $global:FxAccountsThrow = $true
            Test-SensitivePaaSPrivateConnectivity -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'NETWORK-010').Count | Should -BeGreaterThan 0
        }
    }

    Context "MONITORING-004 extended diagnostic coverage" {
        It "storage account without diagnostic settings (bulk ARG read) -> MEDIUM finding" {
            $global:FxAccounts = @((New-SA @{}))
            $global:FxArgRows = @()
            Test-ExtendedResourceDiagnostics -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'MONITORING-004' '*missing diagnostic settings*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'MEDIUM'
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Evidence[0].ResourceName)" | Should -Be 'sa1'
            $m[0].CountType | Should -Be 'UniqueResources'
        }
        It "diagnostic setting scope present in the bulk ARG read -> PASS" {
            $sa = New-SA @{}
            $global:FxAccounts = @($sa)
            $global:FxArgRows = @([PSCustomObject]@{ id = "$($sa.Id)/providers/microsoft.insights/diagnosticSettings/ds1" })
            Test-ExtendedResourceDiagnostics -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'MONITORING-004')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
        }
        It "ARG failure falls back to per-resource reads (covered -> PASS)" {
            $global:FxAccounts = @((New-SA @{}))
            $global:FxArgThrow = $true
            $global:FxDiag = @([PSCustomObject]@{ Name = 'ds1' })
            Test-ExtendedResourceDiagnostics -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'MONITORING-004')
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
        }
        It "ARG failure + per-resource read failure -> NOTEVALUATED, never clean" {
            $global:FxAccounts = @((New-SA @{}))
            $global:FxArgThrow = $true
            $global:FxDiagThrow = $true
            Test-ExtendedResourceDiagnostics -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'MONITORING-004').Count | Should -BeGreaterThan 0
            @(Get-Fin 'MONITORING-004' | Where-Object { "$($_.Status)".ToUpper() -eq 'PASS' }).Count | Should -Be 0
        }
        It "Key Vault and SQL are NOT re-evaluated here (MONITORING-001/KEYVAULT-002 own them)" {
            $global:FxKVs = @([PSCustomObject]@{ VaultName = 'kv1'; ResourceGroupName = 'rg1'; ResourceId = '/kv' })
            $global:FxSqls = @([PSCustomObject]@{ ServerName = 'sql1'; ResourceGroupName = 'rg1'; ResourceId = '/sql' })
            $global:FxArgRows = @()
            Test-ExtendedResourceDiagnostics -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'MONITORING-004' | Where-Object { [int]$_.Count -gt 0 })
            $m.Count | Should -Be 0
        }
        It "resource collection failure -> NOTEVALUATED" {
            $global:FxAccountsThrow = $true
            Test-ExtendedResourceDiagnostics -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'MONITORING-004').Count | Should -BeGreaterThan 0
        }
    }

    Context "STORAGE-007 infrastructure (double) encryption" {
        It "RequireInfrastructureEncryption = false -> INFO control-gap, never escalated, default-encryption caveat" {
            $global:FxAccounts = @((New-SA @{ Encryption = [PSCustomObject]@{ RequireInfrastructureEncryption = $false } }))
            Test-StorageDoubleEncryption -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-MainFin 'STORAGE-007' '*without infrastructure (double) encryption*')
            $m.Count | Should -Be 1
            "$($m[0].Severity)" | Should -Be 'INFO'
            [int]$m[0].Count | Should -Be 1
            "$($m[0].Finding)" | Should -BeLike '*still encrypted at rest by default*'
            "$($m[0].SeverityReason)" | Should -BeLike '*baseline or regulation*'
            $m[0].CountType | Should -Be 'UniqueResources'
        }
        It "RequireInfrastructureEncryption = true -> PASS" {
            $global:FxAccounts = @((New-SA @{ Encryption = [PSCustomObject]@{ RequireInfrastructureEncryption = $true } }))
            Test-StorageDoubleEncryption -Subscriptions @($global:FxSub) -Exclusions @{}
            $m = @(Get-Fin 'STORAGE-007')
            $m.Count | Should -Be 1
            "$($m[0].Status)".ToUpper() | Should -Be 'PASS'
            [int]$m[0].Count | Should -Be 0
        }
        It "property absent (older API surface) -> NOTEVALUATED, not clean" {
            $global:FxAccounts = @((New-SA @{}))
            Test-StorageDoubleEncryption -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'STORAGE-007').Count | Should -BeGreaterThan 0
            @(Get-Fin 'STORAGE-007' | Where-Object { "$($_.Status)".ToUpper() -eq 'PASS' }).Count | Should -Be 0
        }
        It "collection failure -> NOTEVALUATED" {
            $global:FxAccountsThrow = $true
            Test-StorageDoubleEncryption -Subscriptions @($global:FxSub) -Exclusions @{}
            @(Get-NotEval 'STORAGE-007').Count | Should -BeGreaterThan 0
        }
    }

    Context "Registration and display names" {
        BeforeEach {
            Register-AzureIdentityChecks
            Register-AzureComputeChecks
            Register-AzureNetworkChecks
            Register-AzureMonitoringChecks
            Register-AzureStorageChecks
        }
        It "all seven parity checks are registered for the PerSubscription phase" {
            $ids = @('IDENTITY-007', 'COMPUTE-006', 'COMPUTE-007', 'NETWORK-009', 'NETWORK-010', 'MONITORING-004', 'STORAGE-007')
            foreach ($id in $ids) {
                $c = @($script:State.CheckRegistry | Where-Object { $_.CheckId -eq $id })
                $c.Count | Should -Be 1 -Because "$id must be registered exactly once"
                $c[0].Phase | Should -Be 'PerSubscription'
                $c[0].Category | Should -Be 'Azure'
            }
        }
        It "COMPUTE-007 does not require Az.RecoveryServices at registration (module gap must be NotEvaluated, not skipped)" {
            $c = @($script:State.CheckRegistry | Where-Object { $_.CheckId -eq 'COMPUTE-007' })[0]
            @($c.RequiredModules) | Should -Not -Contain 'Az.RecoveryServices'
        }
        It "every parity check has a curated CLI display name" {
            $ids = @('IDENTITY-007', 'COMPUTE-006', 'COMPUTE-007', 'NETWORK-009', 'NETWORK-010', 'MONITORING-004', 'STORAGE-007')
            foreach ($id in $ids) {
                $script:CheckDisplayNames.ContainsKey($id) | Should -BeTrue -Because "$id needs a human display name"
                $script:CheckDisplayNames[$id].Length | Should -BeLessOrEqual 37
                $script:CheckDisplayNames[$id] | Should -Not -Match '\.\.\.'
            }
        }
    }
}
