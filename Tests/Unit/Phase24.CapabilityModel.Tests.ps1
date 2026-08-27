#==============================================================================
# AzureMap v2 - Tests/Unit/Phase24.CapabilityModel.Tests.ps1
# Phase B2 tests: read-only capability / attack-path model. Covers every
# insight builder (storage key capability, public storage combinations, public
# workload + privileged identity, managed identity blast radius, Key Vault
# exposure combinations, network egress paths, monitoring gaps on exposed
# resources), severity/confidence discipline (no escalation without evidence),
# insight sorting and output caps, evidence-clone non-mutation, empty-state
# behavior, HTML/JSON/CLI rendering, a performance guard, and the
# no-Az-call / no-secret-retrieval safety contract of Core/Capability.ps1 and
# Core/Azure/CapabilityModel.Azure.ps1.
# All fixtures are synthetic in-memory state; no Azure/Graph calls are made.
#==============================================================================

BeforeAll {
    $projectRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
    . "$projectRoot\Core\State.ps1"
    . "$projectRoot\Core\Logging.ps1"
    . "$projectRoot\Core\Redaction.ps1"
    . "$projectRoot\Core\Exclusions.ps1"
    . "$projectRoot\Core\Retry.ps1"
    . "$projectRoot\Core\RunStatus.ps1"
    . "$projectRoot\Core\CheckRegistry.ps1"
    . "$projectRoot\Core\Azure\InventoryCache.ps1"
    . "$projectRoot\Core\Capability.ps1"
    . "$projectRoot\Core\Azure\CapabilityModel.Azure.ps1"
    . "$projectRoot\Core\Console.ps1"
    . "$projectRoot\Export\Html.ps1"
    . "$projectRoot\Export\Json.ps1"

    # The HTML/JSON exporters probe Get-AzContext for account/tenant display;
    # stub it so the render tests never touch a real Az session.
    function global:Get-AzContext { $null }

    $script:CapFindingSeq = 0

    # Minimal finding helper mirroring the Write-Finding shape the capability
    # model reads (CheckId / Finding / Severity / Count / Evidence / Status).
    function Add-CapFinding {
        param($CheckId, $Message, $Severity, $Count, $Data, $Status = 'FAIL')
        $script:CapFindingSeq++
        $script:State.Results.Add([PSCustomObject]@{
            FindingId = "t-$CheckId-$($script:CapFindingSeq)"; CheckId = $CheckId; Finding = $Message
            Severity = $Severity; Count = $Count; Evidence = @($Data); Status = $Status; Service = 'Test'
        })
    }

    # Full synthetic fixture (same shape as the proven smoke scenario): yields
    # 7 insights spanning CRITICAL/HIGH/MEDIUM for sorting and render tests.
    function New-FullCapabilityFixture {
        Add-CapFinding 'STORAGE-001' 'Storage accounts allowing shared key authentication (enabled or unspecified)' 'HIGH' 2 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = 'acct1'; ResourceGroupName = 'rg1' },
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = 'acct2'; ResourceGroupName = 'rg2' }
        )
        Add-CapFinding 'STORAGE-006' 'Storage accounts with key/SAS exposure' 'HIGH' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccount = 'acct1'; ResourceGroup = 'rg1'; Principal = 'app-sp'; Role = 'Contributor'; Risk = 'Principal can retrieve/manage storage account keys' }
        )
        Add-CapFinding 'STORAGE-002' 'Storage accounts with public network exposure, blob public access, or unverified firewall' 'HIGH' 2 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccount = 'acct1'; Confirmed = $true; BlobPublicAccess = 'True'; DefaultAction = 'Allow' },
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccount = 'acct2'; Confirmed = $false; BlobPublicAccess = 'Unspecified'; DefaultAction = 'Deny' }
        )
        Add-CapFinding 'STORAGE-004' 'Storage accounts with anonymous/public blob containers' 'CRITICAL' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccount = 'acct1'; PublicContainersCount = 2 }
        )
        Add-CapFinding 'KEYVAULT-001' 'Key Vaults using legacy access policies' 'LOW' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
        )
        Add-CapFinding 'KEYVAULT-002' 'Key Vaults with public access and no firewall restrictions' 'CRITICAL' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
        )
        Add-CapFinding 'KEYVAULT-002' 'Key Vaults without purge protection enabled' 'HIGH' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
        )
        Add-CapFinding 'IDENTITY-006' 'Resources with Managed Identities having Owner/Contributor RBAC (cloud takeover risk)' 'CRITICAL' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'WebApps'; ResourceName = 'web1'; ResourceGroup = 'rg1'; Role = 'Contributor'; Scope = '/subscriptions/SUB-A' }
        )
        Add-CapFinding 'AZURE-EXPOSURE-001' 'Central public exposure inventory' 'INFO' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'AppService'; ResourceName = 'web1'; PublicEndpoint = 'web1.azurewebsites.net' }
        ) 'PASS'
        Add-CapFinding 'NETWORK-008' 'NSG outbound rules allowing internet access (data exfiltration path)' 'HIGH' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceGroup = 'rg1'; NSGName = 'nsg1'; RuleName = 'allow-out'; Destination = 'Internet'; Port = '*' }
        )
        Add-CapFinding 'MONITORING-001' 'Critical resources missing diagnostic settings' 'MEDIUM' 1 @(
            [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'KeyVault'; ResourceName = 'vault1'; ResourceGroup = 'rg1' }
        )

        $script:State.Cache.RBACAssignments['SUB-A'] = @(
            [PSCustomObject]@{ ObjectId = 'p-owner'; ObjectType = 'User'; DisplayName = ''; RoleDefinitionName = 'Owner'; Scope = '/subscriptions/SUB-A' },
            [PSCustomObject]@{ ObjectId = 'p-web1'; ObjectType = 'ServicePrincipal'; DisplayName = ''; RoleDefinitionName = 'Contributor'; Scope = '/subscriptions/SUB-A' }
        )
        $script:State.Cache.ResourceLists['sub-a|WebApps'] = @{ Items = @(
            [PSCustomObject]@{ Name = 'web1'; ResourceGroupName = 'rg1'; DefaultHostName = 'web1.azurewebsites.net'; Identity = [PSCustomObject]@{ PrincipalId = 'p-web1' } }
        ); ProvenEmpty = $false; Unavailable = $false }
        $script:State.Cache.ResourceLists['sub-a|KeyVaults'] = @{ Items = @(
            [PSCustomObject]@{ VaultName = 'vault1'; ResourceGroupName = 'rg1' }
        ); ProvenEmpty = $false; Unavailable = $false }
        $script:State.Footprint = [PSCustomObject]@{ TypeCountsBySub = @{ 'SUB-A' = @{ 'microsoft.web/sites' = 3; 'microsoft.keyvault/vaults' = 1 } } }
    }
}

Describe "Phase B2 capability model" {

    BeforeEach {
        $script:State = Initialize-AuditState
        $script:State.Config.Quiet = $true
        $script:State.Config.NoColor = $true
    }

    Context "storage shared-key capability" {
        BeforeEach {
            Add-CapFinding 'STORAGE-001' 'Storage accounts allowing shared key authentication (enabled or unspecified)' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = 'acct1'; ResourceGroupName = 'rg1' }
            )
            Add-CapFinding 'STORAGE-006' 'Storage accounts with key/SAS exposure' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccount = 'acct1'; ResourceGroup = 'rg1'; Principal = 'app-sp'; Role = 'Contributor'; Risk = 'Principal can retrieve/manage storage account keys' }
            )
        }

        It "models a storage key capability insight (HIGH, High confidence)" {
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' })
            $insight.Count | Should -Be 1
            $insight[0].Severity | Should -Be 'HIGH'
            $insight[0].Confidence | Should -Be 'High'
            $insight[0].ImpactedResourceCount | Should -Be 1
        }

        It "is modeling-only: insight and edges state keys are never retrieved" {
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' })[0]
            $insight.Description | Should -Match 'Modeled'
            $insight.Description | Should -Match 'no keys were retrieved'
            $keyEdges = @($model.Edges | Where-Object { $_.Type -eq 'CanObtainKeys' })
            $keyEdges.Count | Should -BeGreaterThan 0
            foreach ($e in $keyEdges) { $e.Capability | Should -Match 'modeled only - keys never retrieved' }
        }
    }

    Context "public workload + privileged identity" {
        It "confirmed exposure row + IDENTITY-006 produces a HIGH/High insight" {
            Add-CapFinding 'IDENTITY-006' 'Resources with Managed Identities having Owner/Contributor RBAC (cloud takeover risk)' 'CRITICAL' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'WebApps'; ResourceName = 'web1'; ResourceGroup = 'rg1'; Role = 'Contributor'; Scope = '/subscriptions/SUB-A' }
            )
            Add-CapFinding 'AZURE-EXPOSURE-001' 'Central public exposure inventory' 'INFO' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'AppService'; ResourceName = 'web1'; PublicEndpoint = 'web1.azurewebsites.net' }
            ) 'PASS'
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Public workload with privileged identity' })
            $insight.Count | Should -Be 1
            $insight[0].Severity | Should -Be 'HIGH'
            $insight[0].Confidence | Should -Be 'High'
        }

        It "cached DefaultHostName without exposure row produces the inferred MEDIUM/Medium insight" {
            Add-CapFinding 'IDENTITY-006' 'Resources with Managed Identities having Owner/Contributor RBAC (cloud takeover risk)' 'CRITICAL' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'WebApps'; ResourceName = 'web1'; ResourceGroup = 'rg1'; Role = 'Contributor'; Scope = '/subscriptions/SUB-A' }
            )
            $script:State.Cache.ResourceLists['sub-a|WebApps'] = @{ Items = @(
                [PSCustomObject]@{ Name = 'web1'; ResourceGroupName = 'rg1'; DefaultHostName = 'web1.azurewebsites.net'; Identity = [PSCustomObject]@{ PrincipalId = 'p-web1' } }
            ); ProvenEmpty = $false; Unavailable = $false }
            $model = Build-CapabilityModel
            @($model.Insights | Where-Object { $_.Title -eq 'Public workload with privileged identity' }).Count | Should -Be 0
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Potentially public workload with privileged identity' })
            $insight.Count | Should -Be 1
            $insight[0].Severity | Should -Be 'MEDIUM'
            $insight[0].Confidence | Should -Be 'Medium'
        }
    }

    Context "managed identity blast radius" {
        It "models blast radius from cached RBAC (MI principal + Owner at sub scope) as MEDIUM" {
            $script:State.Cache.ResourceLists['sub-a|WebApps'] = @{ Items = @(
                [PSCustomObject]@{ Name = 'web1'; ResourceGroupName = 'rg1'; DefaultHostName = 'web1.azurewebsites.net'; Identity = [PSCustomObject]@{ PrincipalId = 'p-web1' } }
            ); ProvenEmpty = $false; Unavailable = $false }
            $script:State.Cache.RBACAssignments['SUB-A'] = @(
                [PSCustomObject]@{ ObjectId = 'p-web1'; ObjectType = 'ServicePrincipal'; DisplayName = ''; RoleDefinitionName = 'Owner'; Scope = '/subscriptions/SUB-A' }
            )
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Managed identity blast radius' })
            $insight.Count | Should -Be 1
            $insight[0].Severity | Should -Be 'MEDIUM'
            $insight[0].Confidence | Should -Be 'High'
            $insight[0].ImpactedResourceCount | Should -Be 1
        }
    }

    Context "Key Vault exposure combination" {
        BeforeEach {
            Add-CapFinding 'KEYVAULT-001' 'Key Vaults using legacy access policies' 'LOW' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            )
            Add-CapFinding 'KEYVAULT-002' 'Key Vaults with public access and no firewall restrictions' 'CRITICAL' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            )
            Add-CapFinding 'KEYVAULT-002' 'Key Vaults without purge protection enabled' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            )
        }

        It "public + legacy + no purge protection combines into a HIGH insight" {
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -like '*Key Vault exposure combination*' })
            $insight.Count | Should -Be 1
            $insight[0].Severity | Should -Be 'HIGH'
            $insight[0].ImpactedResources[0] | Should -Match 'public access, no firewall'
            $insight[0].ImpactedResources[0] | Should -Match 'legacy access policies'
            $insight[0].ImpactedResources[0] | Should -Match 'no purge protection'
        }

        It "involves no secret values (metadata-only modeling)" {
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -like '*Key Vault exposure combination*' })[0]
            $insight.Description | Should -Match 'no secrets were read'
            ($model | ConvertTo-Json -Depth 6 -Compress) | Should -Not -Match 'SecretValue'
        }
    }

    Context "monitoring gap on exposed critical resource" {
        It "MONITORING-001 + KEYVAULT-002 public-no-firewall produces a HIGH insight" {
            Add-CapFinding 'MONITORING-001' 'Critical resources missing diagnostic settings' 'MEDIUM' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'KeyVault'; ResourceName = 'vault1'; ResourceGroup = 'rg1' }
            )
            Add-CapFinding 'KEYVAULT-002' 'Key Vaults with public access and no firewall restrictions' 'CRITICAL' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            )
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Monitoring gaps on exposed critical resources' })
            $insight.Count | Should -Be 1
            $insight[0].Severity | Should -Be 'HIGH'
            $insight[0].Confidence | Should -Be 'High'
        }
    }

    Context "severity discipline (no escalation without sufficient evidence)" {
        It "vault with only ONE condition (legacy access policies) yields no Key Vault insight" {
            Add-CapFinding 'KEYVAULT-001' 'Key Vaults using legacy access policies' 'LOW' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            )
            $model = Build-CapabilityModel
            @($model.Insights | Where-Object { $_.Title -like '*Key Vault exposure*' }).Count | Should -Be 0
        }

        It "storage account with unconfirmed exposure only yields no public-exposure/CRITICAL insight" {
            Add-CapFinding 'STORAGE-001' 'Storage accounts allowing shared key authentication (enabled or unspecified)' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = 'acct2'; ResourceGroupName = 'rg2' }
            )
            Add-CapFinding 'STORAGE-002' 'Storage accounts with public network exposure, blob public access, or unverified firewall' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccount = 'acct2'; Confirmed = $false; BlobPublicAccess = 'Unspecified'; DefaultAction = 'Deny' }
            )
            $model = Build-CapabilityModel
            @($model.Insights | Where-Object { $_.Title -eq 'Public storage exposure with weak authentication' }).Count | Should -Be 0
            @($model.Insights | Where-Object { $_.Severity -eq 'CRITICAL' }).Count | Should -Be 0
        }

        It "monitoring row for a NON-exposed resource yields no monitoring insight" {
            Add-CapFinding 'MONITORING-001' 'Critical resources missing diagnostic settings' 'MEDIUM' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'KeyVault'; ResourceName = 'vault-internal'; ResourceGroup = 'rg1' }
            )
            $model = Build-CapabilityModel
            @($model.Insights | Where-Object { $_.Title -eq 'Monitoring gaps on exposed critical resources' }).Count | Should -Be 0
        }
    }

    Context "confidence assignment" {
        It "account-scope STORAGE-006 principal path yields High confidence" {
            Add-CapFinding 'STORAGE-001' 'Storage accounts allowing shared key authentication (enabled or unspecified)' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = 'acct1'; ResourceGroupName = 'rg1' }
            )
            Add-CapFinding 'STORAGE-006' 'Storage accounts with key/SAS exposure' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccount = 'acct1'; ResourceGroup = 'rg1'; Principal = 'app-sp'; Role = 'Contributor'; Risk = 'Principal can retrieve/manage storage account keys' }
            )
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' })[0]
            $insight.Confidence | Should -Be 'High'
        }

        It "purely sub-scope-RBAC-inferred storage key path yields Medium confidence" {
            Add-CapFinding 'STORAGE-001' 'Storage accounts allowing shared key authentication (enabled or unspecified)' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = 'acct1'; ResourceGroupName = 'rg1' }
            )
            $script:State.Cache.RBACAssignments['SUB-A'] = @(
                [PSCustomObject]@{ ObjectId = 'p-owner'; ObjectType = 'User'; DisplayName = ''; RoleDefinitionName = 'Owner'; Scope = '/subscriptions/SUB-A' }
            )
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' })
            $insight.Count | Should -Be 1
            $insight[0].Confidence | Should -Be 'Medium'
        }
    }

    Context "custom role key-list capability" {
        BeforeEach {
            Add-CapFinding 'STORAGE-001' 'Storage accounts allowing shared key authentication (enabled or unspecified)' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = 'acct1'; ResourceGroupName = 'rg1' }
            )
        }

        It "custom role with the exact key-list action yields the storage key insight naming principal and role" {
            $script:State.Cache.RoleDefinitions['SUB-A'] = [System.Collections.Generic.List[object]]::new()
            $script:State.Cache.RoleDefinitions['SUB-A'].Add([PSCustomObject]@{
                RoleGuid = 'role-1'; RoleName = 'Storage Key Reader'
                Actions = @('Microsoft.Storage/storageAccounts/listKeys/action'); DataActions = @()
            })
            $script:State.Cache.RBACAssignments['SUB-A'] = @(
                [PSCustomObject]@{
                    ObjectId = 'p-app'; ObjectType = 'ServicePrincipal'; DisplayName = 'app-sp'
                    RoleDefinitionName = 'Storage Key Reader'
                    RoleDefinitionId = '/subscriptions/SUB-A/providers/Microsoft.Authorization/roleDefinitions/role-1'
                    Scope = '/subscriptions/SUB-A'
                }
            )
            $model = Build-CapabilityModel
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' })
            $insight.Count | Should -Be 1
            $insight[0].Confidence | Should -Be 'Medium'
            $insight[0].ImpactedResources[0] | Should -Match 'app-sp'
            $insight[0].ImpactedResources[0] | Should -Match 'Storage Key Reader'
        }

        It "custom role with a covering wildcard action (Microsoft.Storage/*) yields the insight" {
            $script:State.Cache.RoleDefinitions['SUB-A'] = [System.Collections.Generic.List[object]]::new()
            $script:State.Cache.RoleDefinitions['SUB-A'].Add([PSCustomObject]@{
                RoleGuid = 'role-1'; RoleName = 'Storage Key Reader'
                Actions = @('Microsoft.Storage/*'); DataActions = @()
            })
            $script:State.Cache.RBACAssignments['SUB-A'] = @(
                [PSCustomObject]@{
                    ObjectId = 'p-app'; ObjectType = 'ServicePrincipal'; DisplayName = 'app-sp'
                    RoleDefinitionName = 'Storage Key Reader'
                    RoleDefinitionId = '/subscriptions/SUB-A/providers/Microsoft.Authorization/roleDefinitions/role-1'
                    Scope = '/subscriptions/SUB-A'
                }
            )
            $model = Build-CapabilityModel
            @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' }).Count | Should -Be 1
        }

        It "custom role without the key-list action yields no storage key insight" {
            $script:State.Cache.RoleDefinitions['SUB-A'] = [System.Collections.Generic.List[object]]::new()
            $script:State.Cache.RoleDefinitions['SUB-A'].Add([PSCustomObject]@{
                RoleGuid = 'role-1'; RoleName = 'VM Reader'
                Actions = @('Microsoft.Compute/virtualMachines/read'); DataActions = @()
            })
            $script:State.Cache.RBACAssignments['SUB-A'] = @(
                [PSCustomObject]@{
                    ObjectId = 'p-app'; ObjectType = 'ServicePrincipal'; DisplayName = 'app-sp'
                    RoleDefinitionName = 'VM Reader'
                    RoleDefinitionId = '/subscriptions/SUB-A/providers/Microsoft.Authorization/roleDefinitions/role-1'
                    Scope = '/subscriptions/SUB-A'
                }
            )
            $model = Build-CapabilityModel
            @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' }).Count | Should -Be 0
        }
    }

    Context "Test-CapabilityKeyListCapableActions" {
        It "exact key-list action is key-capable" {
            Test-CapabilityKeyListCapableActions -Actions @('Microsoft.Storage/storageAccounts/listKeys/action') -DataActions @() | Should -BeTrue
        }

        It "full wildcard '*' is key-capable" {
            Test-CapabilityKeyListCapableActions -Actions @('*') -DataActions @() | Should -BeTrue
        }

        It "resource-type wildcard 'Microsoft.Storage/storageAccounts/*' is key-capable" {
            Test-CapabilityKeyListCapableActions -Actions @('Microsoft.Storage/storageAccounts/*') -DataActions @() | Should -BeTrue
        }

        It "unrelated action is not key-capable" {
            Test-CapabilityKeyListCapableActions -Actions @('Microsoft.Compute/virtualMachines/read') -DataActions @() | Should -BeFalse
        }

        It "empty or null action sets are not key-capable" {
            Test-CapabilityKeyListCapableActions -Actions @() -DataActions @() | Should -BeFalse
            Test-CapabilityKeyListCapableActions -Actions $null -DataActions $null | Should -BeFalse
        }
    }

    Context "sorting, ids and caps" {
        It "sorts insights severity-first (CRITICAL first) and assigns sequential CAP ids" {
            New-FullCapabilityFixture
            $model = Build-CapabilityModel
            $model.Summary.InsightCount | Should -BeGreaterThan 5
            $rank = @{ CRITICAL = 1; HIGH = 2; MEDIUM = 3; LOW = 4; INFO = 5 }
            $model.Insights[0].Severity | Should -Be 'CRITICAL'
            for ($i = 0; $i -lt $model.Insights.Count; $i++) {
                $model.Insights[$i].Id | Should -Be ('CAP-{0:d3}' -f ($i + 1))
                if ($i -gt 0) {
                    $rank[$model.Insights[$i].Severity] | Should -BeGreaterOrEqual $rank[$model.Insights[$i - 1].Severity]
                }
            }
        }

        It "Add-CapabilityInsight caps ImpactedResources at 50 but keeps the full count" {
            $ctx = New-CapabilityContext
            $resources = 1..60 | ForEach-Object { "resource-$_" }
            Add-CapabilityInsight -Context $ctx -Title 't' -Description 'd' -Severity 'LOW' -Confidence 'Low' `
                -SourceCheckIds @('X-001') -ImpactedResources $resources
            $ctx.Insights.Count | Should -Be 1
            @($ctx.Insights[0].ImpactedResources).Count | Should -Be 50
            $ctx.Insights[0].ImpactedResourceCount | Should -Be 60
        }

        It "Add-CapabilityEdge dedupes on From|To|Capability, unions SourceCheckIds and keeps higher severity" {
            $ctx = New-CapabilityContext
            Add-CapabilityEdge -Context $ctx -From 'a' -To 'b' -Type 'HasRole' -Capability 'cap' `
                -SourceCheckIds @('X-001') -Severity 'LOW' -Confidence 'Medium' | Should -BeTrue
            Add-CapabilityEdge -Context $ctx -From 'a' -To 'b' -Type 'HasRole' -Capability 'cap' `
                -SourceCheckIds @('X-002') -Severity 'HIGH' -Confidence 'High' | Should -BeTrue
            $ctx.Edges.Count | Should -Be 1
            $edge = $ctx.Edges['a|b|cap']
            @($edge.SourceCheckIds.ToArray()) -contains 'X-001' | Should -BeTrue
            @($edge.SourceCheckIds.ToArray()) -contains 'X-002' | Should -BeTrue
            $edge.Severity | Should -Be 'HIGH'
            $edge.Confidence | Should -Be 'High'
        }

        It "Get-CapabilityScopeInfo classifies ARM scopes" {
            (Get-CapabilityScopeInfo -Scope '/subscriptions/x').Kind | Should -Be 'Subscription'
            (Get-CapabilityScopeInfo -Scope '/subscriptions/x').SubscriptionId | Should -Be 'x'
            $rg = Get-CapabilityScopeInfo -Scope '/subscriptions/x/resourceGroups/y'
            $rg.Kind | Should -Be 'ResourceGroup'
            $rg.ResourceGroup | Should -Be 'y'
            (Get-CapabilityScopeInfo -Scope '/subscriptions/x/resourceGroups/y/providers/Microsoft.Web/sites/w1').Kind | Should -Be 'Resource'
            (Get-CapabilityScopeInfo -Scope '/providers/Microsoft.Management/managementGroups/mg1').Kind | Should -Be 'ManagementGroup'
            (Get-CapabilityScopeInfo -Scope '/').Kind | Should -Be 'Root'
        }
    }

    Context "evidence non-mutation" {
        It "original finding evidence gains no _CheckId annotation (clones only)" {
            $row = [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            Add-CapFinding 'KEYVAULT-001' 'Key Vaults using legacy access policies' 'LOW' 1 @($row)
            Add-CapFinding 'KEYVAULT-002' 'Key Vaults without purge protection enabled' 'HIGH' 1 @(
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            )
            [void](Build-CapabilityModel)
            $row.PSObject.Properties.Name | Should -Not -Contain '_CheckId'
            foreach ($f in @($script:State.Results)) {
                foreach ($ev in @($f.Evidence)) {
                    $ev.PSObject.Properties.Name | Should -Not -Contain '_CheckId'
                    $ev.PSObject.Properties.Name | Should -Not -Contain '_FindingMessage'
                }
            }
        }

        It "Get-CapabilityEvidenceRows returns annotated clones" {
            $row = [PSCustomObject]@{ SubscriptionId = 'SUB-A'; VaultName = 'vault1'; ResourceGroup = 'rg1' }
            Add-CapFinding 'KEYVAULT-001' 'Key Vaults using legacy access policies' 'LOW' 1 @($row)
            $rows = @(Get-CapabilityEvidenceRows -CheckIds @('KEYVAULT-001'))
            $rows.Count | Should -Be 1
            $rows[0]._CheckId | Should -Be 'KEYVAULT-001'
            $rows[0]._FindingMessage | Should -Be 'Key Vaults using legacy access policies'
            $row.PSObject.Properties.Name | Should -Not -Contain '_CheckId'
        }
    }

    Context "empty state" {
        It "Build-CapabilityModel does not throw and returns an empty model" {
            { $model = Build-CapabilityModel } | Should -Not -Throw
            $model = Build-CapabilityModel
            $model.Summary.InsightCount | Should -Be 0
            @($model.Nodes).Count | Should -Be 0
            @($model.Edges).Count | Should -Be 0
            @($model.Insights).Count | Should -Be 0
            $model.Summary.HighestSeverity | Should -BeNullOrEmpty
        }
    }

    Context "rendering (HTML / JSON / CLI)" {
        BeforeEach {
            New-FullCapabilityFixture
            $script:State.CapabilityModel = Build-CapabilityModel
        }

        It "HTML export contains the capability section, an insight title and the graph table" {
            $htmlPath = Export-ResultsHtml -Results @($script:State.Results) -OutputPath (Join-Path $TestDrive 'cap.html')
            $html = [System.IO.File]::ReadAllText($htmlPath)
            $html | Should -Match 'id="capability"'
            $html | Should -Match 'Public storage exposure with weak authentication'
            $html | Should -Match 'Capability Graph'
        }

        It "JSON export contains the CapabilityModel with Insights and ModelVersion" {
            $jsonFile = Export-ResultsJson -Results @($script:State.Results) -BaseName (Join-Path $TestDrive 'cap')
            $jsonText = [System.IO.File]::ReadAllText($jsonFile)
            $jsonText | Should -Match '"CapabilityModel"'
            $jsonText | Should -Match '"Insights"'
            $jsonText | Should -Match '"ModelVersion"'
        }

        It "CLI shows 'Capability insights' with at most 5 numbered lines plus the overflow note" {
            $script:State.Config.Quiet = $false
            $out = Show-AuditConsole -ExportedFiles @() 6>&1 | Out-String
            $out | Should -Match 'Capability insights'
            $insightCount = @($script:State.CapabilityModel.Insights).Count
            $insightCount | Should -BeGreaterThan 5   # fixture must exercise the overflow line
            $out | Should -Match ("\.\.\. and {0} more\. See HTML/JSON exports\." -f ($insightCount - 5))
            $capSection = (($out -split 'Capability insights', 2)[1] -split 'Needs attention', 2)[0]
            $numbered = [regex]::Matches($capSection, '(?m)^\s+\d+\.\s')
            $numbered.Count | Should -BeLessOrEqual 5
            $numbered.Count | Should -Be 5
        }
    }

    Context "performance guard" {
        It "builds from a large state in under 30s and respects node/edge caps" {
            $storageRows = 1..2000 | ForEach-Object {
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; StorageAccountName = "acct$_"; ResourceGroupName = 'rg1' }
            }
            Add-CapFinding 'STORAGE-001' 'Storage accounts allowing shared key authentication (enabled or unspecified)' 'HIGH' 2000 $storageRows
            $idRows = 1..300 | ForEach-Object {
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceType = 'WebApps'; ResourceName = "web$_"; ResourceGroup = 'rg1'; Role = 'Contributor'; Scope = '/subscriptions/SUB-A' }
            }
            Add-CapFinding 'IDENTITY-006' 'Resources with Managed Identities having Owner/Contributor RBAC (cloud takeover risk)' 'CRITICAL' 300 $idRows
            $nsgRows = 1..200 | ForEach-Object {
                [PSCustomObject]@{ SubscriptionId = 'SUB-A'; ResourceGroup = 'rg1'; NSGName = "nsg$_"; RuleName = 'allow-out'; Destination = 'Internet'; Port = '*' }
            }
            Add-CapFinding 'NETWORK-008' 'NSG outbound rules allowing internet access (data exfiltration path)' 'HIGH' 200 $nsgRows
            $script:State.Cache.RBACAssignments['SUB-A'] = @(
                [PSCustomObject]@{ ObjectId = 'p-owner'; ObjectType = 'User'; DisplayName = ''; RoleDefinitionName = 'Owner'; Scope = '/subscriptions/SUB-A' }
            )

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $model = Build-CapabilityModel
            $sw.Stop()

            $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
            @($model.Nodes).Count | Should -BeLessOrEqual 500
            @($model.Edges).Count | Should -BeLessOrEqual 1000
            ($model.Limits.NodesTruncated + $model.Limits.EdgesTruncated) | Should -BeGreaterThan 0
            # Impacted-resource cap also exercised: 2000 accounts, 50 listed.
            $insight = @($model.Insights | Where-Object { $_.Title -eq 'Storage key capability with Shared Key enabled' })[0]
            $insight.ImpactedResourceCount | Should -Be 2000
            @($insight.ImpactedResources).Count | Should -Be 50
        }
    }

    Context "safety contract (static analysis of Core/Capability.ps1 + Core/Azure/CapabilityModel.Azure.ps1)" {
        BeforeEach {
            $script:CapModelSrc = (Get-Content -Raw (Join-Path $projectRoot 'Core\Capability.ps1')) + "`n" +
                                  (Get-Content -Raw (Join-Path $projectRoot 'Core\Azure\CapabilityModel.Azure.ps1'))
        }

        It "contains no key/secret/content retrieval or write-API call patterns" {
            $forbidden = @(
                'Get-AzStorageAccountKey', 'listSecrets', 'SecretValue', 'Get-AzKeyVaultSecret',
                'Get-AzStorageBlob', 'Get-AzStorageFileContent', 'Invoke-AzRestMethod',
                'Invoke-RestMethod', 'Invoke-WebRequest', 'Connect-AzAccount', 'Set-AzKeyVaultAccessPolicy'
            )
            foreach ($pattern in $forbidden) {
                $script:CapModelSrc.Contains($pattern) | Should -BeFalse -Because "the capability model modules must not reference '$pattern'"
            }
        }

        It "makes zero Azure API calls (no Az cmdlets outside comments)" {
            $noBlock = [regex]::Replace($script:CapModelSrc, '(?s)<#.*?#>', '')
            $codeLines = @($noBlock -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' })
            $code = $codeLines -join "`n"
            $code | Should -Not -Match '\b(Get-Az|Set-Az|New-Az|Remove-Az|Invoke-Az|Add-Az|Update-Az)[A-Za-z]'
        }
    }
}
