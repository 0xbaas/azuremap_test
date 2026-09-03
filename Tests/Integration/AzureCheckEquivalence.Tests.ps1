#Requires -Modules Pester
<#
.SYNOPSIS
    GATE 3 - Behavioral equivalence tests for AzureMap v2 migrated checks.
    Loads fixture data, mocks Azure commands, and verifies each check function
    produces the expected findings (count, severity, evidence fields).
#>

Describe "AzureMap v2 - Azure Check Behavioral Equivalence" {

BeforeAll {
    $ProjectRoot = Resolve-Path "$PSScriptRoot\..\.."
    $FixturePath = Join-Path $ProjectRoot "Tests\Fixtures"

    # Load fixtures
    $script:StorageAccounts = Get-Content (Join-Path $FixturePath "StorageAccounts.json") | ConvertFrom-Json
    $script:NSGRules        = Get-Content (Join-Path $FixturePath "NSGRules.json")        | ConvertFrom-Json
    $script:KeyVaults       = Get-Content (Join-Path $FixturePath "KeyVaults.json")       | ConvertFrom-Json
    $script:RoleAssignments = Get-Content (Join-Path $FixturePath "RoleAssignments.json") | ConvertFrom-Json
    $script:SQLServers      = Get-Content (Join-Path $FixturePath "SQLServers.json")      | ConvertFrom-Json

    # Simulated subscription context
    $script:TestSubscriptions = @(
        [PSCustomObject]@{ Id = "00000000-0000-0000-0000-000000000001"; Name = "TestSub" }
    )

    # Initialize the script state that v2 checks rely on
    $script:State = @{
        Config = @{
            LongCredentialDays  = 730
            ExpiringSoonDays    = 30
            DangerousPorts      = @("22","21","23","3389","5985","5986","445","139","1433","3306","5432","1521","27017","6379","5984","9200","5601","2375","6443","10250")
            MaxRetryAttempts    = 3
            RetryDelaySeconds   = 2
            MaxRetryDelaySeconds = 30
            BatchSize           = 100
            PageSize            = 1000
            RBACSeverity        = @{
                "Owner" = @{ Root = "CRITICAL"; ManagementGroup = "CRITICAL"; Subscription = "HIGH"; ResourceGroup = "MEDIUM" }
                "User Access Administrator" = @{ Root = "CRITICAL"; ManagementGroup = "CRITICAL"; Subscription = "HIGH"; ResourceGroup = "MEDIUM" }
                "Contributor" = @{ Root = "HIGH"; ManagementGroup = "HIGH"; Subscription = "MEDIUM"; ResourceGroup = "LOW" }
                "Reader" = @{ Root = "LOW"; ManagementGroup = "LOW"; Subscription = "INFO"; ResourceGroup = "INFO" }
            }
        }
    }

    # Accumulator for findings written during check execution
    $script:CapturedFindings = New-Object System.Collections.Generic.List[object]

    # Stub helpers that checks call
    function Set-SubscriptionContext { param($SubscriptionId, $SubscriptionName) return $true }
    function Write-AuditLog          { param([string]$Message, [string]$Level) }
    function Write-Section           { param([string]$Title, [string]$Color, $ProgressId) }
    function Write-Progress          { param([string]$Activity, [string]$Status, $PercentComplete, $Id) }
    function Get-SafeProgressPercent { param($Current, $Total) return 0 }
    function Get-SubscriptionRBACAssignments { param($SubscriptionId, $SubscriptionName) return $script:RoleAssignments }
    # Minimal stand-in for Core/CheckRegistry.ps1's helper (used by InventoryCache);
    # CheckRegistry itself is not sourced here because it would override the stubs above.
    function ConvertTo-ScalarString { param([AllowNull()][object]$Value) if ($null -eq $Value) { return $null }; return [string]$Value }

    # Minimal audit-state shape used by checks that consult the RBAC-unavailable
    # cache (Identity.ps1). Merge into the Config hashtable above - production
    # state (Core/State.ps1) is a single hashtable holding both Config and Cache.
    $script:State.Cache = @{ RBACUnavailable = @{} }

    function Write-Finding {
        param(
            [string]$Severity,
            [string]$Message,
            [int]$Count,
            $Data,
            [string]$Service,
            [string]$Remediation,
            $Exclusions,
            [string]$SubscriptionId,
            [string]$SubscriptionName,
            # B1: swallow coverage/reporting metadata params (Status, coverage
            # counts, etc.) - this harness asserts finding content, not coverage.
            [Parameter(ValueFromRemainingArguments)]$Rest
        )
        # Normalize Data to a plain object[]: callers may pass a generic List, an
        # array, or a scalar (single-element lists unroll on assignment). Never
        # wrap a generic List in @(...) - PS 5.1 throws "Argument types do not match".
        $normData = @()
        if ($null -ne $Data) {
            if ($Data -is [System.Collections.IEnumerable] -and $Data -isnot [string]) {
                foreach ($item in $Data) { $normData += $item }
            } else {
                $normData += $Data
            }
        }
        $script:CapturedFindings.Add([PSCustomObject]@{
            Severity        = $Severity
            Message         = $Message
            Count           = $Count
            Data            = $normData
            Service         = $Service
            Remediation     = $Remediation
            SubscriptionId  = $SubscriptionId
            SubscriptionName = $SubscriptionName
        })
    }

    function Invoke-AzureCommand {
        param(
            [ScriptBlock]$Command,
            [string]$CommandName,
            [int]$MaxRetries,
            [switch]$Critical,
            [switch]$SkipContextCheck
        )
        return (& $Command)
    }

    # Source the shared per-run inventory cache used by converted checks
    . "$ProjectRoot\Products\AzureMap\Core\InventoryCache.ps1"

    # Source all v2 check files (the relocated tenant-identity checks live in
    # the parked EntraMap tree and are covered by Future/EntraMap/Tests)
    $checkFiles = Get-ChildItem (Join-Path $ProjectRoot "Products\AzureMap\Checks\*.ps1")
    foreach ($f in $checkFiles) {
        . $f.FullName
    }
}

BeforeEach {
    $script:CapturedFindings.Clear()
}

# ---------------------------------------------------------------------------
#  STORAGE CHECKS
# ---------------------------------------------------------------------------
Describe "Test-StorageSharedKeyAccess" {
    BeforeAll {
        function Get-AzStorageAccount { return $script:StorageAccounts }
    }

    It "Should flag exactly 1 storage account with SharedKeyAccess=true" {
        Test-StorageSharedKeyAccess -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $finding = $script:CapturedFindings | Where-Object { $_.Service -eq "Storage" -and $_.Severity -eq "HIGH" }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Count | Should -Be 1
        $finding.Data[0].StorageAccountName | Should -Be "stsharedkey01"
    }
}

Describe "Test-StoragePublicAccess" {
    BeforeAll {
        function Get-AzStorageAccount { return $script:StorageAccounts }
        function Get-AzStorageAccountNetworkRuleSet {
            param($ResourceGroupName, $Name)
            $sa = $script:StorageAccounts | Where-Object { $_.StorageAccountName -eq $Name }
            return $sa.NetworkRuleSet | ForEach-Object {
                $obj = [PSCustomObject]@{
                    DefaultAction = $_.DefaultAction
                    Bypass        = $_.Bypass
                    IpRules       = $_.IpRules
                }
                $obj | Add-Member -NotePropertyName 'PublicNetworkAccess' -NotePropertyValue $null -Force
                $obj
            }
        }
    }

    It "Should flag accounts with public exposure or blob public access" {
        Test-StoragePublicAccess -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $findings = $script:CapturedFindings | Where-Object { $_.Service -eq "Storage" }
        $findings | Should -Not -BeNullOrEmpty
        $publicData = $findings.Data
        $publicData.Count | Should -BeGreaterOrEqual 1
        ($publicData | Where-Object { $_.StorageAccount -eq "stpublic02" }) | Should -Not -BeNullOrEmpty
    }
}

Describe "Test-StorageAdvancedSecurity" {
    BeforeAll {
        function Get-AzStorageAccount { return $script:StorageAccounts }
    }

    It "Should detect TLS < 1.2 and cross-tenant replication" {
        Test-StorageAdvancedSecurity -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $highFindings = $script:CapturedFindings | Where-Object { $_.Severity -eq "HIGH" }
        $mediumFindings = $script:CapturedFindings | Where-Object { $_.Severity -eq "MEDIUM" }
        $highFindings.Count | Should -BeGreaterOrEqual 1
        $mediumFindings.Count | Should -BeGreaterOrEqual 1
    }
}

# ---------------------------------------------------------------------------
#  NSG CHECKS
# ---------------------------------------------------------------------------
Describe "Test-NSGPermissiveRules" {
    BeforeAll {
        function Get-AzNetworkSecurityGroup { return $script:NSGRules }
    }

    It "Should flag SSH from Internet as HIGH" {
        Test-NSGPermissiveRules -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $highFinding = $script:CapturedFindings | Where-Object { $_.Severity -eq "HIGH" }
        $highFinding | Should -Not -BeNullOrEmpty
        $highFinding.Data | Where-Object { $_.DestinationPort -eq "22" } | Should -Not -BeNullOrEmpty
    }
}

Describe "Test-NetworkExfiltrationPaths" {
    BeforeAll {
        function Get-AzNetworkSecurityGroup { return $script:NSGRules }
        function Get-AzRouteTable { return @() }
    }

    It "Should flag outbound Allow to Internet" {
        Test-NetworkExfiltrationPaths -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $finding = $script:CapturedFindings | Where-Object { $_.Service -eq "Exfiltration" -and $_.Severity -eq "HIGH" }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Data | Where-Object { $_.NSGName -eq "nsg-permissive" } | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
#  KEY VAULT CHECKS
# ---------------------------------------------------------------------------
Describe "Test-KeyVaultRBAC" {
    BeforeAll {
        # Enriched flow: per-vault GET (-VaultName) returns the matching full
        # vault object; the bare list call returns the list-view objects.
        function Get-AzKeyVault {
            param([string]$VaultName, [string]$ResourceGroupName)
            if ($VaultName) { return @($script:KeyVaults | Where-Object { $_.VaultName -eq $VaultName })[0] }
            return $script:KeyVaults
        }
    }

    It "Should flag exactly 1 vault with RBAC disabled" {
        Test-KeyVaultRBAC -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $finding = $script:CapturedFindings | Where-Object { $_.Service -eq "KeyVault" }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Count | Should -Be 1
        $finding.Data[0].VaultName | Should -Be "kv-legacy-norbac"
    }
}

Describe "Test-KeyVaultNetworkSecurity" {
    BeforeAll {
        function Get-AzKeyVault {
            param([string]$VaultName, [string]$ResourceGroupName)
            if ($VaultName) { return @($script:KeyVaults | Where-Object { $_.VaultName -eq $VaultName })[0] }
            return $script:KeyVaults
        }
        function Get-AzPrivateEndpoint { return @() }
    }

    It "Should flag public vault without firewall as CRITICAL" {
        Test-KeyVaultNetworkSecurity -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $critFinding = $script:CapturedFindings | Where-Object { $_.Severity -eq "CRITICAL" }
        $critFinding | Should -Not -BeNullOrEmpty
        $critFinding.Data | Where-Object { $_.VaultName -eq "kv-legacy-norbac" } | Should -Not -BeNullOrEmpty
    }

    It "Should flag missing purge protection as HIGH" {
        Test-KeyVaultNetworkSecurity -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $highFinding = $script:CapturedFindings | Where-Object { $_.Severity -eq "HIGH" }
        $highFinding | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
#  RBAC / IDENTITY CHECKS
# ---------------------------------------------------------------------------
Describe "Test-ExcessiveRBAC" {
    BeforeAll {
        function Get-SubscriptionRBACAssignments { return $script:RoleAssignments }
    }

    It "Should detect Owner at subscription scope as HIGH" {
        Test-ExcessiveRBAC -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $highFinding = $script:CapturedFindings | Where-Object { $_.Severity -eq "HIGH" }
        $highFinding | Should -Not -BeNullOrEmpty
        $highFinding.Data | Where-Object { $_.RoleDefinitionName -eq "Owner" } | Should -Not -BeNullOrEmpty
    }

    It "Should detect Reader at subscription scope as INFO" {
        Test-ExcessiveRBAC -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $infoFinding = $script:CapturedFindings | Where-Object { $_.Severity -eq "INFO" }
        $infoFinding | Should -Not -BeNullOrEmpty
    }

    It "Should NOT flag Contributor at ResourceGroup scope" {
        Test-ExcessiveRBAC -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $allData = $script:CapturedFindings | ForEach-Object { $_.Data } | Where-Object { $_ }
        $rgContributor = $allData | Where-Object { $_.RoleDefinitionName -eq "Contributor" -and $_.ScopeType -eq "ResourceGroup" }
        $rgContributor | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
#  SQL CHECKS
# ---------------------------------------------------------------------------
Describe "Test-SQLDatabaseSecurity" {
    BeforeAll {
        function Get-AzSqlServer { return $script:SQLServers }
        function Get-AzSqlServerAudit {
            param($ResourceGroupName, $ServerName)
            $srv = $script:SQLServers | Where-Object { $_.ServerName -eq $ServerName }
            return $srv.Auditing
        }
    }

    It "Should flag SQL server with PublicNetworkAccess=Enabled as HIGH" {
        Test-SQLDatabaseSecurity -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $finding = $script:CapturedFindings | Where-Object { $_.Severity -eq "HIGH" -and $_.Service -eq "SQL" }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Data | Where-Object { $_.ServerName -eq "sqlsvr-public" } | Should -Not -BeNullOrEmpty
    }

    It "Should flag SQL server without auditing as MEDIUM" {
        Test-SQLDatabaseSecurity -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $finding = $script:CapturedFindings | Where-Object { $_.Severity -eq "MEDIUM" -and $_.Service -eq "SQL" }
        $finding | Should -Not -BeNullOrEmpty
    }

    It "Should NOT flag the secure SQL server for public access" {
        Test-SQLDatabaseSecurity -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $highData = ($script:CapturedFindings | Where-Object { $_.Severity -eq "HIGH" }).Data
        $secureServer = $highData | Where-Object { $_.ServerName -eq "sqlsvr-secure" }
        $secureServer | Should -BeNullOrEmpty
    }
}

Describe "Test-SQLAdvancedSecurity" {
    BeforeAll {
        function Get-AzSqlServer { return $script:SQLServers }
        function Get-AzSqlServerActiveDirectoryAdministrator {
            param($ResourceGroupName, $ServerName)
            $srv = $script:SQLServers | Where-Object { $_.ServerName -eq $ServerName }
            return $srv.AADAdmin
        }
        function Get-AzSqlServerTransparentDataEncryptionProtector {
            param($ResourceGroupName, $ServerName)
            $srv = $script:SQLServers | Where-Object { $_.ServerName -eq $ServerName }
            return $srv.TDE
        }
    }

    It "Should flag public server with service-managed TDE as HIGH" {
        Test-SQLAdvancedSecurity -Subscriptions $script:TestSubscriptions -Exclusions @{}
        $finding = $script:CapturedFindings | Where-Object { $_.Severity -eq "HIGH" }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Data | Where-Object { $_.ServerName -eq "sqlsvr-public" } | Should -Not -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
#  CROSS-CUTTING: Verify all check functions exist after loading modules
# ---------------------------------------------------------------------------
Describe "All 35 Azure check functions are loadable" {
    It "All 35 Azure check functions should be defined" {
        $expectedFunctions = @(
            "Test-ExcessiveRBAC",
            "Test-CustomRoles", "Test-IdentityResourceMapping",
            "Test-StorageSharedKeyAccess", "Test-StoragePublicAccess", "Test-StorageAdvancedSecurity",
            "Test-StorageAnonymousBlobAccess", "Test-StorageExfiltrationVectors",
            "Test-NSGPermissiveRules", "Test-PrivateEndpointsDNS", "Test-PublicIPInventory",
            "Test-VNetSubnetSecurity", "Test-VNetPeeringSecurity", "Test-AzureFirewallThreatIntel",
            "Test-ApplicationGatewayWAF", "Test-NetworkExfiltrationPaths",
            "Test-SQLDatabaseSecurity", "Test-SQLAdvancedSecurity",
            "Test-KeyVaultRBAC", "Test-KeyVaultNetworkSecurity", "Test-KeyVaultSecretsExpiry",
            "Test-AKSAdvancedSecurity", "Test-AKSPrivilegeEscalation", "Test-ContainerRegistrySecurity",
            "Test-VMMonitoringAgents", "Test-AppServiceSecurity",
            "Test-CriticalResourceDiagnostics", "Test-ResourceLocks", "Test-AutomationRunAsAccounts",
            "Test-EventHubPublicAccess", "Test-ServiceBusSecurity", "Test-APIMSecurity",
            "Test-CosmosDBSecurity", "Test-SynapsePublicAccess",
            "Test-LogicAppsManagedIdentity"
        )
        $missing = @()
        foreach ($fn in $expectedFunctions) {
            if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
                $missing += $fn
            }
        }
        $missing | Should -BeNullOrEmpty -Because "all 35 check functions should be loaded; missing: $($missing -join ', ')"
    }
}

} # end outer Describe
