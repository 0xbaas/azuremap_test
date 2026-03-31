<#
.SYNOPSIS
Azure Subscription Security Review
.DESCRIPTION
Audits various Azure security configurations across all subscriptions.
Identifies misconfigurations, security risks, and compliance violations.
.NOTES
Version: 1.0
Requires: Azure PowerShell Module
#>

# ================================================================================
# CONFIGURATION
# ================================================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile = "AzureSecurityAudit-$Timestamp.log"
$script:Results = @()

# ================================================================================
# FUNCTIONS
# ================================================================================
function Write-Section {
    param([string]$Title, [string]$Color = "Cyan")
    $border = "=" * 80
    Write-Host "`n$border" -ForegroundColor $Color
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host "$border" -ForegroundColor $Color
}

function Write-Finding {
    param(
        [string]$Severity,
        [string]$Message,
        [int]$Count,
        [object]$Data
    )
    
    $severityUpper = $Severity.ToUpper()
    switch ($severityUpper) {
        "CRITICAL" { $Color = "Red" }
        "HIGH"     { $Color = "Red" }
        "MEDIUM"   { $Color = "Yellow" }
        "LOW"      { $Color = "Green" }
        "INFO"     { $Color = "Gray" }
        default    { $Color = "White" }
    }

    # Numeric rank for consistent summary sorting (lower = more severe)
    $severityRank = switch ($severityUpper) {
        "CRITICAL" { 1 }
        "HIGH"     { 2 }
        "MEDIUM"   { 3 }
        "LOW"      { 4 }
        "INFO"     { 5 }
        default    { 6 }
    }

    $subject = $Message
    if ($Message -match "^(.*?)( with | without | - )") {
        $subject = $Matches[1]
    } elseif ($Message -match "^(.*?)\s*\(") {
        $subject = $Matches[1]
    }
    $subject = $subject.Trim()
    if ([string]::IsNullOrWhiteSpace($subject)) {
        $subject = "Issues"
    }

    if ($Count -gt 0) {
        $failColor = "Red"

        # Title first, then status and count
        Write-Host ""
        Write-Host $Message -ForegroundColor $failColor
        Write-Host ("   [FINDING] Severity: {0}" -f $Severity) -ForegroundColor $failColor
        Write-Host ("   {0}: {1}" -f $subject, $Count) -ForegroundColor $failColor

        if ($Data) {
            Write-Host "`n   Details:" -ForegroundColor $failColor
            $Data | Format-Table -AutoSize | Out-Host
        }
    }
    else {
        Write-Host ""
        if ($Message -match '^\s*No\s') {
            Write-Host ("Confirmed: {0}" -f $Message) -ForegroundColor Green
        }
        else {
            Write-Host ("No instances of: {0}" -f $Message) -ForegroundColor Green
        }
        Write-Host ("   {0}: 0" -f $subject) -ForegroundColor Green
        Write-Host "   Status: Configured according to the current baseline." -ForegroundColor Green
    }
    
    # Add to results collection (script-scoped so the summary can see it ofc)
    $script:Results += [PSCustomObject]@{
        Timestamp    = Get-Date
        Severity     = $Severity
        SeverityRank = $severityRank
        Finding      = $Message
        Count        = $Count
        Status       = if ($Count -gt 0) { "Finding" } else { "Pass" }
    }
}

# Subscription helpers to centralize handling of disabled subscriptions
$script:AzureAudit_AllSubscriptions    = @()
$script:AzureAudit_ActiveSubscriptions = @()
$script:AzureAudit_DisabledSubscriptions = @()

function Initialize-AzureAuditSubscriptions {
    if ($script:AzureAudit_AllSubscriptions.Count -gt 0) { return }

    $script:AzureAudit_AllSubscriptions = Get-AzureAuditSubscriptions | Sort-Object Name
    $script:AzureAudit_DisabledSubscriptions = $script:AzureAudit_AllSubscriptions | Where-Object { $_.State -eq 'Disabled' }
    $script:AzureAudit_ActiveSubscriptions  = $script:AzureAudit_AllSubscriptions | Where-Object { $_.State -ne 'Disabled' }
}

function Get-AzureAuditSubscriptions {
    Initialize-AzureAuditSubscriptions
    return $script:AzureAudit_ActiveSubscriptions
}

function Test-StorageSharedKeyAccess {
    Write-Section -Title "STORAGE ACCOUNTS - SHARED KEY AUTHENTICATION" -Color "Red"
    
    $bad = foreach($sub in Get-AzureAuditSubscriptions){
        Set-AzContext -Subscription $sub.Id | Out-Null
        Get-AzStorageAccount -ErrorAction SilentlyContinue |
            Where-Object { $_.AllowSharedKeyAccess -eq $true } |
            Select @{n='Subscription';e={$sub.Name}}, 
                   ResourceGroupName, 
                   StorageAccountName, 
                   AllowSharedKeyAccess
    }
    
    $count = ($bad | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Storage accounts allowing shared key authentication" `
                  -Count $count `
                  -Data $bad
}

function Test-LongLivedCredentials {
    Write-Section -Title "APPLICATION CREDENTIALS - LONG VALIDITY PERIODS" -Color "Yellow"

    try {
        $apps = Get-AzADApplication -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -like "*MicrosoftGraphEndpointResourceId*") {
            Write-Finding -Severity "INFO" `
                          -Message "Application credential validity check skipped (Microsoft Graph authentication required)" `
                          -Count 0 `
                          -Data $null
            return
        } else {
            Write-Finding -Severity "INFO" `
                          -Message "Application credential validity check failed to run (unexpected error)" `
                          -Count 0 `
                          -Data $null
            return
        }
    }
    
    $longLivedCreds = $apps | ForEach-Object {
        $app = $_
        $app.PasswordCredentials + $app.KeyCredentials | Where-Object {
            ($_.EndDateTime - $_.StartDateTime).TotalDays -gt 730
        } | Select-Object @{Name='ApplicationName'; Expression={$app.DisplayName}},
            @{Name='CredentialType'; Expression={ 
                if ($_ -is [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.MicrosoftGraphPasswordCredential]) { 
                    "Password" 
                } else { 
                    "Certificate" 
                } 
            }},
            StartDateTime,
            EndDateTime,
            @{Name='DaysValid'; Expression={ [math]::Round(($_.EndDateTime - $_.StartDateTime).TotalDays) }}
    }
    
    $count = ($longLivedCreds | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Application credentials with validity >2 years" `
                  -Count $count `
                  -Data $longLivedCreds
}

function Test-DormantServicePrincipals {
    Write-Section -Title "SERVICE PRINCIPALS - DORMANT WITH RBAC ASSIGNMENTS" -Color "Yellow"
    
    try {
        $orphans = Get-AzADServicePrincipal -ErrorAction Stop | Where-Object {
            ($_.PasswordCredentials.Count -eq 0) -and ($_.KeyCredentials.Count -eq 0)
        }
    } catch {
        if ($_.Exception.Message -like "*MicrosoftGraphEndpointResourceId*") {
            Write-Finding -Severity "INFO" `
                          -Message "Dormant service principal check skipped (Microsoft Graph authentication required)" `
                          -Count 0 `
                          -Data $null
            return
        } else {
            Write-Finding -Severity "INFO" `
                          -Message "Dormant service principal check failed to run (unexpected error)" `
                          -Count 0 `
                          -Data $null
            return
        }
    }
    
    $assignments = $orphans | ForEach-Object {
        Get-AzRoleAssignment -ObjectId $_.Id -ErrorAction SilentlyContinue
    } | Where-Object { $_ } | Select Scope, RoleDefinitionName, PrincipalName
    
    $count = ($assignments | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Dormant service principals with RBAC assignments" `
                  -Count $count `
                  -Data $assignments
}

function Test-OrphanedServicePrincipals {
    Write-Section -Title "SERVICE PRINCIPALS - EXPIRED CREDENTIALS" -Color "Yellow"
    
    $now = Get-Date
    try {
        $sps = Get-AzADServicePrincipal -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -like "*MicrosoftGraphEndpointResourceId*") {
            Write-Finding -Severity "INFO" `
                          -Message "Expired service principal credential check skipped (Microsoft Graph authentication required)" `
                          -Count 0 `
                          -Data $null
            return
        } else {
            Write-Finding -Severity "INFO" `
                          -Message "Expired service principal credential check failed to run (unexpected error)" `
                          -Count 0 `
                          -Data $null
            return
        }
    }
    $expiredSpCreds = foreach ($sp in $sps) {
        foreach ($c in ($sp.PasswordCredentials + $sp.KeyCredentials)) {
            if ($c.EndDateTime -lt $now) {
                $credType = if ($c.GetType().Name -like "*Password*") { "Password" } else { "Certificate" }
                
                [pscustomobject]@{
                    SPObjectId = $sp.Id
                    SPName     = $sp.DisplayName
                    CredType   = $credType
                    EndDate    = $c.EndDateTime
                }
            }
        }
    }

    $uniqueSpCount = ($expiredSpCreds | Select-Object -Expand SPObjectId -Unique).Count
    
    Write-Finding -Severity "MEDIUM" `
                  -Message "Service principal credentials expired" `
                  -Count $uniqueSpCount `
                  -Data ($expiredSpCreds | Sort-Object EndDate | Select-Object SPName, CredType, EndDate)
}

function Test-ExcessiveRBAC {
    Write-Section -Title "RBAC - EXCESSIVE PRIVILEGES AT ROOT LEVEL" -Color "Yellow"
    
    $rbacRoot = Get-AzRoleAssignment | Where-Object { 
        $_.Scope -eq "/" -or $_.Scope -like "/providers/Microsoft.Management/managementGroups/*" 
    }
    
    $count = ($rbacRoot | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "High privilege RBAC assignments at tenant root/management groups" `
                  -Count $count `
                  -Data ($rbacRoot | Sort-Object Scope,RoleDefinitionName | Select-Object Scope, RoleDefinitionName, PrincipalName, PrincipalType)
}

function Test-StoragePublicAccess {
    Write-Section -Title "STORAGE ACCOUNTS - PUBLIC NETWORK ACCESS" -Color "Red"
    
    $exposed = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id -ErrorAction Stop | Out-Null
        foreach ($sa in Get-AzStorageAccount -ErrorAction SilentlyContinue) {
            $net = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $sa.ResourceGroupName -Name $sa.StorageAccountName -ErrorAction SilentlyContinue
            $pna = if ($sa.PSObject.Properties.Name -contains 'PublicNetworkAccess' -and $sa.PublicNetworkAccess) {
                $sa.PublicNetworkAccess
            } elseif ($net.PSObject.Properties.Name -contains 'PublicNetworkAccess') {
                $net.PublicNetworkAccess
            } else { 'Enabled' }
            if ($pna -eq 'Enabled' -and $net.DefaultAction -eq 'Allow') {
                [pscustomobject]@{
                    Subscription = $sub.Name
                    RG = $sa.ResourceGroupName
                    StorageAccount = $sa.StorageAccountName
                    PublicNetworkAccess = $pna
                    DefaultAction = $net.DefaultAction
                }
            }
        }
    }
    
    $count = ($exposed | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Storage accounts with public network access and firewall disabled" `
                  -Count $count `
                  -Data $exposed
}

function Test-KeyVaultRBAC {
    Write-Section -Title "KEY VAULTS - LEGACY ACCESS POLICIES" -Color "Yellow"
    
    $kv = foreach($sub in Get-AzureAuditSubscriptions){
        Set-AzContext -Subscription $sub.Id | Out-Null
        Get-AzKeyVault -ErrorAction SilentlyContinue |
            Select-Object @{n='Subscription';e={$sub.Name}}, ResourceGroupName, VaultName, EnableRbacAuthorization
    }
    
    $badKV = $kv | Where-Object { -not $_.EnableRbacAuthorization } | Sort Subscription,ResourceGroupName,VaultName
    $count = ($badKV | Measure-Object).Count
    Write-Finding -Severity "LOW" `
                  -Message "Key vaults using legacy access policies instead of Azure RBAC" `
                  -Count $count `
                  -Data $badKV
}

function Test-PrivateEndpointsDNS {
    Write-Section -Title "PRIVATE ENDPOINTS - MISSING DNS CONFIGURATION" -Color "Yellow"
    
    $peWithoutDns = foreach($sub in Get-AzureAuditSubscriptions){
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach($pe in Get-AzPrivateEndpoint -ErrorAction SilentlyContinue){
            $pdzg = Get-AzPrivateDnsZoneGroup -ResourceGroupName $pe.ResourceGroupName -PrivateEndpointName $pe.Name -ErrorAction SilentlyContinue
            if(-not $pdzg){
                [pscustomobject]@{
                    Subscription = $sub.Name
                    RG = $pe.ResourceGroupName
                    PrivateEndpoint = $pe.Name
                    DnsLinked = $false
                }
            }
        }
    }
    
    $count = ($peWithoutDns | Measure-Object).Count
    Write-Finding -Severity "LOW" `
                  -Message "Private endpoints missing private DNS zone linkage" `
                  -Count $count `
                  -Data $peWithoutDns
}

function Test-VMMonitoringAgents {
    Write-Section -Title "VIRTUAL MACHINES - MISSING MONITORING AGENTS" -Color "Yellow"
    
    $gaps = foreach ($s in Get-AzureAuditSubscriptions) {
        Select-AzSubscription -SubscriptionId $s.Id | Out-Null
        foreach ($vm in Get-AzVM -Status -ErrorAction SilentlyContinue) {
            $ext = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue
            $hasAma = $ext | Where-Object { $_.Publisher -eq "Microsoft.Azure.Monitor" -and $_.ExtensionType -in "AzureMonitorWindowsAgent","AzureMonitorLinuxAgent" }
            $hasOms = $ext | Where-Object { $_.Publisher -eq "Microsoft.EnterpriseCloud.Monitoring" -and $_.ExtensionType -like "OmsAgent*" }
            if (-not $hasAma -and -not $hasOms) { 
                [pscustomobject]@{ 
                    Subscription = $s.Name
                    RG=$vm.ResourceGroupName; 
                    VM=$vm.Name; 
                    Agent="None" 
                } 
            }
        }
    }
    
    $count = ($gaps | Measure-Object).Count
    if ($count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "Virtual machines without AMA/OMS monitoring agents (review for critical workloads only)" `
                      -Count $count `
                      -Data $gaps
    } else {
        Write-Finding -Severity "INFO" `
                      -Message "No virtual machines without AMA/OMS monitoring agents found" `
                      -Count 0 `
                      -Data $null
    }
}

function Test-ExpiredCredentials {
    Write-Section -Title "CREDENTIALS - EXPIRED CREDENTIALS" -Color "Yellow"
    
    $now = Get-Date

    # Test expired application credentials
    try {
        $apps = Get-AzADApplication -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -like "*MicrosoftGraphEndpointResourceId*") {
            Write-Finding -Severity "INFO" `
                          -Message "Expired application credential check skipped (Microsoft Graph authentication required)" `
                          -Count 0 `
                          -Data $null
            return
        } else {
            Write-Finding -Severity "INFO" `
                          -Message "Expired application credential check failed to run (unexpected error)" `
                          -Count 0 `
                          -Data $null
            return
        }
    }
    $expiredAppCreds = foreach ($app in $apps) {
        foreach ($c in ($app.PasswordCredentials + $app.KeyCredentials)) {
            if ($c.EndDateTime -lt $now) {
                $credType = if ($c.GetType().Name -like "*Password*") { "Password" } else { "Certificate" }
                
                [pscustomobject]@{
                    AppObjectId = $app.Id
                    AppName = $app.DisplayName
                    CredType = $credType
                    EndDate = $c.EndDateTime
                }
            }
        }
    }
    
    $appCount = ($expiredAppCreds | Select-Object -Expand AppObjectId -Unique).Count
    Write-Finding -Severity "INFO" `
                  -Message "Expired application credentials" `
                  -Count $appCount `
                  -Data ($expiredAppCreds | Sort-Object EndDate | Select-Object AppName, CredType, EndDate)
}

function Test-StorageBlobPublicAccess {
    Write-Section -Title "STORAGE ACCOUNTS - BLOB PUBLIC ACCESS" -Color "Red"
    
    $blobPublic = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        Get-AzStorageAccount -ErrorAction SilentlyContinue |
            Where-Object { $_.AllowBlobPublicAccess -eq $true } |
            Select @{n='Subscription';e={$sub.Name}}, 
                   ResourceGroupName, 
                   StorageAccountName, 
                   AllowBlobPublicAccess
    }
    
    $count = ($blobPublic | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Storage accounts with Blob Public Access enabled" `
                  -Count $count `
                  -Data $blobPublic
}

function Test-ContainerRegistryPublicAccess {
    Write-Section -Title "CONTAINER REGISTRIES - PUBLIC ACCESS & ADMIN ACCOUNT" -Color "Yellow"
    
    $findings = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($acr in Get-AzContainerRegistry -ErrorAction SilentlyContinue) {
            $config = Get-AzContainerRegistry -ResourceGroupName $acr.ResourceGroupName -Name $acr.Name
            
            [pscustomobject]@{
                Subscription = $sub.Name
                RG = $acr.ResourceGroupName
                RegistryName = $acr.Name
                AdminUserEnabled = $config.AdminUserEnabled
                PublicNetworkAccess = if ($config.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $config.PublicNetworkAccess } else { 'Unknown' }
                NetworkRuleSet = if ($config.NetworkRuleSet) { "Configured" } else { "Not Configured" }
                AnonymousPullEnabled = $config.AnonymousPullEnabled
            }
        }
    }
    
    $publicAccess = $findings | Where-Object { 
        $_.PublicNetworkAccess -eq 'Enabled' -and 
        $_.NetworkRuleSet -eq 'Not Configured' 
    }
    $adminEnabled = $findings | Where-Object { $_.AdminUserEnabled -eq $true }
    $anonymousPull = $findings | Where-Object { $_.AnonymousPullEnabled -eq $true }
    
    # Check 1: Public access without network rules
    $publicCount = ($publicAccess | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Container registries with public access and no network rules" `
                  -Count $publicCount `
                  -Data $publicAccess
    
    # Check 2: Admin account enabled
    $adminCount = ($adminEnabled | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Container registries with admin account enabled" `
                  -Count $adminCount `
                  -Data $adminEnabled
    
    # Check 3: Anonymous pull enabled
    $anonCount = ($anonymousPull | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Container registries with anonymous pull enabled" `
                  -Count $anonCount `
                  -Data $anonymousPull
}

function Test-CosmosDBPublicAccess {
    Write-Section -Title "COSMOS DB - PUBLIC ACCESS & FIREWALL RULES" -Color "Yellow"
    
    # Check if CosmosDB module is available
    if (-not (Get-Module -ListAvailable -Name Az.CosmosDB)) {
        Write-Host "`n[WARNING] Az.CosmosDB module not installed. Skipping Cosmos DB checks." -ForegroundColor Yellow
        Write-Host "   Install with: Install-Module -Name Az.CosmosDB -Force" -ForegroundColor White
        return
    }
    
    # First get all resource groups that might contain CosmosDB accounts
    $resourceGroupsWithCosmosDB = @()
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        # Get all CosmosDB accounts by checking each resource group
        $rgs = Get-AzResourceGroup -ErrorAction SilentlyContinue
        foreach ($rg in $rgs) {
            try {
                $accounts = Get-AzCosmosDBAccount -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
                if ($accounts) {
                    $resourceGroupsWithCosmosDB += [pscustomobject]@{
                        Subscription = $sub.Name
                        ResourceGroupName = $rg.ResourceGroupName
                        Accounts = $accounts
                    }
                }
            } catch {
                # Silently skip if no CosmosDB accounts in this resource group
                continue
            }
        }
    }
    
    if ($resourceGroupsWithCosmosDB.Count -eq 0) {
        Write-Finding -Severity "INFO" `
                      -Message "No Cosmos DB accounts found" `
                      -Count 0 `
                      -Data $null
        return
    }
    
    $findings = @()
    foreach ($rgGroup in $resourceGroupsWithCosmosDB) {
        foreach ($account in $rgGroup.Accounts) {
            try {
                # Get the account details with all properties
                $accountDetails = Get-AzCosmosDBAccount -ResourceGroupName $rgGroup.ResourceGroupName -Name $account.Name -ErrorAction SilentlyContinue
                if (-not $accountDetails) {
                    continue
                }
                
                # Get firewall rules
                $firewallRules = ""
                if ($accountDetails.IPRules -and $accountDetails.IPRules.Count -gt 0) {
                    $firewallRules = $accountDetails.IPRules | ForEach-Object {
                        "$($_.IPAddressOrRange)/$($_.SubnetMask)"
                    } -join "; "
                }
                
                $findings += [pscustomobject]@{
                    Subscription = $rgGroup.Subscription
                    RG = $rgGroup.ResourceGroupName
                    AccountName = $account.Name
                    PublicNetworkAccess = if ($accountDetails.PSObject.Properties.Name -contains 'PublicNetworkAccess') { 
                        $accountDetails.PublicNetworkAccess 
                    } else { 'Enabled' }
                    FirewallRules = if ($firewallRules) { $firewallRules } else { "None" }
                    IsVirtualNetworkFilterEnabled = if ($accountDetails.PSObject.Properties.Name -contains 'IsVirtualNetworkFilterEnabled') {
                        $accountDetails.IsVirtualNetworkFilterEnabled
                    } else { $false }
                    BackupPolicy = if ($accountDetails.PSObject.Properties.Name -contains 'BackupPolicy') {
                        $accountDetails.BackupPolicy.Type
                    } else { "Unknown" }
                }
            } catch {
                # Skip if we can't get account details
                continue
            }
        }
    }
    
    if ($findings.Count -eq 0) {
        Write-Finding -Severity "INFO" `
                      -Message "Unable to retrieve Cosmos DB account details" `
                      -Count 0 `
                      -Data $null
        return
    }
    
    # Check 1: Public network access enabled
    $publicAccess = $findings | Where-Object { 
        $_.PublicNetworkAccess -eq 'Enabled' -and 
        $_.IsVirtualNetworkFilterEnabled -eq $false 
    }
    $publicCount = ($publicAccess | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Cosmos DB accounts with public access and no VNet filtering" `
                  -Count $publicCount `
                  -Data $publicAccess
    
    # Check 2: No backup policy configured
    $noBackup = $findings | Where-Object { 
        $_.BackupPolicy -notin @("Periodic", "Continuous") -or 
        [string]::IsNullOrEmpty($_.BackupPolicy) 
    }
    $backupCount = ($noBackup | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Cosmos DB accounts without proper backup policy" `
                  -Count $backupCount `
                  -Data $noBackup
}

function Test-EventHubPublicAccess {
    Write-Section -Title "EVENT HUBS - PUBLIC ACCESS & NETWORK RULES" -Color "Yellow"
    
    $findings = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($namespace in Get-AzEventHubNamespace -ErrorAction SilentlyContinue) {
            $networkRules = Get-AzEventHubNetworkRuleSet -ResourceGroupName $namespace.ResourceGroupName -Name $namespace.Name -ErrorAction SilentlyContinue
            
            [pscustomobject]@{
                Subscription = $sub.Name
                RG = $namespace.ResourceGroupName
                NamespaceName = $namespace.Name
                PublicNetworkAccess = if ($namespace.PSObject.Properties.Name -contains 'PublicNetworkAccess') { $namespace.PublicNetworkAccess } else { 'Enabled' }
                DefaultAction = if ($networkRules) { $networkRules.DefaultAction } else { 'Allow' }
                IPRules = if ($networkRules -and $networkRules.IPRules) { 
                    ($networkRules.IPRules | ForEach-Object { "$($_.IPMask)/$($_.Action)" }) -join "; " 
                } else { "None" }
                IsVirtualNetworkEnabled = if ($networkRules -and $networkRules.VirtualNetworkRules) { $networkRules.VirtualNetworkRules.Count -gt 0 } else { $false }
            }
        }
    }
    
    $exposed = $findings | Where-Object { 
        $_.PublicNetworkAccess -eq 'Enabled' -and 
        $_.DefaultAction -eq 'Allow' 
    }
    $count = ($exposed | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Event Hub namespaces with public access and permissive firewall" `
                  -Count $count `
                  -Data $exposed
}

function Test-LogicAppsManagedIdentity {
    Write-Section -Title "LOGIC APPS - MANAGED IDENTITY CONFIGURATION" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $logicApps = Get-AzLogicApp -ErrorAction SilentlyContinue
        
        foreach ($logicApp in $logicApps) {
            # Skip disabled Logic Apps
            if ($logicApp.State -ne "Enabled") { continue }
            
            try {
                # Get the full resource to check identity
                $resource = Get-AzResource -ResourceId $logicApp.ResourceId -ErrorAction Stop
                
                # Check if managed identity exists
                $hasMI = $false
                if ($resource.Identity -and $resource.Identity.PrincipalId) {
                    $hasMI = $true
                }
                
                # If no managed identity, add to findings
                if (-not $hasMI) {
                    $findings += [pscustomobject]@{
                        Subscription = $sub.Name
                        LogicAppName = $logicApp.Name
                        ResourceGroup = $logicApp.ResourceGroupName
                        State = $logicApp.State
                    }
                }
                
            } catch {
                # Skip if we can't check this Logic App
                continue
            }
        }
    }
    
    $count = ($findings | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Enabled Logic Apps without managed identity" `
                  -Count $count `
                  -Data $findings
}

function Test-ApplicationGatewayWAF {
    Write-Section -Title "APPLICATION GATEWAYS - WAF CONFIGURATION" -Color "Yellow"
    
    $findings = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($appgw in Get-AzApplicationGateway -ErrorAction SilentlyContinue) {
            $wafConfig = $appgw.WebApplicationFirewallConfiguration
            
            [pscustomobject]@{
                Subscription = $sub.Name
                RG = $appgw.ResourceGroupName
                GatewayName = $appgw.Name
                SKU = $appgw.Sku.Name
                WAFEnabled = $wafConfig.Enabled
                WAFMode = if ($wafConfig.Enabled) { $wafConfig.FirewallMode } else { "N/A" }
                RuleSetType = if ($wafConfig.Enabled) { $wafConfig.RuleSetType } else { "N/A" }
                RuleSetVersion = if ($wafConfig.Enabled) { $wafConfig.RuleSetVersion } else { "N/A" }
            }
        }
    }
    
    # Check 1: WAF not enabled on Standard_v2 or WAF_v2 SKUs
    $wafMissing = $findings | Where-Object { 
        $_.SKU -match "_v2" -and 
        $_.WAFEnabled -eq $false 
    }
    $count1 = ($wafMissing | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Application Gateways (v2 SKU) without WAF enabled" `
                  -Count $count1 `
                  -Data $wafMissing
    
    # Check 2: Using Basic/Standard SKU (no WAF capability)
    $basicSku = $findings | Where-Object { 
        $_.SKU -in @("Standard_Small", "Standard_Medium", "Standard_Large", "Basic") 
    }
    $count2 = ($basicSku | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Application Gateways using Basic/Standard SKU (no WAF capability)" `
                  -Count $count2 `
                  -Data $basicSku
}

function Test-AzureFirewallThreatIntel {
    Write-Section -Title "AZURE FIREWALL - THREAT INTELLIGENCE" -Color "Yellow"
    
    $findings = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($fw in Get-AzFirewall -ErrorAction SilentlyContinue) {
            [pscustomobject]@{
                Subscription = $sub.Name
                RG = $fw.ResourceGroupName
                FirewallName = $fw.Name
                ThreatIntelMode = if ($fw.PSObject.Properties.Name -contains 'ThreatIntelMode') { $fw.ThreatIntelMode } else { "Unknown" }
                DNSProxyEnabled = -not [string]::IsNullOrEmpty($fw.DnsServer)
                ForcedTunneling = $fw.AllowActiveFTP -eq $true
                SKU = if ($fw.Sku) { $fw.Sku.Tier } else { "Unknown" }
            }
        }
    }
    
    $noThreatIntel = $findings | Where-Object { 
        $_.ThreatIntelMode -eq "Off" -or 
        [string]::IsNullOrEmpty($_.ThreatIntelMode) 
    }
    $count = ($noThreatIntel | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Azure Firewalls without threat intelligence enabled" `
                  -Count $count `
                  -Data $noThreatIntel
}

function Test-SynapsePublicAccess {
    Write-Section -Title "SYNAPSE ANALYTICS - PUBLIC ACCESS" -Color "Yellow"
    
    $findings = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($workspace in Get-AzSynapseWorkspace -ErrorAction SilentlyContinue) {
            [pscustomobject]@{
                Subscription = $sub.Name
                RG = $workspace.ResourceGroupName
                WorkspaceName = $workspace.Name
                PublicNetworkAccess = if ($workspace.PSObject.Properties.Name -contains 'PublicNetworkAccess') { 
                    $workspace.PublicNetworkAccess 
                } else { "Enabled" }
                ManagedVirtualNetwork = -not [string]::IsNullOrEmpty($workspace.ManagedVirtualNetwork)
                DataExfiltrationProtection = if ($workspace.PSObject.Properties.Name -contains 'DataExfiltrationProtection') {
                    $workspace.DataExfiltrationProtection
                } else { $false }
            }
        }
    }
    
    $exposed = $findings | Where-Object { 
        $_.PublicNetworkAccess -eq "Enabled" -and 
        $_.ManagedVirtualNetwork -eq $false 
    }
    $count = ($exposed | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Synapse workspaces with public access and no managed VNet" `
                  -Count $count `
                  -Data $exposed
}

function Test-SQLDatabaseSecurity {
    Write-Section -Title "SQL DATABASES - BASIC SECURITY CHECKS" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        # Get all SQL servers
        $servers = Get-AzSqlServer -ErrorAction SilentlyContinue
        
        foreach ($server in $servers) {
            # Get server-level auditing
            $serverAuditing = Get-AzSqlServerAudit -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction SilentlyContinue
            
            [pscustomobject]@{
                Subscription = $sub.Name
                RG = $server.ResourceGroupName
                ServerName = $server.ServerName
                PublicNetworkAccess = $server.PublicNetworkAccess
                MinimalTlsVersion = if ($server.MinimalTlsVersion) { $server.MinimalTlsVersion } else { "Unknown" }
                AuditingEnabled = if ($serverAuditing -and $serverAuditing.AuditState -eq "Enabled") { "Yes" } else { "No" }
                Databases = (Get-AzSqlDatabase -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction SilentlyContinue | Measure-Object).Count
            }
        }
    }
    
    # Check 1: SQL servers with public network access
    $publicServers = $findings | Where-Object { $_.PublicNetworkAccess -eq "Enabled" }
    $count1 = ($publicServers | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "SQL servers with public network access enabled" `
                  -Count $count1 `
                  -Data ($publicServers | Select-Object Subscription, RG, ServerName, PublicNetworkAccess, MinimalTlsVersion)
    
    # Check 2: SQL servers without auditing
    $noAuditing = $findings | Where-Object { $_.AuditingEnabled -eq "No" }
    $count2 = ($noAuditing | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "SQL servers without server-level auditing" `
                  -Count $count2 `
                  -Data ($noAuditing | Select-Object Subscription, RG, ServerName, AuditingEnabled, Databases)
}

function Test-AKSAdvancedSecurity {
    Write-Section -Title "AKS - ADVANCED SECURITY CHECKS" -Color "Yellow"
    
    # Check if AKS module is available first
    if (-not (Get-Module -ListAvailable -Name Az.Aks)) {
        Write-Host "`n[WARNING] Az.Aks module not installed. Skipping AKS advanced checks." -ForegroundColor Yellow
        Write-Host "   Install with: Install-Module -Name Az.Aks -Force" -ForegroundColor White
        return
    }
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $aksClusters = Get-AzAksCluster -ErrorAction SilentlyContinue
        
        foreach ($aks in $aksClusters) {
            try {
                $cluster = Get-AzAksCluster -ResourceGroupName $aks.ResourceGroupName -Name $aks.Name -ErrorAction SilentlyContinue
                if (-not $cluster) { continue }
                
                # Get detailed configuration
                $apiAccessProfile = $cluster.APIServerAccessProfile
                $networkProfile = $cluster.NetworkProfile
                $aadProfile = $cluster.AadProfile
                $identityProfile = $cluster.IdentityProfile
                $addonProfile = $cluster.AddonProfile
                
                # Check for Azure Policy add-on
                $policyAddon = $addonProfile["azurepolicy"]
                $policyEnabled = $policyAddon -and $policyAddon.Enabled -eq $true
                
                # Check for OMS/Container Insights
                $omsAddon = $addonProfile["omsagent"]
                $omsEnabled = $omsAddon -and $omsAddon.Enabled -eq $true
                
                # Check for secrets encryption
                $keyVaultSecretsProvider = $addonProfile["azureKeyvaultSecretsProvider"]
                $secretsEncryptionEnabled = $keyVaultSecretsProvider -and $keyVaultSecretsProvider.Enabled -eq $true
                
                # Check workload identity (OIDC issuer)
                $oidcIssuerProfile = $cluster.OidcIssuerProfile
                $oidcEnabled = $oidcIssuerProfile -and $oidcIssuerProfile.Enabled -eq $true
                
                # Check for local accounts
                $disableLocalAccounts = $cluster.DisableLocalAccounts
                
                $findings += [pscustomobject]@{
                    Subscription = $sub.Name
                    ClusterName = $cluster.Name
                    ResourceGroup = $cluster.ResourceGroupName
                    PrivateCluster = if ($apiAccessProfile) { $apiAccessProfile.EnablePrivateCluster } else { $false }
                    AuthorizedIPRanges = if ($apiAccessProfile -and $apiAccessProfile.AuthorizedIPRanges) { "Enabled" } else { "Disabled" }
                    AADIntegration = if ($aadProfile) { 
                        if ($aadProfile.Managed -eq $true) { "Managed AAD" } else { "Legacy AAD" }
                    } else { "Disabled" }
                    NetworkPolicy = if ($networkProfile) { $networkProfile.NetworkPolicy } else { "None" }
                    AzurePolicyAddon = if ($policyEnabled) { "Enabled" } else { "Disabled" }
                    ContainerInsights = if ($omsEnabled) { "Enabled" } else { "Disabled" }
                    SecretsEncryption = if ($secretsEncryptionEnabled) { "Enabled" } else { "Disabled" }
                    OIDCIssuer = if ($oidcEnabled) { "Enabled" } else { "Disabled" }
                    LocalAccountsDisabled = if ($disableLocalAccounts -eq $true) { "Yes" } else { "No" }
                    KubernetesVersion = $cluster.KubernetesVersion
                    NodePools = ($cluster.AgentPoolProfiles | Measure-Object).Count
                }
            } catch {
                Write-Host "   [Warning] Could not query AKS cluster '$($aks.Name)'" -ForegroundColor DarkYellow
                continue
            }
        }
    }
    
    if ($findings.Count -eq 0) {
        Write-Finding -Severity "INFO" `
                      -Message "No AKS clusters found" `
                      -Count 0 `
                      -Data $null
        return
    }
    
    # Check 1: AKS clusters not using private clusters
    $publicClusters = $findings | Where-Object { $_.PrivateCluster -eq $false }
    $count1 = ($publicClusters | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "AKS clusters not using private cluster mode" `
                  -Count $count1 `
                  -Data ($publicClusters | Select-Object Subscription, ClusterName, ResourceGroup, AuthorizedIPRanges)
    
    # Check 2: AKS clusters with legacy AAD or no AAD integration
    $legacyAAD = $findings | Where-Object { 
        $_.AADIntegration -eq "Legacy AAD" -or 
        $_.AADIntegration -eq "Disabled" 
    }
    $count2 = ($legacyAAD | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "AKS clusters without managed Azure AD integration" `
                  -Count $count2 `
                  -Data ($legacyAAD | Select-Object Subscription, ClusterName, ResourceGroup, AADIntegration)
    
    # Check 3: AKS clusters without Azure Policy add-on
    $noPolicyAddon = $findings | Where-Object { $_.AzurePolicyAddon -eq "Disabled" }
    $count3 = ($noPolicyAddon | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "AKS clusters without Azure Policy add-on" `
                  -Count $count3 `
                  -Data ($noPolicyAddon | Select-Object Subscription, ClusterName, ResourceGroup)
    
    # Check 4: AKS clusters without network policy
    $noNetworkPolicy = $findings | Where-Object { 
        $_.NetworkPolicy -eq "None" -or 
        [string]::IsNullOrEmpty($_.NetworkPolicy) 
    }
    $count4 = ($noNetworkPolicy | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "AKS clusters without network policy (Calico/Azure)" `
                  -Count $count4 `
                  -Data ($noNetworkPolicy | Select-Object Subscription, ClusterName, ResourceGroup, NetworkPolicy)
    
    # Check 5: AKS clusters with local accounts enabled
    $localAccountsEnabled = $findings | Where-Object { $_.LocalAccountsDisabled -eq "No" }
    $count5 = ($localAccountsEnabled | Measure-Object).Count
    Write-Finding -Severity "LOW" `
                  -Message "AKS clusters with local accounts enabled" `
                  -Count $count5 `
                  -Data ($localAccountsEnabled | Select-Object Subscription, ClusterName, ResourceGroup)
}

function Test-VNetSubnetSecurity {
    Write-Section -Title "VIRTUAL NETWORKS - SUBNET SECURITY CONFIGURATION" -Color "Yellow"
    
    $findings = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($vnet in Get-AzVirtualNetwork -ErrorAction SilentlyContinue) {
            foreach ($subnet in $vnet.Subnets) {
                # Check if subnet has NSG associated
                $hasNSG = -not [string]::IsNullOrEmpty($subnet.NetworkSecurityGroup.Id)
                
                # Check if subnet has service endpoints
                $serviceEndpoints = if ($subnet.ServiceEndpoints) { 
                    ($subnet.ServiceEndpoints.Service | ForEach-Object { $_ }) -join ", " 
                } else { "None" }
                
                # Check if subnet has private endpoints
                $privateEndpoints = if ($subnet.PrivateEndpointNetworkPolicies -eq "Disabled") { "Enabled" } else { "Disabled" }
                
                [pscustomobject]@{
                    Subscription = $sub.Name
                    RG = $vnet.ResourceGroupName
                    VNetName = $vnet.Name
                    SubnetName = $subnet.Name
                    AddressPrefix = $subnet.AddressPrefix
                    HasNSG = if ($hasNSG) { "Yes" } else { "No" }
                    ServiceEndpoints = $serviceEndpoints
                    PrivateEndpoints = $privateEndpoints
                }
            }
        }
    }
    
    # Check 1: Subnets without NSG protection (excluding well-known system subnets)
    $noNSG = $findings | Where-Object {
        $_.HasNSG -eq "No" -and
        $_.SubnetName -notin @("GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet") -and
        $_.SubnetName -notlike "*appgw*" -and
        $_.SubnetName -notlike "*applicationgateway*"
    }
    $count1 = ($noNSG | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Virtual Network subnets without Network Security Group" `
                  -Count $count1 `
                  -Data $noNSG
    
    # (Large subnet size is an architectural choice; not treated as a security finding here)
}

function Test-ServiceBusSecurity {
    Write-Section -Title "SERVICE BUS - SECURITY CONFIGURATION" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $namespaces = Get-AzServiceBusNamespace -ErrorAction SilentlyContinue
        
        foreach ($ns in $namespaces) {
            try {
                # Get network rule set
                $networkRuleSet = Get-AzServiceBusNetworkRuleSet -ResourceGroupName $ns.ResourceGroupName `
                                                                -Namespace $ns.Name `
                                                                -ErrorAction SilentlyContinue
                
                # Get authorization rules
                $authRules = Get-AzServiceBusAuthorizationRule -ResourceGroupName $ns.ResourceGroupName `
                                                              -Namespace $ns.Name `
                                                              -ErrorAction SilentlyContinue
                
                # Check for SAS policies with long expiry
                $longSASPolicies = @()
                foreach ($rule in $authRules) {
                    $rights = $rule.Rights
                    if ($rights -contains "Manage" -or $rights -contains "Send" -or $rights -contains "Listen") {
                        # Check primary and secondary keys exist
                        $keys = Get-AzServiceBusKey -ResourceGroupName $ns.ResourceGroupName `
                                                    -Namespace $ns.Name `
                                                    -Name $rule.Name `
                                                    -ErrorAction SilentlyContinue
                        
                        if ($keys) {
                            $longSASPolicies += "$($rule.Name) - $($rights -join ',')"
                        }
                    }
                }
                
                $findings += [pscustomobject]@{
                    Subscription = $sub.Name
                    Namespace = $ns.Name
                    ResourceGroup = $ns.ResourceGroupName
                    SKU = $ns.Sku.Name
                    PublicNetworkAccess = if ($ns.PublicNetworkAccess) { $ns.PublicNetworkAccess } else { "Enabled" }
                    DefaultAction = if ($networkRuleSet) { $networkRuleSet.DefaultAction } else { "Allow" }
                    IPRulesCount = if ($networkRuleSet -and $networkRuleSet.IpRules) { $networkRuleSet.IpRules.Count } else { 0 }
                    SASKeyCount = ($authRules | Measure-Object).Count
                    LongSASPolicies = if ($longSASPolicies.Count -gt 0) { ($longSASPolicies -join "; ") } else { "None" }
                    Location = $ns.Location
                }
            } catch {
                Write-Host "   [Warning] Could not query Service Bus namespace '$($ns.Name)'" -ForegroundColor DarkYellow
                continue
            }
        }
    }
    
    # Check 1: Service Bus namespaces with public access and permissive firewall
    $exposedNS = $findings | Where-Object { 
        $_.PublicNetworkAccess -eq "Enabled" -and 
        $_.DefaultAction -eq "Allow" 
    }
    $count1 = ($exposedNS | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Service Bus namespaces with public access and permissive firewall" `
                  -Count $count1 `
                  -Data $exposedNS
    
    # Check 2: Service Bus namespaces with SAS keys (potential long-lived credentials)
    $withSASKeys = $findings | Where-Object { $_.SASKeyCount -gt 0 }
    $count2 = ($withSASKeys | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Service Bus namespaces using SAS keys (consider Managed Identity)" `
                  -Count $count2 `
                  -Data ($withSASKeys | Select-Object Subscription, Namespace, ResourceGroup, SASKeyCount, LongSASPolicies)
}

function Test-APIMSecurity {
    Write-Section -Title "API MANAGEMENT - SECURITY CONFIGURATION" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $apimServices = Get-AzApiManagement -ErrorAction SilentlyContinue
        
        foreach ($apim in $apimServices) {
            try {
                # Get custom domains to check TLS settings
                $customDomains = $apim.HostnameConfigurations
                
                # Check for virtual network configuration
                $virtualNetwork = $apim.VirtualNetwork
                $isInternal = $apim.VirtualNetworkType -eq "Internal"
                
                # Check TLS settings
                $minTlsVersion = "Unknown"
                $sslProtocols = "Unknown"
                
                # Check for policies that might have weak authentication
                $policies = Get-AzApiManagementPolicy -ResourceGroupName $apim.ResourceGroupName `
                                                     -ServiceName $apim.Name `
                                                     -ErrorAction SilentlyContinue
                
                # Check certificates
                $certificates = Get-AzApiManagementCertificate -ResourceGroupName $apim.ResourceGroupName `
                                                              -ServiceName $apim.Name `
                                                              -ErrorAction SilentlyContinue
                
                $expiredCerts = @()
                $nearExpiryCerts = @()
                $now = Get-Date
                
                foreach ($cert in $certificates) {
                    $expiryDate = $cert.ExpirationDate
                    if ($expiryDate) {
                        $daysToExpiry = ($expiryDate - $now).Days
                        if ($daysToExpiry -lt 0) {
                            $expiredCerts += $cert.Subject
                        } elseif ($daysToExpiry -lt 30) {
                            $nearExpiryCerts += $cert.Subject
                        }
                    }
                }
                
                $findings += [pscustomobject]@{
                    Subscription = $sub.Name
                    APIMName = $apim.Name
                    ResourceGroup = $apim.ResourceGroupName
                    SKU = $apim.Sku
                    Location = $apim.Location
                    VirtualNetworkType = $apim.VirtualNetworkType
                    IsInternalVNet = $isInternal
                    PublicIPAddress = if ($apim.PublicIPAddresses) { ($apim.PublicIPAddresses -join ", ") } else { "None" }
                    CustomDomains = ($customDomains | Measure-Object).Count
                    CertificatesCount = ($certificates | Measure-Object).Count
                    ExpiredCertificates = if ($expiredCerts.Count -gt 0) { ($expiredCerts -join "; ") } else { "None" }
                    NearExpiryCertificates = if ($nearExpiryCerts.Count -gt 0) { ($nearExpiryCerts -join "; ") } else { "None" }
                    DeveloperPortalEnabled = $apim.EnableClientCertificate -eq $true
                }
            } catch {
                Write-Host "   [Warning] Could not query API Management service '$($apim.Name)'" -ForegroundColor DarkYellow
                continue
            }
        }
    }
    
    # Check 1: External APIM services (public facing)
    $externalAPIM = $findings | Where-Object { $_.VirtualNetworkType -eq "External" }
    $count1 = ($externalAPIM | Measure-Object).Count
    if ($count1 -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "External (public-facing) API Management services" `
                      -Count $count1 `
                      -Data ($externalAPIM | Select-Object Subscription, APIMName, ResourceGroup, PublicIPAddress)
    }
    
    # Check 2: APIM services with expired certificates
    $withExpiredCerts = $findings | Where-Object { $_.ExpiredCertificates -ne "None" }
    $count2 = ($withExpiredCerts | Measure-Object).Count
    if ($count2 -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "API Management services with expired certificates" `
                      -Count $count2 `
                      -Data ($withExpiredCerts | Select-Object Subscription, APIMName, ResourceGroup, ExpiredCertificates)
    }
    
    # Check 3: APIM services with certificates nearing expiry
    $withNearExpiryCerts = $findings | Where-Object { $_.NearExpiryCertificates -ne "None" }
    $count3 = ($withNearExpiryCerts | Measure-Object).Count
    if ($count3 -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "API Management services with certificates expiring soon (<30 days)" `
                      -Count $count3 `
                      -Data ($withNearExpiryCerts | Select-Object Subscription, APIMName, ResourceGroup, NearExpiryCertificates)
    }
    
    # Check 4: Developer portal without client certificate authentication
    $devPortalWithoutCert = $findings | Where-Object { 
        $_.DeveloperPortalEnabled -eq $false -and 
        $_.VirtualNetworkType -eq "External" 
    }
    $count4 = ($devPortalWithoutCert | Measure-Object).Count
    if ($count4 -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "External APIM services without client certificate authentication for developer portal" `
                      -Count $count4 `
                      -Data $devPortalWithoutCert
    }
}

function Test-NSGPermissiveRules {
    Write-Section -Title "NETWORK SECURITY GROUPS - OVERLY PERMISSIVE RULES" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
        
        foreach ($nsg in $nsgs) {
            foreach ($rule in $nsg.SecurityRules) {
                # Check for overly permissive inbound rules
                if ($rule.Access -eq "Allow" -and $rule.Direction -eq "Inbound") {
                    
                    # Check source prefixes
                    $sourceIsWideOpen = $false
                    if ($rule.SourceAddressPrefix) {
                        $sourceIsWideOpen = $rule.SourceAddressPrefix -in @("Internet", "0.0.0.0/0", "*", "Any")
                    }
                    elseif ($rule.SourceAddressPrefixes) {
                        foreach ($prefix in $rule.SourceAddressPrefixes) {
                            if ($prefix -in @("Internet", "0.0.0.0/0", "*", "Any")) {
                                $sourceIsWideOpen = $true
                                break
                            }
                        }
                    }
                    
                    if ($sourceIsWideOpen) {
                        # Check for dangerous ports, probably missing some here
                        $dangerousPorts = @(
  "22",
  "21",
  "23",
  "3389",
  "5985",
  "5986",
  "2375",
  "2376",
  "6443",
  "445",
  "139",
  "1433",
  "3306",
  "5432",
  "1521",
  "27017",
  "6379",
  "9200",
  "11211",
  "8080",
  "8000",
  "8443",
  "9000",
  "8888",
  "5601"
)

                        
                        # Parse port ranges
                        $portsToCheck = @()
                        if ($rule.DestinationPortRange) {
                            $portsToCheck += $rule.DestinationPortRange
                        }
                        if ($rule.DestinationPortRanges) {
                            $portsToCheck += $rule.DestinationPortRanges
                        }
                        
                        foreach ($portRange in $portsToCheck) {
                            # Check if port range contains dangerous ports
                            foreach ($dangerPort in $dangerousPorts) {
                                if ($portRange -eq $dangerPort -or 
                                    ($portRange -match "^\d+-\d+$" -and 
                                     [int]$dangerPort -ge [int]$portRange.Split("-")[0] -and 
                                     [int]$dangerPort -le [int]$portRange.Split("-")[1])) {
                                    
                                    $findings += [pscustomobject]@{
                                        Subscription = $sub.Name
                                        RG = $nsg.ResourceGroupName
                                        NSGName = $nsg.Name
                                        RuleName = $rule.Name
                                        Source = if ($rule.SourceAddressPrefix) { $rule.SourceAddressPrefix } else { ($rule.SourceAddressPrefixes -join ", ") }
                                        DestinationPort = $portRange
                                        Protocol = $rule.Protocol
                                        Priority = $rule.Priority
                                        Direction = $rule.Direction
                                    }
                                    break
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    $count = ($findings | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "NSG rules allowing internet access to sensitive ports" `
                  -Count $count `
                  -Data ($findings | Sort-Object Subscription, RG, NSGName, Priority | Select-Object Subscription, RG, NSGName, RuleName, Source, DestinationPort, Protocol, Priority)
}

function Test-AppServiceSecurity {
    Write-Section -Title "APP SERVICE - AUTHENTICATION & HTTPS ENFORCEMENT" -Color "Yellow"
    
    $findings = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($webApp in Get-AzWebApp -ErrorAction SilentlyContinue) {
            try {
                # Get auth settings
                $authSettings = Get-AzWebAppAuthSetting -ResourceGroupName $webApp.ResourceGroupName -Name $webApp.Name -ErrorAction SilentlyContinue
                
                [pscustomobject]@{
                    Subscription = $sub.Name
                    RG = $webApp.ResourceGroupName
                    AppName = $webApp.Name
                    HTTPSOnly = $webApp.HttpsOnly
                    MinimumTlsVersion = $webApp.SiteConfig.MinTlsVersion
                    AuthenticationEnabled = if ($authSettings -and $authSettings.Enabled) { "Yes" } else { "No" }
                    ClientCertEnabled = $webApp.ClientCertEnabled
                    Kind = $webApp.Kind
                    State = $webApp.State
                }
            } catch {
                continue
            }
        }
    }
    
    # Check 1: Web apps without HTTPS enforcement
    $noHTTPS = $findings | Where-Object { 
        $_.HTTPSOnly -eq $false -and 
        $_.State -eq "Running" 
    }
    $count1 = ($noHTTPS | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "App Service applications without HTTPS Only enabled" `
                  -Count $count1 `
                  -Data $noHTTPS
    
    # Check 2: Web apps without authentication
    $noAuth = $findings | Where-Object { 
        $_.AuthenticationEnabled -eq "No" -and 
        $_.State -eq "Running" 
    }
    $count2 = ($noAuth | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "App Service applications without authentication enabled" `
                  -Count $count2 `
                  -Data $noAuth
}

function Test-PublicIPInventory {
    Write-Section -Title "NETWORK - PUBLIC IP INVENTORY" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        # Get all public IPs
        $publicIPs = Get-AzPublicIpAddress -ErrorAction SilentlyContinue
        
        foreach ($pip in $publicIPs) {
            $associatedResource = "Unknown"
            $resourceType = "Unknown"
            $resourceName = "Unknown"
            
            # Check IP configuration (NIC association)
            if ($pip.IpConfiguration) {
                $resourceId = $pip.IpConfiguration.Id
                if ($resourceId -match "Microsoft.Network/networkInterfaces/") {
                    $resourceType = "NetworkInterface"
                    $resourceName = $resourceId.Split('/')[-3]  # NIC name
                } elseif ($resourceId -match "Microsoft.Network/loadBalancers/") {
                    $resourceType = "LoadBalancer"
                    $resourceName = $resourceId.Split('/')[-3]  # LB name
                }
                $associatedResource = "$resourceType/$resourceName"
            }
            # Check for Frontend IP Configuration (Application Gateway, Firewall, etc.)
            elseif ($pip.IpConfiguration -eq $null -and $pip.Tag) {
                # Try to infer from tags
                $associatedResource = "Standalone"
            }
            
            # Get DNS settings
            $dnsName = $pip.DnsSettings.Fqdn
            
            $findings += [pscustomobject]@{
                Subscription = $sub.Name
                PublicIPName = $pip.Name
                ResourceGroup = $pip.ResourceGroupName
                IPAddress = $pip.IpAddress
                AssociatedResource = $associatedResource
                ResourceType = $resourceType
                SKU = if ($pip.Sku) { $pip.Sku.Name } else { "Basic" }
                AllocationMethod = $pip.PublicIpAllocationMethod
                DNSEndpoint = if ($dnsName) { $dnsName } else { "None" }
                Location = $pip.Location
            }
        }
    }
    
    # Check 1: Public IPs with DNS endpoints (inventory of named endpoints)
    $withDNS = $findings | Where-Object { $_.DNSEndpoint -ne "None" }
    $count1 = ($withDNS | Measure-Object).Count
    Write-Finding -Severity "INFO" `
                  -Message "Public IPs with DNS endpoints (named internet endpoints)" `
                  -Count $count1 `
                  -Data ($withDNS | Select-Object Subscription, PublicIPName, IPAddress, DNSEndpoint, ResourceType, AssociatedResource)
    
    # Check 2: Basic SKU public IPs (not zone-redundant)
    $basicSKU = $findings | Where-Object { $_.SKU -eq "Basic" }
    $count2 = ($basicSKU | Measure-Object).Count
    Write-Finding -Severity "LOW" `
                  -Message "Basic SKU Public IPs (not zone-redundant)" `
                  -Count $count2 `
                  -Data ($basicSKU | Select-Object Subscription, PublicIPName, IPAddress, ResourceType)
    
    # Return full inventory for review
    $totalCount = ($findings | Measure-Object).Count
    Write-Finding -Severity "INFO" `
                  -Message "Total public IP addresses found" `
                  -Count $totalCount `
                  -Data ($findings | Select-Object Subscription, PublicIPName, IPAddress, ResourceType, AssociatedResource, DNSEndpoint)
}

function Test-NSGAnyAnyRules {
    Write-Section -Title "NSG - OVERLY PERMISSIVE 'ANY TO ANY' RULES" -Color "Red"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
        
        foreach ($nsg in $nsgs) {
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Access -eq "Allow" -and $rule.Direction -eq "Inbound") {
                    
                    $sourceAny = $false
                    $destAny = $false
                    $protocolAny = $false
                    
                    # Check source
                    if ($rule.SourceAddressPrefix -eq "*" -or 
                        $rule.SourceAddressPrefix -eq "0.0.0.0/0" -or 
                        $rule.SourceAddressPrefix -eq "Internet" -or
                        $rule.SourceAddressPrefix -eq "Any") {
                        $sourceAny = $true
                    }
                    elseif ($rule.SourceAddressPrefixes -contains "*" -or
                           $rule.SourceAddressPrefixes -contains "0.0.0.0/0" -or
                           $rule.SourceAddressPrefixes -contains "Internet" -or
                           $rule.SourceAddressPrefixes -contains "Any") {
                        $sourceAny = $true
                    }
                    
                    # Check destination
                    if ($rule.DestinationAddressPrefix -eq "*" -or 
                        $rule.DestinationAddressPrefix -eq "0.0.0.0/0") {
                        $destAny = $true
                    }
                    elseif ($rule.DestinationAddressPrefixes -contains "*" -or
                           $rule.DestinationAddressPrefixes -contains "0.0.0.0/0") {
                        $destAny = $true
                    }
                    
                    # Check protocol
                    if ($rule.Protocol -eq "*") {
                        $protocolAny = $true
                    }
                    
                    # Check port ranges
                    $widePortRange = $false
                    if ($rule.DestinationPortRange -eq "*" -or 
                        $rule.DestinationPortRange -eq "0-65535") {
                        $widePortRange = $true
                    }
                    elseif ($rule.DestinationPortRanges -contains "*" -or
                           $rule.DestinationPortRanges -contains "0-65535") {
                        $widePortRange = $true
                    }
                    
                    if ($sourceAny -or $destAny -or $protocolAny -or $widePortRange) {
                        $findings += [pscustomobject]@{
                            Subscription = $sub.Name
                            ResourceGroup = $nsg.ResourceGroupName
                            NSGName = $nsg.Name
                            RuleName = $rule.Name
                            Direction = $rule.Direction
                            Source = if ($rule.SourceAddressPrefix) { $rule.SourceAddressPrefix } else { ($rule.SourceAddressPrefixes -join ", ") }
                            Destination = if ($rule.DestinationAddressPrefix) { $rule.DestinationAddressPrefix } else { ($rule.DestinationAddressPrefixes -join ", ") }
                            Protocol = $rule.Protocol
                            Port = if ($rule.DestinationPortRange) { $rule.DestinationPortRange } else { ($rule.DestinationPortRanges -join ", ") }
                            Priority = $rule.Priority
                            SourceIsAny = $sourceAny
                            DestIsAny = $destAny
                            ProtocolIsAny = $protocolAny
                            PortIsWide = $widePortRange
                        }
                    }
                }
            }
        }
    }
    
    # Categorize findings by severity
    $criticalRules = $findings | Where-Object { 
        $_.SourceIsAny -eq $true -and 
        ($_.PortIsWide -eq $true -or $_.ProtocolIsAny -eq $true) 
    }
    
    $highRules = $findings | Where-Object { 
        $_.SourceIsAny -eq $true -and 
        $_.PortIsWide -eq $false -and 
        $_.ProtocolIsAny -eq $false 
    }
    
    $mediumRules = $findings | Where-Object { 
        $_.SourceIsAny -eq $false -and 
        ($_.PortIsWide -eq $true -or $_.ProtocolIsAny -eq $true) 
    }
    
    if (($criticalRules | Measure-Object).Count -gt 0) {
        Write-Finding -Severity "CRITICAL" `
                      -Message "NSG rules allowing internet access to all ports/protocols" `
                      -Count ($criticalRules | Measure-Object).Count `
                      -Data ($criticalRules | Select-Object Subscription, ResourceGroup, NSGName, RuleName, Source, Port, Protocol, Priority)
    }
    
    if (($highRules | Measure-Object).Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "NSG rules allowing internet access to specific ports" `
                      -Count ($highRules | Measure-Object).Count `
                      -Data ($highRules | Select-Object Subscription, ResourceGroup, NSGName, RuleName, Source, Port, Protocol, Priority)
    }
    
    if (($mediumRules | Measure-Object).Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "NSG rules with wide port ranges or any protocol" `
                      -Count ($mediumRules | Measure-Object).Count `
                      -Data ($mediumRules | Select-Object Subscription, ResourceGroup, NSGName, RuleName, Source, Port, Protocol, Priority)
    }
}

function Test-VNetPeeringSecurity {
    Write-Section -Title "VNET PEERING - SECURITY CONFIGURATION" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
        
        foreach ($vnet in $vnets) {
            $peerings = Get-AzVirtualNetworkPeering -ResourceGroupName $vnet.ResourceGroupName `
                                                   -VirtualNetworkName $vnet.Name `
                                                   -ErrorAction SilentlyContinue
            
            foreach ($peering in $peerings) {
                # Check if peered with shared services or external networks
                $remoteVNetId = $peering.RemoteVirtualNetwork.Id
                $remoteVNetName = $remoteVNetId.Split('/')[-1]
                $remoteSub = $remoteVNetId.Split('/')[2]
                
                # Check for gateway transit settings
                $allowGatewayTransit = $peering.AllowGatewayTransit
                $useRemoteGateways = $peering.UseRemoteGateways
                
                # Check for forwarded traffic and traffic to remote networks
                $allowForwardedTraffic = $peering.AllowForwardedTraffic
                $allowVirtualNetworkAccess = $peering.AllowVirtualNetworkAccess
                
                $findings += [pscustomobject]@{
                    Subscription = $sub.Name
                    LocalVNet = $vnet.Name
                    ResourceGroup = $vnet.ResourceGroupName
                    RemoteVNet = $remoteVNetName
                    RemoteSubscription = $remoteSub
                    AllowGatewayTransit = $allowGatewayTransit
                    UseRemoteGateways = $useRemoteGateways
                    AllowForwardedTraffic = $allowForwardedTraffic
                    AllowVirtualNetworkAccess = $allowVirtualNetworkAccess
                    PeeringState = $peering.PeeringState
                    IsSameSubscription = ($sub.Id -eq $remoteSub)
                }
            }
        }
    }
    
    if ($findings.Count -gt 0) {
        # Check 1: Cross-subscription peering
        $crossSubPeering = $findings | Where-Object { $_.IsSameSubscription -eq $false }
        $count1 = ($crossSubPeering | Measure-Object).Count
        if ($count1 -gt 0) {
            Write-Finding -Severity "MEDIUM" `
                          -Message "Cross-subscription VNet peering (requires careful review)" `
                          -Count $count1 `
                          -Data $crossSubPeering
        }
        
        # Check 2: Gateway transit enabled
        $gatewayTransit = $findings | Where-Object { $_.AllowGatewayTransit -eq $true -or $_.UseRemoteGateways -eq $true }
        $count2 = ($gatewayTransit | Measure-Object).Count
        if ($count2 -gt 0) {
            Write-Finding -Severity "LOW" `
                          -Message "VNet peering with gateway transit enabled" `
                          -Count $count2 `
                          -Data $gatewayTransit
        }
        
        # Check 3: Forwarded traffic allowed
        $forwardedTraffic = $findings | Where-Object { $_.AllowForwardedTraffic -eq $true }
        $count3 = ($forwardedTraffic | Measure-Object).Count
        if ($count3 -gt 0) {
            Write-Finding -Severity "MEDIUM" `
                          -Message "VNet peering allowing forwarded traffic" `
                          -Count $count3 `
                          -Data $forwardedTraffic
        }
    } else {
        Write-Finding -Severity "INFO" `
                      -Message "No VNet peering configurations found" `
                      -Count 0 `
                      -Data $null
    }
}

function Test-StorageAdvancedSecurity {
    Write-Section -Title "STORAGE - ADVANCED SECURITY CHECKS" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
        
        foreach ($sa in $storageAccounts) {
            try {
                # Check secure transfer (HTTPS required)
                $secureTransfer = $sa.EnableHttpsTrafficOnly
                
                # Check minimum TLS version
                $minTlsVersion = $sa.MinimumTlsVersion
                
                # Check soft delete settings
                $softDeletePolicy = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName `
                                                                    -StorageAccountName $sa.StorageAccountName `
                                                                    -ErrorAction SilentlyContinue
                
                $blobSoftDeleteEnabled = $softDeletePolicy.DeleteRetentionPolicy.Enabled
                $blobSoftDeleteDays = if ($blobSoftDeleteEnabled) { 
                    $softDeletePolicy.DeleteRetentionPolicy.Days 
                } else { 0 }
                
                # Check for cross-tenant replication
                $allowCrossTenantReplication = $sa.AllowCrossTenantReplication
                
                # Check for SAS policies (long expiry)
                $sasPolicies = @()
                try {
                    $accountSasPolicy = Get-AzStorageAccount -ResourceGroupName $sa.ResourceGroupName `
                                                            -Name $sa.StorageAccountName `
                                                            -IncludeAccountSASPolicy
                    
                    if ($accountSasPolicy.AccountSasPolicy) {
                        $sasExpiry = $accountSasPolicy.AccountSasPolicy.SasExpirationPeriod
                        $sasExpiryDays = [math]::Round($sasExpiry.TotalDays, 2)
                        if ($sasExpiryDays -gt 365) {
                            $sasPolicies += "Account SAS: $sasExpiryDays days"
                        }
                    }
                } catch {
                    # Account SAS policies not supported or accessible
                }
                
                $findings += [pscustomobject]@{
                    Subscription = $sub.Name
                    StorageAccount = $sa.StorageAccountName
                    ResourceGroup = $sa.ResourceGroupName
                    Location = $sa.Location
                    SecureTransfer = if ($secureTransfer) { "Enabled" } else { "Disabled" }
                    MinimumTlsVersion = if ($minTlsVersion) { $minTlsVersion } else { "TLS1_0" }
                    BlobSoftDelete = if ($blobSoftDeleteEnabled) { "Enabled ($blobSoftDeleteDays days)" } else { "Disabled" }
                    AllowCrossTenantReplication = if ($allowCrossTenantReplication -eq $true) { "Yes" } else { "No" }
                    LongSASPolicies = if ($sasPolicies.Count -gt 0) { ($sasPolicies -join "; ") } else { "None" }
                }
            } catch {
                Write-Host "   [Warning] Could not query advanced settings for '$($sa.StorageAccountName)'" -ForegroundColor DarkYellow
                continue
            }
        }
    }
    
    # Check 1: Storage accounts without secure transfer
    $noSecureTransfer = $findings | Where-Object { $_.SecureTransfer -eq "Disabled" }
    $count1 = ($noSecureTransfer | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Storage accounts without secure transfer (HTTPS) required" `
                  -Count $count1 `
                  -Data $noSecureTransfer
    
    # Check 2: Storage accounts with TLS < 1.2
    $oldTls = $findings | Where-Object { 
        $_.MinimumTlsVersion -ne "TLS1_2" -and 
        $_.MinimumTlsVersion -ne "TLS1_3" 
    }
    $count2 = ($oldTls | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Storage accounts with minimum TLS version < 1.2" `
                  -Count $count2 `
                  -Data $oldTls
    
    # Combined check: blob soft delete disabled and/or cross-tenant replication enabled
    $noSoftDelete = $findings | Where-Object { $_.BlobSoftDelete -like "Disabled*" }
    $crossTenantReplication = $findings | Where-Object { $_.AllowCrossTenantReplication -eq "Yes" }

    $combined = @()
    if ($noSoftDelete) { $combined += $noSoftDelete }
    if ($crossTenantReplication) { $combined += $crossTenantReplication }

    if ($combined.Count -gt 0) {
        $combinedUnique = $combined | Sort-Object Subscription, StorageAccount, ResourceGroup -Unique
        $countCombined = ($combinedUnique | Measure-Object).Count

        Write-Finding -Severity "MEDIUM" `
                      -Message "Storage accounts with blob soft delete disabled and/or cross-tenant replication enabled" `
                      -Count $countCombined `
                      -Data $combinedUnique
    }
}

function Test-KeyVaultNetworkSecurity {
    Write-Section -Title "KEY VAULT - NETWORK SECURITY" -Color "Red"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        
        foreach ($kv in $keyVaults) {
            # Get network rules
            $networkRuleSet = $kv.NetworkAcls
            
            # Check public access
            $hasPublicAccess = $true
            $hasFirewall = $false
            
            if ($networkRuleSet) {
                if ($networkRuleSet.DefaultAction -eq "Deny") {
                    $hasPublicAccess = $false
                    $hasFirewall = $true
                }
                
                # Check if only specific IPs are allowed
                if ($networkRuleSet.IpAddressRanges -and $networkRuleSet.IpAddressRanges.Count -gt 0) {
                    $hasFirewall = $true
                }
            }
            
            # Check private endpoints
            $privateEndpoints = Get-AzPrivateEndpoint -ResourceGroupName $kv.ResourceGroupName -ErrorAction SilentlyContinue |
                               Where-Object { $_.PrivateLinkServiceConnections.PrivateLinkServiceId -eq $kv.ResourceId }
            
            # Check soft delete and purge protection
            $hasSoftDelete = $kv.EnableSoftDelete
            $hasPurgeProtection = $kv.EnablePurgeProtection
            
            $findings += [pscustomobject]@{
                Subscription = $sub.Name
                VaultName = $kv.VaultName
                ResourceGroup = $kv.ResourceGroupName
                PublicAccess = if ($hasPublicAccess) { "Enabled" } else { "Disabled" }
                FirewallEnabled = if ($hasFirewall) { "Yes" } else { "No" }
                PrivateEndpoints = ($privateEndpoints | Measure-Object).Count
                SoftDelete = if ($hasSoftDelete) { "Enabled" } else { "Disabled" }
                PurgeProtection = if ($hasPurgeProtection) { "Enabled" } else { "Disabled" }
                RBACEnabled = $kv.EnableRbacAuthorization
            }
        }
    }
    
    # Check 1: Key Vaults with public access and no firewall
    $exposedKV = $findings | Where-Object { 
        $_.PublicAccess -eq "Enabled" -and 
        $_.FirewallEnabled -eq "No" 
    }
    $count1 = ($exposedKV | Measure-Object).Count
    Write-Finding -Severity "CRITICAL" `
                  -Message "Key Vaults with public access and no firewall" `
                  -Count $count1 `
                  -Data $exposedKV
    
    # Check 2: Missing purge protection
    $noPurgeProtection = $findings | Where-Object { $_.PurgeProtection -eq "Disabled" }
    $count2 = ($noPurgeProtection | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Key Vaults without purge protection" `
                  -Count $count2 `
                  -Data $noPurgeProtection
    
    # Check 3: No private endpoints despite being critical
    $criticalPatterns = @("*prod*", "*prd*", "*secret*", "*key*", "*cert*")
    $criticalKV = $findings | Where-Object {
        foreach ($pattern in $criticalPatterns) {
            if ($_.VaultName -like $pattern) {
                return $true
            }
        }
        return $false
    }
    
    $noPrivateEndpoint = $criticalKV | Where-Object { $_.PrivateEndpoints -eq 0 }
    $count3 = ($noPrivateEndpoint | Measure-Object).Count
    if ($count3 -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Critical Key Vaults without private endpoints" `
                      -Count $count3 `
                      -Data $noPrivateEndpoint
    }
}

function Test-KeyVaultSecretsExpiry {
    Write-Section -Title "KEY VAULT - SECRETS EXPIRATION" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        
        foreach ($kv in $keyVaults) {
            try {
                # Get secrets
                $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction SilentlyContinue
                
                foreach ($secret in $secrets) {
                    $expiryDate = $secret.Expires
                    $createdDate = $secret.Created
                    $enabled = $secret.Enabled
                    
                    if ($enabled) {
                        $daysToExpiry = if ($expiryDate) {
                            [math]::Round(($expiryDate - (Get-Date)).TotalDays)
                        } else {
                            $null
                        }
                        
                        # Check for no expiry
                        if (-not $expiryDate) {
                            $findings += [pscustomobject]@{
                                Subscription = $sub.Name
                                VaultName = $kv.VaultName
                                SecretName = $secret.Name
                                ExpiryStatus = "No Expiry"
                                DaysToExpiry = "N/A"
                                CreatedDate = $createdDate
                                Enabled = $enabled
                            }
                        }
                        # Check for far-future expiry (>2 years)
                        elseif ($daysToExpiry -gt 730) {
                            $findings += [pscustomobject]@{
                                Subscription = $sub.Name
                                VaultName = $kv.VaultName
                                SecretName = $secret.Name
                                ExpiryStatus = "Far Future"
                                DaysToExpiry = $daysToExpiry
                                ExpiryDate = $expiryDate
                                CreatedDate = $createdDate
                                Enabled = $enabled
                            }
                        }
                        # Check for expired secrets
                        elseif ($daysToExpiry -lt 0) {
                            $findings += [pscustomobject]@{
                                Subscription = $sub.Name
                                VaultName = $kv.VaultName
                                SecretName = $secret.Name
                                ExpiryStatus = "Expired"
                                DaysToExpiry = $daysToExpiry
                                ExpiryDate = $expiryDate
                                CreatedDate = $createdDate
                                Enabled = $enabled
                            }
                        }
                    }
                }
            } catch {
                # Skip if we can't access secrets
                Write-Host "   [Warning] Could not access secrets in '$($kv.VaultName)'" -ForegroundColor DarkYellow
                continue
            }
        }
    }
    
    # Group by status
    $noExpiry = $findings | Where-Object { $_.ExpiryStatus -eq "No Expiry" }
    $farFuture = $findings | Where-Object { $_.ExpiryStatus -eq "Far Future" }
    $expired = $findings | Where-Object { $_.ExpiryStatus -eq "Expired" }
    
    if (($noExpiry | Measure-Object).Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Key Vault secrets without expiration date" `
                      -Count ($noExpiry | Measure-Object).Count `
                      -Data ($noExpiry | Select-Object Subscription, VaultName, SecretName, CreatedDate)
    }
    
    if (($farFuture | Measure-Object).Count -gt 0) {
        Write-Finding -Severity "LOW" `
                      -Message "Key Vault secrets with far-future expiry (>2 years)" `
                      -Count ($farFuture | Measure-Object).Count `
                      -Data ($farFuture | Select-Object Subscription, VaultName, SecretName, DaysToExpiry, ExpiryDate)
    }
    
    if (($expired | Measure-Object).Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Key Vault secrets that are expired" `
                      -Count ($expired | Measure-Object).Count `
                      -Data ($expired | Select-Object Subscription, VaultName, SecretName, DaysToExpiry, ExpiryDate)
    }
}

function Test-CustomRoles {
    Write-Section -Title "CUSTOM RBAC ROLES - DANGEROUS PERMISSIONS" -Color "Yellow"
    
    # Should update this with more later on
    $dangerousPatterns = @(
        "Microsoft.Authorization/*",
        "Microsoft.ManagedIdentity/*",
        "Microsoft.KeyVault/vaults/secrets/*",
        "Microsoft.Compute/virtualMachines/runCommand/*",
        "*"
    ) 
    
    $findings = @()

    # Suppress noisy "No role definitions were found..." warnings while scanning
    $originalWarningPreference = $WarningPreference
    $WarningPreference = 'SilentlyContinue'
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        # Get custom roles (non-built-in)
        $customRoles = Get-AzRoleDefinition -Custom -ErrorAction SilentlyContinue
        if (-not $customRoles) { continue }

        $customRoles = $customRoles | Where-Object { $_.IsCustom -eq $true }
        
        foreach ($role in $customRoles) {
            $dangerousActions = @()
            
            # Check Actions
            foreach ($action in $role.Actions) {
                foreach ($pattern in $dangerousPatterns) {
                    if ($action -like $pattern) {
                        $dangerousActions += $action
                        break
                    }
                }
            }
            
            # Check DataActions (if any)
            if ($role.DataActions) {
                foreach ($dataAction in $role.DataActions) {
                    foreach ($pattern in $dangerousPatterns) {
                        if ($dataAction -like $pattern) {
                            $dangerousActions += "[DataAction] $dataAction"
                            break
                        }
                    }
                }
            }
            
            if ($dangerousActions.Count -gt 0) {
                $findings += [pscustomobject]@{
                    Subscription     = $sub.Name
                    RoleName         = $role.Name
                    RoleId           = $role.Id
                    IsCustom         = $role.IsCustom
                    DangerousActions = ($dangerousActions -join "; ")
                    AssignmentsCount = (Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -RoleDefinitionId $role.Id -ErrorAction SilentlyContinue | Measure-Object).Count
                }
            }
        }
    }

    # Restore original warning preference
    $WarningPreference = $originalWarningPreference
    
    $count = ($findings | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Custom roles with dangerous/wildcard permissions" `
                  -Count $count `
                  -Data $findings
}

function Test-CosmosDBSecurity {
    Write-Section -Title "COSMOS DB SECURITY CHECK" -Color "Red"
    
    $findings = @()
    $allAccounts = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        try {
            Set-AzContext -Subscription $sub.Id -ErrorAction Stop | Out-Null
            
            # Get CosmosDB accounts using REST API (most reliable)
            $cosmosResources = Get-AzResource -ResourceType "Microsoft.DocumentDb/databaseAccounts" -ErrorAction SilentlyContinue
            
            foreach ($resource in $cosmosResources) {
                try {
                    # Extract resource group
                    $rgName = "Unknown"
                    if ($resource.ResourceId -match "resourceGroups/([^/]+)/") {
                        $rgName = $matches[1]
                    }
                    
                    # Use REST API
                    $apiPath = "/subscriptions/$($sub.Id)/resourceGroups/$rgName/providers/Microsoft.DocumentDb/databaseAccounts/$($resource.Name)?api-version=2023-04-15"
                    $response = Invoke-AzRestMethod -Method GET -Path $apiPath -ErrorAction Stop
                    
                    if ($response.StatusCode -eq 200) {
                        $details = $response.Content | ConvertFrom-Json
                        
                        # Get basic properties
                        $publicAccess = if ($details.properties.publicNetworkAccess) {
                            $details.properties.publicNetworkAccess
                        } else { "Enabled" }
                        
                        # Check IP rules
                        $hasFirewall = $false
                        $hasAllowAll = $false
                        $ipRulesCount = 0
                        if ($details.properties.ipRules -and $details.properties.ipRules.Count -gt 0) {
                            $hasFirewall = $true
                            $ipRulesCount = $details.properties.ipRules.Count
                            foreach ($rule in $details.properties.ipRules) {
                                if ($rule.ipAddressOrRange -eq "0.0.0.0") {
                                    $hasAllowAll = $true
                                }
                            }
                        }
                        
                        # Check VNet rules
                        $hasVNet = $false
                        $vnetRulesCount = 0
                        if ($details.properties.virtualNetworkRules -and $details.properties.virtualNetworkRules.Count -gt 0) {
                            $hasVNet = $true
                            $vnetRulesCount = $details.properties.virtualNetworkRules.Count
                        }
                        
                        # Check AAD auth
                        $hasAAD = $false
                        if ($details.properties.capabilities) {
                            foreach ($cap in $details.properties.capabilities) {
                                if ($cap.name -eq "EnableAzureActiveDirectory") {
                                    $hasAAD = $true
                                    break
                                }
                            }
                        }
                        
                        # Determine risk
                        $severity = "LOW"
                        $issues = @()
                        
                        if ($publicAccess -eq "Enabled") {
                            if (-not $hasFirewall -and -not $hasVNet) {
                                $severity = "CRITICAL"
                                $issues += "Public with no restrictions"
                            }
                            elseif ($hasAllowAll) {
                                $severity = "CRITICAL"
                                $issues += "Firewall allows all IPs (0.0.0.0)"
                            }
                            else {
                                $severity = "HIGH"
                                $issues += "Public access enabled"
                            }
                        }
                        
                        if (-not $hasAAD) {
                            if ($severity -eq "LOW") { $severity = "MEDIUM" }
                            $issues += "No AAD authentication"
                        }
                        
                        $accountInfo = [pscustomobject]@{
                            Subscription = $sub.Name
                            AccountName = $resource.Name
                            ResourceGroup = $rgName
                            Location = $resource.Location
                            Kind = $details.kind
                            PublicAccess = $publicAccess
                            HasFirewall = if ($hasFirewall) { "Yes ($ipRulesCount rules)" } else { "No" }
                            HasVNet = if ($hasVNet) { "Yes ($vnetRulesCount rules)" } else { "No" }
                            HasAAD = if ($hasAAD) { "Yes" } else { "No" }
                            Issues = if ($issues.Count -gt 0) { ($issues -join "; ") } else { "None" }
                            Severity = $severity
                        }
                        
                        $allAccounts += $accountInfo
                        $findings += $accountInfo
                    }
                } catch {
                Write-Host "   [WARNING] Could not check '$($resource.Name)': $_" -ForegroundColor DarkYellow
                    continue
                }
            }
        } catch {
            Write-Host "   [WARNING] Could not access subscription '$($sub.Name)'" -ForegroundColor DarkYellow
            continue
        }
    }
    
    # No accounts found
    if ($allAccounts.Count -eq 0) {
        Write-Finding -Severity "INFO" `
                      -Message "No Cosmos DB accounts found" `
                      -Count 0 `
                      -Data $null
        return
    }
    
    # Show all accounts first
    Write-Host "`n[$checkMark] All Cosmos DB Accounts Found:" -ForegroundColor Green
    Write-Host "===========================================" -ForegroundColor Green
    $allAccounts | Format-Table -Property Subscription, AccountName, ResourceGroup, Location, Kind -AutoSize
    
    # Report by severity
    $critical = $findings | Where-Object { $_.Severity -eq "CRITICAL" }
    $high = $findings | Where-Object { $_.Severity -eq "HIGH" }
    $medium = $findings | Where-Object { $_.Severity -eq "MEDIUM" }
    $low = $findings | Where-Object { $_.Severity -eq "LOW" }
    
    # Critical findings
    if ($critical.Count -gt 0) {
        Write-Finding -Severity "CRITICAL" `
                      -Message "Cosmos DB accounts with critical risks" `
                      -Count $critical.Count `
                      -Data ($critical | Select-Object Subscription, AccountName, ResourceGroup, Issues)
    }
    
    # High risk findings
    if ($high.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Cosmos DB accounts with public access" `
                      -Count $high.Count `
                      -Data ($high | Select-Object Subscription, AccountName, ResourceGroup, PublicAccess, HasFirewall, HasVNet)
    }
    
    # Medium risk findings
    if ($medium.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Cosmos DB accounts without AAD auth" `
                      -Count $medium.Count `
                      -Data ($medium | Select-Object Subscription, AccountName, ResourceGroup, HasAAD)
    }
    
    # Low risk findings
    if ($low.Count -gt 0) {
        Write-Finding -Severity "INFO" `
                      -Message "Securely configured Cosmos DB accounts" `
                      -Count $low.Count `
                      -Data ($low | Select-Object Subscription, AccountName, ResourceGroup)
    }
    
    # Summary
    $summary = [pscustomobject]@{
        "Total Accounts" = $findings.Count
        "Critical" = $critical.Count
        "High" = $high.Count
        "Medium" = $medium.Count
        "Low" = $low.Count
        "Public Access" = ($findings | Where-Object { $_.PublicAccess -eq "Enabled" }).Count
        "With AAD" = ($findings | Where-Object { $_.HasAAD -eq "Yes" }).Count
    }
    
    Write-Finding -Severity "INFO" `
                  -Message "Cosmos DB security summary" `
                  -Count $findings.Count `
                  -Data $summary
}

function Test-CriticalResourceDiagnostics {
    Write-Section -Title "DIAGNOSTIC SETTINGS - CRITICAL RESOURCES" -Color "Yellow"
    
    # Suppress breaking change warnings from Get-AzDiagnosticSetting for this check, should fix this later
    $originalWarningPreference = $WarningPreference
    $WarningPreference = 'SilentlyContinue'
    $originalBreakingEnv = $env:SuppressAzurePowerShellBreakingChangeWarnings
    $env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
    
    $criticalResources = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        # Key Vaults
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        foreach ($kv in $keyVaults) {
            try {
                $diag = Get-AzDiagnosticSetting -ResourceId $kv.ResourceId -ErrorAction SilentlyContinue
                
                $criticalResources += [pscustomobject]@{
                    Subscription = $sub.Name
                    ResourceType = "KeyVault"
                    ResourceName = $kv.VaultName
                    ResourceGroup = $kv.ResourceGroupName
                    DiagnosticsConfigured = if ($diag) { "Yes" } else { "No" }
                }
            } catch {
                Write-Host "   [Warning] Could not query diagnostics for Key Vault '$($kv.VaultName)'" -ForegroundColor DarkYellow
            }
        }
        
        # SQL Servers
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        foreach ($sql in $sqlServers) {
            try {
                $resourceId = "/subscriptions/$($sub.Id)/resourceGroups/$($sql.ResourceGroupName)/providers/Microsoft.Sql/servers/$($sql.ServerName)"
                $diag = Get-AzDiagnosticSetting -ResourceId $resourceId -ErrorAction SilentlyContinue
                
                $criticalResources += [pscustomobject]@{
                    Subscription = $sub.Name
                    ResourceType = "SQLServer"
                    ResourceName = $sql.ServerName
                    ResourceGroup = $sql.ResourceGroupName
                    DiagnosticsConfigured = if ($diag) { "Yes" } else { "No" }
                }
            } catch {
                Write-Host "   [Warning] Could not query diagnostics for SQL Server '$($sql.ServerName)'" -ForegroundColor DarkYellow
            }
        }
    }
    
    # Restore original warning preference and breaking change env flag
    $WarningPreference = $originalWarningPreference
    if ($null -ne $originalBreakingEnv) {
        $env:SuppressAzurePowerShellBreakingChangeWarnings = $originalBreakingEnv
    } else {
        Remove-Item Env:SuppressAzurePowerShellBreakingChangeWarnings -ErrorAction SilentlyContinue
    }
    
    $noDiagnostics = $criticalResources | Where-Object { $_.DiagnosticsConfigured -eq "No" }
    $count = ($noDiagnostics | Measure-Object).Count
    
    Write-Finding -Severity "MEDIUM" `
                  -Message "Critical resources without diagnostic settings" `
                  -Count $count `
                  -Data ($noDiagnostics | Select-Object Subscription, ResourceType, ResourceName, ResourceGroup)
}

function Test-ResourceLocks {
    Write-Section -Title "RESOURCE LOCKS - PROTECTION STATUS" -Color "Yellow"
    
    $criticalPatterns = @("*prod*", "*prd*", "*production*", "*core*", "*shared*", "*management*")
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        # Get all resource groups
        $resourceGroups = Get-AzResourceGroup -ErrorAction SilentlyContinue
        
        foreach ($rg in $resourceGroups) {
            # Check if RG name matches critical patterns
            $isCritical = $false
            foreach ($pattern in $criticalPatterns) {
                if ($rg.ResourceGroupName -like $pattern) {
                    $isCritical = $true
                    break
                }
            }
            
            # Check for locks
            $locks = Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue
            $hasDeleteLock = $locks | Where-Object { 
                $_.Properties.Level -eq "CanNotDelete" -and 
                $_.Properties.Scope -match "/resourceGroups/$($rg.ResourceGroupName)"
            }
            
            if ($isCritical -and -not $hasDeleteLock) {
                $findings += [pscustomobject]@{
                    Subscription = $sub.Name
                    ResourceGroup = $rg.ResourceGroupName
                    Location = $rg.Location
                    Critical = "Yes"
                    DeleteLock = "Missing"
                    ReadOnlyLock = if ($locks | Where-Object { $_.Properties.Level -eq "ReadOnly" }) { "Present" } else { "Missing" }
                }
            }
        }
    }
    
    $count = ($findings | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "Critical resource groups without delete locks" `
                  -Count $count `
                  -Data $findings
}

function Test-SQLAdvancedSecurity {
    Write-Section -Title "SQL - ADVANCED SECURITY CHECKS" -Color "Yellow"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        
        foreach ($server in $sqlServers) {
            try {
                # Get Azure AD admin configuration
                $aadAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $server.ResourceGroupName `
                                                                        -ServerName $server.ServerName `
                                                                        -ErrorAction SilentlyContinue
                
                # Get TDE configuration
                $tdeSettings = Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $server.ResourceGroupName `
                                                                                -ServerName $server.ServerName `
                                                                                -ErrorAction SilentlyContinue
                
                # Get auditing settings
                $auditing = Get-AzSqlServerAudit -ResourceGroupName $server.ResourceGroupName `
                                                -ServerName $server.ServerName `
                                                -ErrorAction SilentlyContinue
                
                # Get vulnerability assessment settings
                $vaSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $server.ResourceGroupName `
                                                                           -ServerName $server.ServerName `
                                                                           -ErrorAction SilentlyContinue
                
                # Check Defender for SQL
                $defenderSettings = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $server.ResourceGroupName `
                                                                                  -ServerName $server.ServerName `
                                                                                  -ErrorAction SilentlyContinue
                
                $findings += [pscustomobject]@{
                    Subscription = $sub.Name
                    ServerName = $server.ServerName
                    ResourceGroup = $server.ResourceGroupName
                    AzureADAdmin = if ($aadAdmin -and $aadAdmin.DisplayName) { $aadAdmin.DisplayName } else { "Not Configured" }
                    TDEProtector = if ($tdeSettings) { $tdeSettings.Type } else { "Unknown" }
                    TDEKeyType = if ($tdeSettings) { $tdeSettings.ServerKeyType } else { "Unknown" }
                    AuditingEnabled = if ($auditing) { $auditing.AuditState } else { "Disabled" }
                    AuditDestination = if ($auditing) { $auditing.AuditDestination } else { "None" }
                    VulnerabilityAssessment = if ($vaSettings) { "Enabled" } else { "Disabled" }
                    DefenderForSQL = if ($defenderSettings) { $defenderSettings.State } else { "Disabled" }
                    PublicNetworkAccess = $server.PublicNetworkAccess
                    MinimalTlsVersion = if ($server.MinimalTlsVersion) { $server.MinimalTlsVersion } else { "Unknown" }
                }
            } catch {
                Write-Host "   [Warning] Could not query advanced SQL settings for '$($server.ServerName)'" -ForegroundColor DarkYellow
                continue
            }
        }
    }
    
    # Check 1: SQL servers without Azure AD admin
    $noAadAdmin = $findings | Where-Object { $_.AzureADAdmin -eq "Not Configured" }
    $count1 = ($noAadAdmin | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "SQL servers without Azure AD administrator" `
                  -Count $count1 `
                  -Data ($noAadAdmin | Select-Object Subscription, ServerName, ResourceGroup, PublicNetworkAccess)
    
    # Check 2: SQL servers with service-managed TDE keys
    $serviceManagedTDE = $findings | Where-Object { $_.TDEKeyType -eq "ServiceManaged" }
    $count2 = ($serviceManagedTDE | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "SQL servers using service-managed TDE keys (not customer-managed)" `
                  -Count $count2 `
                  -Data ($serviceManagedTDE | Select-Object Subscription, ServerName, ResourceGroup, TDEProtector, TDEKeyType)
    
    # Check 3: SQL servers without Defender for SQL
    $noDefender = $findings | Where-Object { $_.DefenderForSQL -ne "Enabled" }
    $count3 = ($noDefender | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "SQL servers without Defender for SQL enabled" `
                  -Count $count3 `
                  -Data ($noDefender | Select-Object Subscription, ServerName, ResourceGroup, DefenderForSQL)
    
    # Check 4: SQL servers without vulnerability assessment
    $noVA = $findings | Where-Object { $_.VulnerabilityAssessment -eq "Disabled" }
    $count4 = ($noVA | Measure-Object).Count
    Write-Finding -Severity "MEDIUM" `
                  -Message "SQL servers without vulnerability assessment" `
                  -Count $count4 `
                  -Data ($noVA | Select-Object Subscription, ServerName, ResourceGroup, VulnerabilityAssessment)
    
    # Check 5: Auditing disabled or misconfigured
    $auditingIssues = $findings | Where-Object { 
        $_.AuditingEnabled -ne "Enabled" -or 
        $_.AuditDestination -eq "None" 
    }
    $count5 = ($auditingIssues | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "SQL servers with auditing disabled or misconfigured" `
                  -Count $count5 `
                  -Data ($auditingIssues | Select-Object Subscription, ServerName, ResourceGroup, AuditingEnabled, AuditDestination)
}

function Test-AKSPrivilegeEscalation {
    Write-Section -Title "P1 - AKS PRIVILEGE ESCALATION RISKS" -Color "Red"
    
    # Check if AKS module is available
    if (-not (Get-Module -ListAvailable -Name Az.Aks)) {
        Write-Host "`n  [WARNING] Az.Aks module not installed. Skipping AKS privilege escalation checks." -ForegroundColor Yellow
        Write-Host "     Install with: Install-Module -Name Az.Aks -Force" -ForegroundColor White
        return
    }
    
    $criticalFindings = @()
    $highFindings = @()
    $totalChecks = 0
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $aksClusters = Get-AzAksCluster -ErrorAction SilentlyContinue
        
        foreach ($aks in $aksClusters) {
            $totalChecks++
            try {
                $cluster = Get-AzAksCluster -ResourceGroupName $aks.ResourceGroupName `
                                           -Name $aks.Name `
                                           -ErrorAction SilentlyContinue
                if (-not $cluster) { continue }
                
                $apiAccessProfile = $cluster.APIServerAccessProfile
                
                # CRITICAL: Public API server without authorized IP ranges
                $publicAPIWithNoIPRestriction = $false
                if ($apiAccessProfile -and 
                    $apiAccessProfile.EnablePrivateCluster -eq $false -and
                    (-not $apiAccessProfile.AuthorizedIPRanges -or 
                     $apiAccessProfile.AuthorizedIPRanges.Count -eq 0)) {
                    $publicAPIWithNoIPRestriction = $true
                }
                
                # Check for local accounts
                $localAccountsEnabled = ($cluster.DisableLocalAccounts -eq $false)
                
                # Check AAD integration
                $aadProfile = $cluster.AadProfile
                $hasAzureRBAC = ($aadProfile -and $aadProfile.Managed -eq $true)
                
                # RISK ASSESSMENT
                
                # CRITICAL: Public API with no IP restrictions
                if ($publicAPIWithNoIPRestriction) {
                    $criticalFindings += [pscustomobject]@{
                        Subscription = $sub.Name
                        ClusterName = $cluster.Name
                        ResourceGroup = $cluster.ResourceGroupName
                        Risk = "CRITICAL"
                        Issues = "Public API server without IP restrictions"
                        PublicAPI = "Enabled"
                        IPRestrictions = "None"
                        PrivateCluster = if ($apiAccessProfile.EnablePrivateCluster) { "Yes" } else { "No" }
                        LocalAccounts = if ($localAccountsEnabled) { "Enabled" } else { "Disabled" }
                        AzureRBAC = if ($hasAzureRBAC) { "Yes" } else { "No" }
                    }
                }
                # HIGH: Local accounts enabled with AAD
                elseif ($localAccountsEnabled -and $hasAzureRBAC) {
                    $highFindings += [pscustomobject]@{
                        Subscription = $sub.Name
                        ClusterName = $cluster.Name
                        ResourceGroup = $cluster.ResourceGroupName
                        Risk = "HIGH"
                        Issues = "Local accounts enabled with Azure RBAC"
                        PublicAPI = if ($publicAPIWithNoIPRestriction) { "Public" } else { "Private/Restricted" }
                        LocalAccounts = "Enabled"
                        AzureRBAC = "Yes"
                    }
                }
                # HIGH: No Azure RBAC (legacy RBAC)
                elseif (-not $hasAzureRBAC) {
                    $highFindings += [pscustomobject]@{
                        Subscription = $sub.Name
                        ClusterName = $cluster.Name
                        ResourceGroup = $cluster.ResourceGroupName
                        Risk = "HIGH"
                        Issues = "No Azure RBAC (using legacy Kubernetes RBAC)"
                        PublicAPI = if ($publicAPIWithNoIPRestriction) { "Public" } else { "Private/Restricted" }
                        LocalAccounts = if ($localAccountsEnabled) { "Enabled" } else { "Disabled" }
                        AzureRBAC = "No"
                    }
                }
                
            } catch {
                Write-Host "    [WARNING] Could not check AKS cluster '$($aks.Name)'" -ForegroundColor DarkYellow
            }
        }
    }
    
    # Report findings
    $criticalCount = ($criticalFindings | Measure-Object).Count
    $highCount = ($highFindings | Measure-Object).Count
    
    if ($criticalCount -gt 0) {
        Write-Finding -Severity "CRITICAL" `
                      -Message "AKS clusters with public API servers without IP restrictions" `
                      -Count $criticalCount `
                      -Data ($criticalFindings | Select-Object Subscription, ClusterName, ResourceGroup, Issues, PublicAPI, IPRestrictions)
    }
    
    if ($highCount -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "AKS clusters with privilege escalation risks" `
                      -Count $highCount `
                      -Data ($highFindings | Select-Object Subscription, ClusterName, ResourceGroup, Issues, AzureRBAC, LocalAccounts)
    }
    
    if ($criticalCount -eq 0 -and $highCount -eq 0) {
        Write-Finding -Severity "INFO" `
                      -Message "No critical AKS privilege escalation risks found" `
                      -Count 0 `
                      -Data $null
    }
    
    Write-Host "`n  Total AKS clusters checked: $totalChecks" -ForegroundColor Gray
}

function Test-SQLExfiltrationRisks {
    Write-Section -Title "P1 - SQL DATABASE EXPOSURE" -Color "Red"
    
    $criticalFindings = @()
    $highFindings = @()
    $totalChecks = 0
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        
        foreach ($server in $sqlServers) {
            $totalChecks++
            try {
                # Check if server is public
                $isPublic = ($server.PublicNetworkAccess -eq "Enabled")
                
                # Check AAD admin
                $aadAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $server.ResourceGroupName `
                                                                        -ServerName $server.ServerName `
                                                                        -ErrorAction SilentlyContinue
                $hasAADAdmin = ($aadAdmin -and $aadAdmin.DisplayName)
                
                # Check if managed identity has excessive permissions
                $miHasHighPrivilege = $false
                if ($server.Identity -and $server.Identity.PrincipalId) {
                    $assignments = Get-AzRoleAssignment -ObjectId $server.Identity.PrincipalId -ErrorAction SilentlyContinue
                    foreach ($assignment in $assignments) {
                        if ($assignment.RoleDefinitionName -in @("Owner", "Contributor", "SQL DB Contributor")) {
                            $miHasHighPrivilege = $true
                            break
                        }
                    }
                }
                
                # Get databases to check exposure
                $databases = Get-AzSqlDatabase -ResourceGroupName $server.ResourceGroupName `
                                              -ServerName $server.ServerName `
                                              -ErrorAction SilentlyContinue
                
                $hasSensitiveDatabases = $false
                $dbNames = @()
                if ($databases) {
                    foreach ($db in $databases) {
                        $dbName = $db.DatabaseName.ToLower()
                        if ($dbName -match "(prod|prd|production|master|user|customer|personal|credit|payment)") {
                            $hasSensitiveDatabases = $true
                            $dbNames += $db.DatabaseName
                            if ($dbNames.Count -ge 3) { break }
                        }
                    }
                }
                
                # RISK ASSESSMENT
                
                # CRITICAL: Public without AAD admin AND has sensitive databases
                if ($isPublic -and -not $hasAADAdmin -and $hasSensitiveDatabases) {
                    $criticalFindings += [pscustomobject]@{
                        Subscription = $sub.Name
                        ServerName = $server.ServerName
                        ResourceGroup = $server.ResourceGroupName
                        Risk = "CRITICAL"
                        Issues = "Public access without AAD admin + sensitive databases"
                        PublicAccess = "Enabled"
                        AADAdmin = "No"
                        SensitiveDBs = ($dbNames -join ", ") + "..."
                        MIHasHighPriv = if ($miHasHighPrivilege) { "Yes" } else { "No" }
                    }
                }
                # HIGH: Public without AAD admin (any database)
                elseif ($isPublic -and -not $hasAADAdmin) {
                    $highFindings += [pscustomobject]@{
                        Subscription = $sub.Name
                        ServerName = $server.ServerName
                        ResourceGroup = $server.ResourceGroupName
                        Risk = "HIGH"
                        Issues = "Public access without AAD admin"
                        PublicAccess = "Enabled"
                        AADAdmin = "No"
                        DatabaseCount = if ($databases) { $databases.Count } else { 0 }
                        MIHasHighPriv = if ($miHasHighPrivilege) { "Yes" } else { "No" }
                    }
                }
                # HIGH: SQL Server MI with high privileges
                elseif ($miHasHighPrivilege) {
                    $highFindings += [pscustomobject]@{
                        Subscription = $sub.Name
                        ServerName = $server.ServerName
                        ResourceGroup = $server.ResourceGroupName
                        Risk = "HIGH"
                        Issues = "SQL Server MI has Owner/Contributor RBAC"
                        PublicAccess = if ($isPublic) { "Enabled" } else { "Disabled" }
                        AADAdmin = if ($hasAADAdmin) { "Yes" } else { "No" }
                        DatabaseCount = if ($databases) { $databases.Count } else { 0 }
                    }
                }
                
            } catch {
                Write-Host "    [WARNING] Could not check SQL Server '$($server.ServerName)'" -ForegroundColor DarkYellow
            }
        }
    }
    
    # Report findings
    $criticalCount = ($criticalFindings | Measure-Object).Count
    $highCount = ($highFindings | Measure-Object).Count
    
    if ($criticalCount -gt 0) {
        Write-Finding -Severity "CRITICAL" `
                      -Message "SQL servers public without AAD admin + sensitive databases (Brute Force Risk)" `
                      -Count $criticalCount `
                      -Data ($criticalFindings | Select-Object Subscription, ServerName, ResourceGroup, Issues, SensitiveDBs)
    }
    
    if ($highCount -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "SQL servers with security misconfigurations" `
                      -Count $highCount `
                      -Data ($highFindings | Select-Object Subscription, ServerName, ResourceGroup, Issues, PublicAccess, AADAdmin)
    }
    
    if ($criticalCount -eq 0 -and $highCount -eq 0) {
        Write-Finding -Severity "INFO" `
                      -Message "No critical SQL server exposure risks found" `
                      -Count 0 `
                      -Data $null
    }
    
    Write-Host "`n  Total SQL servers checked: $totalChecks" -ForegroundColor Gray
}

function Test-NetworkExfiltrationPaths {
    Write-Section -Title "P1 - NETWORK DATA EXFILTRATION PATHS" -Color "Red"
    
    $highFindings = @()
    $mediumFindings = @()
    $totalChecks = 0
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        Write-Host "  Scanning subscription: $($sub.Name)" -ForegroundColor Gray
        
        # 1. Check NSG outbound rules allowing internet
        $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
        
        foreach ($nsg in $nsgs) {
            $totalChecks++
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Access -eq "Allow" -and $rule.Direction -eq "Outbound") {
                    
                    # Check if destination is internet/any - FIXED PROPERTY ACCESS
                    $destIsInternet = $false
                    $destAddress = ""
                    
                    # Check single prefix property
                    if ($rule.DestinationAddressPrefix) {
                        $destAddress = $rule.DestinationAddressPrefix
                        $destIsInternet = $destAddress -in @("Internet", "0.0.0.0/0", "*")
                    }
                    
                    # Check array prefixes property - safely
                    if (-not $destIsInternet -and $rule.PSObject.Properties.Name -contains "DestinationAddressPrefixes") {
                        if ($rule.DestinationAddressPrefixes -and $rule.DestinationAddressPrefixes.Count -gt 0) {
                            $destAddress = $rule.DestinationAddressPrefixes -join ", "
                            foreach ($prefix in $rule.DestinationAddressPrefixes) {
                                if ($prefix -in @("Internet", "0.0.0.0/0", "*")) {
                                    $destIsInternet = $true
                                    break
                                }
                            }
                        }
                    }
                    
                    if ($destIsInternet) {
                        $highFindings += [pscustomobject]@{
                            Subscription = $sub.Name
                            ResourceGroup = $nsg.ResourceGroupName
                            ResourceType = "NSG"
                            ResourceName = $nsg.Name
                            RuleName = $rule.Name
                            Issue = "Outbound rule to Internet/0.0.0.0"
                            Destination = $destAddress
                            Protocol = $rule.Protocol
                            Port = if ($rule.DestinationPortRange) { $rule.DestinationPortRange } else { "Multiple" }
                            Priority = $rule.Priority
                            Risk = "HIGH - Data exfiltration path"
                        }
                    }
                }
            }
        }
        
        # 2. Check Route Tables with default route to internet
        $routeTables = Get-AzRouteTable -ErrorAction SilentlyContinue
        
        foreach ($rt in $routeTables) {
            $totalChecks++
            foreach ($route in $rt.Routes) {
                if ($route.AddressPrefix -eq "0.0.0.0/0" -and $route.NextHopType -eq "Internet") {
                    $mediumFindings += [pscustomobject]@{
                        Subscription = $sub.Name
                        ResourceGroup = $rt.ResourceGroupName
                        ResourceType = "Route Table"
                        ResourceName = $rt.Name
                        RouteName = $route.Name
                        Issue = "Default route (0.0.0.0/0) to Internet"
                        NextHop = $route.NextHopType
                        Risk = "MEDIUM - Bypasses Azure Firewall"
                    }
                }
            }
        }
        
        # 3. Check Private Endpoints without DNS configuration
        $privateEndpoints = Get-AzPrivateEndpoint -ErrorAction SilentlyContinue
        
        foreach ($pe in $privateEndpoints) {
            $totalChecks++
            $dnsZoneGroups = Get-AzPrivateDnsZoneGroup -ResourceGroupName $pe.ResourceGroupName `
                                                      -PrivateEndpointName $pe.Name `
                                                      -ErrorAction SilentlyContinue
            
            if (-not $dnsZoneGroups -or ($dnsZoneGroups | Measure-Object).Count -eq 0) {
                $mediumFindings += [pscustomobject]@{
                    Subscription = $sub.Name
                    ResourceGroup = $pe.ResourceGroupName
                    ResourceType = "Private Endpoint"
                    ResourceName = $pe.Name
                    Issue = "No Private DNS Zone configured"
                    Risk = "MEDIUM - DNS leakage possible"
                }
            }
        }
    }
    
    # Report findings
    $highCount = ($highFindings | Measure-Object).Count
    $mediumCount = ($mediumFindings | Measure-Object).Count
    
    if ($highCount -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "NSG outbound rules allowing internet access (Data Exfiltration)" `
                      -Count $highCount `
                      -Data ($highFindings | Select-Object Subscription, ResourceGroup, ResourceName, RuleName, Destination, Port, Priority)
    } else {
        Write-Finding -Severity "INFO" `
                      -Message "No NSG outbound rules found allowing internet access" `
                      -Count 0 `
                      -Data $null
    }
    
    if ($mediumCount -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Network misconfigurations enabling data exfiltration" `
                      -Count $mediumCount `
                      -Data ($mediumFindings | Select-Object Subscription, ResourceType, ResourceName, Issue, Risk)
    }
    
    Write-Host "`n  Total network resources checked: $totalChecks" -ForegroundColor Gray
}

function Test-StorageExfiltrationVectors {
    Write-Section -Title "P1 - STORAGE ACCOUNT DATA EXFILTRATION VECTORS" -Color "Red"
    
    $findings = @()
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        
        $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
        
        foreach ($sa in $storageAccounts) {
            try {
                # Get Account SAS policy
                $accountSASPolicy = $null
                try {
                    $accountDetails = Get-AzStorageAccount -ResourceGroupName $sa.ResourceGroupName `
                                                          -Name $sa.StorageAccountName `
                                                          -IncludeAccountSASPolicy `
                                                          -ErrorAction SilentlyContinue
                    $accountSASPolicy = $accountDetails.AccountSasPolicy
                } catch {
                    # SAS policies not accessible
                }
                
                # Check for long SAS expiry
                $hasLongSASPolicy = $false
                $sasExpiryDays = 0
                if ($accountSASPolicy -and $accountSASPolicy.SasExpirationPeriod) {
                    $sasExpiryDays = [math]::Round($accountSASPolicy.SasExpirationPeriod.TotalDays)
                    $hasLongSASPolicy = $sasExpiryDays -gt 30  # More than 30 days is risky
                }
                
                # Check trusted Microsoft services bypass
                $networkRuleSet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $sa.ResourceGroupName `
                                                                    -AccountName $sa.StorageAccountName `
                                                                    -ErrorAction SilentlyContinue
                
                $bypassTrustedServices = $false
                if ($networkRuleSet -and $networkRuleSet.Bypass) {
                    $bypassTrustedServices = $networkRuleSet.Bypass -contains "AzureServices"
                }
                
                # Check cross-tenant replication
                $allowCrossTenant = $sa.AllowCrossTenantReplication
                
                # Check if managed identity has data plane access
                $hasManagedIdentity = $sa.Identity -and $sa.Identity.PrincipalId
                $miHasDataAccess = $false
                if ($hasManagedIdentity) {
                    $roleAssignments = Get-AzRoleAssignment -ObjectId $sa.Identity.PrincipalId -Scope $sa.Id -ErrorAction SilentlyContinue
                    foreach ($assignment in $roleAssignments) {
                        if ($assignment.RoleDefinitionName -like "*Storage Blob Data*" -or
                            $assignment.RoleDefinitionName -like "*Storage Queue Data*") {
                            $miHasDataAccess = $true
                            break
                        }
                    }
                }
                
                # Build risk assessment
                $riskLevel = "LOW"
                $issues = @()
                
                if ($hasLongSASPolicy) {
                    $riskLevel = "HIGH"
                    $issues += "Account SAS policy: $sasExpiryDays days"
                }
                
                if ($bypassTrustedServices -and $networkRuleSet.DefaultAction -eq "Deny") {
                    $riskLevel = "MEDIUM"
                    $issues += "Trusted services bypass enabled"
                }
                
                if ($allowCrossTenant -eq $true) {
                    $riskLevel = "HIGH"
                    $issues += "Cross-tenant replication allowed"
                }
                
                if ($sa.AllowSharedKeyAccess -eq $true -and 
                    $sa.PublicNetworkAccess -eq "Enabled" -and
                    ($networkRuleSet -eq $null -or $networkRuleSet.DefaultAction -eq "Allow")) {
                    $riskLevel = "CRITICAL"
                    $issues += "Public + Shared Key + No firewall"
                }
                
                if ($issues.Count -gt 0) {
                    $findings += [pscustomobject]@{
                        Subscription = $sub.Name
                        StorageAccount = $sa.StorageAccountName
                        ResourceGroup = $sa.ResourceGroupName
                        RiskLevel = $riskLevel
                        Issues = ($issues -join "; ")
                        PublicAccess = $sa.PublicNetworkAccess
                        SharedKeyAccess = $sa.AllowSharedKeyAccess
                        CrossTenantReplication = if ($allowCrossTenant) { "Yes" } else { "No" }
                        MIHasDataAccess = if ($miHasDataAccess) { "Yes" } else { "No" }
                    }
                }
                
            } catch {
                Write-Host "   [WARNING] Could not check Storage Account '$($sa.StorageAccountName)'" -ForegroundColor DarkYellow
            }
        }
    }
    
    # Report by severity
    $critical = $findings | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    $high = $findings | Where-Object { $_.RiskLevel -eq "HIGH" }
    $medium = $findings | Where-Object { $_.RiskLevel -eq "MEDIUM" }
    
    if ($critical.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Storage accounts with public access + shared key + no firewall" `
                      -Count $critical.Count `
                      -Data ($critical | Select-Object Subscription, StorageAccount, ResourceGroup, Issues)
    }
    
    if ($high.Count -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Storage accounts with long SAS policies or cross-tenant replication" `
                      -Count $high.Count `
                      -Data ($high | Select-Object Subscription, StorageAccount, ResourceGroup, Issues, CrossTenantReplication)
    }
    
    if ($medium.Count -gt 0) {
        Write-Finding -Severity "MEDIUM" `
                      -Message "Storage accounts with trusted services bypass" `
                      -Count $medium.Count `
                      -Data $medium
    }
}

function Test-IdentityResourceMapping {
    Write-Section -Title "P1 - IDENTITY-RESOURCE LINKAGE ANALYSIS" -Color "Red"
    
    $criticalFindings = @()
    $highFindings = @()
    $totalChecks = 0
    
    foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        Write-Host "  Scanning subscription: $($sub.Name)" -ForegroundColor Gray
        
        # 1. Check App Services with Managed Identity
        $webApps = Get-AzWebApp -ErrorAction SilentlyContinue
        foreach ($app in $webApps) {
            $totalChecks++
            if ($app.Identity -and $app.Identity.PrincipalId) {
                try {
                    $assignments = Get-AzRoleAssignment -ObjectId $app.Identity.PrincipalId -ErrorAction SilentlyContinue
                    foreach ($assignment in $assignments) {
                        if ($assignment.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator")) {
                            $criticalFindings += [pscustomobject]@{
                                Subscription = $sub.Name
                                ResourceType = "App Service"
                                ResourceName = $app.Name
                                ResourceGroup = $app.ResourceGroupName
                                IdentityType = "System-Assigned"
                                PrincipalId = $app.Identity.PrincipalId
                                Role = $assignment.RoleDefinitionName
                                Scope = $assignment.Scope
                                Risk = "CRITICAL - WebApp with Owner/Contributor rights"
                            }
                        }
                    }
                } catch {
                    Write-Host "    [WARNING] Could not check RBAC for $($app.Name)" -ForegroundColor DarkYellow
                }
            }
        }
        
        # 2. Check Virtual Machines with Managed Identity
        $vms = Get-AzVM -ErrorAction SilentlyContinue
        foreach ($vm in $vms) {
            $totalChecks++
            if ($vm.Identity -and $vm.Identity.PrincipalId) {
                try {
                    $assignments = Get-AzRoleAssignment -ObjectId $vm.Identity.PrincipalId -ErrorAction SilentlyContinue
                    foreach ($assignment in $assignments) {
                        if ($assignment.RoleDefinitionName -in @("Owner", "Contributor", "Virtual Machine Contributor")) {
                            $criticalFindings += [pscustomobject]@{
                                Subscription = $sub.Name
                                ResourceType = "Virtual Machine"
                                ResourceName = $vm.Name
                                ResourceGroup = $vm.ResourceGroupName
                                IdentityType = "System-Assigned"
                                PrincipalId = $vm.Identity.PrincipalId
                                Role = $assignment.RoleDefinitionName
                                Scope = $assignment.Scope
                                Risk = "CRITICAL - VM with high-privilege rights"
                            }
                        }
                    }
                } catch {
                    Write-Host "    [WARNING] Could not check RBAC for VM $($vm.Name)" -ForegroundColor DarkYellow
                }
            }
        }
        
        # 3. Check Function Apps with Managed Identity
        $functionApps = Get-AzFunctionApp -ErrorAction SilentlyContinue
        foreach ($func in $functionApps) {
            $totalChecks++
            if ($func.Identity -and $func.Identity.PrincipalId) {
                try {
                    $assignments = Get-AzRoleAssignment -ObjectId $func.Identity.PrincipalId -ErrorAction SilentlyContinue
                    foreach ($assignment in $assignments) {
                        if ($assignment.RoleDefinitionName -in @("Owner", "Contributor")) {
                            $criticalFindings += [pscustomobject]@{
                                Subscription = $sub.Name
                                ResourceType = "Function App"
                                ResourceName = $func.Name
                                ResourceGroup = $func.ResourceGroupName
                                IdentityType = "System-Assigned"
                                PrincipalId = $func.Identity.PrincipalId
                                Role = $assignment.RoleDefinitionName
                                Scope = $assignment.Scope
                                Risk = "CRITICAL - Function with Owner/Contributor rights"
                            }
                        }
                        if ($assignment.RoleDefinitionName -like "*Storage Blob Data*" -or 
                            $assignment.RoleDefinitionName -like "*Key Vault*") {
                            $highFindings += [pscustomobject]@{
                                Subscription = $sub.Name
                                ResourceType = "Function App"
                                ResourceName = $func.Name
                                ResourceGroup = $func.ResourceGroupName
                                IdentityType = "System-Assigned"
                                Role = $assignment.RoleDefinitionName
                                Scope = $assignment.Scope
                                Risk = "HIGH - Function with data plane access"
                            }
                        }
                    }
                } catch {
                    Write-Host "    [WARNING] Could not check RBAC for Function $($func.Name)" -ForegroundColor DarkYellow
                }
            }
        }
    }
    
    # Report findings
    $criticalCount = ($criticalFindings | Measure-Object).Count
    $highCount = ($highFindings | Measure-Object).Count
    
    if ($criticalCount -gt 0) {
        Write-Finding -Severity "CRITICAL" `
                      -Message "Resources with Managed Identities having Owner/Contributor RBAC (Cloud Takeover Risk)" `
                      -Count $criticalCount `
                      -Data ($criticalFindings | Select-Object Subscription, ResourceType, ResourceName, ResourceGroup, Role, Risk)
    } else {
        Write-Finding -Severity "INFO" `
                      -Message "No resources found with Managed Identities having high-privilege RBAC" `
                      -Count 0 `
                      -Data $null
    }
    
    if ($highCount -gt 0) {
        Write-Finding -Severity "HIGH" `
                      -Message "Resources with Managed Identities having data plane access" `
                      -Count $highCount `
                      -Data ($highFindings | Select-Object Subscription, ResourceType, ResourceName, ResourceGroup, Role)
    }
    
    Write-Host "`n  Total resources checked: $totalChecks" -ForegroundColor Gray
}

function Test-StorageAnonymousBlobAccess {
    Write-Section -Title "STORAGE ACCOUNTS - ANONYMOUS BLOB ACCESS" -Color "Yellow"
    
    $anonymousAccess = foreach ($sub in Get-AzureAuditSubscriptions) {
        Set-AzContext -Subscription $sub.Id | Out-Null
        foreach ($sa in Get-AzStorageAccount -ErrorAction SilentlyContinue) {
            # Check for containers with public access
            try {
                $ctx = $sa.Context
                $containers = Get-AzStorageContainer -Context $ctx -ErrorAction SilentlyContinue
                $publicContainers = @()
                
                foreach ($container in $containers) {
                    if ($container.PublicAccess -ne "Off") {
                        $publicContainers += [pscustomobject]@{
                            ContainerName = $container.Name
                            PublicAccess = $container.PublicAccess
                            LastModified = $container.LastModified
                        }
                    }
                }
                
                if ($publicContainers.Count -gt 0) {
                    [pscustomobject]@{
                        Subscription = $sub.Name
                        RG = $sa.ResourceGroupName
                        StorageAccount = $sa.StorageAccountName
                        PublicContainersCount = $publicContainers.Count
                        PublicContainers = ($publicContainers | ForEach-Object { "$($_.ContainerName) ($($_.PublicAccess))" }) -join "; "
                        Location = $sa.Location
                    }
                }
            } catch {
                # Skip if we can't access container info
                continue
            }
        }
    }
    
    $count = ($anonymousAccess | Measure-Object).Count
    Write-Finding -Severity "HIGH" `
                  -Message "Storage accounts with anonymous blob container access" `
                  -Count $count `
                  -Data $anonymousAccess
}

function Show-Summary {
    Write-Section -Title "AUDIT SUMMARY" -Color "Magenta"
    
    $totalFindings = ($script:Results | Where-Object { $_.Count -gt 0 }).Count

    $criticalResources = ($script:Results | Where-Object { $_.Severity -eq "CRITICAL" -and $_.Count -gt 0 } | Measure-Object -Property Count -Sum).Sum
    $highResources     = ($script:Results | Where-Object { $_.Severity -eq "HIGH"     -and $_.Count -gt 0 } | Measure-Object -Property Count -Sum).Sum
    $mediumResources   = ($script:Results | Where-Object { $_.Severity -eq "MEDIUM"   -and $_.Count -gt 0 } | Measure-Object -Property Count -Sum).Sum
    $lowResources      = ($script:Results | Where-Object { $_.Severity -eq "LOW"      -and $_.Count -gt 0 } | Measure-Object -Property Count -Sum).Sum
    
    Write-Host "`nAUDIT RESULTS:" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host "Total Tests Run: $($script:Results.Count)" -ForegroundColor White
    Write-Host "Total Findings: $totalFindings" -ForegroundColor White
    
    if ($criticalResources -gt 0) {
        Write-Host "Critical resources impacted: $criticalResources" -ForegroundColor Red
    }
    if ($highResources -gt 0) {
        Write-Host "High resources impacted: $highResources" -ForegroundColor Red
    }
    if ($mediumResources -gt 0) {
        Write-Host "Medium resources impacted: $mediumResources" -ForegroundColor Yellow
    }
    if ($lowResources -gt 0) {
        Write-Host "Low resources impacted: $lowResources" -ForegroundColor Green
    }
    
    Write-Host "`nDETAILED FINDINGS:" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    $script:Results |
        Where-Object { $_.Count -gt 0 } |
        Sort-Object `
            @{ Expression = {
                    switch ($_.Severity.ToUpper()) {
                        "CRITICAL" { 1 }
                        "HIGH"     { 2 }
                        "MEDIUM"   { 3 }
                        "LOW"      { 4 }
                        "INFO"     { 5 }
                        default    { 6 }
                    }
                }
            },
            @{ Expression = { $_.Count }; Descending = $true } |
        Format-Table `
            @{Name="Type"; Expression={ "Finding" }},
            Severity,
            Finding,
            @{Name="Amount"; Expression={ $_.Count }} -AutoSize
    
    # Save results to CSV
    $Results | Export-Csv -Path "AzureSecurityAudit-$Timestamp.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "`nResults saved to: AzureSecurityAudit-$Timestamp.csv" -ForegroundColor Green
}

# ================================================================================
# MAIN EXECUTION
# ================================================================================
Clear-Host
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "                       AZUREMAP" -ForegroundColor Cyan
Write-Host "             Azure Subscription Security Review" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Made by @baas" -ForegroundColor Gray
Write-Host "Recommendation: Assign Global Reader and Security Reader at the tenant level, and Reader at the subscription level to ensure full visibility during testing." -ForegroundColor Gray
Write-Host "Starting audit at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Cyan

try {
    # Check if we're connected to Azure
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-Host "`nNot connected to Azure. Please run:" -ForegroundColor Yellow
        Write-Host "   Connect-AzAccount" -ForegroundColor White
        Write-Host "   Then run this script again." -ForegroundColor White
        exit 1
    }
    
    Write-Host "`nConnected to Tenant: $($context.Tenant.Id)" -ForegroundColor Green
    Write-Host "Account: $($context.Account.Id)" -ForegroundColor Green

    # Tenant metadata (similar to Graph tenantInformation: displayName + defaultDomain)
    try {
        $tenantInfo = Get-AzTenant -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $context.Tenant.Id } | Select-Object -First 1
        if ($tenantInfo) {
            $tenantDisplayName = $tenantInfo.DisplayName
            $tenantDefaultDomain = $null

            if ($tenantInfo.Domains -and $tenantInfo.Domains.Count -gt 0) {
                $tenantDefaultDomain = $tenantInfo.Domains[0]
            }

            if (-not $tenantDisplayName -and $tenantDefaultDomain) {
                # Fallback: derive a simple name from the default domain
                $tenantDisplayName = ($tenantDefaultDomain -replace '\.onmicrosoft\.com$','')
            }

            if ($tenantDisplayName) {
                Write-Host ("Tenant display name : {0}" -f $tenantDisplayName) -ForegroundColor White
            }
            if ($tenantDefaultDomain) {
                Write-Host ("Default domain      : {0}" -f $tenantDefaultDomain) -ForegroundColor White
            }
        }
    } catch {
        # Best-effort only; skip if we can't resolve tenant metadata
    }

    # External tenant lookup (tenantidlookup.com) – best-effort HTML scrape
    try {
        $lookupUri = "https://tenantidlookup.com/$($context.Tenant.Id)"
        $lookupResponse = Invoke-WebRequest -Uri $lookupUri -UseBasicParsing -ErrorAction Stop
        $lines = $lookupResponse.Content -split "`n" | ForEach-Object {
            ($_ -replace '\r','').Trim()
        } | Where-Object { $_ -ne "" }

        $defaultDomainLookup = $null
        $orgNameLookup = $null
        $regionLookup = $null

        for ($i = 0; $i -lt $lines.Count - 1; $i++) {
            if (-not $defaultDomainLookup -and $lines[$i] -like "*Default domain name*") {
                $defaultDomainLookup = ($lines[$i + 1] -replace '<.*?>','').Trim()
            }
            if (-not $orgNameLookup -and $lines[$i] -like "*Organization Name*") {
                $orgNameLookup = ($lines[$i + 1] -replace '<.*?>','').Trim()
            }
            if (-not $regionLookup -and $lines[$i] -like "*Tenant Region Scope*") {
                $regionLookup = ($lines[$i + 1] -replace '<.*?>','').Trim()
            }
        }

        if ($defaultDomainLookup -or $orgNameLookup -or $regionLookup) {
            Write-Host "" -ForegroundColor White
            Write-Host "Tenant information (tenantidlookup.com):" -ForegroundColor DarkGray
            if ($defaultDomainLookup) {
                Write-Host ("  Default domain : {0}" -f $defaultDomainLookup) -ForegroundColor DarkGray
            }
            if ($orgNameLookup) {
                Write-Host ("  Org name       : {0}" -f $orgNameLookup) -ForegroundColor DarkGray
            }
            if ($regionLookup) {
                Write-Host ("  Region scope   : {0}" -f $regionLookup) -ForegroundColor DarkGray
            }
        }
    } catch {
        # Best-effort only; silently skip on failure
    }

    # Resolve subscriptions up front so the user knows what will be scanned
    Initialize-AzureAuditSubscriptions
    $activeCount   = $script:AzureAudit_ActiveSubscriptions.Count
    $disabledCount = $script:AzureAudit_DisabledSubscriptions.Count

    Write-Host "" -ForegroundColor White
    Write-Host ("Active subscriptions to be scanned : {0}" -f $activeCount) -ForegroundColor White
    if ($activeCount -gt 0) {
        Write-Host "Active subscriptions:" -ForegroundColor White
        $script:AzureAudit_ActiveSubscriptions |
            Select-Object Name, Id, State |
            Sort-Object Name |
            Format-Table -AutoSize | Out-Host
    }
    
    # Run all tests
    # Test-StorageSharedKeyAccess
    Test-EventHubPublicAccess
    Test-LogicAppsManagedIdentity
    Test-ApplicationGatewayWAF
    Test-SynapsePublicAccess
    Test-ContainerRegistryPublicAccess
    # Test-AppServiceSecurity
    Test-NSGPermissiveRules
    Test-StorageExfiltrationVectors
    Test-NetworkExfiltrationPaths  # This will now work finally
    Test-SQLExfiltrationRisks
    Test-AKSPrivilegeEscalation    # New check for AKS
    Test-ServiceBusSecurity
    Test-APIMSecurity
    Test-VNetSubnetSecurity
    Test-AKSAdvancedSecurity
    Test-PublicIPInventory
    Test-SQLDatabaseSecurity
    Test-SQLAdvancedSecurity
    Test-CustomRoles
    Test-LongLivedCredentials
    Test-DormantServicePrincipals
    Test-OrphanedServicePrincipals
    Test-ResourceLocks
    Test-CosmosDBSecurity
    Test-ExcessiveRBAC
    Test-KeyVaultNetworkSecurity
    Test-KeyVaultRBAC
    Test-KeyVaultSecretsExpiry
    Test-CriticalResourceDiagnostics
    Test-StorageAdvancedSecurity
    Test-PrivateEndpointsDNS
    Test-VMMonitoringAgents
    Test-ExpiredCredentials
    # Test-StorageBlobPublicAccess
    Test-StorageAnonymousBlobAccess
    
    # Show summary
    Show-Summary
    
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Gray
    exit 1
}

Write-Host "`nAudit completed successfully!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
