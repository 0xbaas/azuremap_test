#==============================================================================
# AzureMap v2 - Core/InventoryCache.ps1
# Per-run, in-memory inventory cache for per-subscription resource lists
# (perf phase). Checks previously re-enumerated the same resource types once
# per check per subscription (e.g. Get-AzStorageAccount 7x per subscription);
# this module fetches each (subscription, kind) list at most once per run and
# shares it. Read-only only: every fetch is a Get-* list call. Nothing is
# written to disk and no secret values/keys/content are ever retrieved.
#==============================================================================

# Maps an inventory kind to the ARM resource types it covers (used for
# footprint-based proven-empty gating) and the read-only list call that
# fetches it. Fetch scriptblocks run AFTER Set-SubscriptionContext succeeded.
$script:InventoryKindMap = @{
    StorageAccounts = @{
        Types = @('microsoft.storage/storageaccounts')
        # -IncludeAccountSASPolicy is a superset of the plain list (same call,
        # extra AccountSASPolicy property) so STORAGE-005/006 and the other
        # storage checks share one enumeration. Older Az.Storage versions lack
        # the parameter: feature-detect and fall back to the plain list (the
        # checks flag SAS-policy evidence as unavailable themselves).
        Fetch = {
            $cmd = Get-Command Get-AzStorageAccount -ErrorAction SilentlyContinue
            if ($cmd -and $cmd.Parameters -and $cmd.Parameters.ContainsKey('IncludeAccountSASPolicy')) {
                Get-AzStorageAccount -IncludeAccountSASPolicy -ErrorAction Stop
            } else {
                Get-AzStorageAccount -ErrorAction Stop
            }
        }
    }
    KeyVaults = @{
        Types = @('microsoft.keyvault/vaults')
        Fetch = { Get-AzKeyVault -ErrorAction Stop }
    }
    NetworkSecurityGroups = @{
        Types = @('microsoft.network/networksecuritygroups')
        Fetch = { Get-AzNetworkSecurityGroup -ErrorAction Stop }
    }
    VirtualNetworks = @{
        Types = @('microsoft.network/virtualnetworks')
        Fetch = { Get-AzVirtualNetwork -ErrorAction Stop }
    }
    PublicIpAddresses = @{
        Types = @('microsoft.network/publicipaddresses')
        Fetch = { Get-AzPublicIpAddress -ErrorAction Stop }
    }
    PrivateEndpoints = @{
        Types = @('microsoft.network/privateendpoints')
        Fetch = { Get-AzPrivateEndpoint -ErrorAction Stop }
    }
    RouteTables = @{
        Types = @('microsoft.network/routetables')
        Fetch = { Get-AzRouteTable -ErrorAction Stop }
    }
    ApplicationGateways = @{
        Types = @('microsoft.network/applicationgateways')
        Fetch = { Get-AzApplicationGateway -ErrorAction Stop }
    }
    Firewalls = @{
        Types = @('microsoft.network/azurefirewalls')
        Fetch = { Get-AzFirewall -ErrorAction Stop }
    }
    WebApps = @{
        Types = @('microsoft.web/sites')
        Fetch = { Get-AzWebApp -ErrorAction Stop }
    }
    FunctionApps = @{
        Types = @('microsoft.web/sites')
        Fetch = { Get-AzFunctionApp -ErrorAction Stop }
    }
    VirtualMachines = @{
        Types = @('microsoft.compute/virtualmachines')
        # -Status is a superset of the plain list (adds instance view/status)
        # so COMPUTE-004 and IDENTITY-006 share one enumeration.
        Fetch = { Get-AzVM -Status -ErrorAction Stop }
    }
    AksClusters = @{
        Types = @('microsoft.containerservice/managedclusters')
        Fetch = { Get-AzAksCluster -ErrorAction Stop }
    }
    ContainerRegistries = @{
        Types = @('microsoft.containerregistry/registries')
        Fetch = { Get-AzContainerRegistry -ErrorAction Stop }
    }
    SqlServers = @{
        Types = @('microsoft.sql/servers')
        Fetch = { Get-AzSqlServer -ErrorAction Stop }
    }
    CosmosAccounts = @{
        Types = @('microsoft.documentdb/databaseaccounts')
        Fetch = { Get-AzResource -ResourceType 'Microsoft.DocumentDb/databaseAccounts' -ErrorAction Stop }
    }
    SynapseWorkspaces = @{
        Types = @('microsoft.synapse/workspaces')
        Fetch = { Get-AzSynapseWorkspace -ErrorAction Stop }
    }
    EventHubNamespaces = @{
        Types = @('microsoft.eventhub/namespaces')
        Fetch = { Get-AzEventHubNamespace -ErrorAction Stop }
    }
    ServiceBusNamespaces = @{
        Types = @('microsoft.servicebus/namespaces')
        Fetch = { Get-AzServiceBusNamespace -ErrorAction Stop }
    }
    ApiManagementServices = @{
        Types = @('microsoft.apimanagement/service')
        Fetch = { Get-AzApiManagement -ErrorAction Stop }
    }
    LogicApps = @{
        Types = @('microsoft.logic/workflows')
        Fetch = { Get-AzLogicApp -ErrorAction Stop }
    }
    AutomationAccounts = @{
        Types = @('microsoft.automation/automationaccounts')
        Fetch = { Get-AzAutomationAccount -ErrorAction Stop }
    }
    ResourceGroups = @{
        # Resource groups are not rows in the Resources table, so there is no
        # footprint type to gate on; they are enumerated directly when asked.
        Types = @()
        Fetch = { Get-AzResourceGroup -ErrorAction Stop }
    }
}

function Test-SubscriptionProvenEmpty {
    <#
    .SYNOPSIS
        Decides whether the footprint PROVES a subscription has none of the
        given resource types (so enumeration can be skipped safely).
    .DESCRIPTION
        Returns $true only under the same fail-safe rules as check-level
        applicability: the footprint must be Complete with High confidence,
        per-subscription type data must exist for this subscription, and none
        of the supplied types may be present. Any doubt -> $false (enumerate).
        Proven-empty via footprint is semantically identical to a real empty
        ARM list response: coverage counts the subscription as evaluated with
        zero resources.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [string[]]$ResourceTypes = @()
    )

    if ($ResourceTypes.Count -eq 0) { return $false }

    $fp = $script:State.Footprint
    if (-not $fp) { return $false }
    if ("$($fp.CoverageStatus)" -ne 'Complete' -or "$($fp.Confidence)" -ne 'High') { return $false }
    if (-not ($fp.PSObject.Properties.Name -contains 'TypeCountsBySub') -or -not $fp.TypeCountsBySub) { return $false }

    $subKey = "$SubscriptionId".ToLowerInvariant()
    if (-not $fp.TypeCountsBySub.ContainsKey($subKey)) { return $false }

    $subTypes = $fp.TypeCountsBySub[$subKey]
    foreach ($t in $ResourceTypes) {
        $tk = "$t".ToLowerInvariant()
        if ($tk -and $subTypes.ContainsKey($tk) -and [int]$subTypes[$tk] -gt 0) { return $false }
    }
    return $true
}

function Get-SubscriptionInventory {
    <#
    .SYNOPSIS
        Returns the cached resource list for a (subscription, kind) pair,
        fetching it at most once per run.
    .DESCRIPTION
        Perf-phase replacement for per-check Get-Az* enumerations:
          * cache hit          -> shared list, no context switch, no ARM call
          * proven empty       -> footprint proves the kind absent in this
                                  subscription: no context switch, no ARM call
          * cache miss         -> Set-SubscriptionContext (deduped) + one
                                  read-only list call, then cached
          * fetch failure      -> recorded Unavailable and CACHED, so later
                                  checks never retry the same denied/failing
                                  operation (denied-call guard); one WARN per
                                  (subscription, kind) per run.
        Fetch time is accumulated into State.Timing.SubscriptionFetchSeconds
        for the Performance summary. In-memory only; never written to disk.
    .OUTPUTS
        [pscustomobject] @{ Items; ProvenEmpty; Unavailable; UnavailableReason;
        FromCache }. UnavailableReason is 'ContextSwitch' (the subscription
        could not be entered - old "skipped subscription" semantics) or
        'Fetch' (the list call failed - old "collection failed" semantics).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$SubscriptionId,

        [object]$SubscriptionName,
        [object]$TenantId,

        [Parameter(Mandatory)]
        [string]$Kind,

        [switch]$ForceRefresh
    )

    $SubscriptionId   = ConvertTo-ScalarString $SubscriptionId
    $SubscriptionName = ConvertTo-ScalarString $SubscriptionName

    if (-not $script:InventoryKindMap.ContainsKey($Kind)) {
        throw "Get-SubscriptionInventory: unknown inventory kind '$Kind'."
    }
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        return [PSCustomObject]@{ Items = @(); ProvenEmpty = $false; Unavailable = $true; UnavailableReason = 'Fetch'; FromCache = $false }
    }

    if (-not $script:State.Cache.ContainsKey('ResourceLists')) {
        $script:State.Cache.ResourceLists = @{}
    }
    $cacheKey = "{0}|{1}" -f $SubscriptionId.ToLowerInvariant(), $Kind

    if (-not $ForceRefresh -and $script:State.Cache.ResourceLists.ContainsKey($cacheKey)) {
        $cached = $script:State.Cache.ResourceLists[$cacheKey]
        return [PSCustomObject]@{
            Items             = $cached.Items
            ProvenEmpty       = $cached.ProvenEmpty
            Unavailable       = $cached.Unavailable
            UnavailableReason = $cached.UnavailableReason
            FromCache         = $true
        }
    }

    $kindDef = $script:InventoryKindMap[$Kind]

    # Footprint proven-empty gate: skip the context switch AND the list call
    # when the environment footprint proves this kind is absent in this sub.
    if (Test-SubscriptionProvenEmpty -SubscriptionId $SubscriptionId -ResourceTypes $kindDef.Types) {
        $record = @{ Items = @(); ProvenEmpty = $true; Unavailable = $false; UnavailableReason = $null }
        $script:State.Cache.ResourceLists[$cacheKey] = $record
        return [PSCustomObject]@{ Items = @(); ProvenEmpty = $true; Unavailable = $false; UnavailableReason = $null; FromCache = $false }
    }

    $label = if ($SubscriptionName) { $SubscriptionName } else { $SubscriptionId }

    if (-not (Set-SubscriptionContext -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -TenantId $TenantId)) {
        $record = @{ Items = @(); ProvenEmpty = $false; Unavailable = $true; UnavailableReason = 'ContextSwitch' }
        $script:State.Cache.ResourceLists[$cacheKey] = $record
        return [PSCustomObject]@{ Items = @(); ProvenEmpty = $false; Unavailable = $true; UnavailableReason = 'ContextSwitch'; FromCache = $false }
    }

    $fetchStart = Get-Date
    $addFetchTime = {
        $elapsed = ((Get-Date) - $fetchStart).TotalSeconds
        if ($script:State.Timing -and $script:State.Timing.SubscriptionFetchSeconds) {
            if ($script:State.Timing.SubscriptionFetchSeconds.ContainsKey($label)) {
                $script:State.Timing.SubscriptionFetchSeconds[$label] += $elapsed
            } else {
                $script:State.Timing.SubscriptionFetchSeconds[$label] = $elapsed
            }
        }
    }

    try {
        $items = @(Invoke-AzureCommand -Command $kindDef.Fetch -CommandName "Get-Inventory-$Kind" -SkipContextCheck)
        & $addFetchTime
        $record = @{ Items = $items; ProvenEmpty = $false; Unavailable = $false; UnavailableReason = $null }
        $script:State.Cache.ResourceLists[$cacheKey] = $record
        Write-AuditLog -Message ("Inventory cached: {0} in {1} ({2} item(s))" -f $Kind, $label, $items.Count) -Level DEBUG
        return [PSCustomObject]@{ Items = $items; ProvenEmpty = $false; Unavailable = $false; UnavailableReason = $null; FromCache = $false }
    }
    catch {
        # Denied/failed list call: classify once, cache the failure, and never
        # retry this (subscription, kind) again this run. Callers treat
        # Unavailable as collection failed (partial / could not check).
        & $addFetchTime
        Write-AuditLog -Message ("Inventory unavailable: {0} in {1}: {2}" -f $Kind, $label, $_.Exception.Message) -Level WARN
        $record = @{ Items = @(); ProvenEmpty = $false; Unavailable = $true; UnavailableReason = 'Fetch' }
        $script:State.Cache.ResourceLists[$cacheKey] = $record
        return [PSCustomObject]@{ Items = @(); ProvenEmpty = $false; Unavailable = $true; UnavailableReason = 'Fetch'; FromCache = $false }
    }
}
