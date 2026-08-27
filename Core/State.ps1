#==============================================================================
# AzureMap v2 - Core/State.ps1
# Central audit state initialization and module requirement definitions.
# All modules reference $script:State as the single source of truth.
#==============================================================================

function Initialize-AuditState {
    <#
    .SYNOPSIS
        Creates and returns the central $script:State hashtable for AzureMap.
    .DESCRIPTION
        Initializes every sub-structure that other Core modules depend on:
        Config, Metadata, Cache, EntraData, TenantWideData, Results,
        FailedSubscriptions, ExecutedChecks, CircuitBreaker, LogBuffer,
        GraphToken/GraphTokenExpiry, Timestamp, LogFile, CheckRegistry,
        and module requirement definitions.
    .OUTPUTS
        [hashtable] The initialized state object (also stored in $script:State).
    #>
    [CmdletBinding()]
    param()

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    $script:State = @{

        # --- Metadata ---
        Metadata = @{
            ToolName = "AzureMap"
            Version  = "2.0"
            Author   = "@baas"
        }

        Timestamp = $timestamp
        StartTime = Get-Date
        LogFile   = "AzureMap-$timestamp.log"
        # Console dedupe for identical WARN/ERROR lines (key -> occurrence count).
        # Every occurrence still lands in the log file; the console prints the
        # first occurrence plus one suppression note.
        LogConsoleSeen = @{}
        # Per-check CLI status-line numbering (global across both phases) and
        # verbose finding-block dedupe (CheckId|Severity|Message -> count).
        CheckRunIndex      = 0
        CheckRunTotal      = 0
        FindingConsoleSeen = @{}

        # Performance timing (perf phase): phase-level durations in seconds
        # (Discovery, Collection, Assessment, Export) and per-subscription
        # collection time accumulated by the inventory cache. Per-check
        # durations live on the execution records (DurationSeconds).
        Timing = @{
            Phases                  = [ordered]@{}
            SubscriptionFetchSeconds = @{}
        }

        # Footprint: normalized subscription list for error-message normalization.
        Subscriptions = @()
        # Environment footprint (Core/Azure/Footprint.ps1): subscriptions/RGs/resources/
        # resource-type counts. $null until the pre-scan runs; drives applicability.
        Footprint = $null
        # Phase B2 capability model (Core/Capability.ps1 +
        # Core/Azure/CapabilityModel.Azure.ps1): nodes/edges/
        # insights built AFTER assessment from already-collected data only.
        # $null until Build-CapabilityModel runs; consumed by JSON/HTML/CLI.
        CapabilityModel = $null
        # Applicability/error plumbing for the per-check CLI summary:
        # CurrentCheckId is set while a check executes; CheckErrors aggregates
        # normalized WARN/ERROR messages per check (message -> count) so the CLI
        # can print one summarized line instead of repeated raw errors.
        CurrentCheckId = $null
        CheckErrors    = @{}

        # --- Default configuration ---
        Config = @{
            LongCredentialDays   = 730
            ExpiringSoonDays     = 30
            DangerousPorts       = @(
                "22","21","23","3389","5985","5986","445","139",
                "1433","3306","5432","1521","27017","6379","5984",
                "9200","5601","2375","6443","10250"
            )

            MaxRetryAttempts     = 3
            RetryDelaySeconds    = 2
            MaxRetryDelaySeconds = 30

            BatchSize  = 100
            PageSize   = 1000

            ExportFormats       = @("CSV", "JSON", "HTML")
            GenerateHTMLReport  = $true

            SendEmail       = $false
            EmailRecipients = @()

            SeverityLevel = "All"
            Services      = @("All")
            Quiet         = $false
            NoColor       = $false
            UseGraphBeta  = $false
            SkipEntra     = $false
            VerboseOutput = $false
            DebugOutput   = $false
            # Opt-in detail switches: the normal CLI stays clean; these re-add
            # raw finding blocks, remediation text, and the full check list.
            ShowFindings    = $false
            ShowRemediation = $false
            DetailedSummary = $false
            # Phase B3: data-plane checks (STORAGE-004, KEYVAULT-003) are OFF by
            # default. AzureMap is safely read-only on the ARM control plane
            # unless -IncludeDataPlane is passed explicitly. Even then, checks
            # read safe metadata only - never values, keys, SAS tokens,
            # connection strings, or blob/file content.
            IncludeDataPlane = $false
            RedactSensitive = $false
            RedactPublicIps = $false

            RBACSeverity = @{
                "Owner"                        = @{ Root = "CRITICAL"; ManagementGroup = "CRITICAL"; Subscription = "HIGH";   ResourceGroup = "MEDIUM" }
                "User Access Administrator"    = @{ Root = "CRITICAL"; ManagementGroup = "CRITICAL"; Subscription = "HIGH";   ResourceGroup = "MEDIUM" }
                "Privileged Role Administrator"= @{ Root = "CRITICAL"; ManagementGroup = "CRITICAL"; Subscription = "HIGH";   ResourceGroup = "HIGH"   }
                "Contributor"                  = @{ Root = "HIGH";     ManagementGroup = "HIGH";     Subscription = "MEDIUM"; ResourceGroup = "LOW"    }
                "Key Vault Contributor"        = @{ Root = "HIGH";     ManagementGroup = "HIGH";     Subscription = "HIGH";   ResourceGroup = "MEDIUM" }
                "Network Contributor"          = @{ Root = "HIGH";     ManagementGroup = "HIGH";     Subscription = "HIGH";   ResourceGroup = "MEDIUM" }
                "Reader"                       = @{ Root = "LOW";      ManagementGroup = "LOW";      Subscription = "INFO";   ResourceGroup = "INFO"   }
            }
        }

        # --- Three-tier cache ---
        Cache = @{
            Subscriptions   = $null
            RBACAssignments = @{}
            # Per-subscription custom role definitions as fetched by IDENTITY-005
            # (Get-AzRoleDefinition -Custom), retained for read-only capability
            # modeling (Phase B2): key "<subscriptionId>" -> slim projections
            # @{ RoleGuid; RoleName; Actions; DataActions }. In-memory only.
            RoleDefinitions = @{}
            # Per-run inventory cache (Core/Azure/InventoryCache.ps1): key
            # "<subscriptionId>|<Kind>" -> @{ Items; ProvenEmpty; Unavailable }.
            # In-memory only, cleared at end of run; never written to disk.
            ResourceLists   = @{}
            # Per-subscription flag: $true when an RBAC read could not be evaluated
            # (e.g. ARM RBAC unreadable). Lets RBAC checks emit NotEvaluated instead
            # of a misleading PASS when collection failed.
            RBACUnavailable = @{}
            Graph           = @{}
            AzBatch         = @{}
            General         = @{}
        }

        # --- Entra ID / tenant-wide data ---
        EntraData = @{
            Users             = $null
            Groups            = $null
            DirectoryRoles    = $null
            ConditionalAccess = $null
        }

        TenantWideData = @{
            Applications      = $null
            ServicePrincipals = $null
            TenantId          = $null
            FetchedAt         = $null
        }

        # --- Authentication preflight result (populated by Test-AuthenticationPreflight) ---
        Auth = $null

        # --- Runtime slots (initialized so Windows PowerShell 5.1 StrictMode does not
        #     throw "property cannot be found" on first access before they are set) ---
        CurrentCheck = $null
        Entra        = $null

        # --- Results tracking ---
        Results             = [System.Collections.Generic.List[object]]::new()
        FailedSubscriptions = [System.Collections.Generic.List[object]]::new()
        ExecutedChecks      = [System.Collections.Generic.List[object]]::new()

        # --- Circuit breaker ---
        CircuitBreaker = @{
            FailureCount          = 0
            LastFailureTime       = $null
            State                 = "Closed"   # Closed | Open | HalfOpen
            OpenDurationSeconds   = 60
            FailureThreshold      = 5
            HalfOpenProbeInFlight = $false
        }

        # --- Logging ---
        LogBuffer     = [System.Collections.Generic.List[string]]::new()
        LogBufferSize = 50
        LastLogFlush  = Get-Date
        LogLock       = [System.Object]::new()

        # --- Graph API tokens ---
        GraphToken       = $null
        GraphTokenExpiry = $null

        # --- Check registry ---
        CheckRegistry = [System.Collections.Generic.List[object]]::new()

        # --- Exclusions (loaded later) ---
        Exclusions = @{
            Resources     = @()
            Findings      = @()
            Subscriptions = @()
            Tags          = @()
        }

        # --- Module-check flag ---
        ModuleCheckComplete = $false
        ContextRetryCount   = 0

        # --- Unicode status icons ---
        CheckMark   = [char]0x2714  # checkmark
        CrossMark   = [char]0x2718  # X
        WarningMark = [char]0x26A0  # warning triangle
    }

    # ---- Module requirement definitions (static, referenced by Config/CheckRegistry) ----

    $script:State.RequiredModules = @{
        "Az.Accounts"  = "2.0.0"
        "Az.Resources" = "6.0.0"
        "Az.Storage"   = "5.0.0"
        "Az.Sql"       = "4.0.0"
        "Az.Compute"   = "7.0.0"
        "Az.Network"   = "6.0.0"
        "Az.KeyVault"  = "4.0.0"
        "Az.Monitor"   = "4.0.0"
    }

    $script:State.OptionalModules = @{
        "Az.Aks"               = "5.0.0"
        "Az.ResourceGraph"     = "2.0.0"
        "Az.CosmosDB"          = "1.0.0"
        "Az.ContainerRegistry" = "2.0.0"
        "Az.EventHub"          = "2.0.0"
        "Az.ServiceBus"        = "2.0.0"
        "Az.ApiManagement"     = "3.0.0"
        "Az.Synapse"           = "2.0.0"
        "Az.Automation"        = "1.0.0"
        "Az.Websites"          = "2.0.0"
        "Az.LogicApp"          = "1.0.0"
    }

    $script:State.ServiceModules = @{
        "Storage"           = @("Az.Storage")
        "SQL"               = @("Az.Sql")
        "AKS"               = @("Az.Aks")
        "KeyVault"          = @("Az.KeyVault")
        "Network"           = @("Az.Network")
        "Compute"           = @("Az.Compute")
        "Identity"          = @("Az.Resources")
        "ContainerRegistry" = @("Az.ContainerRegistry")
        "CosmosDB"          = @("Az.CosmosDB")
        "EventHub"          = @("Az.EventHub")
        "ServiceBus"        = @("Az.ServiceBus")
        "APIM"              = @("Az.ApiManagement")
        "Synapse"           = @("Az.Synapse")
        "Automation"        = @("Az.Automation")
        "Monitoring"        = @("Az.Monitor")
        "Diagnostics"       = @("Az.Monitor")
        "PublicIP"          = @("Az.Network")
        "Exfiltration"      = @("Az.Network", "Az.Storage")
        "AppService"        = @("Az.Websites")
        "LogicApp"          = @("Az.LogicApp")
    }

    return $script:State
}
