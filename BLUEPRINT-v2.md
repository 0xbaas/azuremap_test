# AzureMap v2 — Engineering Blueprint

**Date:** 2026-02-18
**Author:** Generated from triple-repo deep analysis
**Repos Analyzed:**
- `AnassBali/AzureMap` (5,545-line single script, 61 functions, 38 security checks)
- `azurekid/ScEntra` (Entra risk + escalation analysis, 14 PS files, ~4,500 LOC)
- `azurekid/blackcat` (Azure security toolkit, 80+ PS files, ~12,000 LOC)

---

## TABLE OF CONTENTS

1. [Current State Summary (AzureMap)](#1-current-state-summary-azuremap)
2. [What to Adopt from ScEntra + What to Avoid](#2-what-to-adopt-from-scentra)
3. [What to Adopt from Blackcat + What to Avoid](#3-what-to-adopt-from-blackcat)
4. [Entra Expansion Plan](#4-entra-expansion-plan)
5. [Architecture & Refactor Blueprint](#5-architecture--refactor-blueprint)
6. [Performance & Scalability Plan](#6-performance--scalability-plan)
7. [Testing Plan + PR Acceptance Checklist](#7-testing-plan--pr-acceptance-checklist)
8. [Phased Roadmap](#8-phased-roadmap)

---

## 1. CURRENT STATE SUMMARY (AzureMap)

### 1.1 Script Metadata

| Property | Value | Code Proof |
|----------|-------|------------|
| File | `AzureMap.ps1` | Single monolith, 5,545 lines |
| Version | 1.0 | `$script:Metadata.Version = "1.0"` (line 117) |
| Total Functions | 61 | 12 utility + 6 framework + 38 checks + 5 orchestration/export |
| Required Modules | 9 | `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.Sql`, `Az.Compute`, `Az.Network`, `Az.KeyVault`, `Az.Monitor`, `Az.AD` (lines 162–172) |
| Optional Modules | 11 | `Az.Aks`, `Az.ResourceGraph`, `Az.CosmosDB`, `Az.ContainerRegistry`, `Az.EventHub`, `Az.ServiceBus`, `Az.ApiManagement`, `Az.Synapse`, `Az.Automation`, `Az.Websites`, `Az.LogicApp` (lines 175–187) |

### 1.2 Complete Check Inventory

#### Identity (6 checks)

| CheckId | Function | Detects | API Method | Severity |
|---------|----------|---------|------------|----------|
| IDENT-01 | `Test-LongLivedCredentials` | App registrations with credential validity > LongCredentialDays (730d default) | `Get-AzADApplication` via `Get-TenantWideData` | MEDIUM |
| IDENT-02 | `Test-DormantServicePrincipals` | SPs with zero credentials but active RBAC assignments (orphaned privilege) | `Get-AzADServicePrincipal` + `Get-AzRoleAssignment` per sub | MEDIUM |
| IDENT-03 | `Test-ExcessiveRBAC` | Broad RBAC at Root/MgmtGroup/Sub scope with role-based severity matrix | `Get-AzRoleAssignment` (cached per sub) | CRITICAL–LOW (dynamic) |
| IDENT-04 | `Test-ExpiredCredentials` | SP/app credentials past their EndDateTime | `Get-AzADServicePrincipal` + `Get-AzADApplication` | INFO |
| IDENT-05 | `Test-CustomRoles` | Custom RBAC roles with wildcard/dangerous permissions (e.g. `Microsoft.Authorization/*`) | `Get-AzRoleDefinition -Custom` + `Get-AzRoleAssignment` | HIGH |
| IDENT-06 | `Test-IdentityResourceMapping` | Managed identities on WebApps/VMs/FuncApps holding Owner/Contributor/UAA roles | `Get-AzWebApp` + `Get-AzVM` + `Get-AzFunctionApp` + `Get-AzRoleAssignment` | CRITICAL/HIGH |

**Proof — severity matrix in `Test-ExcessiveRBAC`:**
```
150:158:c:\Users\ns\Tools\OPus\AzureMap-review\AzureMap.ps1
    RBACSeverity = @{
        "Owner" = @{ Root = "CRITICAL"; ManagementGroup = "CRITICAL"; Subscription = "HIGH"; ResourceGroup = "MEDIUM" }
        "User Access Administrator" = @{ Root = "CRITICAL"; ManagementGroup = "CRITICAL"; Subscription = "HIGH"; ResourceGroup = "MEDIUM" }
        "Contributor" = @{ Root = "HIGH"; ManagementGroup = "HIGH"; Subscription = "MEDIUM"; ResourceGroup = "LOW" }
        ...
    }
```

#### Storage (4 checks)

| CheckId | Function | Detects | API | Severity |
|---------|----------|---------|-----|----------|
| STOR-01 | `Test-StorageSharedKeyAccess` | Shared key auth enabled on storage accounts | `Get-AzStorageAccount` | HIGH |
| STOR-02 | `Test-StoragePublicAccess` | Public network + blob public access | `Get-AzStorageAccount` + `Get-AzStorageAccountNetworkRuleSet` | HIGH/MEDIUM |
| STOR-03 | `Test-StorageAdvancedSecurity` | HTTPS disabled, TLS <1.2, cross-tenant replication | `Get-AzStorageAccount` | HIGH/MEDIUM |
| STOR-04 | `Test-StorageAnonymousBlobAccess` | Containers with anonymous read access | `Get-AzStorageAccount` + `Get-AzStorageContainer` | CRITICAL |

#### SQL (2 checks)

| CheckId | Function | Detects | API | Severity |
|---------|----------|---------|-----|----------|
| SQL-01 | `Test-SQLDatabaseSecurity` | Public access + missing auditing | `Get-AzSqlServer` + `Get-AzSqlServerAudit` | HIGH/MEDIUM |
| SQL-02 | `Test-SQLAdvancedSecurity` | Public access + missing AAD admin + service-managed TDE | `Get-AzSqlServer` + AD admin + TDE protector | HIGH/MEDIUM |

#### Network (7 checks)

| CheckId | Function | Detects | Severity |
|---------|----------|---------|----------|
| NET-01 | `Test-NSGPermissiveRules` | Inbound Allow from Internet on dangerous ports (22 ports list) | HIGH/MEDIUM |
| NET-02 | `Test-PrivateEndpointsDNS` | Private endpoints missing DNS zone groups | MEDIUM |
| NET-03 | `Test-PublicIPInventory` | PIPs with DNS endpoints, Basic SKU | MEDIUM/LOW/INFO |
| NET-04 | `Test-VNetSubnetSecurity` | Subnets without NSGs, large subnets (>/24) | MEDIUM/LOW |
| NET-05 | `Test-VNetPeeringSecurity` | Cross-sub peering, gateway transit, forwarded traffic | MEDIUM/LOW |
| NET-06 | `Test-AzureFirewallThreatIntel` | Firewall threat intel mode off/empty | MEDIUM |
| NET-07 | `Test-ApplicationGatewayWAF` | V2 gateways without WAF, Basic SKU gateways | HIGH/MEDIUM |

#### KeyVault (3 checks)

| CheckId | Function | Detects | Severity |
|---------|----------|---------|----------|
| KV-01 | `Test-KeyVaultRBAC` | Vaults using legacy access policies (RBAC disabled) | LOW |
| KV-02 | `Test-KeyVaultNetworkSecurity` | Public + no firewall (CRITICAL), no purge protection (HIGH), critical vaults without PE (MEDIUM) | CRITICAL/HIGH/MEDIUM |
| KV-03 | `Test-KeyVaultSecretsExpiry` | Secrets with no expiry, far-future expiry, already expired | MEDIUM/LOW |

#### Remaining Services (16 checks)

| CheckId | Function | Service | Detects | Severity |
|---------|----------|---------|---------|----------|
| AKS-01 | `Test-AKSAdvancedSecurity` | AKS | Non-private, no AAD, no policy, no network policy, local accounts, no OIDC | HIGH–LOW |
| AKS-02 | `Test-AKSPrivilegeEscalation` | AKS | Public API no IP restrict (CRITICAL), legacy RBAC/local accounts (HIGH) | CRITICAL/HIGH |
| ACR-01 | `Test-ContainerRegistrySecurity` | ACR | Public+no rules, admin user, anonymous pull | HIGH/MEDIUM |
| CDB-01 | `Test-CosmosDBSecurity` | CosmosDB | Public+allow-all (CRITICAL), public w/rules (HIGH), no AAD, no backup policy | CRITICAL–MEDIUM |
| EH-01 | `Test-EventHubPublicAccess` | EventHub | Public access + permissive firewall | HIGH |
| SB-01 | `Test-ServiceBusSecurity` | ServiceBus | Public + permissive (HIGH), SAS key usage (MEDIUM) | HIGH/MEDIUM |
| APIM-01 | `Test-APIMSecurity` | APIM | External instances (INFO), expired/expiring certs | HIGH/MEDIUM/INFO |
| SYN-01 | `Test-SynapsePublicAccess` | Synapse | Public access + no managed VNet | HIGH |
| AUTO-01 | `Test-AutomationRunAsAccounts` | Automation | Deprecated RunAs accounts | MEDIUM |
| MON-01 | `Test-VMMonitoringAgents` | Monitoring | VMs missing AMA + OMS agents | LOW |
| DIAG-01 | `Test-CriticalResourceDiagnostics` | Diagnostics | KeyVaults/SQL without diagnostic settings | HIGH |
| DIAG-02 | `Test-ResourceLocks` | Diagnostics | Critical RGs missing CanNotDelete locks | MEDIUM |
| EXFIL-01 | `Test-NetworkExfiltrationPaths` | Exfiltration | NSG outbound to Internet (HIGH), default route to Internet (MEDIUM) | HIGH/MEDIUM |
| EXFIL-02 | `Test-StorageExfiltrationVectors` | Exfiltration | Public+SharedKey+no FW (CRITICAL), long SAS/cross-tenant (HIGH), trusted bypass (MEDIUM) | CRITICAL–MEDIUM |
| APP-01 | `Test-AppServiceSecurity` | AppService | HTTPS disabled (HIGH), no auth (MEDIUM) | HIGH/MEDIUM |
| LOGIC-01 | `Test-LogicAppsManagedIdentity` | LogicApp | Enabled Logic Apps without managed identity | MEDIUM |

### 1.3 Finding Object Schema

Proven from `Write-Finding` (lines 961–977):

```powershell
[PSCustomObject]@{
    FindingId        = [guid]       # New-Guid per finding
    Timestamp        = [datetime]   # Get-Date at creation
    Severity         = [string]     # CRITICAL | HIGH | MEDIUM | LOW | INFO
    Finding          = [string]     # Human-readable message
    Count            = [int]        # Affected resources (0 = PASS)
    EvidenceCount    = [int]        # Total items before truncation
    Service          = [string]     # Service category
    Status           = [string]     # FAIL (Count>0) | PASS
    SubscriptionId   = [string]     # Sub ID or "Multiple"/"Tenant-wide"
    SubscriptionName = [string]     # Sub name
    ResourceId       = [string]     # Azure resource ID
    ResourceName     = [string]     # Resource name
    Tags             = [hashtable]  # Resource tags
    Remediation      = [string]     # Fix guidance
    Evidence         = [array]      # PSCustomObjects, capped at 1000
}
```

### 1.4 Runtime Behavior

| Behavior | Implementation | Code Proof |
|----------|---------------|------------|
| **Subscription Discovery** | Cached in `$script:Cache.Subscriptions` via `Get-AzSubscription`, filtered by exclusion IDs | Lines 1016–1024, 5507–5514 |
| **Config Merge** | Recursive `Merge-Hashtable` — scalars/arrays replaced, nested hashtables merged deeply | Lines 614–636 |
| **Exclusions** | 4 dimensions: subscription ID, resource ID/name pattern, tag key/value, finding type+severity | `Test-Exclusion` lines 708–756 |
| **Circuit Breaker** | 3-state (Closed/Open/HalfOpen), opens after 5 failures, 60s open duration, half-open probe | Lines 232–239, `Test-CircuitBreaker` line 370 |
| **Retry Logic** | `Invoke-AzureCommand`: Auth retry (reconnect), throttle (exp backoff + jitter + Retry-After), service error (linear backoff), max 3 retries | Lines 424–523 |
| **Export** | CSV (summary + detailed), JSON (depth-5, evidence capped at 10), HTML (XSS-safe, severity-sorted) | `Export-Results` line 5073 |

### 1.5 What AzureMap Does NOT Cover Today

- **No Entra ID analysis** (no Graph API calls, no directory role checks, no PIM)
- **No app permission analysis** (doesn't check Graph/API permission grants on SPs)
- **No ownership chain analysis** (no escalation path detection)
- **No Conditional Access analysis**
- **No Resource Graph queries** (despite `Az.ResourceGraph` being listed as optional — never used)
- **No batching** of per-resource API calls
- **No parallel execution** of checks across subscriptions

---

## 2. WHAT TO ADOPT FROM ScEntra

### 2.1 ADOPT (Safe, Read-Only Patterns)

| # | Pattern | Source | Why Adopt | Adaptation Notes |
|---|---------|--------|-----------|-----------------|
| A1 | **Graph API direct REST calls** (no MS Graph SDK dependency) | `GraphHelpers.ps1` → `Invoke-GraphRequest` | Zero module dependency for Entra checks; just `Invoke-RestMethod` with Bearer token | Rewrite as `Invoke-GraphCommand` wrapper inside AzureMap's `Invoke-AzureCommand` retry framework |
| A2 | **JWT token decode without modules** | `GraphHelpers.ps1` → `Get-GraphTokenScopeInfo` lines 30–65 | Validate token scopes at startup without importing Microsoft.Graph | Copy approach into `Test-GraphPermissions` helper |
| A3 | **Permission hierarchy map** | `GraphHelpers.ps1` line 8 — `$script:GraphPermissionHierarchy` | `Directory.Read.All` satisfies `User.Read.All`, etc. — prevents false "missing permission" warnings | Include as static reference data in AzureMap |
| A4 | **Batch Graph requests (up to 20 per POST)** | `Get-ScEntraServicePrincipals.ps1` lines 53–65 | Collects appRoleAssignments + oauth2Grants in single batch call per 100 SPs — massive API savings | Generalize into `Invoke-GraphBatch` helper |
| A5 | **Adaptive environment sizing** | `Invoke-ScEntraAnalysis` → `Get-ScEntraEnvironmentConfig` | Adjusts batch throttle, delay, parallelism based on tenant size (Small/Medium/Large/Enterprise) | Adopt scoring formula: `envScore = users*1 + groups*2 + SPs*0.5 + apps*0.5` |
| A6 | **Escalation path risk types** (8 types) | `Get-ScEntraEscalationPaths.ps1` lines 131–159, 165–777 | Core Entra risk model: RoleEnabledGroup, NestedGroupMembership, SPOwnership, AppPermissionEscalation, AppRegistrationOwnership, AppAdminEscalation, RoleAdminEscalation, MultiplePIMRoles | Reimplement with AzureMap's Finding schema (see Section 4) |
| A7 | **Permission escalation map** (7 dangerous Graph permissions) | `Get-ScEntraEscalationPaths.ps1` lines 151–159 | `Domain.ReadWrite.All` (Critical), `RoleManagement.ReadWrite.Directory` (Critical), `AppRoleAssignment.ReadWrite.All` (High), `Application.ReadWrite.All` (High), `Group.ReadWrite.All` (High), `Directory.ReadWrite.All` (Medium), `DeviceManagementConfiguration.ReadWrite.All` (High) | Expand to 25+ permissions using Blackcat's larger map |
| A8 | **PIM eligible vs active analysis** | `Get-ScEntraPIMAssignments.ps1` — dual endpoint: `roleEligibilitySchedules` + `roleAssignmentSchedules` | Differentiates standing access from JIT-eligible — critical for true privilege posture | Emit separate findings for standing vs eligible |
| A9 | **Parallel data collection** | `Invoke-ScEntraAnalysis` Step 2: `ForEach-Object -Parallel` with 3 threads for users+groups, SPs, apps | 3x speedup on collection phase | Adopt for AzureMap's subscription-level checks too |
| A10 | **Report redaction** | `RedactionHelpers.ps1` — deterministic SHA-256 based `REDACTED_<8hex>` | Enables sharing reports without PII. Deterministic = same input always same hash, preserves correlation | Add `-Redact` switch to AzureMap export |

### 2.2 AVOID

| # | What | Why Avoid |
|---|------|-----------|
| X1 | **Interactive TUI menu** (`Invoke-ScEntraAnalysis` switch statement with `Read-Host`) | AzureMap is a headless audit script, not an interactive tool. CI/CD incompatible. |
| X2 | **vis-network HTML visualization** (~200KB embedded JS) | Too heavy, browser-dependent. AzureMap's clean HTML table report is better for audit deliverables. Extract graph data as JSON instead. |
| X3 | **Self-decrypting HTML (AES-256-CBC in browser)** | 1000 PBKDF2 iterations is too low for production. If needed, use proper file-level encryption separately. |
| X4 | **`$global:ScEntraAccessToken`** (global scope token storage) | AzureMap uses `$script:` scope throughout — no globals. |
| X5 | **Graph beta endpoint as default** (`$script:GraphBaseUrl = ".../beta"`) | Beta APIs can break without notice. Use `v1.0` for stable checks, `beta` only for PIM endpoints that require it. |
| X6 | **No persistent caching** (every run re-fetches everything) | AzureMap already has `$script:Cache`; extend it, don't regress. |
| X7 | **BFS graph traversal in PowerShell** (`New-ScEntraGraphData` ~1,981 lines) | Overly complex for our needs. We need risk *findings*, not a graph visualization engine. |

---

## 3. WHAT TO ADOPT FROM Blackcat

### 3.1 ADOPT (Safe, Read-Only Patterns)

| # | Pattern | Source | Why Adopt |
|---|---------|--------|-----------|
| B1 | **Three-tier in-memory cache with LRU eviction** | `Use-BlackCatCache.ps1` → `Set-BlackCatCache`/`Get-BlackCatCache` (lines 3–86) | Superior to AzureMap's simple hashtable cache. LRU eviction prevents unbounded memory. GZip for large payloads. TTL-based expiry. |
| B2 | **`Invoke-CacheableOperation` pattern** | `Use-BlackCatCache.ps1` — wraps any scriptblock in cache check → execute → store | Clean abstraction: `Invoke-CacheableOperation -CacheKey $k -Operation { API call } -CacheType 'MSGraph'` |
| B3 | **Azure Resource Graph via batch endpoint** | `Invoke-AzBatch` — `management.azure.com/batch?api-version=2020-06-01` with KQL queries | AzureMap lists `Az.ResourceGraph` as optional but NEVER uses it. Resource Graph can replace dozens of per-sub `Get-Az*` calls with a single cross-sub KQL query. |
| B4 | **Privileged roles reference data** | `support-files/privileged-roles.json` — 20 roles with GUID, criticality, description | Eliminates API call to resolve role definitions. Use as static lookup. |
| B5 | **appRoleIds.csv** (584 rows) | Maps every Graph permission name → GUID → type | GUID-to-name resolution without API calls. Critical for permission analysis. |
| B6 | **Parallel per-subscription processing** | `Get-RoleAssignment.ps1` — `ForEach-Object -Parallel` with `[ConcurrentBag]` | AzureMap iterates subscriptions sequentially. Parallel = proportional speedup. |
| B7 | **Multi-endpoint token acquisition** | `New-AuthHeader` — `Get-AzAccessToken -ResourceUrl $endpoints[$type]` for 17+ endpoints | Clean pattern for acquiring both ARM and Graph tokens from the same `Az.Accounts` context. |
| B8 | **Structured output formatting** | `Format-BlackCatOutput` — Object/JSON/CSV/Table via `-OutputFormat` parameter | Adopt as internal pattern for check functions to support multiple output modes. |
| B9 | **Permission wildcard matching** | `Find-AzurePermissionHolder` → `Test-PermissionMatch` — handles `*` globs in RBAC actions, respects `notActions` | Needed for custom role analysis to detect "effectively Owner" custom roles. |
| B10 | **Pester test structure** | `Tests/*.Tests.ps1` — dot-source function, mock dependencies, test params/output/errors | Adopt as template for AzureMap's test suite. |

### 3.2 AVOID

| # | What | Why Avoid |
|---|------|-----------|
| Y1 | **ALL Persistence functions** (`Set-*`, `Add-GroupObject`, etc.) | Write operations. AzureMap is audit-only, read-only. |
| Y2 | **ALL Credential Access** (`Get-KeyVaultSecret`, `Get-StorageAccountKey`, `Get-ManagedIdentityToken`) | Reads secrets/keys — unnecessary for posture assessment and crosses audit boundary. |
| Y3 | **Stealth/evasion patterns** (`Invoke-StealthOperation`, `Set-UserAgentRotation`, `New-JWT`) | Offensive tooling patterns. AzureMap should use honest, identifiable User-Agent. |
| Y4 | **External recon** (`Find-AzurePublicResource`, `Find-SubDomain`, `Find-PublicStorageContainer`) | Brute-force/enumeration against external targets. Not audit. |
| Y5 | **`Invoke-BlackCat` private bootstrap** (auto-installs `Az.Accounts`, checks version from GitHub) | Side-effects at import time. AzureMap should validate deps explicitly at startup. |
| Y6 | **Token forging** (`New-JWT`, `Invoke-FederatedTokenExchange`) | Offensive. Never. |
| Y7 | **Attack infrastructure** (`Attacks/` folder — fake OIDC issuer setup) | Offensive. Never. |

---

## 4. ENTRA EXPANSION PLAN

### 4.1 New Entra Check Set (Prioritized)

#### P0 — Critical (Phase 1)

| CheckId | Name | Detects | Graph Endpoint | Severity |
|---------|------|---------|---------------|----------|
| ENTRA-01 | `Test-PrivilegedRoleAssignments` | Users/SPs/groups with standing assignments to Global Admin, Priv Role Admin, App Admin, etc. (no PIM = standing access) | `GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal` + `roleDefinitions` | CRITICAL (GA/PRA), HIGH (App/Cloud App/User Admin) |
| ENTRA-02 | `Test-PIMEligibleVsActive` | Compare PIM-eligible vs PIM-active. Flag standing-active assignments that should be PIM-eligible | `GET /beta/roleManagement/directory/roleEligibilitySchedules`, `roleAssignmentSchedules` | HIGH (standing where PIM available), MEDIUM (eligible w/o time-bound) |
| ENTRA-03 | `Test-DangerousAppPermissions` | Service principals with high-impact Graph application permissions (7+ from ScEntra's map, expanded to 25 using Blackcat's `permissionEscalationTargets`) | `GET /v1.0/servicePrincipals?$select=id,displayName,appId` + batch `appRoleAssignments` | CRITICAL (`Domain.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`), HIGH (others) |
| ENTRA-04 | `Test-AppOwnershipChains` | App registrations/SPs owned by non-admin users who could add credentials to escalate | `GET /v1.0/applications/{id}/owners`, `servicePrincipals/{id}/owners` | HIGH (owner of app with privileged permissions), MEDIUM (>5 owners) |

#### P1 — High (Phase 2)

| CheckId | Name | Detects | Graph Endpoint | Severity |
|---------|------|---------|---------------|----------|
| ENTRA-05 | `Test-RoleAssignableGroups` | Security groups with `isAssignableToRole=true` that hold privileged directory roles — membership = implicit privilege | `GET /v1.0/groups?$filter=isAssignableToRole eq true` + members | HIGH |
| ENTRA-06 | `Test-NestedGroupEscalation` | Groups with roles where `transitiveMemberCount > directMemberCount` (hidden nested access) | `GET /v1.0/groups/{id}/transitiveMembers/$count` vs `/members/$count` | MEDIUM |
| ENTRA-07 | `Test-CrossTierBridges` | Accounts/groups that appear in BOTH low-privilege AND high-privilege role assignments (bridge accounts) | Cross-reference ENTRA-01 + ENTRA-05 data | HIGH |
| ENTRA-08 | `Test-StalePrivilegedAccounts` | Privileged role holders with `signInSessionsValidFromDateTime` older than 90 days or `accountEnabled=false` | `GET /v1.0/users?$select=id,...,signInSessionsValidFromDateTime` cross-ref with role assignments | MEDIUM |

#### P2 — Medium (Phase 3)

| CheckId | Name | Detects | Graph Endpoint | Severity |
|---------|------|---------|---------------|----------|
| ENTRA-09 | `Test-DelegatedPermissionGrants` | Broad delegated permission grants (e.g., `Directory.ReadWrite.All` delegated to apps) | `GET /v1.0/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'` | MEDIUM |
| ENTRA-10 | `Test-MultiTenantApps` | App registrations with `signInAudience` set to `AzureADMultipleOrgs` or `AzureADandPersonalMicrosoftAccount` | `GET /v1.0/applications?$select=id,displayName,signInAudience` | LOW |
| ENTRA-11 | `Test-AppCredentialHygiene` | Apps/SPs with credentials expiring beyond 2 years, or multiple active credentials | `GET /v1.0/applications?$select=id,passwordCredentials,keyCredentials` | MEDIUM |
| ENTRA-12 | `Test-AdminConsentWorkflow` | Whether admin consent workflow is configured (or if every admin can consent) | `GET /v1.0/policies/adminConsentRequestPolicy` | LOW |

### 4.2 Detection Approach Detail (P0 Checks)

#### ENTRA-01: `Test-PrivilegedRoleAssignments`

```
Collection Phase:
  1. GET /v1.0/roleManagement/directory/roleDefinitions
     → Cache all role definitions with ID, displayName, isBuiltIn
     → Filter to privileged set using embedded privileged-roles.json
  
  2. GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal
     → For each assignment, resolve roleDefinitionId → role name
     → Resolve principal type from @odata.type (#microsoft.graph.user/group/servicePrincipal)

Analysis Phase:
  For each assignment to a privileged role:
    - If principalType == 'user' AND role criticality == 'Critical':
        Severity = CRITICAL, Finding = "User {UPN} has standing {RoleName} assignment"
    - If principalType == 'servicePrincipal':
        Severity = HIGH, Finding = "Service principal {Name} has standing {RoleName} assignment"
    - If principalType == 'group':
        Cross-reference with group member count → escalation multiplier

Output Fields (merged into standard Finding schema):
  Evidence = @{
      PrincipalId; PrincipalType; PrincipalDisplayName;
      RoleName; RoleCriticality; AssignmentType = 'Direct-Standing';
      RoleDefinitionId; IsBuiltIn
  }
```

#### ENTRA-03: `Test-DangerousAppPermissions`

```
Collection Phase:
  1. GET /v1.0/servicePrincipals?$filter=servicePrincipalType eq 'Application'&$top=999
     → Page through all SPs
  
  2. Batch requests (20 per POST to /$batch):
     For each SP: GET /servicePrincipals/{id}/appRoleAssignments
  
  3. Resolve appRoleId → permission name using embedded appRoleIds.csv
     (584 rows, no API call needed)

Analysis Phase:
  Permission Escalation Map (25 entries):
    Critical: Domain.ReadWrite.All, RoleManagement.ReadWrite.Directory
    High: AppRoleAssignment.ReadWrite.All, Application.ReadWrite.All,
          Group.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All,
          Mail.ReadWrite, Files.ReadWrite.All, Sites.ReadWrite.All,
          User.ReadWrite.All, MailboxSettings.ReadWrite,
          Policy.ReadWrite.ConditionalAccess, ...
    Medium: Directory.ReadWrite.All, ...

  For each SP with any escalation-mapped permission:
    Severity = max(permission severities)
    Finding = "SP {Name} has {count} dangerous permissions: {list}"

Output Fields:
  Evidence = @{
      ServicePrincipalId; DisplayName; AppId;
      DangerousPermissions = @(
          @{ Permission; Severity; AttackPath; Recommendation }
      )
      TotalPermissionCount; HighestSeverity
  }
```

### 4.3 Graph Permissions Required (Read-Only Only)

| Permission | Type | Required For |
|------------|------|-------------|
| `Directory.Read.All` | Application | Users, groups, SPs, apps, org info |
| `RoleManagement.Read.Directory` | Application | Role definitions, role assignments |
| `RoleEligibilitySchedule.Read.Directory` | Application | PIM eligible assignments |
| `RoleAssignmentSchedule.Read.Directory` | Application | PIM active assignments |
| `Application.Read.All` | Application | App registrations, owners |
| `Group.Read.All` | Application | Group memberships, transitive members |
| `PrivilegedAccess.Read.AzureADGroup` | Application | PIM for Groups |
| `DelegatedPermissionGrant.Read.All` | Application | OAuth2 delegated permission grants |
| `Policy.Read.All` | Application | Admin consent policy |

**All permissions are `.Read.` — zero write permissions required.**

---

## 5. ARCHITECTURE & REFACTOR BLUEPRINT

### 5.1 Proposed File/Module Structure

While keeping the single-script approach for initial simplicity, the internal structure will have clear region boundaries designed for eventual extraction:

```
AzureMap.ps1                        (main script — stays monolith for now)
├── #region Configuration            (params, defaults, state)
├── #region Core-Utilities           (logging, errors, retry, cache)
├── #region Command-Runners          (Invoke-AzureCommand, Invoke-GraphCommand, Invoke-GraphBatch)
├── #region Check-Registry           (check metadata table)
├── #region Azure-Checks             (38 existing Test-* functions)
├── #region Entra-Checks             (12 new Test-* functions)
├── #region Entra-Collectors         (Get-EntraRoleData, Get-EntraPIMData, etc.)
├── #region Export-Pipeline          (CSV, JSON, HTML, redaction)
├── #region Orchestration            (Invoke-SecurityAudit, Show-Summary)
├── #region Main-Execution           (entry point)

config.example.json                  (extended with Entra settings)
exclusions.example.json              (extended with Entra exclusion types)
reference-data/
├── privileged-roles.json            (20 Entra roles with GUIDs + criticality)
├── app-role-ids.csv                 (584 Graph permission GUID→name mappings)
├── permission-escalation-map.json   (25 dangerous permissions with attack paths)
```

### 5.2 Check Registry

Replace the current `Invoke-SecurityAudit` conditional chain with a declarative registry:

```powershell
$script:CheckRegistry = @(
    # --- Azure Checks ---
    @{
        CheckId          = "STOR-01"
        Category         = "Azure"
        Service          = "Storage"
        Name             = "Test-StorageSharedKeyAccess"
        Function         = "Test-StorageSharedKeyAccess"
        DefaultSeverity  = "HIGH"
        RequiredModules  = @("Az.Storage")
        RequiredPerms    = @()                          # Az RBAC — Reader is sufficient
        Phase            = "PerSubscription"             # Collection scope
        Description      = "Storage accounts with shared key access enabled"
    },
    # Additional Azure check registry entries follow the same structure.
    # The live script registers the full set of checks from the module files.

    # --- Entra Checks ---
    @{
        CheckId          = "ENTRA-01"
        Category         = "Entra"
        Service          = "EntraRoles"
        Name             = "Test-PrivilegedRoleAssignments"
        Function         = "Test-PrivilegedRoleAssignments"
        DefaultSeverity  = "CRITICAL"
        RequiredModules  = @()                          # No Az module needed — Graph REST
        RequiredPerms    = @("RoleManagement.Read.Directory")
        Phase            = "TenantWide"                 # Runs once, not per-sub
        Description      = "Standing privileged role assignments"
    },
    @{
        CheckId          = "ENTRA-02"
        Category         = "Entra"
        Service          = "EntraPIM"
        Name             = "Test-PIMEligibleVsActive"
        Function         = "Test-PIMEligibleVsActive"
        DefaultSeverity  = "HIGH"
        RequiredModules  = @()
        RequiredPerms    = @("RoleEligibilitySchedule.Read.Directory", "RoleAssignmentSchedule.Read.Directory")
        Phase            = "TenantWide"
        Description      = "PIM eligible vs standing active assignments"
    },
    @{
        CheckId          = "ENTRA-03"
        Category         = "Entra"
        Service          = "EntraApps"
        Name             = "Test-DangerousAppPermissions"
        Function         = "Test-DangerousAppPermissions"
        DefaultSeverity  = "CRITICAL"
        RequiredModules  = @()
        RequiredPerms    = @("Application.Read.All")
        Phase            = "TenantWide"
        Description      = "SPs with high-impact Graph application permissions"
    },
    @{
        CheckId          = "ENTRA-04"
        Category         = "Entra"
        Service          = "EntraApps"
        Name             = "Test-AppOwnershipChains"
        Function         = "Test-AppOwnershipChains"
        DefaultSeverity  = "HIGH"
        RequiredModules  = @()
        RequiredPerms    = @("Application.Read.All")
        Phase            = "TenantWide"
        Description      = "Ownership chains enabling credential injection"
    }
    # Additional Entra checks continue in the same structure.
    # The live script defines ENTRA-05 through ENTRA-12 in the corresponding module files.
)
```

### 5.3 Centralized Command Runners

#### Existing: `Invoke-AzureCommand` (keep, refactor)

Already handles retry, circuit breaker, auth recovery. No changes needed to the core logic.

#### New: `Invoke-GraphCommand`

```powershell
function Invoke-GraphCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,                          # Relative: "roleManagement/directory/roleAssignments"
        [string]$ApiVersion = "v1.0",          # v1.0 default, beta for PIM
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [switch]$AllPages,                     # Auto-follow @odata.nextLink
        [string]$CommandName,
        [switch]$Critical
    )

    # Acquire Graph token via Az.Accounts (same session, no new login)
    if (-not $script:GraphToken -or $script:GraphTokenExpiry -lt (Get-Date).AddMinutes(-5)) {
        $tokenResult = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
        $script:GraphToken = $tokenResult.Token
        $script:GraphTokenExpiry = $tokenResult.ExpiresOn
    }

    $fullUri = "https://graph.microsoft.com/$ApiVersion/$Uri"
    $allHeaders = @{
        'Authorization'    = "Bearer $($script:GraphToken)"
        'Content-Type'     = 'application/json'
        'ConsistencyLevel' = 'eventual'
        'User-Agent'       = "AzureMap/$($script:Metadata.Version)"
    }
    foreach ($k in $Headers.Keys) { $allHeaders[$k] = $Headers[$k] }

    # Delegate to Invoke-AzureCommand for retry/circuit-breaker
    $result = Invoke-AzureCommand -Command {
        $response = Invoke-RestMethod -Uri $fullUri -Headers $allHeaders -Method $Method -ErrorAction Stop
        $response
    } -CommandName $CommandName -Critical:$Critical

    # Pagination
    if ($AllPages -and $result.'@odata.nextLink') {
        $allItems = [System.Collections.Generic.List[object]]::new()
        if ($result.value) { $allItems.AddRange($result.value) }
        $nextLink = $result.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-AzureCommand -Command {
                Invoke-RestMethod -Uri $nextLink -Headers $allHeaders -Method GET -ErrorAction Stop
            } -CommandName "$CommandName-Page"
            if ($page.value) { $allItems.AddRange($page.value) }
            $nextLink = $page.'@odata.nextLink'
        }
        return $allItems
    }

    return $result.value ?? $result
}
```

#### New: `Invoke-GraphBatch`

```powershell
function Invoke-GraphBatch {
    param(
        [Parameter(Mandatory)]
        [array]$Requests,                       # Array of @{ id; method; url }
        [string]$ApiVersion = "v1.0",
        [int]$MaxBatchSize = 20,
        [int]$DelayBetweenBatchesMs = 0
    )

    $results = @{}
    for ($i = 0; $i -lt $Requests.Count; $i += $MaxBatchSize) {
        $chunk = $Requests[$i..([Math]::Min($i + $MaxBatchSize - 1, $Requests.Count - 1))]
        $payload = @{ requests = $chunk } | ConvertTo-Json -Depth 10

        $response = Invoke-GraphCommand -Uri '$batch' -Method POST -Body $payload `
                        -ApiVersion $ApiVersion -CommandName "GraphBatch"

        foreach ($item in $response.responses) {
            $results[$item.id] = @{
                Success = ($item.status -eq 200)
                Data    = $item.body
                Status  = $item.status
            }
        }

        if ($DelayBetweenBatchesMs -gt 0 -and ($i + $MaxBatchSize) -lt $Requests.Count) {
            Start-Sleep -Milliseconds $DelayBetweenBatchesMs
        }
    }
    return $results
}
```

### 5.4 Orchestration Flow (Updated)

```
Main Execution
│
├─ 1. Validate modules + config + exclusions (existing)
├─ 2. Authenticate Az context (existing)
├─ 3. Acquire Graph token IF any Entra checks are requested
│     └─ Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
│     └─ Validate token scopes against RequiredPerms from CheckRegistry
│
├─ 4. Collection Phase
│     ├─ TenantWide Azure data (apps, SPs — existing Get-TenantWideData)
│     ├─ TenantWide Entra data (NEW — parallel):
│     │   ├─ Get-EntraRoleDefinitions  → $script:EntraData.RoleDefinitions
│     │   ├─ Get-EntraRoleAssignments  → $script:EntraData.RoleAssignments
│     │   ├─ Get-EntraPIMAssignments   → $script:EntraData.PIMAssignments
│     │   ├─ Get-EntraSPPermissions    → $script:EntraData.SPPermissions
│     │   └─ Get-EntraAppOwners        → $script:EntraData.AppOwners
│     └─ Per-subscription Azure data (existing — make parallel)
│
├─ 5. Analysis Phase (sequential per check, checks are idempotent)
│     ├─ Azure checks (existing 38)
│     └─ Entra checks (new 12)
│
├─ 6. Export Phase
│     ├─ CSV / JSON / HTML (existing, extended with Entra service)
│     └─ Optional redaction
│
└─ 7. Summary + cleanup
```

### 5.5 State Object Design

Replace scattered `$script:*` variables with a single state object:

```powershell
$script:State = @{
    Config          = @{ ... }           # Sample merged configuration object
    Metadata        = @{ ... }           # Sample tool metadata object
    Cache           = @{
        Subscriptions   = $null
        RBACAssignments = @{}
        GraphResponses  = @{}            # NEW: Graph API response cache
    }
    EntraData       = @{                 # NEW
        RoleDefinitions = $null
        RoleAssignments = $null
        PIMAssignments  = $null
        SPPermissions   = $null
        AppOwners       = $null
        GroupMemberships= @{}
    }
    TenantWideData  = @{
        Applications    = $null
        ServicePrincipals = $null
    }
    Results         = [System.Collections.Generic.List[object]]::new()
    FailedSubscriptions = [System.Collections.Generic.List[object]]::new()
    ExecutedChecks  = [System.Collections.Generic.List[object]]::new()
    CircuitBreaker  = @{ FailureCount = 0; State = "Closed"; RetryWindow = 0 }  # Example circuit-breaker state structure
    LogBuffer       = [System.Collections.Generic.List[string]]::new()
    GraphToken      = $null
    GraphTokenExpiry= $null
}
```

### 5.6 Updated Parameters

```powershell
param(
    # Existing
    [ValidateSet("CriticalOnly", "HighAndAbove", "All")]
    [string]$SeverityLevel = "All",

    [ValidateSet("Storage", "SQL", "AKS", "KeyVault", "Network", "Compute",
                 "Identity", "ContainerRegistry", "CosmosDB", "EventHub",
                 "ServiceBus", "APIM", "Synapse", "Automation", "Monitoring",
                 "Diagnostics", "PublicIP", "Exfiltration", "AppService", "LogicApp",
                 # NEW Entra services:
                 "EntraRoles", "EntraPIM", "EntraApps", "EntraGroups",
                 "All")]
    [string[]]$Services = @("All"),

    [string]$ConfigPath,
    [string]$ExclusionPath,
    [switch]$Quiet,
    [switch]$SkipModuleCheck,

    # NEW
    [switch]$SkipEntra,            # Skip all Entra checks (if no Graph perms)
    [switch]$EntraOnly,            # Only run Entra checks
    [switch]$Redact,               # Apply PII redaction to exports
    [switch]$Parallel              # Enable parallel subscription processing
)
```

---

## 6. PERFORMANCE & SCALABILITY PLAN

### 6.1 Resource Graph First

**Current problem:** AzureMap makes per-subscription `Get-Az*` calls for every service. For 50 subscriptions × 38 checks, that's ~1,900 API call batches.

**Solution:** For services where Resource Graph supports the resource type, replace per-sub iteration with a single cross-subscription KQL query:

| Service | Current API | Proposed Resource Graph KQL |
|---------|------------|---------------------------|
| Storage | `Get-AzStorageAccount` per sub | `resources \| where type == 'microsoft.storage/storageaccounts' \| project id, name, subscriptionId, properties.allowSharedKeyAccess, properties.publicNetworkAccess, ...` |
| SQL | `Get-AzSqlServer` per sub | `resources \| where type == 'microsoft.sql/servers' \| project id, name, properties.publicNetworkAccess, ...` |
| NSG | `Get-AzNetworkSecurityGroup` per sub | `resources \| where type == 'microsoft.network/networksecuritygroups' \| project id, name, properties.securityRules` |
| KeyVault | `Get-AzKeyVault` per sub | `resources \| where type == 'microsoft.keyvault/vaults' \| project id, name, properties.enableRbacAuthorization, properties.enablePurgeProtection, ...` |
| PublicIP | `Get-AzPublicIpAddress` per sub | `resources \| where type == 'microsoft.network/publicipaddresses'` |
| VNet | `Get-AzVirtualNetwork` per sub | `resources \| where type == 'microsoft.network/virtualnetworks'` |

**Implementation:** New `Invoke-ResourceGraphQuery` helper:

```powershell
function Invoke-ResourceGraphQuery {
    param(
        [string]$Query,
        [string[]]$SubscriptionIds,
        [int]$BatchSize = 1000
    )
    # Uses Search-AzGraph if Az.ResourceGraph available
    # Falls back to REST: POST management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01
    $allResults = @()
    $skipToken = $null
    do {
        $body = @{
            query = $Query
            subscriptions = $SubscriptionIds
            options = @{ '$top' = $BatchSize; '$skipToken' = $skipToken }
        }
        $response = Invoke-AzureCommand -Command {
            Invoke-AzRestMethod -Method POST -Path "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" `
                -Payload ($body | ConvertTo-Json -Depth 5)
        } -CommandName "ResourceGraph"
        $parsed = $response.Content | ConvertFrom-Json
        $allResults += $parsed.data
        $skipToken = $parsed.'$skipToken'
    } while ($skipToken)
    return $allResults
}
```

### 6.2 Caching Strategy

| Cache Layer | Scope | TTL | Key Pattern | What's Cached |
|-------------|-------|-----|-------------|--------------|
| Subscription list | Session | Forever | `"subscriptions"` | `Get-AzSubscription` result |
| RBAC assignments | Per-sub | Session | `"rbac-{subId}"` | `Get-AzRoleAssignment` per sub |
| Graph role definitions | Session | Forever | `"entra-role-defs"` | `roleManagement/directory/roleDefinitions` |
| Graph role assignments | Session | Forever | `"entra-role-assignments"` | All role assignments |
| SP permissions | Per-SP batch | Session | `"sp-perms-batch-{n}"` | Batch appRoleAssignment results |
| Resource Graph | Per-query | Session | `"rg-{queryHash}"` | KQL query results |
| Reference data | Static | Forever | N/A | `privileged-roles.json`, `app-role-ids.csv` |

### 6.3 Batching

| Operation | Current | Proposed |
|-----------|---------|----------|
| Per-sub Azure checks | Sequential | `ForEach-Object -Parallel -ThrottleLimit 5` with `[ConcurrentBag]` |
| Entra SP permission collection | N/A | Graph batch: 20 SPs per `/$batch` POST (two requests per SP = 10 SPs per batch) |
| App owner collection | N/A | Graph batch: 20 apps per POST |
| Group membership resolution | N/A | Graph batch: 20 groups per POST |

### 6.4 Adaptive Throttling (from ScEntra)

```powershell
function Get-EnvironmentProfile {
    $counts = @{
        Users = (Invoke-GraphCommand -Uri 'users/$count' -ApiVersion 'v1.0').value
        Groups = (Invoke-GraphCommand -Uri 'groups/$count' -ApiVersion 'v1.0').value
        SPs = (Invoke-GraphCommand -Uri 'servicePrincipals/$count' -ApiVersion 'v1.0').value
    }
    $score = $counts.Users + ($counts.Groups * 2) + ($counts.SPs * 0.5)

    if ($score -lt 25000)  { return @{ Profile = "Small";   BatchDelay = 0;    MaxParallel = 5 } }
    if ($score -lt 75000)  { return @{ Profile = "Medium";  BatchDelay = 100;  MaxParallel = 3 } }
    if ($score -lt 200000) { return @{ Profile = "Large";   BatchDelay = 250;  MaxParallel = 2 } }
    return                           @{ Profile = "Enterprise"; BatchDelay = 500; MaxParallel = 1 }
}
```

---

## 7. TESTING PLAN + PR ACCEPTANCE CHECKLIST

### 7.1 Pester Test Strategy

#### Unit Tests (Pure Logic — No API Mocking)

| Test File | Tests What | Example |
|-----------|-----------|---------|
| `Tests/Unit/Merge-Hashtable.Tests.ps1` | Config merge: deep merge, array replace, scalar override | `@{a=@{b=1}} merged with @{a=@{c=2}}` → `@{a=@{b=1;c=2}}` |
| `Tests/Unit/Test-Exclusion.Tests.ps1` | All 4 exclusion dimensions: sub, resource, tag, finding | Tag wildcard, name pattern glob, empty exclusions |
| `Tests/Unit/Get-ErrorClass.Tests.ps1` | Error classification: 401→Auth, 429→Throttle, 500→Service, 400→Client | Edge cases: null error, nested exception |
| `Tests/Unit/Write-Finding.Tests.ps1` | Severity filter, evidence truncation (>1000), priority sorting, schema compliance | CriticalOnly mode, evidence cap, _Truncated annotation |
| `Tests/Unit/CheckRegistry.Tests.ps1` | All registry entries have valid CheckId, Category, Phase, unique IDs | No duplicate CheckIds, valid function references |
| `Tests/Unit/SeverityMapping.Tests.ps1` | RBAC severity matrix, permission escalation map | Owner+Root=CRITICAL, Reader+Sub=INFO |
| `Tests/Unit/PermissionEscalationMap.Tests.ps1` | All 25 entries have valid Permission, Severity, AttackPath, Recommendation | No empty fields, severity in valid set |
| `Tests/Unit/FindingSchema.Tests.ps1` | Finding objects have all required fields, correct types | Guid is valid, Timestamp is DateTime, Severity in set |

#### Mocked Integration Tests (API Wrappers)

| Test File | Tests What | Mock |
|-----------|-----------|------|
| `Tests/Integration/Invoke-AzureCommand.Tests.ps1` | Retry logic (3 attempts), circuit breaker (opens after 5), throttle backoff | Mock script blocks that throw specific HTTP errors |
| `Tests/Integration/Invoke-GraphCommand.Tests.ps1` | Token acquisition, pagination (`@odata.nextLink`), 429 handling | Mock `Invoke-RestMethod` with paged responses |
| `Tests/Integration/Invoke-GraphBatch.Tests.ps1` | Batch splitting (>20 requests), partial failures, 404 handling | Mock batch response with mixed success/failure |
| `Tests/Integration/Invoke-ResourceGraphQuery.Tests.ps1` | Pagination via `$skipToken`, large result sets | Mock `Invoke-AzRestMethod` with skipToken |
| `Tests/Integration/Export-Results.Tests.ps1` | CSV structure, JSON depth, HTML XSS safety | Feed synthetic findings, validate output files |

#### Check-Level Tests (Per Security Check)

```powershell
# Template for each check function test:
Describe "Test-StorageSharedKeyAccess" {
    BeforeAll {
        # Dot-source the function (or import from module)
        . $PSScriptRoot/../../AzureMap.ps1  # In module form: Import-Module

        # Mock the Azure command wrapper
        Mock Invoke-AzureCommand {
            return @(
                [PSCustomObject]@{
                    StorageAccountName = "testsa1"
                    AllowSharedKeyAccess = $true
                    Id = "/subscriptions/xxx/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/testsa1"
                },
                [PSCustomObject]@{
                    StorageAccountName = "testsa2"
                    AllowSharedKeyAccess = $false
                    Id = "/subscriptions/xxx/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/testsa2"
                }
            )
        }
    }

    It "Should detect storage accounts with shared key access" {
        # Execute
        Test-StorageSharedKeyAccess -Subscriptions @(@{Id="xxx";Name="test"}) -Exclusions @{}

        # Validate
        $findings = $script:Results | Where-Object { $_.Finding -match "Shared Key" }
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be "HIGH"
        $findings[0].Evidence[0].StorageAccountName | Should -Be "testsa1"
    }
}
```

### 7.2 PR Acceptance Checklist

```markdown
## PR Review Gates

### Schema Validation
- [ ] All findings use `Write-Finding` (no direct `$script:Results.Add()`)
- [ ] Every check function documents its CheckId in the registry
- [ ] Finding schema validated: FindingId (guid), Severity (enum), Evidence (array)
- [ ] New Entra findings follow same schema as Azure findings

### Deterministic Output
- [ ] JSON export produces stable key ordering (use `[ordered]@{}`)
- [ ] Findings sorted by Severity → Service → Finding for diffable output
- [ ] No `Get-Date` in evidence objects (timestamps only in Finding.Timestamp)
- [ ] Evidence items have consistent property names across similar checks

### Performance Guardrails
- [ ] No unbounded loops without progress reporting
- [ ] All Graph API calls go through `Invoke-GraphCommand` or `Invoke-GraphBatch`
- [ ] Batch requests ≤ 20 per POST
- [ ] Pagination handled for all `$top` queries
- [ ] Cache used for repeated lookups (role definitions, RBAC, etc.)
- [ ] Resource Graph used where supported (not per-sub `Get-Az*`)

### Security (Read-Only Guarantee)
- [ ] No `POST`/`PUT`/`PATCH`/`DELETE` to resource endpoints (only to `/$batch` and Resource Graph)
- [ ] No `Set-*`, `New-*`, `Remove-*`, `Add-*` Azure cmdlets
- [ ] No `Invoke-AzRestMethod -Method PUT/PATCH/DELETE`
- [ ] Graph permissions are all `.Read.` scopes — zero `.ReadWrite.`
- [ ] No secret/key reading (`Get-AzKeyVaultSecret`, etc.)
- [ ] User-Agent identifies the tool: `AzureMap/{version}`

### Test Coverage
- [ ] New check has a corresponding Pester test with mock data
- [ ] Unit tests pass: `Invoke-Pester ./Tests/Unit -CI`
- [ ] Integration tests pass: `Invoke-Pester ./Tests/Integration -CI`
- [ ] No new linter warnings (PSScriptAnalyzer)

### Documentation
- [ ] Check added to README check inventory table
- [ ] `config.example.json` updated if new config keys added
- [ ] `exclusions.example.json` updated if new exclusion dimensions added
```

---

## 8. PHASED ROADMAP

### Phase 1: Foundation + P0 Entra Checks (Complexity: L, ~2-3 weeks)

| Task | Size | Description |
|------|------|-------------|
| 1.1 | M | **Check Registry refactor**: Replace `Invoke-SecurityAudit` conditional chain with declarative `$script:CheckRegistry` array. Wire up dynamic check discovery by `Category`/`Service`/`Phase`. |
| 1.2 | M | **Command runner for Graph**: Implement `Invoke-GraphCommand` with token acquisition via `Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"`, retry, pagination. Reuse existing `Invoke-AzureCommand` retry/CB logic internally. |
| 1.3 | S | **`Invoke-GraphBatch`**: Batch helper splitting requests into chunks of 20, parsing mixed responses. |
| 1.4 | S | **Reference data embedding**: Add `privileged-roles.json` (20 roles), `app-role-ids.csv` (584 permissions), `permission-escalation-map.json` (25 entries) as embedded data or sidecar files. |
| 1.5 | M | **ENTRA-01: `Test-PrivilegedRoleAssignments`**: Collect role definitions + assignments via Graph. Cross-reference with privileged-roles.json. Emit findings via standard `Write-Finding`. |
| 1.6 | M | **ENTRA-02: `Test-PIMEligibleVsActive`**: Dual endpoint for eligible/active schedules. Flag standing assignments where PIM is available. Uses `beta` API for PIM endpoints. |
| 1.7 | L | **ENTRA-03: `Test-DangerousAppPermissions`**: Enumerate all SPs, batch-fetch `appRoleAssignments`, resolve via `app-role-ids.csv`, match against escalation map. |
| 1.8 | M | **ENTRA-04: `Test-AppOwnershipChains`**: Batch-fetch owners for apps with privileged SP permissions. Flag non-admin owners of privileged apps. |
| 1.9 | S | **Parameter additions**: Add `$SkipEntra`, `$EntraOnly`, new service names in `$Services` ValidateSet. |
| 1.10 | M | **Pester test foundation**: Create `Tests/Unit/` and `Tests/Integration/` folders. Write tests for `Invoke-GraphCommand`, `Invoke-GraphBatch`, all 4 P0 Entra checks with mocked Graph responses. |

### Phase 2: P1 Entra + Performance (Complexity: L, ~2-3 weeks)

| Task | Size | Description |
|------|------|-------------|
| 2.1 | M | **ENTRA-05: `Test-RoleAssignableGroups`**: Groups with `isAssignableToRole=true` holding privileged roles. Batch-fetch members. |
| 2.2 | M | **ENTRA-06: `Test-NestedGroupEscalation`**: Compare `transitiveMembers/$count` vs `members/$count` for groups with roles. |
| 2.3 | L | **ENTRA-07: `Test-CrossTierBridges`**: Cross-reference all role assignments to find accounts spanning low and high privilege. |
| 2.4 | S | **ENTRA-08: `Test-StalePrivilegedAccounts`**: Privileged users with old sign-in sessions or disabled accounts. |
| 2.5 | L | **Resource Graph integration**: Implement `Invoke-ResourceGraphQuery`. Migrate Storage, SQL, NSG, KeyVault, PublicIP, VNet checks to Resource Graph for collection phase. Keep per-resource detail calls where needed (e.g., `Get-AzKeyVaultSecret` for expiry check). |
| 2.6 | M | **Parallel subscription processing**: Wrap per-sub check execution in `ForEach-Object -Parallel -ThrottleLimit 5` with `[ConcurrentBag]` for findings. |
| 2.7 | M | **Adaptive throttling**: Implement `Get-EnvironmentProfile` for Graph calls. Adjust `BatchDelay` and `MaxParallel` based on tenant size score. |
| 2.8 | S | **Cache upgrade**: Replace simple `$script:Cache` hashtable with LRU-evicting, TTL-based cache inspired by Blackcat's `Set-BlackCatCache`/`Get-BlackCatCache`. |
| 2.9 | M | **Expanded test suite**: Tests for all P1 checks, Resource Graph mock tests, parallel execution correctness tests. |

### Phase 3: P2 Entra + Polish (Complexity: M, ~1-2 weeks)

| Task | Size | Description |
|------|------|-------------|
| 3.1 | S | **ENTRA-09: `Test-DelegatedPermissionGrants`**: Broad `AllPrincipals` grants for sensitive scopes. |
| 3.2 | S | **ENTRA-10: `Test-MultiTenantApps`**: `signInAudience` check for multi-org exposure. |
| 3.3 | S | **ENTRA-11: `Test-AppCredentialHygiene`**: Long-lived or multi-credential apps/SPs. |
| 3.4 | S | **ENTRA-12: `Test-AdminConsentWorkflow`**: Policy check for admin consent configuration. |
| 3.5 | M | **Redaction support**: Implement `-Redact` switch using deterministic SHA-256 truncated hashing (from ScEntra's `Get-ScEntraRedactedName`). Apply across all export formats. |
| 3.6 | M | **Enhanced HTML report**: Add Entra section to HTML report with separate severity summary for Azure vs Entra categories. |
| 3.7 | S | **JSON schema stability**: Enforce `[ordered]@{}` in all output hashtables for deterministic JSON key ordering. |
| 3.8 | S | **PSScriptAnalyzer compliance**: Run analyzer, fix all warnings. Add as CI gate. |
| 3.9 | M | **Documentation**: Update README with new check inventory, Entra section, required Graph permissions, example output. |
| 3.10 | S | **Final integration tests**: End-to-end test with synthetic tenant data, validate all 50 checks produce valid findings. |

### Complexity Legend

| Size | Estimated Effort | Characteristics |
|------|-----------------|----------------|
| **S** | 2–4 hours | Single function, straightforward logic |
| **M** | 0.5–1.5 days | Multiple functions, API integration, test writing |
| **L** | 2–4 days | Complex logic, multiple API endpoints, batch processing, extensive testing |

---

## APPENDIX A: Reference Data Schemas

### privileged-roles.json

```json
{
    "privilegedRoles": [
        {
            "roleName": "Global Administrator",
            "roleId": "62e90394-69f5-4237-9190-012177145e10",
            "description": "Can manage all aspects of Entra ID and Microsoft services",
            "criticality": "Critical"
        }
    ]
}
```

20 roles total. Source: Blackcat `support-files/privileged-roles.json` (verified).

### permission-escalation-map.json

```json
{
    "permissions": [
        {
            "permission": "Domain.ReadWrite.All",
            "severity": "Critical",
            "attackPath": "Can add/verify federated domains enabling token forging",
            "recommendation": "Restrict to trusted workloads, prefer cloud-only privileged accounts",
            "compromisedRoles": ["Global Administrator"]
        },
        {
            "permission": "RoleManagement.ReadWrite.Directory",
            "severity": "Critical",
            "attackPath": "Can assign any directory role including Global Administrator",
            "recommendation": "Limit to break-glass workloads, monitor assignment events",
            "compromisedRoles": ["Global Administrator", "Privileged Role Administrator"]
        }
    ]
}
```

25 entries total. Merged from ScEntra's 7-entry map + Blackcat's `permissionEscalationTargets` 25-entry map.

### app-role-ids.csv

```csv
Permission,Type,appRoleId
Application.ReadWrite.All,Application,1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9
Directory.Read.All,Application,7ab1d382-f21e-4acd-a863-ba3e13f7da61
...
```

584 rows. Source: Blackcat `support-files/appRoleIds.csv` (verified).

---

## APPENDIX B: Graph API Endpoint Inventory (Read-Only)

| Endpoint | API Version | Used By | HTTP Method |
|----------|-------------|---------|-------------|
| `/roleManagement/directory/roleDefinitions` | v1.0 | ENTRA-01 | GET |
| `/roleManagement/directory/roleAssignments?$expand=principal` | v1.0 | ENTRA-01 | GET |
| `/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition` | beta | ENTRA-02 | GET |
| `/roleManagement/directory/roleAssignmentSchedules?$expand=principal,roleDefinition` | beta | ENTRA-02 | GET |
| `/servicePrincipals?$filter=servicePrincipalType eq 'Application'&$top=999` | v1.0 | ENTRA-03 | GET |
| `/servicePrincipals/{id}/appRoleAssignments` | v1.0 | ENTRA-03 (batch) | GET |
| `/applications/{id}/owners` | v1.0 | ENTRA-04 (batch) | GET |
| `/servicePrincipals/{id}/owners` | v1.0 | ENTRA-04 (batch) | GET |
| `/groups?$filter=isAssignableToRole eq true&$top=999` | v1.0 | ENTRA-05 | GET |
| `/groups/{id}/members` | v1.0 | ENTRA-05, 06 (batch) | GET |
| `/groups/{id}/transitiveMembers/$count` | v1.0 | ENTRA-06 | GET |
| `/users?$select=id,displayName,userPrincipalName,accountEnabled,signInSessionsValidFromDateTime&$top=999` | v1.0 | ENTRA-08 | GET |
| `/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'` | v1.0 | ENTRA-09 | GET |
| `/applications?$select=id,displayName,signInAudience&$top=999` | v1.0 | ENTRA-10 | GET |
| `/applications?$select=id,displayName,passwordCredentials,keyCredentials&$top=999` | v1.0 | ENTRA-11 | GET |
| `/policies/adminConsentRequestPolicy` | v1.0 | ENTRA-12 | GET |
| `/$batch` | v1.0/beta | All batch operations | POST (read-only GET requests inside) |

**Every single endpoint is read-only. The only POST is to `/$batch` which wraps GET requests.**
