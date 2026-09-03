# AzureMap — Static Read-Only Safety Audit

Static inspection of all runtime `.ps1` files (`Core/`, `Checks/Azure/`,
`Checks/Entra/`, `Export/`, `azuremap.ps1`). Legacy files
(`AzureMap - Copy - Copy.ps1`, `azure_resources.ps1`) are **not** loaded by the
modular tool and are excluded except where noted. No live Azure/Graph calls were
made to produce this audit.

## Verdict

Default mode is **read-only**: no writes, updates, deletes, or permission
changes; no `listKeys`/`*/action`; no secret **value** reads; and (after the
no-auto-login hardening) **no automatic `Connect-AzAccount`**. Two data-plane
**list** operations exist (metadata only, no values/keys) — see Concerns.

The previously-identified functional blocker (`Set-SubscriptionContext` undefined)
has been **resolved** — a minimal read-only, local-session helper is now defined in
`Core/CheckRegistry.ps1` (see Concern #1).

## Command inventory & classification

### Control-plane ARM reads — SAFE read-only
All Azure data collection uses `Get-Az*` metadata cmdlets wrapped in
`Invoke-AzureCommand`. Representative set (counts approximate):

`Get-AzContext`, `Get-AzSubscription`, `Get-AzResource`, `Get-AzResourceGroup`,
`Get-AzResourceLock`, `Get-AzRoleDefinition`,
`Get-AzStorageAccount`, `Get-AzStorageAccountNetworkRuleSet`, `Get-AzKeyVault`,
`Get-AzSqlServer*`, `Get-AzVM`, `Get-AzVMExtension`, `Get-AzNetworkSecurityGroup`,
`Get-AzVirtualNetwork(Peering)`, `Get-AzPublicIpAddress`, `Get-AzPrivateEndpoint`,
`Get-AzPrivateDnsZoneGroup`, `Get-AzRouteTable`, `Get-AzFirewall`,
`Get-AzApplicationGateway`, `Get-AzDiagnosticSetting`, `Get-AzAksCluster`,
`Get-AzContainerRegistry`, `Get-AzWebApp(AuthSetting)`, `Get-AzFunctionApp`,
`Get-AzLogicApp`, `Get-AzEventHub*`, `Get-AzServiceBus*`, `Get-AzApiManagement*`,
`Get-AzSynapseWorkspace`, `Get-AzAutomation*`, `Get-AzADApplication`,
`Get-AzADServicePrincipal`. → **SAFE read-only.**

### Token acquisition — SAFE
`Get-AzAccessToken -ResourceUrl https://graph.microsoft.com` (via `Get-GraphToken`).
Token is normalized (SecureString → plaintext) **in memory only**, never logged,
printed, or exported. → **SAFE.**

### REST reads — SAFE read-only
- `Invoke-AzRestMethod -Method POST -Path /providers/Microsoft.ResourceGraph/resources`
  (`Core/ResourceGraph.ps1`) — Azure Resource Graph **query** API. POST is the
  query verb; it returns resource metadata and mutates nothing. → **SAFE.**
- `Invoke-AzRestMethod -Method GET …/Microsoft.DocumentDb/databaseAccounts/…`
  (`Checks/Azure/DataPlatform.ps1`) — control-plane metadata GET. → **SAFE.**
- `Invoke-AzRestMethod -Method GET …/Microsoft.Authorization/roleAssignments|roleDefinitions`
  (`Core/Rbac.ps1`) — subscription-scope RBAC reads straight from ARM (no Graph
  principal enrichment; works under ARM-only auth). → **SAFE.**

### Microsoft Graph — SAFE read-only
`Invoke-GraphCommand` forces `GET` (non-GET is blocked unless explicitly opted in,
which no caller does); `Invoke-GraphBatch` forces every inner request to `GET`.
The only POST is the read-only `/$batch` envelope itself. Endpoints used (all GET):
`roleManagement/directory/roleDefinitions|roleAssignments|roleEligibilitySchedules|roleAssignmentSchedules`,
`servicePrincipals`, `applications`, `groups`, `oauth2PermissionGrants`,
`policies/crossTenantAccessPolicy`, `directoryObjects/{id}`,
`servicePrincipals/{id}/appRoleAssignments|owners`, `applications/{id}/owners`,
`groups/{id}/members`. → **SAFE read-only.**

### Mutating `Set-Az*` verbs — NOT USED (text only)
The only `Set-Az*` occurrences (`Set-AzStorageAccount`,
`Set-AzStorageAccountNetworkRuleSet` in `Checks/Azure/Storage.ps1`) appear **inside
remediation guidance strings** shown to the user. They are string literals, never
executed. → **NOT USED (documentation only).**

### `Connect-AzAccount` — SAFE (never auto-invoked)
After the no-auto-login hardening, no runtime code calls `Connect-AzAccount`.
Remaining occurrences are guidance strings, comments, tests, and the legacy
monolith. → **SAFE.**

### `listKeys` / `*/action` / key retrieval — NONE
No `listKeys`, `*/action`, `Get-AzStorageAccountKey`, `New-AzStorageContext
-StorageAccountKey`, or `regenerateKey` usage. → **NONE.**

### Local output side effects — LOCAL-only, acceptable
`Export-Csv`, `ConvertTo-Json | Out-File`, HTML `Out-File`
(`Export/Csv.ps1`, `Export/Json.ps1`, `Export/Html.ps1`) and the log
`StreamWriter`/`Add-Content` (`Core/Logging.ps1`). These write **local files only**.
The files can contain sensitive identifiers and are covered by `.gitignore` with a
warning in `SAFE-RUN.md`. → **LOCAL-only side effect, acceptable (see Concern #3).**

### Raw object printing — NONE
No `Format-Table`, `Format-List`, `Out-Host`, or `Write-Output` of raw objects in
runtime code. `Write-Finding`'s raw evidence dump was removed; per-finding console
lines print only formatted text and only under `-VerboseOutput`; `Show-AuditConsole`
prints aggregate counts and finding **titles** only. → **SAFE.**

## Remaining concerns

### 1. RESOLVED: `Set-SubscriptionContext` helper restored
`Set-SubscriptionContext -SubscriptionId … -SubscriptionName …` is called **37
times** across the Azure checks (at the top of each per-subscription loop) and was
previously **undefined** in the modular runtime (it existed only in the legacy
monolith), which would have made every PerSubscription Azure check error.

Now defined in `Core/CheckRegistry.ps1` (loaded before checks run). It performs a
read-only, **local-session** context switch via `Set-AzContext -SubscriptionId`
(optionally `-TenantId`), returns `$true`/`$false` (never throws for a single
failed subscription), logs a clean by-name warning on failure, and never emits the
subscription/tenant id or calls `Connect-AzAccount`. → **SAFE read-only.**

### 2. Two data-plane LIST reads (metadata only — no values/keys)
- `Get-AzKeyVaultSecret -VaultName <vault>` (`KeyVault.ps1`, KEYVAULT-003): **lists
  secret metadata** (`Name`, `Enabled`, `Expires`, `Created`) to evaluate expiry.
  It does **not** read secret values (no `-Name`, no `.SecretValue`). Requires
  Key Vault data-plane *secret list* permission; secret **names** are written to
  exports.
- `Get-AzStorageContainer -Context $sa.Context` (`Storage.ps1`, STORAGE-004): **lists
  blob containers** (`Name`, `PublicAccess`) to detect anonymous access. Uses the
  storage account's AAD/OAuth context (`$sa.Context`) — **no account keys /
  `listKeys`**. Container **names** are written to exports.

These are read-only and expose no secret values or keys, but they are data-plane
operations and write resource names into reports. If strict *control-plane-only*
is required, gate them behind an explicit opt-in switch (e.g. `-IncludeDataPlane`)
in a future phase. Left unchanged here to avoid altering existing checks.

### 3. Exports and logs contain sensitive identifiers
CSV/JSON/HTML exports and the run log can contain tenant IDs, subscription IDs,
object IDs, principal names, resource IDs, and (from Concern #2) secret/container
names. Mitigations already in place: `.gitignore` excludes them and `SAFE-RUN.md`
carries a sensitive-output warning. Treat these files as sensitive.

## Confirmation

With the exception of the two data-plane **list** reads in Concern #2 (metadata
only), AzureMap's default mode performs **only** control-plane read operations and
local file output. It performs no writes/updates/deletes/permission changes, no
`listKeys`/`*/action`, no secret **value** reads, and never automatically calls
`Connect-AzAccount`. The `Set-SubscriptionContext` gap (Concern #1) is a
functionality blocker to resolve before live Azure checks will execute.
