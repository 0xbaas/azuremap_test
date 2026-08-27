# AzureMap v2 — PR Gate Checklist

All gates must pass before merge. Tick each box when verified.

---

## Gate 0: Repository Structure
- [x] Folder layout matches spec (`Products/AzureMap/`, `Products/EntraMap/`, `Shared/Core/`, `Shared/Export/`, `Tests/`, `ReferenceData/`)
- [x] `azuremap.ps1` and `entramap.ps1` entrypoints exist and dot-source their product modules
- [x] `Shared/Core/State.ps1` initializes `$script:State` with all required sub-structures
- [x] `Shared/Core/Logging.ps1`, `Shared/Core/Config.ps1`, `Shared/Core/Exclusions.ps1` present
- [x] `Shared/Export/` modules for CSV, JSON, HTML exist

## Gate 1: Core Infrastructure
- [x] `Initialize-AuditState` returns fully populated state hashtable
- [x] `Write-AuditLog` writes to buffer and flushes at threshold
- [x] `Invoke-AzureCommand` wraps calls with retry + circuit breaker
- [x] `Write-Finding` normalizes evidence, applies severity filter, checks exclusions
- [x] `Register-AuditCheck` adds checks to `$script:State.CheckRegistry`
- [x] `Invoke-AuditChecks` orchestrates by Phase (TenantWide, then PerSubscription)

## Gate 2: Azure Checks
- [x] All Azure check files register via `Register-Azure*Checks`
- [x] Checks cover: Storage, SQL, Network, KeyVault, Compute, Identity, Monitoring, DataPlatform, Messaging, AppService, LogicApps
- [x] Each check uses `Write-Finding` with proper severity/service/remediation

## Gate 3: Export Pipeline
- [x] CSV export with timestamp-stamped filenames
- [x] JSON export with structured output
- [x] HTML report generation with severity color-coding
- [x] `Show-AuditSummary` prints final statistics

## Gate 4: Entra Design Compliance
- [x] `Invoke-EntraCollection` called ONCE, outside subscription loops (via `Invoke-AzureMapCollection` in `Products/EntraMap/Core/Collection.ps1`, invoked by `entramap.ps1`)
- [x] TenantWide checks do NOT run inside per-subscription loops
- [x] No Entra check file (except `Collect.ps1`) calls `Invoke-GraphCommand` or `Invoke-GraphBatch`
- [x] PIM endpoints (`roleEligibilitySchedules`, `roleAssignmentSchedules`) use beta API version
- [x] PIM endpoints gated behind `-UseGraphBeta` flag
- [x] When beta is skipped, INFO finding emitted ("PIM data not collected -- use -UseGraphBeta")
- [x] All Entra checks registered with `Phase = "TenantWide"`
- [x] Severity alignment matches spec:
  - CRITICAL: `Test-EntraPrivilegedRoleAssignments`, `Test-EntraDangerousServicePrincipalPermissions`, `Test-EntraRoleAssignableGroups`, `Test-EntraOwnershipRisks`
  - HIGH: `Test-EntraOAuthConsentRisks`, `Test-EntraAppCredentialHygiene`, `Test-EntraExternalCollaborationRisks`
  - Beta-gated: `Test-EntraPIMEligibleAssignments` (HIGH)

## Gate 5: BlackCat-Inspired Improvements
- [x] **Multi-layer cache** (`Shared/Core/Cache.ps1`): Graph, AzBatch, General tiers with TTL, LRU eviction, GZip compression (>1KB)
- [x] **Cacheable-operation wrapper** (`Invoke-CacheableOperation`): cache-check → execute → store pattern
- [x] **Resource Graph batching** (`Products/AzureMap/Core/ResourceGraph.ps1`): `Invoke-ResourceGraphQuery` with `$skipToken` pagination + `Search-AzGraph` fallback
- [x] **Permission risk mapping** (`ReferenceData/`): `privileged-roles.json` (20 roles), `permission-escalation-map.json` (24 dangerous perms)
- [ ] **Parallel per-subscription processing**: Declared (`-Parallel` switch) but NOT YET IMPLEMENTED — known gap
- [x] **Config knobs** (`Shared/Core/State.ps1`): `MaxRetryAttempts`, `RetryDelaySeconds`, `MaxRetryDelaySeconds`, `BatchSize`, `PageSize` + `$script:MaxCacheSize` in Cache.ps1

## Gate 6: Tests & Static Analysis
- [x] Pester tests pass: 38/38 (CheckRegistry, Config, Retry)
- [x] PSScriptAnalyzer: 0 errors, warnings only (PSUseSingularNouns, PSAvoidUsingWriteHost — by design for console tool)
- [x] No `Error`-severity PSScriptAnalyzer findings in AzureMap source
- [x] This `PR-GATE.md` checklist created

---

### Known Gaps (to address in future PRs)
1. **Parallel subscription processing** — not implemented; the legacy `-Parallel` switch declaration was dropped in the modular rewrite. Blueprint item 2.6.
2. **Resource Graph migration** — `Invoke-ResourceGraphQuery` exists but no Azure checks use it yet. Blueprint item 2.5.
3. **Adaptive environment sizing** — Not yet implemented. Blueprint item A5.
4. **Integration tests** — Only unit tests exist for Core modules. No integration or Entra mock tests yet.
