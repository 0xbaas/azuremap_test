# AzureMap / EntraMap Architecture

## Product split

Two products share one core; the repository is split into product and shared
trees:

```
azuremap.ps1 / entramap.ps1      # root compatibility wrappers (param pass-through)
Products/
  AzureMap/                      # real azuremap.ps1 entrypoint
    Core/       ResourceGraph, Footprint, InventoryCache, Rbac, Preflight.Azure
    Capability/ CapabilityModel.Azure
    Checks/     ARM check modules (45 checks)
    Docs/       AzureMap.md
  EntraMap/                      # real entramap.ps1 entrypoint
    Core/       Graph, Collection, TenantWide, Footprint.Entra, Preflight.Entra
    Capability/ CapabilityModel.Entra
    Checks/     Entra + tenant-identity check modules
    Docs/       EntraMap.md
Shared/
  Core/         State, Logging, Config, Exclusions, Console, RunStatus,
                CheckRegistry, Retry, Cache, Redaction, Preflight, Capability
  Export/       Csv, Json, Html, Summary
ReferenceData/  privileged-roles.json, permission-escalation-map.json
Tests/
  AzureMap/     tests exercising AzureMap product code
  EntraMap/     tests exercising EntraMap product code
  Shared/       shared-framework and cross-product composition tests
  Integration/  offline equivalence checks
  Fixtures/     canned API/test data
```

- `azuremap.ps1` (root wrapper → `Products/AzureMap/azuremap.ps1`) — AzureMap,
  the Azure (ARM control-plane) product. Loads `Shared/Core/` +
  `Products/AzureMap/{Core,Capability,Checks}` + `Shared/Export/`. Never loads
  Graph code and never acquires a Microsoft Graph token. Deprecated switches:
  `-SkipEntra` (no-op; Azure-only is the only mode), `-EntraOnly` (prints
  guidance to use `entramap.ps1` and stops).
- `entramap.ps1` (root wrapper → `Products/EntraMap/entramap.ps1`) — EntraMap,
  the Entra ID (Microsoft Graph) product. Loads `Shared/Core/` +
  `Products/EntraMap/{Core,Capability,Checks}` + `Shared/Export/`. Uses an Az
  context only as the token vehicle; performs no subscription discovery and no
  ARM scanning. Runs TenantWide checks only (`Invoke-AuditChecks -Phase
  TenantWide -Subscriptions @()`). Flow: preflight → Assessment scope block →
  check registration → tenant discovery (`Build-EntraFootprint`) → assessment
  plan (with Graph permission-limited count) → collection → checks → Entra
  capability model → summary/exports.

Run modes: Azure-only (AzureMap), Graph-only (EntraMap). A combined run
loading both product cores in one session is a possible future mode, not a
current entrypoint.

Shared core contract (`Shared/Core/`): Logging, Console, State (base
`Initialize-AuditState` + per-product wrappers layering product slots onto an
optional existing state), RunStatus, CheckRegistry, Retry, Cache, Config,
Exclusions, Redaction, Capability primitives (`Shared/Shared/Core/Capability.ps1`),
and the `Shared/Export/` modules. `ReferenceData/` stays at the repo root;
both JSON files are currently consumed only by EntraMap collection
(`Products/EntraMap/Checks/Collect.ps1`).

Product cores:

- `Products/AzureMap/Core/`: ResourceGraph, Footprint, InventoryCache, Rbac,
  Preflight.Azure (`Test-AzureAuthPreflight`, `Test-AzureSubscriptionScope`);
  `Products/AzureMap/Capability/`: CapabilityModel.Azure.
- `Products/EntraMap/Core/`: Graph (`Get-GraphToken`, `Get-GraphTokenScopeInfo`,
  `Invoke-GraphCommand/Batch`, all GET-only), Collection
  (`Invoke-AzureMapCollection`), TenantWide (`Get-TenantWideData`),
  Footprint.Entra (`Build-EntraFootprint`, `Show-EntraFootprint`,
  `Show-EntraAssessmentScope`), Preflight.Entra (`Test-EntraAuthPreflight`);
  `Products/EntraMap/Capability/`: CapabilityModel.Entra
  (`Build-EntraCapabilityModel`).

Both products are discovery-first: AzureMap runs Get-EnvironmentFootprint
after subscription discovery and before checks; EntraMap runs
Build-EntraFootprint (tenant discovery) after check registration and before
the assessment plan/collection, so the operator sees the environment shape
and any permission-limited surface up front.

Check layout:

- `Products/AzureMap/Checks/` — 45 ARM checks (incl. per-subscription
  IDENTITY-003/005/006/007), registered via `Register-Azure*Checks`.
- `Products/EntraMap/Checks/` — ENTRA-01..12 plus the relocated tenant-wide
  identity checks IDENTITY-001/002/004 (`TenantIdentity.ps1`; CheckIds and
  logic unchanged), registered as hashtable definitions returned by
  `Register-Entra*Checks`.

Core concepts:

- Checks are registered centrally (State.CheckRegistry).
- Checks run as TenantWide or PerSubscription.
- Findings are created through Write-Finding / New-AzureMapFinding.
- Results are exported to JSON, CSV, and HTML.

Important files:

- Shared/Core/CheckRegistry.ps1
- Shared/Shared/Core/RunStatus.ps1
- Shared/Shared/Core/Console.ps1
- Products/EntraMap/Core/Collection.ps1
- Shared/Export/Json.ps1
- Shared/Export/Csv.ps1
- Shared/Export/Html.ps1



Current architectural weakness:

Coverage and Status are not yet strongly linked.

## Perf phase: inventory cache, proven-empty gating, timing

Per-run inventory cache (Products/AzureMap/Core/InventoryCache.ps1):

- Get-SubscriptionInventory -Kind <Kind> returns @{ Items; ProvenEmpty;
  Unavailable; UnavailableReason ('ContextSwitch'|'Fetch'); FromCache } for a
  (subscription, kind) pair, fetched at most once per run and shared by all
  checks (e.g. one Get-AzStorageAccount enumeration serves all six storage
  checks). In-memory only (State.Cache.ResourceLists); never written to disk.
- $script:InventoryKindMap maps each kind to its ARM types and its read-only
  Get-* list call. StorageAccounts includes AccountSasPolicy when supported
  (superset); VirtualMachines uses Get-AzVM -Status (superset).
- Proven-empty gating: when the footprint is Complete/High-confidence AND
  Footprint.TypeCountsBySub (subId -> type -> count, built by both the ARG and
  Get-AzResource footprint paths) proves the kind absent in that subscription,
  enumeration is skipped entirely (no context switch, no ARM call). Any doubt
  (partial/low-confidence footprint, subscription missing from per-sub data)
  means enumerate. Semantically identical to a successful empty list.
- Failure records are cached too (denied-call guard): a failed fetch or
  context switch is classified once per (subscription, kind) and never
  retried; callers map UnavailableReason to the old ctx-fail vs
  collection-failed coverage paths.
- Checks with nested per-resource Az calls still call Set-SubscriptionContext
  after reading inventory (required on cache hits); Set-SubscriptionContext is
  deduped via Get-AzContext, so it is a no-op when the session is already on
  the target subscription.
- RBAC: IDENTITY-005/006 reuse the cached subscription-scope RBAC read
  (Get-SubscriptionRBACAssignments) with client-side ObjectId/RoleDefinitionId
  filters instead of per-resource/per-role Get-AzRoleAssignment calls.

Timing (State.Timing, Get-PerformanceSummary in Shared/Core/Logging.ps1):

- Per-check DurationSeconds on execution records (Complete-CheckExecutionRecord).
- Phase totals (Discovery/Collection/Assessment/Export) and per-subscription
  collection seconds (State.Timing.SubscriptionFetchSeconds).
- CLI summary gains a Performance section (phases, slowest checks top 10,
  slowest subscriptions top 10, total runtime); JSON gains a Performance
  block. HTML/console finding rendering is unchanged.



## Phase B2: capability / attack-path modeling (read-only)

Capability modeling is per-product, built on the shared primitives in
Shared/Core/Capability.ps1 (model version, output caps, context, node/edge/insight
constructors with dedupe + truncation, evidence readers). Each entrypoint
runs its own builder after assessment (step 8.5, timed as the CapabilityModel
phase): azuremap.ps1 calls Build-CapabilityModel
(Products/AzureMap/Capability/CapabilityModel.Azure.ps1), entramap.ps1 calls
Build-EntraCapabilityModel (Products/EntraMap/Capability/CapabilityModel.Entra.ps1). Both build
from already-collected data only and perform NO Azure/Graph API calls, never
retrieve keys/secrets/SAS/tokens/content and never execute write actions
(enforced by source-grep tests; the Entra model is additionally pinned by a
runtime test with all Graph/Azure entry points stubbed to throw).

Azure builders read finding evidence (State.Results), the inventory cache
(State.Cache.ResourceLists), the RBAC cache (State.Cache.RBACAssignments) and
the footprint. Entra builders read finding evidence (State.Results), the
Entra collection (State.Entra, e.g. PrincipalCache for guest classification),
tenant-wide data and the tenant footprint (State.EntraFootprint).

- Model: Nodes (Id/Type/Name/Scope/ResourceType/Sensitivity/Exposure), Edges
  (From/To/Type/Capability/SourceCheckIds/Confidence/Severity/Reason, deduped
  on From|To|Capability), Insights (grouped, severity-sorted, ids CAP-001..).
  Both products emit the same model shape so the shared renderers work
  unchanged.
- 7 Azure builders: storage key capability (Shared Key + key-retrieval RBAC -
  well-known role names OR custom roles whose cached definition Actions grant
  the key-list action, matched statically via Test-CapabilityKeyListCapableActions;
  modeled only, never invoked), public storage exposure combination, public
  workload + privileged identity, managed identity blast radius, Key Vault
  exposure combination, network exfiltration paths, monitoring gaps on exposed
  critical resources. Custom role definitions fetched by IDENTITY-005 are
  retained in State.Cache.RoleDefinitions (in-memory only) for this matching.
- 10 Entra builders: permanent privileged role assignments (Critical role + no
  PIM eligible + no admin-MFA policy combination), PIM without strong
  activation controls, high-privilege Graph app permissions, dangerous
  permissions + weak ownership, long-lived app credentials (metadata only),
  role-assignable groups, guest/external privileged access, break-glass/GA
  hygiene, workload identity federation into privileged apps, Conditional
  Access coverage gaps.
- Severity discipline: CRITICAL only for combined confirmed high-impact
  paths; single-condition evidence never escalates. Confidence: High =
  directly confirmed by collected metadata, Medium = inferred from
  role/scope combination (Entra adds Low for heuristic-only findings that
  need manual validation).
- Caps: 100 insights / 500 nodes / 1000 edges / 50 impacted resources per
  insight (full count preserved). Truncation counters in Limits.
- Output: CLI shows top 5 insights only (Shared/Core/Console.ps1); HTML gains a
  Capability Insights section (insight cards + capped graph table); JSON
  gains a top-level CapabilityModel block. CSV unchanged.



## Phase B3: data-plane gating

Data-plane checks are opt-in (-IncludeDataPlane) and disabled by default; a
default run is control-plane only. Registration flag RequiresDataPlane on the
check definition gates execution (Skipped: data-plane checks disabled) and
flows to execution records (DataPlaneRequired) so exports can show gated
checks even when they never ran. Only STORAGE-004 (blob container names +
public-access levels) and KEYVAULT-003 (secret name/enabled/created/expires)
are data-plane checks; both read safe metadata only - never secret values,
keys, SAS tokens, connection strings, or blob/file content. Permission
failures degrade to Partial/NotEvaluated with coverage metadata, never to a
false Pass. JSON Metadata.DataPlaneIncluded records the mode.



## Phase B1: Status x Coverage contract

Canonical check statuses (Shared/Core/RunStatus.ps1):

\- PASS, FAIL, PARTIAL, WARNING, NOTEVALUATED, ERROR.

Resolve-CheckStatus precedence:

\- Threw -> ERROR; else worst finding status wins:
  FAIL > PARTIAL > WARNING > NOTEVALUATED > PASS.

\- A check that produces zero findings resolves to NOTEVALUATED,
  never PASS. Silence is not proof of evaluation.

PASS semantics:

\- PASS requires successful collection AND (resources evaluated with no
  issues OR proof that no resources exist in scope).

\- PASS is never inferred from Count = 0 alone.

\- Proven-empty scope (complete coverage, 0 resources discovered) is
  reported at INFO severity; clean passes over evaluated resources keep
  the check's default severity.

\- Zero-risky coverage records (PASS or PARTIAL, Count = 0) are INFO and
  are NOT printed as per-finding console blocks; they surface via the
  per-check Check Results line. NOTEVALUATED/ERROR Count = 0 records
  still print with a '!' icon (never a green checkmark).

Finding/reporting fields (optional, emitted by coverage-aware checks):

\- CountType: what Count enumerates (UniqueResources / Containers /
  RoleAssignments / RiskSignals / Observations / NotEvaluatedItems).
  NotEvaluatedItems are never affected. Display layers map it to a short
  label via Get-CountTypeLabel (Shared/Core/Console.ps1; fallback 'affected')
  and attach static per-finding caveats from $script:FindingCaveatMap
  (presentation only - no severity/status logic).

\- DiscoveredResourceCount, EvaluatedResourceCount, SkippedResourceCount,
  FailedCollectionCount (use `$null` for "unknown", never fake 0).

\- SubscriptionsEvaluated, SubscriptionsSkipped.

\- CollectionStatus: Complete / Partial / Failed.

\- CompleteEvaluation, PartialEvaluation, CoverageSummary.

\- SummaryText, TechnicalSummary, Confidence, FindingType, ApiSources,
  DataPlaneRequired, ManualValidationRequired.

Execution records (Invoke-AuditChecks) aggregate produced findings via
Get-CheckCoverage (counts: Max across findings, subscriptions: union).

Exports and console must preserve explicit Status and Coverage;

\- JSON/CSV/HTML/CLI never recompute status from finding Count.

Reference implementation:

\- Products/AzureMap/Checks/Storage.ps1 (New-StorageCoverage / New-StorageCoverageParams
  helpers; all seven STORAGE checks emit explicit status + coverage).


Status model (UX phase addition):

\- NotApplicable = the environment footprint proves no relevant resources exist
  in scope. Distinct from NotEvaluated (relevant resources may exist but the
  check could not evaluate). Inventory/context records (IsInventoryOnly) never
  fail a check by themselves; a check whose produced records are ALL
  inventory-only resolves to the display status Inventory (never plain Pass).

Applicability:

\- Register-AuditCheck accepts RequiredResourceTypes / AlwaysRun /
  RequiresDataPlane. Before a check runs, Get-CheckApplicability consults
  State.Footprint.TypeCounts; absent types -> NotApplicable, footprint
  unavailable -> check runs (unknown is never treated as empty).
\- NotApplicable additionally requires a HIGH-confidence footprint
  (CoverageStatus = Complete, Confidence = High). Partial or low-confidence
  footprints disable applicability gating entirely (checks run).

Environment footprint (Products/AzureMap/Core/Footprint.ps1):

\- Get-EnvironmentFootprint runs after subscription discovery, before checks.
  Read-only: Azure Resource Graph preferred, Get-AzResource per subscription as
  fallback (Set-AzContext local switch only). Stored in State.Footprint,
  exported to JSON and shown in CLI + HTML.
\- ARG scoping is verified: a ResourceContainers subscription query proves
  which in-scope subscriptions ARG actually covered. Subscriptions ARG missed
  are enumerated via the Get-AzResource fallback and merged; any subscription
  that remains uncovered makes the footprint Partial / Low confidence.
  A suspiciously narrow result (single resource type across 3+ subscriptions)
  is also forced to Low confidence. NotApplicable is never derived from a
  low-confidence footprint.

Scope guard:

\- Test-AzureSubscriptionScope (Products/AzureMap/Core/Preflight.Azure.ps1): when neither
  Get-AzSubscription nor the current Az context yields a usable subscription,
  azuremap.ps1 stops before collection/checks
  with an actionable message instead of emitting an empty report.

CLI output discipline:

\- Human display labels, not raw internal statuses: the console maps
  Pass=Clean, Fail=Needs review, Partial=Partially checked,
  NotEvaluated=Could not check, NotApplicable=Not in scope, Skipped=Skipped,
  Error=Tool error, Inventory=Inventory (Get-StatusDisplayInfo). Internal
  statuses stay verbatim in JSON/CSV/HTML and tests.
\- Per-check lines are grouped under domain section headers (Identity, Key
  Vault, Storage, Networking, Data platforms, Compute & apps, Messaging &
  integration, Monitoring & governance, Exposure) and lead with a curated
  display name (CheckDisplayNames); the CheckId is muted secondary metadata
  at the end of the line. Checks execute in domain order within each phase
  so sections print contiguously.
\- Mode skips are visible: each entrypoint registers only its own product's
  checks, so cross-product checks no longer appear at all; in-product skips
  (e.g. data-plane checks without -IncludeDataPlane) are recorded as Skipped
  with the reason instead of vanishing from the run.
\- Show-AssessmentPlan prints planned/relevant/skipped-by-mode/not-in-scope
  counts before execution.
\- The log file is the system of record; the console is an operator summary.
  Write-AuditLog prints nothing by default: INFO appears under
  -VerboseOutput, raw WARN/ERROR only under -DebugOutput; -ForceConsole
  (preflight/fatal guidance) always prints. Legacy ===== section banners
  (Write-Section) render only under -DebugOutput.
\- Per-check errors are bucketed per check (State.CheckErrors, GUIDs and
  subscription names normalized away); the most frequent reason becomes the
  check-line summary and one "Details saved to <log>" line points to the log.
\- Footprint fallback (ARG -> Get-AzResource) is silent on success;
  "Environment discovery incomplete" warns only when discovery is genuinely
  partial (and applicability gating is disabled).
\- Finding blocks deduped per CheckId+Severity+Message; blocks print only
  under -ShowFindings/-VerboseOutput, remediation text only under
  -ShowRemediation. Not in scope / Skipped rows and the final Check results
  section render only under -DetailedSummary.
\- -NoColor flag and NO_COLOR env var disable colors (Write-UiHost).
\- Severity colors follow a CVSS-like ramp: INFO #38A8DC, LOW #9BE7A1,
  MEDIUM #D6A84B, HIGH #E68A3A, CRITICAL #F05252; Needs review derives its
  color from the check severity when known.


AzureMap visual identity:
Clean charcoal/graphite dark mode with Azure-cyan BAAS accent.

Base:    #111214
Surface: #1D1F23
Border:  #30343A
Accent:  #38A8DC
Text:    #F1F3F5
Muted:   #9AA5B1
Warning: #D6A84B

