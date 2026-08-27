\# AzureMap Architecture



Main entrypoint:

\- azuremap.ps1



Main folders:

\- Core/

\- Checks/Azure/

\- Checks/Entra/

\- Export/

\- Tests/Unit/



Core concepts:

\- Checks are registered centrally.

\- Checks run as TenantWide or PerSubscription.

\- Azure-only mode uses -SkipEntra.

\- Graph/Entra checks require Graph collection.

\- Findings are created through Write-Finding / New-AzureMapFinding.

\- Results are exported to JSON, CSV, and HTML.



Important files:

\- Core/CheckRegistry.ps1

\- Core/RunStatus.ps1

\- Core/Console.ps1

\- Core/Collection.ps1

\- Export/Json.ps1

\- Export/Csv.ps1

\- Export/Html.ps1



Current architectural weakness:

Coverage and Status are not yet strongly linked.

## Perf phase: inventory cache, proven-empty gating, timing

Per-run inventory cache (Core/InventoryCache.ps1):

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

Timing (State.Timing, Get-PerformanceSummary in Core/Logging.ps1):

- Per-check DurationSeconds on execution records (Complete-CheckExecutionRecord).
- Phase totals (Discovery/Collection/Assessment/Export) and per-subscription
  collection seconds (State.Timing.SubscriptionFetchSeconds).
- CLI summary gains a Performance section (phases, slowest checks top 10,
  slowest subscriptions top 10, total runtime); JSON gains a Performance
  block. HTML/console finding rendering is unchanged.



## Phase B2: capability / attack-path modeling (read-only)

Core/CapabilityModel.ps1 builds a capability graph + grouped insights AFTER
assessment (azuremap.ps1 step 9.5, timed as the CapabilityModel phase) from
already-collected data only: finding evidence (State.Results), the inventory
cache (State.Cache.ResourceLists), the RBAC cache (State.Cache.RBACAssignments)
and the footprint. It performs NO Azure/Graph API calls, never retrieves
keys/secrets/SAS/tokens/content and never executes write actions (enforced by
source-grep tests).

- Model: Nodes (Id/Type/Name/Scope/ResourceType/Sensitivity/Exposure), Edges
  (From/To/Type/Capability/SourceCheckIds/Confidence/Severity/Reason, deduped
  on From|To|Capability), Insights (grouped, severity-sorted, ids CAP-001..).
- 7 builders: storage key capability (Shared Key + key-retrieval RBAC -
  well-known role names OR custom roles whose cached definition Actions grant
  the key-list action, matched statically via Test-CapabilityKeyListCapableActions;
  modeled only, never invoked), public storage exposure combination, public
  workload + privileged identity, managed identity blast radius, Key Vault
  exposure combination, network exfiltration paths, monitoring gaps on exposed
  critical resources. Custom role definitions fetched by IDENTITY-005 are
  retained in State.Cache.RoleDefinitions (in-memory only) for this matching.
- Severity discipline: CRITICAL only for combined confirmed high-impact
  paths; single-condition evidence never escalates. Confidence: High =
  directly confirmed by collected metadata, Medium = inferred from
  role/scope combination.
- Caps: 100 insights / 500 nodes / 1000 edges / 50 impacted resources per
  insight (full count preserved). Truncation counters in Limits.
- Output: CLI shows top 5 insights only (Core/Console.ps1); HTML gains a
  Capability Insights section (insight cards + capped graph table); JSON
  gains a top-level CapabilityModel block. CSV unchanged.



## Phase B1: Status x Coverage contract

Canonical check statuses (Core/RunStatus.ps1):

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

\- Checks/Azure/Storage.ps1 (New-StorageCoverage / New-StorageCoverageParams
  helpers; all five STORAGE checks emit explicit status + coverage).


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

Environment footprint (Core/Footprint.ps1):

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

\- Test-AzureSubscriptionScope (Core/Preflight.ps1): when neither
  Get-AzSubscription nor the current Az context yields a usable subscription
  (and the run is not Entra-only), azuremap.ps1 stops before collection/checks
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
\- Mode skips are visible: Entra checks under -SkipEntra (and Azure checks
  under -EntraOnly) are recorded as Skipped with the mode reason instead of
  vanishing from the run.
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

